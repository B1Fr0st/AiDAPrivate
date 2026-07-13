#include "symbol_type_candidates.hpp"

#include "../readers/elf_reader.hpp"
#include "../readers/macho_reader.hpp"
#include "../readers/managed/managed_reader_contracts.hpp"
#include "../readers/pe_coff_reader.hpp"
#include "checked_range.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <map>
#include <new>
#include <set>
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
    symbol_type_candidate_result_t result;
    std::vector<pending_relation_t> pending_relations;
    std::uint64_t result_bytes = 0;
    std::uint64_t string_bytes = 0;
    std::uint64_t checks = 0;
    const auto poll = [&]() -> workspace_result_t<void> {
        if (++checks < limits.cancellation_check_interval)
            return workspace_result_t<void>::success();
        checks = 0;
        return cancel.stop_requested()
            ? workspace_result_t<void>::failure(stop_error(cancel))
            : workspace_result_t<void>::success();
    };
    const auto charge = [&](std::uint64_t fixed, std::uint64_t strings)
        -> workspace_result_t<void> {
        if (!checked_add_u64(string_bytes, strings, string_bytes) ||
            string_bytes > limits.max_string_bytes ||
            !checked_add_u64(fixed, strings, fixed) ||
            !checked_add_u64(result_bytes, fixed, result_bytes) ||
            result_bytes > limits.max_result_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "symbol and type candidate storage exceeds its bound",
                "symbol_type_candidates"));
        }
        return workspace_result_t<void>::success();
    };
    const auto append_symbol = [&](address_t address, std::string name,
        symbol_kind_t kind, fact_provenance_t provenance, std::uint8_t confidence)
        -> workspace_result_t<void> {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (name.empty() || confidence > 100 || result.symbols.size() >= limits.max_symbols) {
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
        result.symbols.push_back(std::move(symbol));
        return workspace_result_t<void>::success();
    };
    const auto append_type = [&](symbol_type_candidate_record_t candidate)
        -> workspace_result_t<void> {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (candidate.display_name.empty() || candidate.confidence > 100 ||
            result.type_candidates.size() >= limits.max_type_candidates) {
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
        result.type_candidates.push_back(std::move(candidate));
        return workspace_result_t<void>::success();
    };
    const auto append_pending = [&](pending_relation_t relation)
        -> workspace_result_t<void> {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (pending_relations.size() >= limits.max_type_references) {
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
        pending_relations.push_back(std::move(relation));
        return workspace_result_t<void>::success();
    };
    const auto append_conflict = [&](metadata_conflict_record_t conflict)
        -> workspace_result_t<void> {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (result.conflicts.size() >= limits.max_conflicts) {
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
        result.conflicts.push_back(std::move(conflict));
        return workspace_result_t<void>::success();
    };
    for (const auto& imported : image.imports) {
        const auto address = canonical_address(image, imported.address);
        if (!address)
            continue;
        std::string name = imported.library;
        name.push_back('!');
        name += imported.name.value_or("#" + std::to_string(imported.ordinal.value_or(0)));
        auto appended = append_symbol(*address, name, symbol_kind_t::import_symbol,
            fact_provenance_t::relocation, 100);
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        symbol_type_candidate_record_t type;
        type.address = *address;
        type.kind = symbol_type_candidate_kind_t::import_prototype;
        type.display_name = std::move(name);
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "import:" + type.display_name;
        type.provenance = metadata_provenance_t::import_metadata;
        type.confidence = 100;
        auto typed = append_type(std::move(type));
        if (!typed)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(typed.error());
    }
    for (const auto& exported : image.exports) {
        const auto address = canonical_address(image, exported.address);
        if (!address)
            continue;
        const auto name = exported.name.value_or("ordinal_" + std::to_string(exported.ordinal));
        const auto kind = executable(image, *address) && !exported.forwarder
            ? symbol_kind_t::function : symbol_kind_t::export_symbol;
        auto appended = append_symbol(*address, name, kind,
            fact_provenance_t::export_entry, 100);
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
    }
    for (const auto& source : image.symbols) {
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
        auto appended = append_symbol(*address, source.name, kind, provenance,
            source.binding == image_symbol_binding_t::local ? 85 : 92);
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
    }
    if (metadata.elf) {
        for (const auto& source : metadata.elf->symbol_seeds) {
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
            auto appended = append_symbol(*address, source.name, kind, provenance,
                source.weak ? 78 : 90);
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        }
        for (const auto& seed : metadata.elf->type_seeds) {
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
            auto appended = append_type(std::move(type));
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        }
    }
    if (metadata.pe_coff) {
        for (const auto& seed : metadata.pe_coff->type_seeds) {
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
            auto appended = append_type(std::move(type));
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        }
    }
    if (metadata.macho) {
        for (const auto& slice : metadata.macho->slices) {
            if (slice.identity.architecture != image.architecture)
                continue;
            const auto slice_key = slice.identity.stable_key();
            for (const auto& source : slice.symbols) {
                const auto address = canonical_value(image, source.value);
                if (!address || source.name.empty())
                    continue;
                const auto kind = executable(image, *address)
                    ? symbol_kind_t::function : symbol_kind_t::data;
                auto appended = append_symbol(*address, source.name, kind,
                    fact_provenance_t::linear_validation, 88);
                if (!appended)
                    return workspace_result_t<symbol_type_candidate_result_t>::failure(
                        appended.error());
            }
            for (const auto& binding : slice.bindings) {
                const auto address = canonical_value(image, binding.address);
                if (!address || binding.symbol.empty())
                    continue;
                auto appended = append_symbol(*address, binding.symbol,
                    symbol_kind_t::import_symbol, fact_provenance_t::relocation, 96);
                if (!appended)
                    return workspace_result_t<symbol_type_candidate_result_t>::failure(
                        appended.error());
            }
            for (const auto& exported : slice.exports) {
                const auto address = canonical_value(image, exported.address);
                if (!address || exported.name.empty())
                    continue;
                auto appended = append_symbol(*address, exported.name,
                    executable(image, *address) ? symbol_kind_t::function
                                                : symbol_kind_t::export_symbol,
                    fact_provenance_t::export_entry, 98);
                if (!appended)
                    return workspace_result_t<symbol_type_candidate_result_t>::failure(
                        appended.error());
            }
            for (const auto& seed : slice.metadata_seeds) {
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
                auto appended = append_type(std::move(type));
                if (!appended)
                    return workspace_result_t<symbol_type_candidate_result_t>::failure(
                        appended.error());
            }
        }
    }
    for (const auto* artifact : metadata.managed_artifacts) {
        if (!artifact || !artifact->valid())
            continue;
        const auto module = artifact->module_identity.assembly_name + ":" +
            artifact->module_identity.module_name;
        std::map<std::uint32_t, std::string> method_keys;
        for (const auto& source : artifact->types) {
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
            auto appended = append_type(type);
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
            if (source.base_type_name && !source.base_type_name->empty()) {
                pending_relation_t relation;
                relation.source_key = type.source_key;
                relation.target_name = *source.base_type_name;
                relation.kind = type_reference_kind_t::inheritance;
                relation.provenance = metadata_provenance_t::managed_metadata;
                relation.confidence = 100;
                auto related = append_pending(std::move(relation));
                if (!related)
                    return workspace_result_t<symbol_type_candidate_result_t>::failure(
                        related.error());
            }
        }
        for (const auto& source : artifact->methods) {
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
                auto symbol = append_symbol(*type.address, type.display_name,
                    symbol_kind_t::function, fact_provenance_t::debug_symbol, 100);
                if (!symbol)
                    return workspace_result_t<symbol_type_candidate_result_t>::failure(
                        symbol.error());
            }
            auto appended = append_type(std::move(type));
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        }
        for (const auto& source : artifact->fields) {
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
            auto appended = append_type(std::move(type));
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        }
        for (const auto& reference : artifact->member_references) {
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
            auto appended = append_pending(std::move(relation));
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        }
    }
    std::set<std::uint64_t> named_functions;
    for (const auto& symbol : result.symbols) {
        if (symbol.kind == symbol_kind_t::function)
            named_functions.insert(symbol.address.value);
    }
    for (const auto& function : functions) {
        const auto address = canonical_address(image, function.start);
        if (!address)
            continue;
        const auto name = "sub_" + hex_value(address->value);
        if (named_functions.find(address->value) == named_functions.end()) {
            auto appended = append_symbol(*address, name, symbol_kind_t::function,
                function.provenance, function.confidence);
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
        }
        symbol_type_candidate_record_t type;
        type.address = *address;
        type.kind = symbol_type_candidate_kind_t::function_prototype;
        type.display_name = name;
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "function:" + hex_value(address->value);
        type.provenance = metadata_from_fact(function.provenance);
        type.confidence = function.confidence;
        auto appended = append_type(std::move(type));
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
    }
    for (const auto& data : data_candidates) {
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
        auto appended = append_type(std::move(type));
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
    }
    std::sort(result.symbols.begin(), result.symbols.end(), [](const auto& lhs,
                                                               const auto& rhs) {
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
    std::vector<symbol_record_t> symbols;
    symbols.reserve(result.symbols.size());
    for (const auto& symbol : result.symbols) {
        if (symbols.empty() || symbols.back().address != symbol.address ||
            symbols.back().name != symbol.name) {
            symbols.push_back(symbol);
            continue;
        }
        ++result.duplicate_symbols;
        const auto& selected = symbols.back();
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
        auto appended = append_conflict(std::move(conflict));
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
    }
    result.symbols = std::move(symbols);
    for (std::size_t index = 0; index < result.symbols.size(); ++index)
        result.symbols[index].id = kSymbolEntityTag | static_cast<std::uint64_t>(index + 1);
    for (const auto& symbol : result.symbols) {
        const auto classified = classify_name(symbol.name);
        if (!classified && symbol.kind != symbol_kind_t::type_symbol)
            continue;
        symbol_type_candidate_record_t type;
        type.address = symbol.address;
        type.kind = classified ? classified->first
            : symbol_type_candidate_kind_t::debug_type;
        type.display_name = symbol.name;
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "symbol:" + symbol.name + ":" + hex_value(symbol.address.value);
        type.provenance = classified ? classified->second
            : metadata_provenance_t::debug_metadata;
        type.confidence = (std::max)(symbol.confidence, static_cast<std::uint8_t>(88));
        type.explicitly_unknown = false;
        auto appended = append_type(std::move(type));
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(appended.error());
    }
    const auto pointer_width = static_cast<std::uint64_t>(image.address_width_bits / 8U);
    if (pointer_width == 4 || pointer_width == 8) {
        std::vector<const data_candidate_record_t*> pointers;
        pointers.reserve(data_candidates.size());
        for (const auto& data : data_candidates) {
            if (!data.target || !executable(image, *data.target))
                continue;
            const auto address = canonical_address(image, data.address);
            const auto target = canonical_address(image, *data.target);
            if (address && target && data.size == pointer_width)
                pointers.push_back(&data);
        }
        std::sort(pointers.begin(), pointers.end(), [&](const auto* lhs, const auto* rhs) {
            const auto left = to_rva(image, lhs->address).value_or(image.image_size);
            const auto right = to_rva(image, rhs->address).value_or(image.image_size);
            if (left != right)
                return left < right;
            return lhs->target < rhs->target;
        });
        std::size_t begin = 0;
        while (begin < pointers.size()) {
            std::size_t end = begin + 1;
            auto previous = to_rva(image, pointers[begin]->address).value_or(image.image_size);
            while (end < pointers.size()) {
                const auto current = to_rva(image, pointers[end]->address).value_or(image.image_size);
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
                if (address) {
                    std::string name = "vtable_" + hex_value(address->value);
                    for (const auto& symbol : result.symbols) {
                        if (symbol.address == *address && classify_name(symbol.name)) {
                            name = symbol.name;
                            break;
                        }
                    }
                    symbol_type_candidate_record_t type;
                    type.address = *address;
                    type.kind = symbol_type_candidate_kind_t::virtual_table;
                    type.display_name = name;
                    type.canonical_type = canonical_type_for(type.kind);
                    type.source_key = "vtable:" + hex_value(address->value);
                    type.provenance = metadata_provenance_t::vtable_validation;
                    type.confidence = 90;
                    type.explicitly_unknown = false;
                    const auto source_key = type.source_key;
                    auto appended = append_type(std::move(type));
                    if (!appended)
                        return workspace_result_t<symbol_type_candidate_result_t>::failure(
                            appended.error());
                    for (std::size_t index = 0; index < accepted; ++index) {
                        pending_relation_t relation;
                        relation.source_key = source_key;
                        relation.source = canonical_address(image, pointers[begin + index]->address);
                        relation.target = canonical_address(image, *pointers[begin + index]->target);
                        relation.kind = type_reference_kind_t::virtual_table_slot;
                        relation.provenance = metadata_provenance_t::vtable_validation;
                        relation.confidence = pointers[begin + index]->confidence;
                        auto related = append_pending(std::move(relation));
                        if (!related)
                            return workspace_result_t<symbol_type_candidate_result_t>::failure(
                                related.error());
                    }
                }
            }
            begin = end;
        }
    }
    std::sort(result.type_candidates.begin(), result.type_candidates.end(),
        [](const auto& lhs, const auto& rhs) {
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
    std::vector<symbol_type_candidate_record_t> types;
    types.reserve(result.type_candidates.size());
    for (const auto& type : result.type_candidates) {
        if (types.empty() || !same_type_identity(types.back(), type)) {
            types.push_back(type);
            continue;
        }
        ++result.duplicate_type_candidates;
        const auto& selected = types.back();
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
            return append_conflict(std::move(conflict));
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
        if (!conflict)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(conflict.error());
    }
    result.type_candidates = std::move(types);
    for (std::size_t index = 0; index < result.type_candidates.size(); ++index)
        result.type_candidates[index].id = kTypeEntityTag |
            static_cast<std::uint64_t>(index + 1);
    std::map<std::string, entity_id_t> key_to_entity;
    std::map<std::string, entity_id_t> name_to_entity;
    const auto append_reference = [&](type_reference_fact_t reference)
        -> workspace_result_t<void> {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (result.type_references.size() >= limits.max_type_references) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "type reference count exceeds its bound", "symbol_type_candidates"));
        }
        auto charged = charge(sizeof(type_reference_fact_t), reference.source_key.size());
        if (!charged)
            return charged;
        result.type_references.push_back(std::move(reference));
        return workspace_result_t<void>::success();
    };
    for (const auto& type : result.type_candidates) {
        key_to_entity.emplace(type.source_key, type.id);
        name_to_entity.emplace(type.display_name, type.id);
        if (type.address) {
            type_reference_fact_t reference;
            reference.source = type.address;
            reference.source_entity = type.id;
            reference.kind = type_reference_kind_t::definition;
            reference.provenance = type.provenance;
            reference.confidence = type.confidence;
            reference.source_key = type.source_key;
            auto appended = append_reference(std::move(reference));
            if (!appended)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(
                    appended.error());
        }
    }
    for (const auto& pending : pending_relations) {
        type_reference_fact_t reference;
        reference.source = pending.source;
        reference.target = pending.target;
        const auto source = key_to_entity.find(pending.source_key);
        if (source != key_to_entity.end())
            reference.source_entity = source->second;
        const auto target = name_to_entity.find(pending.target_name);
        if (target != name_to_entity.end())
            reference.target_entity = target->second;
        reference.kind = pending.kind;
        reference.provenance = pending.provenance;
        reference.confidence = pending.confidence;
        reference.source_key = pending.source_key;
        if (!pending.target_name.empty())
            reference.source_key += "->" + pending.target_name;
        auto appended = append_reference(std::move(reference));
        if (!appended)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(
                appended.error());
    }
    std::sort(result.type_references.begin(), result.type_references.end(),
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
    const auto reference_end = std::unique(result.type_references.begin(),
        result.type_references.end(), [](const auto& lhs, const auto& rhs) {
            return lhs.source == rhs.source && lhs.target == rhs.target &&
                   lhs.source_entity == rhs.source_entity &&
                   lhs.target_entity == rhs.target_entity && lhs.kind == rhs.kind;
        });
    result.duplicate_type_references = static_cast<std::uint64_t>(
        std::distance(reference_end, result.type_references.end()));
    result.type_references.erase(reference_end, result.type_references.end());
    for (std::size_t index = 0; index < result.type_references.size(); ++index)
        result.type_references[index].id = kTypeXrefEntityTag |
            static_cast<std::uint64_t>(index + 1);
    std::sort(result.conflicts.begin(), result.conflicts.end(), [](const auto& lhs,
                                                                   const auto& rhs) {
        return std::tie(lhs.address, lhs.identity, lhs.kind, lhs.selected_value,
                   lhs.rejected_value, lhs.selected_provenance,
                   lhs.rejected_provenance, lhs.selected_confidence,
                   lhs.rejected_confidence) <
               std::tie(rhs.address, rhs.identity, rhs.kind, rhs.selected_value,
                   rhs.rejected_value, rhs.selected_provenance,
                   rhs.rejected_provenance, rhs.selected_confidence,
                   rhs.rejected_confidence);
    });
    result.conflicts.erase(std::unique(result.conflicts.begin(), result.conflicts.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.address == rhs.address && lhs.identity == rhs.identity &&
                   lhs.kind == rhs.kind && lhs.selected_value == rhs.selected_value &&
                   lhs.rejected_value == rhs.rejected_value &&
                   lhs.selected_provenance == rhs.selected_provenance &&
                   lhs.rejected_provenance == rhs.rejected_provenance &&
                   lhs.selected_confidence == rhs.selected_confidence &&
                   lhs.rejected_confidence == rhs.rejected_confidence;
        }), result.conflicts.end());
    for (std::size_t index = 0; index < result.conflicts.size(); ++index)
        result.conflicts[index].id = kMetadataConflictEntityTag |
            static_cast<std::uint64_t>(index + 1);
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
