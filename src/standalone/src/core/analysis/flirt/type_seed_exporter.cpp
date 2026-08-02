#include "type_seed_exporter.hpp"

#include <algorithm>
#include <unordered_map>

namespace aida::analysis::static_recognition {
namespace {

address_t rva_address(std::uint64_t rva)
{
    return address_t{address_space_id_t::relative_virtual, rva,
                     architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

source_coordinate_t seed_coordinate(const decompiler_entity_key_t& entity,
                                    std::uint64_t generation,
                                    std::uint64_t rva)
{
    source_coordinate_t coordinate;
    coordinate.layer = decompiler_coordinate_layer_t::provider_ir;
    coordinate.workspace_generation = generation;
    coordinate.entity = entity;
    const auto begin = rva_address(rva);
    auto end = begin;
    ++end.value;
    coordinate.address_range = decompiler_address_range_t{begin, end};
    return coordinate;
}

std::string class_canonical(const std::string& name)
{
    return "class " + name;
}

std::string recovered_kind_token(recovered_type_kind_t kind, bool is_signed, std::uint16_t bits)
{
    switch (kind) {
    case recovered_type_kind_t::void_type: return "void";
    case recovered_type_kind_t::boolean: return "bool";
    case recovered_type_kind_t::integer:
        return (is_signed ? "int" : "uint") + std::to_string(bits == 0 ? 64 : bits) + "_t";
    case recovered_type_kind_t::floating_point:
        return bits == 32 ? "float" : "double";
    case recovered_type_kind_t::pointer: return "void*";
    case recovered_type_kind_t::function_type: return "function";
    case recovered_type_kind_t::function_pointer: return "function*";
    case recovered_type_kind_t::struct_type: return "struct";
    case recovered_type_kind_t::union_type: return "union";
    case recovered_type_kind_t::class_type: return "class";
    case recovered_type_kind_t::enum_type: return "enum";
    default: return "unknown";
    }
}

std::uint8_t clamp_confidence(int score)
{
    if (score <= 0)
        return 0;
    if (score >= 255)
        return 255;
    return static_cast<std::uint8_t>(score);
}

}

std::vector<type_recovery_evidence_t>
make_static_rtti_evidence(const recognition_records_t& records,
                          std::uint64_t image_base)
{
    const auto as_rva = [image_base](std::uint64_t value) {
        return image_base != 0 && value >= image_base ? value - image_base : value;
    };
    std::vector<type_recovery_evidence_t> out;
    if (records.rtti.types.empty())
        return out;
    for (const auto& type : records.rtti.types) {
        const std::uint8_t confidence = clamp_confidence(type.score);
        type_recovery_evidence_t class_evidence;
        class_evidence.subject.kind = type_subject_kind_t::rtti_type;
        class_evidence.subject.address = rva_address(as_rva(type.type_descriptor_rva));
        class_evidence.subject.stable_name = type.name;
        class_evidence.candidate.kind = recovered_type_kind_t::class_type;
        class_evidence.candidate.language = type_language_t::cpp;
        class_evidence.candidate.declared_name = type.name;
        class_evidence.provenance = type_evidence_provenance_t::rtti;
        class_evidence.kind = type_evidence_kind_t::rtti_descriptor;
        class_evidence.source_address = rva_address(as_rva(type.col_rva));
        class_evidence.confidence = confidence;
        class_evidence.detail = "static_rtti_scan";
        out.push_back(class_evidence);
        for (const auto& base : type.bases) {
            if (base.type_descriptor_va == 0 ||
                base.type_descriptor_va == type.type_descriptor_rva)
                continue;
            type_recovery_evidence_t inheritance;
            inheritance.subject.kind = type_subject_kind_t::rtti_type;
            inheritance.subject.address = rva_address(as_rva(type.type_descriptor_rva));
            inheritance.subject.stable_name = type.name;
            type_subject_t base_subject;
            base_subject.kind = type_subject_kind_t::rtti_type;
            base_subject.address = rva_address(as_rva(base.type_descriptor_va));
            base_subject.stable_name = base.name;
            inheritance.related_subject = base_subject;
            inheritance.candidate.kind = recovered_type_kind_t::unknown;
            inheritance.provenance = type_evidence_provenance_t::rtti;
            inheritance.kind = type_evidence_kind_t::inheritance;
            inheritance.source_address = rva_address(as_rva(base.base_descriptor_va));
            inheritance.confidence = confidence;
            inheritance.detail = "static_rtti_scan";
            out.push_back(std::move(inheritance));
        }
        for (const auto vtable_rva : type.vtable_rvas) {
            type_recovery_evidence_t vtable_evidence;
            vtable_evidence.subject.kind = type_subject_kind_t::virtual_table;
            vtable_evidence.subject.address = rva_address(as_rva(vtable_rva));
            vtable_evidence.subject.stable_name = type.name;
            vtable_evidence.candidate.kind = recovered_type_kind_t::class_type;
            vtable_evidence.candidate.language = type_language_t::cpp;
            vtable_evidence.candidate.declared_name = type.name;
            vtable_evidence.provenance = type_evidence_provenance_t::vtable;
            vtable_evidence.kind = type_evidence_kind_t::vtable_descriptor;
            vtable_evidence.source_address = rva_address(as_rva(vtable_rva));
            vtable_evidence.confidence = confidence;
            vtable_evidence.detail = "static_rtti_scan";
            out.push_back(vtable_evidence);
        }
    }
    for (const auto& slot : records.vtables.slots) {
        const re::rtti::static_rtti_type_t* owner = nullptr;
        for (const auto& type : records.rtti.types) {
            if (std::binary_search(type.vtable_rvas.begin(), type.vtable_rvas.end(), slot.vtable_rva)) {
                owner = &type;
                break;
            }
        }
        type_recovery_evidence_t slot_evidence;
        slot_evidence.subject.kind = type_subject_kind_t::virtual_slot;
        slot_evidence.subject.address = rva_address(as_rva(slot.vtable_rva + slot.slot_index * 8));
        slot_evidence.subject.ordinal = static_cast<std::uint32_t>(slot.slot_index);
        slot_evidence.subject.stable_name = owner ? owner->name : std::string();
        type_subject_t table_subject;
        table_subject.kind = type_subject_kind_t::virtual_table;
        table_subject.address = rva_address(as_rva(slot.vtable_rva));
        table_subject.stable_name = owner ? owner->name : std::string();
        slot_evidence.related_subject = table_subject;
        slot_evidence.candidate.kind = recovered_type_kind_t::function_pointer;
        slot_evidence.candidate.language = type_language_t::cpp;
        slot_evidence.candidate.referenced_type_id = slot.function_rva;
        slot_evidence.provenance = type_evidence_provenance_t::vtable;
        slot_evidence.kind = type_evidence_kind_t::vtable_slot;
        slot_evidence.source_address = rva_address(as_rva(slot.function_rva));
        slot_evidence.confidence = slot.confidence;
        slot_evidence.detail = "static_rtti_scan";
        out.push_back(std::move(slot_evidence));
    }
    return out;
}

workspace_result_t<std::vector<type_graph::type_seed_batch_t>>
make_recognition_seed_batches(const recognition_records_t& records,
                              const decompiler_entity_key_t& entity,
                              std::uint64_t generation,
                              const type_seed_export_options_t& options,
                              const type_recovery_result_t* recovered)
{
    std::vector<type_graph::type_seed_batch_t> batches;
    std::unordered_map<std::uint64_t, std::string> prototype_canonical_by_rva;
    if (options.include_prototypes) {
        type_graph::type_seed_batch_t prototypes;
        prototypes.source = decompiler_fact_provenance_t::call_signature;
        prototypes.source_label = "flirt_crt_prototypes";
        for (const auto& record : records.prototypes) {
            if (record.confidence < options.min_confidence || record.prototype_text.empty())
                continue;
            if (prototypes.candidates.size() >= options.max_candidates)
                break;
            type_graph::type_candidate_t candidate;
            candidate.kind = decompiler_type_kind_t::function;
            candidate.canonical_name = record.prototype_text;
            candidate.display_name = record.name;
            candidate.confidence = record.confidence;
            candidate.provenance = decompiler_fact_provenance_t::call_signature;
            candidate.source_detail = "flirt." +
                (records.db_toolset.empty() ? std::string("embedded") : records.db_toolset);
            candidate.coordinate = seed_coordinate(entity, generation, record.rva);
            prototype_canonical_by_rva.emplace(record.rva, candidate.canonical_name);
            prototypes.candidates.push_back(std::move(candidate));
        }
        if (!prototypes.candidates.empty())
            batches.push_back(std::move(prototypes));
    }
    if (options.include_rtti && !records.rtti.types.empty()) {
        type_graph::type_seed_batch_t rtti;
        rtti.source = decompiler_fact_provenance_t::rtti;
        rtti.source_label = "static_rtti_types";
        std::unordered_map<std::uint64_t, std::string> slot_method_canonical;
        for (const auto& slot : records.vtables.slots) {
            const auto found = prototype_canonical_by_rva.find(slot.function_rva);
            if (found != prototype_canonical_by_rva.end())
                slot_method_canonical.emplace(
                    (slot.vtable_rva << 20) + slot.slot_index, found->second);
        }
        for (const auto& type : records.rtti.types) {
            const std::uint8_t confidence = clamp_confidence(type.score);
            if (confidence < options.min_confidence)
                continue;
            if (rtti.candidates.size() >= options.max_candidates)
                break;
            type_graph::type_candidate_t candidate;
            candidate.kind = decompiler_type_kind_t::class_type;
            candidate.canonical_name = class_canonical(type.name);
            candidate.display_name = type.name;
            candidate.confidence = confidence;
            candidate.provenance = decompiler_fact_provenance_t::rtti;
            candidate.source_detail = "static_rtti_scan";
            candidate.coordinate = seed_coordinate(entity, generation, type.type_descriptor_rva);
            for (const auto& base : type.bases) {
                if (candidate.edges.size() >= options.max_edges_per_candidate)
                    break;
                if (base.name.empty() || base.name == type.name)
                    continue;
                type_graph::type_edge_candidate_t edge;
                edge.kind = decompiler_type_edge_kind_t::base;
                edge.target_canonical_name = class_canonical(base.name);
                edge.stable_name = base.name;
                edge.local_ordinal = static_cast<std::uint32_t>(candidate.edges.size() + 1);
                edge.confidence = confidence;
                edge.provenance = decompiler_fact_provenance_t::rtti;
                edge.source_detail = "static_rtti_scan";
                candidate.edges.push_back(std::move(edge));
            }
            for (const auto vtable_rva : type.vtable_rvas) {
                for (const auto& slot : records.vtables.slots) {
                    if (slot.vtable_rva != vtable_rva ||
                        candidate.edges.size() >= options.max_edges_per_candidate)
                        continue;
                    const auto canonical = slot_method_canonical.find(
                        (slot.vtable_rva << 20) + slot.slot_index);
                    if (canonical == slot_method_canonical.end())
                        continue;
                    type_graph::type_edge_candidate_t edge;
                    edge.kind = decompiler_type_edge_kind_t::member;
                    edge.target_canonical_name = canonical->second;
                    edge.stable_name = "slot_" + std::to_string(slot.slot_index);
                    edge.byte_offset = slot.slot_index * 8;
                    edge.local_ordinal = static_cast<std::uint32_t>(candidate.edges.size() + 1);
                    edge.confidence = slot.confidence;
                    edge.provenance = decompiler_fact_provenance_t::rtti;
                    edge.source_detail = "static_rtti_scan";
                    candidate.edges.push_back(std::move(edge));
                }
            }
            rtti.candidates.push_back(std::move(candidate));
        }
        if (!rtti.candidates.empty())
            batches.push_back(std::move(rtti));
    }
    if (options.include_structs && recovered) {
        type_graph::type_seed_batch_t local;
        local.source = decompiler_fact_provenance_t::debug_metadata;
        local.source_label = "recovered_local_types";
        for (const auto& structure : recovered->structs) {
            if (structure.confidence < options.min_confidence)
                continue;
            if (local.candidates.size() >= options.max_candidates)
                break;
            type_graph::type_candidate_t candidate;
            candidate.kind = decompiler_type_kind_t::structure;
            candidate.canonical_name = "struct " + (structure.name.empty()
                ? "recovered_" + std::to_string(structure.rva) : structure.name);
            candidate.display_name = structure.name.empty()
                ? "recovered_" + std::to_string(structure.rva) : structure.name;
            if (structure.estimated_size != 0)
                candidate.byte_size = structure.estimated_size;
            candidate.confidence = structure.confidence;
            candidate.provenance = decompiler_fact_provenance_t::debug_metadata;
            candidate.source_detail = "type_recovery";
            candidate.coordinate = seed_coordinate(entity, generation, structure.rva);
            for (const auto& field : structure.fields) {
                if (candidate.edges.size() >= options.max_edges_per_candidate)
                    break;
                type_graph::type_edge_candidate_t edge;
                edge.kind = decompiler_type_edge_kind_t::member;
                edge.target_canonical_name = recovered_kind_token(
                    field.kind, false, field.bit_width);
                edge.stable_name = field.name.empty()
                    ? "field_" + std::to_string(field.offset) : field.name;
                edge.byte_offset = field.offset;
                edge.local_ordinal = static_cast<std::uint32_t>(candidate.edges.size() + 1);
                edge.confidence = field.confidence;
                edge.provenance = decompiler_fact_provenance_t::debug_metadata;
                edge.source_detail = "type_recovery";
                candidate.edges.push_back(std::move(edge));
            }
            local.candidates.push_back(std::move(candidate));
        }
        for (const auto& prototype : recovered->prototypes) {
            if (prototype.confidence < options.min_confidence)
                continue;
            if (local.candidates.size() >= options.max_candidates)
                break;
            std::string text = recovered_kind_token(
                prototype.return_type, false, prototype.return_bit_width) + " __cdecl fn_" +
                std::to_string(prototype.target_function_rva) + "(";
            for (std::size_t index = 0; index < prototype.argument_types.size(); ++index) {
                if (index != 0)
                    text += ", ";
                text += recovered_kind_token(prototype.argument_types[index], false,
                    index < prototype.argument_bit_widths.size()
                        ? prototype.argument_bit_widths[index] : 0);
                text += " arg" + std::to_string(index);
            }
            text += ")";
            type_graph::type_candidate_t candidate;
            candidate.kind = decompiler_type_kind_t::function;
            candidate.canonical_name = text;
            candidate.display_name = "fn_" + std::to_string(prototype.target_function_rva);
            candidate.confidence = prototype.confidence;
            candidate.provenance = decompiler_fact_provenance_t::debug_metadata;
            candidate.source_detail = "type_recovery";
            candidate.coordinate = seed_coordinate(entity, generation, prototype.target_function_rva);
            local.candidates.push_back(std::move(candidate));
        }
        if (!local.candidates.empty())
            batches.push_back(std::move(local));
    }
    return workspace_result_t<std::vector<type_graph::type_seed_batch_t>>::success(
        std::move(batches));
}

}
