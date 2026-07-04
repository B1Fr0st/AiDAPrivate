#include "chain_regression_specs.hpp"

#include <utility>

namespace aida
{
namespace vuln
{
namespace chain
{
namespace
{

nlohmann::json corpus()
{
    return nlohmann::json::array({{{"corpus_id", "mod"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "synthetic"}}}, {"trust", "recorded_dynamic"}}});
}

nlohmann::json objective_goal()
{
    return nlohmann::json::array({{{"id", "goal"}, {"dimension", "final_objective"}, {"subject", "goal"}, {"predicate", "achieved"}, {"required", {{"achieved", true}}}}});
}

nlohmann::json content_fact(const std::string& id, const std::string& subject, bool controlled)
{
    return nlohmann::json{{"id", id},
                          {"kind", "content_fact"},
                          {"subject", subject},
                          {"predicate", "content"},
                          {"value", {{"content_class", controlled ? "controlled" : "zero_bytes"}, {"controlled", controlled}, {"zero", !controlled}}},
                          {"proof_state", "proven"},
                          {"criticality", "chain_critical"}};
}

nlohmann::json objective_fact()
{
    return nlohmann::json{{"id", "goal_done"},
                          {"kind", "objective_fact"},
                          {"subject", "goal"},
                          {"predicate", "achieved"},
                          {"value", {{"achieved", true}}},
                          {"proof_state", "proven"},
                          {"criticality", "objective_critical"}};
}

nlohmann::json base_doc(const std::string& chain_id)
{
    return nlohmann::json{{"schema", "aida_chain_document_v2"},
                          {"chain_id", chain_id},
                          {"target", {{"architecture", "x86_64"}, {"platform", "kernel_or_user"}}},
                          {"corpus", corpus()},
                          {"objectives", objective_goal()}};
}

chain_regression_spec_t spec(const std::string& suite,
                             const std::string& case_id,
                             nlohmann::json document,
                             const std::string& verdict,
                             const std::string& failure)
{
    document["expected"] = {{"verdict", verdict}, {"failure", failure}, {"suite", suite}, {"case_id", case_id}};
    chain_regression_spec_t out;
    out.suite = suite;
    out.case_id = case_id;
    out.document = std::move(document);
    out.expected = out.document.at("expected");
    return out;
}

}

std::vector<chain_regression_spec_t> universal_chain_regression_specs()
{
    std::vector<chain_regression_spec_t> out;

    nlohmann::json ntfs_copy = base_doc("suite_a_ntfs_etw_controlled_copy");
    ntfs_copy["facts"] = nlohmann::json::array({content_fact("input_control", "irp.SystemBuffer", true)});
    ntfs_copy["links"] = nlohmann::json::array({
        {{"id", "ntfs_to_etw_copy"},
         {"preconditions", {{{"id", "input_controlled"}, {"dimension", "content"}, {"subject", "irp.SystemBuffer"}, {"predicate", "content"}, {"required", {{"controlled", true}}}}}},
         {"transfers", {{{"kind", "memory_copy"}, {"destination", "etw.EventData"}, {"source", {{"text", "irp.SystemBuffer"}, {"controlled_by_input", true}}}, {"proof_state", "proven"}, {"source_layer", "path_trace"}, {"reason", "RtlCopyMemory callsite"}}}},
         {"postconditions", {content_fact("etw_controlled", "etw.EventData", true)}}},
        {{"id", "goal"},
         {"transfers", {{{"kind", "objective"}, {"subject", "goal"}, {"achieved", true}, {"proof_state", "proven"}, {"source_layer", "objective_trace"}}}},
         {"postconditions", {objective_fact()}}}
    });
    out.push_back(spec("A", "ntfs_etw_controlled_copy", ntfs_copy, "confirmed", "none"));

    nlohmann::json ntfs_zero = base_doc("suite_b_ntfs_etw_zero_refutes_control");
    ntfs_zero["links"] = nlohmann::json::array({
        {{"id", "ntfs_zero_fill"},
         {"transfers", {{{"kind", "memory_set"}, {"destination", "etw.EventData"}, {"source", {{"value_origin", "constant_zero"}, {"concrete", true}, {"concrete_value", "0"}}}, {"proof_state", "proven"}, {"source_layer", "path_trace"}, {"reason", "RtlZeroMemory callsite"}}}},
         {"postconditions", {content_fact("etw_controlled", "etw.EventData", true)}}},
        {{"id", "goal"},
         {"transfers", {{{"kind", "objective"}, {"subject", "goal"}, {"achieved", true}, {"proof_state", "proven"}, {"source_layer", "objective_trace"}}}},
         {"postconditions", {objective_fact()}}}
    });
    out.push_back(spec("B", "ntfs_etw_zero_refutes_control", ntfs_zero, "refuted", "content_provenance_mismatch"));

    nlohmann::json afd_bad = base_doc("suite_c_afd_setjmp_missing_address_discovery");
    afd_bad["links"] = nlohmann::json::array({
        {{"id", "afd_hidden_check"},
         {"transfers", {{{"kind", "read"}, {"source", "AfdConnection.Timer2"}, {"destination", "scratch"}, {"proof_state", "proven"}, {"source_layer", "path_trace"}}}},
         {"postconditions", {{{"id", "timer2_self_reference"}, {"kind", "alias_fact"}, {"subject", "AfdConnection.Timer2"}, {"predicate", "self_reference"}, {"value", {{"self_reference", true}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}}},
        {{"id", "goal"},
         {"transfers", {{{"kind", "objective"}, {"subject", "goal"}, {"achieved", true}, {"proof_state", "proven"}, {"source_layer", "objective_trace"}}}},
         {"postconditions", {objective_fact()}}}
    });
    out.push_back(spec("C", "afd_setjmp_missing_address_discovery", afd_bad, "inconclusive", "self_reference_unproven"));

    nlohmann::json afd_ok = base_doc("suite_d_afd_setjmp_address_discovery");
    afd_ok["links"] = nlohmann::json::array({
        {{"id", "afd_address_discovery"},
         {"transfers", {{{"kind", "address_discovery"}, {"object_id", "AfdConnection.Timer2"}, {"proof_state", "proven"}, {"source_layer", "path_trace"}},
                        {{"kind", "self_reference"}, {"subject", "AfdConnection.Timer2"}, {"target", "AfdConnection.Timer2"}, {"proof_state", "proven"}, {"source_layer", "path_trace"}}}},
         {"postconditions", {{{"id", "timer2_self_reference"}, {"kind", "alias_fact"}, {"subject", "AfdConnection.Timer2"}, {"predicate", "self_reference"}, {"value", {{"self_reference", true}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}}},
        {{"id", "goal"},
         {"transfers", {{{"kind", "objective"}, {"subject", "goal"}, {"achieved", true}, {"proof_state", "proven"}, {"source_layer", "objective_trace"}}}},
         {"postconditions", {objective_fact()}}}
    });
    out.push_back(spec("D", "afd_setjmp_address_discovery", afd_ok, "confirmed", "none"));

    nlohmann::json pv_bad = base_doc("suite_e_pvscan0_bad_slot");
    pv_bad["links"] = nlohmann::json::array({{{"id", "pvscan0_bad_write"},
                                              {"transfers", {{{"kind", "points_to"}, {"subject", "surface.slot"}, {"target", "global.manager"}, {"proof_state", "proven"}, {"source_layer", "path_trace"}},
                                                             {{"kind", "write"}, {"destination", "global.manager"}, {"source", "target"}, {"proof_state", "proven"}, {"source_layer", "path_trace"}}}}}});
    pv_bad["objectives"] = nlohmann::json::array({{{"id", "redirect_slot"}, {"dimension", "final_objective"}, {"subject", "surface.slot"}, {"predicate", "written"}, {"required", {{"operation", {{"kind", "write_through"}, {"pointer_slot", "surface.slot"}, {"required_updated_location", "surface.slot"}}}}}}});
    out.push_back(spec("E", "pvscan0_bad_slot", pv_bad, "refuted", "objective_not_achieved"));

    nlohmann::json pv_ok = base_doc("suite_f_pvscan0_correct_slot");
    pv_ok["links"] = nlohmann::json::array({{{"id", "pvscan0_correct_write"},
                                             {"transfers", {{{"kind", "points_to"}, {"subject", "surface.slot"}, {"target", "surface.slot"}, {"proof_state", "proven"}, {"source_layer", "path_trace"}},
                                                            {{"kind", "write"}, {"destination", "surface.slot"}, {"source", "target"}, {"proof_state", "proven"}, {"source_layer", "path_trace"}}}}}});
    pv_ok["objectives"] = nlohmann::json::array({{{"id", "redirect_slot"}, {"dimension", "final_objective"}, {"subject", "surface.slot"}, {"predicate", "written"}, {"required", {{"operation", {{"kind", "write_through"}, {"pointer_slot", "surface.slot"}, {"required_updated_location", "surface.slot"}}}}}}});
    out.push_back(spec("F", "pvscan0_correct_slot", pv_ok, "confirmed", "none"));

    nlohmann::json protocol_ok = base_doc("suite_g_protocol_length_checksum");
    protocol_ok["links"] = nlohmann::json::array({
        {{"id", "protocol_decode"},
         {"transfers", {{{"kind", "protocol"}, {"protocol_id", "afd.packet"}, {"protocol_state", "decoded"}, {"length", "64"}, {"checksum_validated", true}, {"proof_state", "proven"}, {"source_layer", "microcode"}}}},
         {"postconditions", {{{"id", "protocol_state"}, {"kind", "protocol_fact"}, {"subject", "afd.packet"}, {"predicate", "state"}, {"value", {{"protocol_state", "decoded"}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}},
                              {{"id", "protocol_length"}, {"kind", "protocol_fact"}, {"subject", "afd.packet"}, {"predicate", "length"}, {"value", {{"length", "64"}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}},
                              {{"id", "protocol_checksum"}, {"kind", "protocol_fact"}, {"subject", "afd.packet"}, {"predicate", "checksum"}, {"value", {{"checksum_validated", true}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}}},
        {{"id", "goal"},
         {"transfers", {{{"kind", "objective"}, {"subject", "goal"}, {"achieved", true}, {"proof_state", "proven"}, {"source_layer", "objective_trace"}}}},
         {"postconditions", {objective_fact()}}}
    });
    out.push_back(spec("G", "protocol_length_checksum", protocol_ok, "confirmed", "none"));

    nlohmann::json stale_peer = base_doc("suite_h_cross_domain_stale_peer");
    stale_peer["corpus"] = nlohmann::json::array({{{"corpus_id", "mod"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "synthetic"}}}, {"trust", "recorded_dynamic"}},
                                                  {{"corpus_id", "peer"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "peer"}}}, {"trust", "recorded_dynamic"}}});
    stale_peer["links"] = nlohmann::json::array({
        {{"id", "cross_peer"},
         {"cross_domain", {{"peer", {{"peer_id", "peer"}, {"stale_generation", true}}}, {"abi", {{"proven", true}}}}},
         {"transfers", {{{"kind", "call"}, {"callee_name", "peer!Target"}, {"resolved", true}, {"proof_state", "proven"}, {"source_layer", "cross_edge"}}}}},
        {{"id", "goal"},
         {"transfers", {{{"kind", "objective"}, {"subject", "goal"}, {"achieved", true}, {"proof_state", "proven"}, {"source_layer", "objective_trace"}}}},
         {"postconditions", {objective_fact()}}}
    });
    out.push_back(spec("H", "cross_domain_stale_peer", stale_peer, "unsupported", "stale_generation"));

    nlohmann::json callback_ok = base_doc("suite_i_callback_event_chain");
    callback_ok["links"] = nlohmann::json::array({
        {{"id", "callback_dispatch"},
         {"cross_domain", {{"callback", {{"id", "notify.Callback"}, {"registered", true}, {"invoked", true}}}, {"peer", {{"peer_id", "mod"}}}}},
         {"transfers", {{{"kind", "callback_dispatch"}, {"subject", "notify.Callback"}, {"proof_state", "proven"}, {"source_layer", "xref_trace"}}}}},
        {{"id", "goal"},
         {"transfers", {{{"kind", "objective"}, {"subject", "goal"}, {"achieved", true}, {"proof_state", "proven"}, {"source_layer", "objective_trace"}}}},
         {"postconditions", {objective_fact()}}}
    });
    out.push_back(spec("I", "callback_event_chain", callback_ok, "confirmed", "none"));

    return out;
}

std::vector<nlohmann::json> universal_chain_regression_documents()
{
    std::vector<nlohmann::json> docs;
    for (const auto& item : universal_chain_regression_specs())
        docs.push_back(item.document);
    return docs;
}

}
}
}
