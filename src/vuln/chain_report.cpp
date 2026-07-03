#include "chain_report.hpp"

#include <algorithm>
#include <utility>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

template <typename EnumT>
struct enum_name_t
{
    EnumT value;
    const char* name;
};

constexpr enum_name_t<chain_verdict_t> k_verdict_names[] = {
    {chain_verdict_t::confirmed, "confirmed"},
    {chain_verdict_t::refuted, "refuted"},
    {chain_verdict_t::inconclusive, "inconclusive"},
    {chain_verdict_t::timeout, "timeout"},
    {chain_verdict_t::unsupported, "unsupported"},
};

constexpr enum_name_t<report_acceptance_t> k_acceptance_names[] = {
    {report_acceptance_t::accepted, "accepted"},
    {report_acceptance_t::rejected, "rejected"},
    {report_acceptance_t::blocked, "blocked"},
};

constexpr enum_name_t<proof_level_t> k_proof_level_names[] = {
    {proof_level_t::p0_schema, "p0_schema"},
    {proof_level_t::p1_corpus, "p1_corpus"},
    {proof_level_t::p2_extraction, "p2_extraction"},
    {proof_level_t::p3_path, "p3_path"},
    {proof_level_t::p4_state, "p4_state"},
    {proof_level_t::p5_solver, "p5_solver"},
    {proof_level_t::p6_goal, "p6_goal"},
};

constexpr enum_name_t<confidence_policy_t> k_confidence_policy_names[] = {
    {confidence_policy_t::strict_proof_only, "strict_proof_only"},
    {confidence_policy_t::diagnostic_confidence_only, "diagnostic_confidence_only"},
};

template <typename EnumT, std::size_t N>
const char* enum_to_string(EnumT value, const enum_name_t<EnumT> (&items)[N], const char* fallback)
{
    for (const auto& item : items)
    {
        if (item.value == value)
            return item.name;
    }
    return fallback;
}

template <typename EnumT, std::size_t N>
std::optional<EnumT> enum_from_string(const std::string& value, const enum_name_t<EnumT> (&items)[N])
{
    for (const auto& item : items)
    {
        if (value == item.name)
            return item.value;
    }
    return std::nullopt;
}

template <typename T>
void push_json_array(nlohmann::json& j, const char* key, const std::vector<T>& values)
{
    j[key] = nlohmann::json::array();
    for (const auto& value : values)
        j[key].push_back(to_json(value));
}

std::vector<failure_record_t> all_failures(const chain_report_t& report)
{
    std::vector<failure_record_t> failures;
    if (!report.first_failure.code.empty())
        failures.push_back(report.first_failure);
    for (const auto& phase : report.phase_status)
    {
        failures.insert(failures.end(), phase.failures.begin(), phase.failures.end());
    }
    for (const auto& c : report.corpus)
    {
        if (corpus_blocks_confirmation(c))
        {
            failure_record_t f;
            f.code = "missing_corpus";
            f.acceptance_blocker = true;
            f.summary = "corpus " + c.identity.corpus_id + " availability is " + to_string(c.availability);
            failures.push_back(std::move(f));
        }
    }
    for (const auto& fact : report.unproven_critical_facts)
    {
        failure_record_t f;
        f.code = fact.proof_state == proof_state_t::refuted ? "critical_fact_refuted" : "critical_fact_unproven";
        f.acceptance_blocker = true;
        f.summary = "critical fact " + fact.fact_id + " is " + to_string(fact.proof_state);
        f.fact_ids.push_back(fact.fact_id);
        f.evidence = fact.evidence;
        failures.push_back(std::move(f));
    }
    for (const auto& boundary : report.boundaries)
    {
        if (!boundary.mismatches.empty())
        {
            failure_record_t f;
            f.code = "postcondition_precondition_mismatch";
            f.acceptance_blocker = true;
            f.summary = "boundary " + boundary.producer_link + " -> " + boundary.consumer_link + " has mismatches";
            f.fact_ids = boundary.mismatches;
            failures.push_back(std::move(f));
        }
        if (!boundary.unproven.empty())
        {
            failure_record_t f;
            f.code = "boundary_unproven";
            f.acceptance_blocker = true;
            f.summary = "boundary " + boundary.producer_link + " -> " + boundary.consumer_link + " has unproven requirements";
            f.fact_ids = boundary.unproven;
            failures.push_back(std::move(f));
        }
    }
    for (const auto& link : report.links)
    {
        for (const auto& fact : link.unproven_facts)
        {
            failure_record_t f;
            f.code = fact.proof_state == proof_state_t::refuted ? "link_fact_refuted" : "link_fact_unproven";
            f.acceptance_blocker = critical_fact_blocks_confirmation(fact);
            f.summary = "link " + link.link_id + " fact " + fact.fact_id + " is " + to_string(fact.proof_state);
            f.fact_ids.push_back(fact.fact_id);
            failures.push_back(std::move(f));
        }
        for (const auto& se : link.side_effects)
        {
            if (se.safety == side_effect_safety_t::fatal || se.safety == side_effect_safety_t::collateral_unproven)
            {
                failure_record_t f;
                f.code = se.safety == side_effect_safety_t::fatal ? "fatal_side_effect" : "collateral_damage_unproven";
                f.acceptance_blocker = true;
                f.summary = "link " + link.link_id + " side effect " + se.side_effect_id + " is " + to_string(se.safety);
                failures.push_back(std::move(f));
            }
        }
        for (const auto& refutation : link.refutations)
        {
            failure_record_t f;
            f.code = refutation.code.empty() ? "link_refuted" : refutation.code;
            f.acceptance_blocker = true;
            f.summary = refutation.summary;
            f.fact_ids.push_back(refutation.producer_fact_id);
            f.fact_ids.push_back(refutation.consumer_fact_id);
            f.evidence = refutation.evidence;
            failures.push_back(std::move(f));
        }
    }
    for (const auto& objective : report.objectives)
    {
        if (objective.verdict != chain_verdict_t::confirmed)
        {
            failure_record_t f;
            f.code = objective.verdict == chain_verdict_t::refuted ? "objective_refuted" : "objective_not_achieved";
            f.acceptance_blocker = true;
            f.summary = "objective " + objective.objective_id + " is " + to_string(objective.verdict);
            f.fact_ids = objective.required_fact_ids;
            failures.push_back(std::move(f));
        }
        for (const auto& contradiction : objective.contradictions)
        {
            failure_record_t f;
            f.code = contradiction.code.empty() ? "objective_refuted" : contradiction.code;
            f.acceptance_blocker = true;
            f.summary = contradiction.summary;
            f.fact_ids.push_back(contradiction.producer_fact_id);
            f.fact_ids.push_back(contradiction.consumer_fact_id);
            f.evidence = contradiction.evidence;
            failures.push_back(std::move(f));
        }
    }
    return failures;
}

bool any_acceptance_blocker(const std::vector<failure_record_t>& failures)
{
    for (const auto& f : failures)
    {
        if (f.acceptance_blocker)
            return true;
    }
    return false;
}

bool has_refutation(const chain_report_t& report)
{
    if (report.verdict == chain_verdict_t::refuted)
        return true;
    for (const auto& link : report.links)
    {
        if (link.verdict == chain_verdict_t::refuted || !link.refutations.empty())
            return true;
    }
    for (const auto& objective : report.objectives)
    {
        if (objective.verdict == chain_verdict_t::refuted || !objective.contradictions.empty())
            return true;
    }
    for (const auto& fact : report.unproven_critical_facts)
    {
        if (fact.proof_state == proof_state_t::refuted)
            return true;
    }
    return false;
}

}

const char* to_string(chain_verdict_t value)
{
    return enum_to_string(value, k_verdict_names, "inconclusive");
}

const char* to_string(report_acceptance_t value)
{
    return enum_to_string(value, k_acceptance_names, "blocked");
}

const char* to_string(proof_level_t value)
{
    return enum_to_string(value, k_proof_level_names, "p0_schema");
}

const char* to_string(confidence_policy_t value)
{
    return enum_to_string(value, k_confidence_policy_names, "strict_proof_only");
}

std::optional<chain_verdict_t> chain_verdict_from_string(const std::string& value)
{
    return enum_from_string(value, k_verdict_names);
}

std::optional<report_acceptance_t> report_acceptance_from_string(const std::string& value)
{
    return enum_from_string(value, k_acceptance_names);
}

std::optional<proof_level_t> proof_level_from_string(const std::string& value)
{
    return enum_from_string(value, k_proof_level_names);
}

std::optional<confidence_policy_t> confidence_policy_from_string(const std::string& value)
{
    return enum_from_string(value, k_confidence_policy_names);
}

nlohmann::json to_json(const failure_record_t& value)
{
    nlohmann::json j;
    j["code"] = value.code;
    j["acceptance_blocker"] = value.acceptance_blocker;
    j["summary"] = value.summary;
    j["fact_ids"] = value.fact_ids;
    push_json_array(j, "evidence", value.evidence);
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const refutation_record_t& value)
{
    nlohmann::json j;
    j["refutation_id"] = value.refutation_id;
    j["code"] = value.code;
    j["producer_fact_id"] = value.producer_fact_id;
    j["consumer_fact_id"] = value.consumer_fact_id;
    j["summary"] = value.summary;
    push_json_array(j, "evidence", value.evidence);
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const boundary_matrix_entry_t& value)
{
    return nlohmann::json{
        {"producer_link", value.producer_link},
        {"consumer_link", value.consumer_link},
        {"requirements", value.requirements},
        {"matches", value.matches},
        {"mismatches", value.mismatches},
        {"unproven", value.unproven},
        {"content_provenance_matrix", value.content_provenance_matrix},
        {"lifetime_temporal_matrix", value.lifetime_temporal_matrix},
        {"alias_matrix", value.alias_matrix},
    };
}

nlohmann::json to_json(const phase_status_t& value)
{
    nlohmann::json j;
    j["phase"] = value.phase;
    j["verdict"] = to_string(value.verdict);
    j["elapsed_ms"] = value.elapsed_ms;
    push_json_array(j, "failures", value.failures);
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const link_report_t& value)
{
    nlohmann::json j;
    j["link_id"] = value.link_id;
    j["role"] = to_string(value.role);
    j["verdict"] = to_string(value.verdict);
    j["proof_level"] = to_string(value.proof_level);
    j["entry_state_summary"] = value.entry_state_summary;
    j["path_corridors"] = value.path_corridors;
    j["branches"] = value.branches;
    j["calls"] = value.calls;
    j["effects"] = value.effects;
    push_json_array(j, "side_effects", value.side_effects);
    push_json_array(j, "postconditions", value.postconditions);
    push_json_array(j, "unproven_facts", value.unproven_facts);
    push_json_array(j, "refutations", value.refutations);
    return j;
}

nlohmann::json to_json(const objective_report_t& value)
{
    nlohmann::json j;
    j["objective_id"] = value.objective_id;
    j["kind"] = to_string(value.kind);
    j["operation_sequence"] = value.operation_sequence;
    j["required_fact_ids"] = value.required_fact_ids;
    j["proven_fact_ids"] = value.proven_fact_ids;
    push_json_array(j, "contradictions", value.contradictions);
    j["collateral_safety"] = value.collateral_safety;
    j["verdict"] = to_string(value.verdict);
    return j;
}

nlohmann::json to_json(const chain_report_t& value)
{
    nlohmann::json j;
    j["schema"] = value.schema;
    j["version"] = value.version;
    j["report_id"] = value.report_id;
    j["chain_id"] = value.chain_id;
    j["job_id"] = value.job_id;
    j["verdict"] = to_string(value.verdict);
    j["acceptance"] = to_string(value.acceptance);
    j["confidence"] = to_string(value.confidence);
    j["proof_level_reached"] = to_string(value.proof_level_reached);
    j["refutation_level"] = value.refutation_level;
    j["summary"] = value.summary;
    j["first_failure"] = to_json(value.first_failure);
    push_json_array(j, "unproven_critical_facts", value.unproven_critical_facts);
    push_json_array(j, "corpus", value.corpus);
    push_json_array(j, "phase_status", value.phase_status);
    push_json_array(j, "links", value.links);
    push_json_array(j, "boundaries", value.boundaries);
    push_json_array(j, "objectives", value.objectives);
    j["trace_manifest"] = value.trace_manifest;
    j["fact_manifest"] = value.fact_manifest;
    j["solver_manifest"] = value.solver_manifest;
    j["resource_manifest"] = value.resource_manifest;
    j["generation_manifest"] = value.generation_manifest;
    j["budget_manifest"] = value.budget_manifest;
    j["diagnostics"] = value.diagnostics;
    return j;
}

failure_record_t failure_from_validation(const validation_error_t& value)
{
    failure_record_t out;
    out.code = value.code;
    out.acceptance_blocker = value.acceptance_blocker;
    out.summary = value.path.empty() ? value.message : value.path + ": " + value.message;
    out.metadata["severity"] = to_string(value.severity);
    return out;
}

chain_report_t make_schema_report(const chain_document_t& document, const validation_result_t& validation)
{
    chain_report_t report = make_report_skeleton(document, "schema");
    report.proof_level_reached = proof_level_t::p0_schema;
    report.verdict = validation.ok() ? chain_verdict_t::inconclusive : chain_verdict_t::unsupported;
    phase_status_t phase;
    phase.phase = "schema";
    phase.verdict = validation.ok() ? chain_verdict_t::confirmed : chain_verdict_t::unsupported;
    for (const auto& e : validation.errors)
        phase.failures.push_back(failure_from_validation(e));
    report.phase_status.push_back(std::move(phase));
    finalize_report_acceptance(report);
    return report;
}

chain_report_t make_report_skeleton(const chain_document_t& document, const std::string& job_id)
{
    chain_report_t report;
    report.chain_id = document.chain_id;
    report.job_id = job_id;
    nlohmann::json id_payload;
    id_payload["chain_id"] = report.chain_id;
    id_payload["job_id"] = report.job_id;
    id_payload["document"] = to_json(document);
    report.report_id = stable_id("report", id_payload);
    report.corpus = document.corpus;
    for (const auto& link : document.links)
    {
        link_report_t lr;
        lr.link_id = link.link_id;
        lr.role = link.role;
        lr.postconditions = link.postconditions;
        for (const auto& f : link.preconditions)
        {
            if (critical_fact_blocks_confirmation(f))
                lr.unproven_facts.push_back(f);
        }
        for (const auto& f : link.postconditions)
        {
            if (critical_fact_blocks_confirmation(f))
                lr.unproven_facts.push_back(f);
        }
        report.links.push_back(std::move(lr));
    }
    for (const auto& objective : document.objectives)
    {
        objective_report_t obj;
        obj.objective_id = objective.objective_id;
        obj.kind = objective.kind;
        obj.operation_sequence = objective.operation_sequence;
        obj.required_fact_ids = objective.required_fact_ids;
        obj.verdict = objective.required_fact_ids.empty() && objective.required_facts.empty()
            ? chain_verdict_t::inconclusive
            : chain_verdict_t::confirmed;
        for (const auto& f : objective.required_facts)
        {
            if (critical_fact_blocks_confirmation(f))
            {
                obj.verdict = chain_verdict_t::inconclusive;
                report.unproven_critical_facts.push_back(f);
            }
            else
            {
                obj.proven_fact_ids.push_back(f.fact_id);
            }
        }
        report.objectives.push_back(std::move(obj));
    }
    for (const auto& fact : document.facts)
    {
        if (critical_fact_blocks_confirmation(fact))
            report.unproven_critical_facts.push_back(fact);
    }
    for (const auto& fact : critical_fact_blockers(document.initial_state))
        report.unproven_critical_facts.push_back(fact);
    report.budget_manifest = to_json(document.policies);
    report.generation_manifest["document_id"] = stable_id("chain_doc", to_json(document));
    return report;
}

void finalize_report_acceptance(chain_report_t& report)
{
    std::vector<failure_record_t> failures = all_failures(report);
    if (!failures.empty())
        report.first_failure = failures.front();
    if (has_refutation(report))
    {
        report.verdict = chain_verdict_t::refuted;
        report.acceptance = report_acceptance_t::rejected;
        if (report.summary.empty())
            report.summary = "Chain refuted by proven contradiction";
        return;
    }
    if (any_acceptance_blocker(failures))
    {
        if (report.verdict == chain_verdict_t::confirmed)
            report.verdict = chain_verdict_t::inconclusive;
        report.acceptance = report_acceptance_t::blocked;
        if (report.summary.empty())
            report.summary = "Chain not confirmed because critical evidence is unproven";
        return;
    }
    if (report.verdict == chain_verdict_t::confirmed)
    {
        const bool all_objectives_confirmed = std::all_of(report.objectives.begin(), report.objectives.end(), [](const objective_report_t& objective) {
            return objective.verdict == chain_verdict_t::confirmed;
        });
        if (all_objectives_confirmed)
        {
            report.acceptance = report_acceptance_t::accepted;
            report.proof_level_reached = proof_level_t::p6_goal;
            if (report.summary.empty())
                report.summary = "Chain confirmed with all critical objectives proven";
            return;
        }
        report.verdict = chain_verdict_t::inconclusive;
    }
    report.acceptance = report_acceptance_t::blocked;
    if (report.summary.empty())
        report.summary = "Chain proof incomplete";
}

validation_result_t validate_chain_report(const chain_report_t& report)
{
    validation_result_t result;
    if (report.schema != k_chain_report_schema)
        result.add("invalid_report_schema", "/schema", "report schema mismatch");
    if (report.chain_id.empty())
        result.add("missing_required_field", "/chain_id", "chain id is required");
    if (report.report_id.empty())
        result.add("missing_required_field", "/report_id", "report id is required");
    std::vector<failure_record_t> failures = all_failures(report);
    if (report.verdict == chain_verdict_t::confirmed && any_acceptance_blocker(failures))
        result.add("invalid_report_acceptance", "/verdict", "confirmed report contains acceptance blockers");
    if (report.verdict == chain_verdict_t::confirmed && report.acceptance != report_acceptance_t::accepted)
        result.add("invalid_report_acceptance", "/acceptance", "confirmed report must be accepted");
    if (report.acceptance == report_acceptance_t::accepted && report.verdict != chain_verdict_t::confirmed)
        result.add("invalid_report_acceptance", "/acceptance", "accepted report must be confirmed");
    return result;
}

nlohmann::json report_machine_export(const chain_report_t& report)
{
    nlohmann::json out = to_json(report);
    out["machine_export"] = nlohmann::json{
        {"schema", k_chain_report_schema},
        {"acceptance_blockers", nlohmann::json::array()},
        {"failure_taxonomy", nlohmann::json::array({
            "invalid_chain_schema",
            "ambiguous_corpus_binding",
            "missing_corpus",
            "stale_generation",
            "analysis_unsettled",
            "extractor_layer_failed",
            "hexrays_unavailable",
            "microcode_unavailable",
            "unsupported_instruction",
            "unsupported_helper",
            "path_target_unreachable",
            "reachable_set_incomplete",
            "branch_required_direction_unsat",
            "branch_required_direction_unknown",
            "indirect_target_unproven",
            "call_target_mismatch",
            "abi_state_mismatch",
            "register_clobber_unproven",
            "postcondition_precondition_mismatch",
            "content_provenance_mismatch",
            "controlledness_unproven",
            "alias_must_not_proven",
            "self_reference_unproven",
            "lifetime_order_unproven",
            "address_knowledge_gap",
            "allocator_reuse_unproven",
            "callback_registration_unproven",
            "trigger_path_not_reached",
            "protocol_state_mismatch",
            "protocol_length_mismatch",
            "protocol_checksum_mismatch",
            "firmware_dispatch_unproven",
            "collateral_damage_unproven",
            "fatal_side_effect",
            "solver_timeout",
            "solver_unknown",
            "peer_unavailable",
            "resource_exhausted",
            "objective_not_achieved"
        })},
    };
    for (const auto& failure : all_failures(report))
    {
        if (failure.acceptance_blocker)
            out["machine_export"]["acceptance_blockers"].push_back(to_json(failure));
    }
    return out;
}

validation_result_t chain_report_self_check()
{
    chain_document_t doc;
    doc.chain_id = "report_self_check";
    doc.target.pointer_width_bits = 64;
    corpus_record_t corpus = make_missing_corpus("mod", "mod.bin", "self check");
    corpus.availability = corpus_availability_t::recorded_only;
    doc.corpus.push_back(corpus);
    fact_t fact;
    fact.fact_id = "critical_unknown";
    fact.kind = fact_kind_t::value_fact;
    fact.subject = nlohmann::json{{"register", "rcx"}};
    fact.predicate = "equals";
    fact.value.kind = value_kind_t::unknown;
    fact.proof_state = proof_state_t::unknown;
    fact.criticality = fact_criticality_t::chain_critical;
    doc.facts.push_back(fact);
    link_spec_t link;
    link.link_id = "link0";
    link.corpus_id = "mod";
    doc.links.push_back(link);
    objective_spec_t objective;
    objective.objective_id = "goal0";
    objective.required_fact_ids.push_back("critical_unknown");
    doc.objectives.push_back(objective);
    chain_report_t report = make_report_skeleton(doc, "self");
    report.verdict = chain_verdict_t::confirmed;
    finalize_report_acceptance(report);
    validation_result_t result;
    if (report.verdict == chain_verdict_t::confirmed || report.acceptance == report_acceptance_t::accepted)
        result.add("self_check_failed", "/verdict", "unknown critical fact was accepted");
    validation_result_t validation = validate_chain_report(report);
    result.errors.insert(result.errors.end(), validation.errors.begin(), validation.errors.end());
    return result;
}

}
}
}
