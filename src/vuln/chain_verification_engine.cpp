#include "chain_verification_engine.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_set>

#include <ida.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string read_string(const nlohmann::json& value, const char* key, const std::string& fallback = {})
{
    if (!value.is_object() || !value.contains(key))
        return fallback;
    const auto& item = value.at(key);
    if (item.is_string())
        return item.get<std::string>();
    if (item.is_boolean())
        return item.get<bool>() ? "true" : "false";
    if (item.is_number_integer())
        return std::to_string(item.get<int64_t>());
    if (item.is_number_unsigned())
        return std::to_string(item.get<uint64_t>());
    return fallback;
}

bool read_bool(const nlohmann::json& value, const char* key, bool fallback = false)
{
    if (!value.is_object() || !value.contains(key))
        return fallback;
    const auto& item = value.at(key);
    if (item.is_boolean())
        return item.get<bool>();
    if (item.is_string())
    {
        const std::string s = lower_copy(item.get<std::string>());
        return s == "true" || s == "1" || s == "yes";
    }
    if (item.is_number_integer())
        return item.get<int64_t>() != 0;
    return fallback;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string bytes_to_hex(const uchar* bytes, size_t count)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; ++i)
        oss << std::setw(2) << static_cast<unsigned>(bytes[i]);
    return oss.str();
}

bool accepted_corpus_availability(const std::string& availability)
{
    const std::string s = lower_copy(availability);
    return s == "loaded" || s == "peer_loaded" || s == "recorded_only";
}

std::vector<nlohmann::json> json_array_or_empty(const nlohmann::json& object, const std::vector<const char*>& keys)
{
    if (!object.is_object())
        return {};
    for (const char* key : keys)
    {
        if (object.contains(key) && object.at(key).is_array())
        {
            std::vector<nlohmann::json> out;
            for (const auto& item : object.at(key))
                out.push_back(item);
            return out;
        }
    }
    return {};
}

void append_contracts(std::vector<state_contract_t>& out,
                      const nlohmann::json& object,
                      const std::vector<const char*>& keys,
                      const std::string& link_id,
                      contract_dimension_t default_dimension)
{
    for (const nlohmann::json& item : json_array_or_empty(object, keys))
        out.push_back(contract_from_json(item, link_id, default_dimension));
}

void append_solver_obligations(std::vector<solver_obligation_t>& out,
                               const nlohmann::json& object,
                               const std::vector<const char*>& keys,
                               const std::string& link_id,
                               solver_obligation_kind_t default_kind)
{
    for (const nlohmann::json& item : json_array_or_empty(object, keys))
        out.push_back(solver_obligation_from_json(item, link_id, default_kind));
}

nlohmann::json get_object_or_empty(const nlohmann::json& object, const char* key)
{
    if (object.is_object() && object.contains(key) && object.at(key).is_object())
        return object.at(key);
    return nlohmann::json::object();
}

std::string value_as_identity(const nlohmann::json& value)
{
    if (value.is_string())
        return value.get<std::string>();
    if (value.is_number_unsigned())
        return std::to_string(value.get<uint64_t>());
    if (value.is_number_integer())
        return std::to_string(value.get<int64_t>());
    if (value.is_object())
    {
        for (const char* key : {"location", "address", "target", "value", "slot", "field", "object", "subject"})
        {
            const std::string candidate = read_string(value, key);
            if (!candidate.empty())
                return candidate;
        }
    }
    return {};
}

std::string fact_value_identity(const chain_fact_t& fact)
{
    if (fact.value.is_object())
    {
        for (const char* key : {"target", "address", "location", "value", "points_to", "alias"})
        {
            const std::string value = read_string(fact.value, key);
            if (!value.empty())
                return value;
        }
    }
    return value_as_identity(fact.value);
}

std::string find_state_value(const contract_trace_state_t& state,
                             const std::string& subject,
                             const std::vector<std::string>& predicates)
{
    for (const chain_fact_t& fact : state.facts)
    {
        if (!subject.empty() && fact.subject != subject)
            continue;
        if (!predicates.empty() &&
            std::find(predicates.begin(), predicates.end(), lower_copy(fact.predicate)) == predicates.end())
            continue;
        if (fact.proof_state != contract_proof_state_t::proven)
            continue;
        const std::string out = fact_value_identity(fact);
        if (!out.empty())
            return out;
    }
    return {};
}

bool same_identity(const std::string& a, const std::string& b)
{
    if (a.empty() || b.empty())
        return false;
    return lower_copy(a) == lower_copy(b);
}

void add_failure(std::vector<failure_code_t>& failures, failure_code_t code)
{
    if (code == failure_code_t::none)
        return;
    if (std::find(failures.begin(), failures.end(), code) == failures.end())
        failures.push_back(code);
}

chain_verdict_t verdict_for_budget(budget_exhaustion_t exhaustion)
{
    if (exhaustion == budget_exhaustion_t::none)
        return chain_verdict_t::confirmed;
    if (exhaustion == budget_exhaustion_t::cancelled)
        return chain_verdict_t::inconclusive;
    return chain_verdict_t::timeout;
}

struct idb_snapshot_request_t : exec_request_t
{
    verification_module_snapshot_t snapshot;

    ssize_t idaapi execute() override
    {
        try
        {
            char root[MAXSTR] = {};
            char path[QMAXPATH] = {};
            char proc[IDAINFO_PROCNAME_SIZE] = {};
            get_root_filename(root, sizeof(root));
            get_input_file_path(path, sizeof(path));
            inf_get_procname(proc, sizeof(proc));
            uchar sha[32] = {};
            snapshot.root_filename = root;
            snapshot.input_path = path;
            snapshot.sha256 = retrieve_input_file_sha256(sha) ? bytes_to_hex(sha, sizeof(sha)) : std::string();
            snapshot.image_base = static_cast<uint64_t>(get_imagebase());
            snapshot.min_ea = static_cast<uint64_t>(inf_get_min_ea());
            snapshot.max_ea = static_cast<uint64_t>(inf_get_max_ea());
            snapshot.pointer_width_bits = inf_is_64bit() ? 64u : (inf_is_32bit_exactly() ? 32u : 16u);
            snapshot.processor = proc;
            snapshot.endianness = inf_is_be() ? "big" : "little";
            snapshot.dll = inf_is_dll();
            snapshot.kernel_mode = inf_is_kernel_mode();
            snapshot.valid = true;
            snapshot.snapshot_id = "idb_" + stable_hash_hex(snapshot.root_filename + snapshot.sha256 +
                                                            std::to_string(snapshot.image_base) +
                                                            std::to_string(snapshot.min_ea) +
                                                            std::to_string(snapshot.max_ea));
            return 1;
        }
        catch (...)
        {
            snapshot.valid = false;
            snapshot.error = "IDA snapshot capture failed";
            return 0;
        }
    }
};

std::vector<failure_code_t> failures_from_contract_eval(const contract_evaluation_t& eval)
{
    std::vector<failure_code_t> out;
    for (failure_code_t code : eval.failures)
        add_failure(out, code);
    return out;
}

}

struct ChainVerificationEngine::impl_t
{
    std::atomic_bool cancelled{false};
    mutable std::mutex mutex;
    chain_solver_t solver;

    impl_t()
        : solver({})
    {
    }
};

ChainVerificationEngine::ChainVerificationEngine()
    : m_impl(std::make_unique<impl_t>())
{
}

ChainVerificationEngine::~ChainVerificationEngine() = default;

bool ChainVerificationEngine::normalize_document(const nlohmann::json& input,
                                                 verification_document_t& out,
                                                 std::vector<failure_code_t>& failures,
                                                 std::string& error) const
{
    out = {};
    failures.clear();
    error.clear();

    if (!input.is_object())
    {
        failures.push_back(failure_code_t::invalid_chain_schema);
        error = "chain document must be a JSON object";
        return false;
    }

    out.raw = input;
    out.schema = read_string(input, "schema");
    if (out.schema != "aida_chain_document_v2")
    {
        failures.push_back(failure_code_t::invalid_chain_schema);
        error = "schema must be aida_chain_document_v2";
        return false;
    }

    out.chain_id = read_string(input, "chain_id", read_string(input, "id"));
    out.title = read_string(input, "title", read_string(input, "description"));
    out.target = input.contains("target") ? input.at("target") : nlohmann::json::object();
    out.policies = input.contains("policies") ? input.at("policies") : nlohmann::json::object();
    out.document_hash = canonical_json_hash(input);

    if (out.chain_id.empty())
    {
        failures.push_back(failure_code_t::invalid_chain_schema);
        error = "chain_id is required";
        return false;
    }

    if (!input.contains("corpus") || !input.at("corpus").is_array() || input.at("corpus").empty())
    {
        failures.push_back(failure_code_t::missing_corpus);
        error = "corpus must contain at least one code or data domain";
        return false;
    }

    std::unordered_set<std::string> corpus_ids;
    for (const auto& item : input.at("corpus"))
    {
        verification_corpus_record_t corpus;
        corpus.corpus_id = read_string(item, "corpus_id", read_string(item, "id"));
        corpus.kind = read_string(item, "kind", "binary");
        corpus.identity = item.contains("identity") ? item.at("identity") : nlohmann::json::object();
        corpus.availability = read_string(item, "availability", "missing");
        corpus.loader_model = item.contains("loader_model") ? item.at("loader_model") : nlohmann::json::object();
        corpus.trust = read_string(item, "trust", "user_declared");
        corpus.chain_critical = read_bool(item, "chain_critical", true);
        if (corpus.corpus_id.empty() || corpus_ids.find(corpus.corpus_id) != corpus_ids.end())
        {
            failures.push_back(failure_code_t::ambiguous_corpus_binding);
            error = "corpus ids must be unique and non-empty";
            return false;
        }
        corpus_ids.insert(corpus.corpus_id);
        out.corpus.push_back(std::move(corpus));
    }

    for (const char* key : {"facts", "objects", "inputs", "events"})
    {
        if (!input.contains(key) || !input.at(key).is_array())
            continue;
        for (const auto& item : input.at(key))
            out.initial_facts.push_back(fact_from_json(item, "initial", key));
    }

    if (!input.contains("links") || !input.at("links").is_array() || input.at("links").empty())
    {
        failures.push_back(failure_code_t::invalid_chain_schema);
        error = "links must contain at least one transition";
        return false;
    }

    size_t link_index = 0;
    for (const auto& item : input.at("links"))
    {
        if (!item.is_object())
        {
            failures.push_back(failure_code_t::invalid_chain_schema);
            error = "each link must be an object";
            return false;
        }
        verification_chain_link_t link;
        link.raw = item;
        link.link_id = read_string(item, "link_id", read_string(item, "id"));
        if (link.link_id.empty())
            link.link_id = "link_" + stable_hash_hex(item.dump() + std::to_string(link_index));
        link.role = read_string(item, "role", read_string(item, "kind", "transition"));

        append_contracts(link.preconditions, item, {"preconditions", "requires", "requirements"}, link.link_id, contract_dimension_t::value);
        for (const nlohmann::json& fact_json : json_array_or_empty(item, {"postconditions", "produces", "facts", "effects"}))
            link.produced_facts.push_back(fact_from_json(fact_json, link.link_id, link.link_id));

        append_solver_obligations(link.solver_obligations, item, {"solver_obligations", "branches", "branch_obligations"}, link.link_id, solver_obligation_kind_t::branch);
        const nlohmann::json obligations = get_object_or_empty(item, "obligations");
        append_solver_obligations(link.solver_obligations, obligations, {"branches", "branch_obligations", "solver"}, link.link_id, solver_obligation_kind_t::branch);

        link.path_job.job_id = "path_" + stable_hash_hex(out.document_hash + link.link_id + std::to_string(link_index));
        link.path_job.link_id = link.link_id;
        link.path_job.link_index = link_index;
        link.path_job.branch_obligations = link.solver_obligations;
        append_contracts(link.path_job.call_obligations, item, {"calls", "call_obligations"}, link.link_id, contract_dimension_t::identity);
        append_contracts(link.path_job.call_obligations, obligations, {"calls", "call_obligations"}, link.link_id, contract_dimension_t::identity);
        append_contracts(link.path_job.return_obligations, item, {"returns", "return_obligations"}, link.link_id, contract_dimension_t::value);
        append_contracts(link.path_job.return_obligations, obligations, {"returns", "return_obligations"}, link.link_id, contract_dimension_t::value);
        append_contracts(link.path_job.side_effect_obligations, item, {"side_effects", "side_effect_obligations"}, link.link_id, contract_dimension_t::value);
        append_contracts(link.path_job.side_effect_obligations, obligations, {"side_effects", "side_effect_obligations"}, link.link_id, contract_dimension_t::value);

        out.links.push_back(std::move(link));
        ++link_index;
    }

    if (!input.contains("objectives") || !input.at("objectives").is_array() || input.at("objectives").empty())
    {
        failures.push_back(failure_code_t::objective_not_achieved);
        error = "objectives must contain at least one final objective";
        return false;
    }

    for (const auto& objective : input.at("objectives"))
        out.objectives.push_back(contract_from_json(objective, "objective", contract_dimension_t::final_objective));

    return true;
}

verification_module_snapshot_t ChainVerificationEngine::capture_current_idb_snapshot() const
{
    idb_snapshot_request_t req;
    const ssize_t rc = execute_sync(req, MFF_READ);
    if (rc <= 0 && req.snapshot.error.empty())
        req.snapshot.error = "execute_sync snapshot request failed";
    return req.snapshot;
}

namespace
{

contract_evaluation_t evaluate_side_effects(const contract_trace_state_t& state,
                                            const verification_chain_link_t& link,
                                            verification_link_report_t& report)
{
    contract_evaluation_t eval = match_contracts(state, link.path_job.side_effect_obligations, proof_level_t::p2_link_obligations);
    for (const nlohmann::json& item : json_array_or_empty(link.raw, {"side_effects", "side_effect_obligations"}))
    {
        const std::string classification = lower_copy(read_string(item, "classification", read_string(item, "kind")));
        const contract_proof_state_t proof = parse_proof_state(read_string(item, "proof_state", read_string(item, "state", "unknown")));
        if ((classification == "fatal" || classification == "fatal_side_effect") && proof == contract_proof_state_t::proven)
        {
            contract_match_t match;
            match.contract_id = read_string(item, "id", "fatal_side_effect");
            match.dimension = contract_dimension_t::value;
            match.verdict = chain_verdict_t::refuted;
            match.proof_state = contract_proof_state_t::refuted;
            match.failure = failure_code_t::fatal_side_effect;
            match.acceptance_blocker = true;
            match.rationale = "fatal side effect is proven on the path";
            match.evidence = item;
            eval.matches.push_back(match);
            eval.failures.push_back(failure_code_t::fatal_side_effect);
            eval.has_acceptance_blocker = true;
            eval.verdict = chain_verdict_t::refuted;
        }
    }
    for (failure_code_t failure : eval.failures)
        add_failure(report.failures, failure);
    return eval;
}

verification_objective_report_t evaluate_objective(const contract_trace_state_t& state, const state_contract_t& objective)
{
    verification_objective_report_t out;
    out.objective_id = objective.contract_id;
    out.match = match_contract(state, objective);
    out.verdict = out.match.verdict;
    out.failure = out.match.failure;

    const nlohmann::json& req = objective.required;
    nlohmann::json sequence = nlohmann::json::array();
    if (req.is_object() && req.contains("operation_sequence") && req.at("operation_sequence").is_array())
        sequence = req.at("operation_sequence");
    else if (req.is_object() && req.contains("operation"))
        sequence.push_back(req.at("operation"));

    if (sequence.empty())
        return out;

    chain_verdict_t sequence_verdict = chain_verdict_t::confirmed;
    nlohmann::json op_reports = nlohmann::json::array();
    for (const auto& op : sequence)
    {
        const std::string op_kind = lower_copy(read_string(op, "kind", read_string(op, "operation", read_string(op, "op"))));
        nlohmann::json op_report = op;
        if (op_kind == "write_through" || op_kind == "read_through")
        {
            const std::string pointer_slot = read_string(op, "pointer_slot", read_string(op, "slot"));
            std::string actual = read_string(op, "actual_destination", read_string(op, "actual_source"));
            if (actual.empty())
                actual = find_state_value(state, pointer_slot, {"points_to", "value", "target", "address"});
            const std::string required = read_string(op, "required_updated_location",
                                                     read_string(op, "required_read_location",
                                                                 read_string(op, "updated_location",
                                                                             read_string(op, "read_location"))));
            op_report["actual_location"] = actual;
            op_report["required_location"] = required;
            if (actual.empty() || required.empty())
            {
                op_report["verdict"] = "inconclusive";
                op_report["failure"] = failure_code_str(failure_code_t::address_knowledge_gap);
                sequence_verdict = combine_verdict(sequence_verdict, chain_verdict_t::inconclusive);
                out.failure = failure_code_t::address_knowledge_gap;
            }
            else if (!same_identity(actual, required))
            {
                op_report["verdict"] = "refuted";
                op_report["failure"] = failure_code_str(failure_code_t::objective_not_achieved);
                sequence_verdict = combine_verdict(sequence_verdict, chain_verdict_t::refuted);
                out.failure = failure_code_t::objective_not_achieved;
            }
            else
            {
                op_report["verdict"] = "confirmed";
                op_report["failure"] = failure_code_str(failure_code_t::none);
            }
        }
        else
        {
            const contract_proof_state_t proof = parse_proof_state(read_string(op, "proof_state", read_string(op, "state", "unknown")));
            if (proof == contract_proof_state_t::proven)
                op_report["verdict"] = "confirmed";
            else if (proof == contract_proof_state_t::refuted)
            {
                op_report["verdict"] = "refuted";
                op_report["failure"] = failure_code_str(failure_code_t::objective_not_achieved);
                sequence_verdict = combine_verdict(sequence_verdict, chain_verdict_t::refuted);
                out.failure = failure_code_t::objective_not_achieved;
            }
            else
            {
                op_report["verdict"] = verdict_str(proof == contract_proof_state_t::timeout ? chain_verdict_t::timeout : chain_verdict_t::inconclusive);
                op_report["failure"] = failure_code_str(proof == contract_proof_state_t::timeout ? failure_code_t::solver_timeout : failure_code_t::objective_not_achieved);
                sequence_verdict = combine_verdict(sequence_verdict, proof == contract_proof_state_t::timeout ? chain_verdict_t::timeout : chain_verdict_t::inconclusive);
                out.failure = proof == contract_proof_state_t::timeout ? failure_code_t::solver_timeout : failure_code_t::objective_not_achieved;
            }
        }
        op_reports.push_back(std::move(op_report));
    }

    out.operation_evidence = nlohmann::json{{"operations", op_reports}};
    out.verdict = combine_verdict(out.verdict, sequence_verdict);
    if (out.match.verdict == chain_verdict_t::inconclusive && sequence_verdict == chain_verdict_t::confirmed)
    {
        out.verdict = chain_verdict_t::confirmed;
        out.failure = failure_code_t::none;
    }
    return out;
}

void seal_report_job(verification_report_t& report,
                     const verification_request_t& request,
                     const verification_document_t& document,
                     const budget_state_t& budget)
{
    report.job.chain_id = document.chain_id;
    report.job.document_hash = document.document_hash;
    report.job.elapsed_ms = budget.elapsed_ms();
    report.job.updated_ms = now_ms();
    report.job.phase = proof_level_str(report.proof_level);
    report.job.status = verdict_str(report.verdict);
    report.job.partial = report.verdict != chain_verdict_t::confirmed && report.proof_level != proof_level_t::p5_complete;
    report.job.resumable = report.job.partial;
    report.job.cursor.document_hash = document.document_hash;
    report.job.cursor.phase = report.job.phase;
    report.job.cursor.sealed = !report.job.resumable;
    for (failure_code_t code : report.failures)
        report.job.failure_codes.push_back(failure_code_str(code));
    if (report.job.job_id.empty())
        report.job.job_id = "job_" + stable_hash_hex(document.document_hash + request.resume.phase + std::to_string(report.job.started_ms));
}

}

verification_report_t ChainVerificationEngine::verify(const verification_request_t& request)
{
    verification_document_t document;
    std::vector<failure_code_t> normalization_failures;
    std::string normalization_error;

    verification_report_t report;
    report.job.started_ms = now_ms();

    if (!normalize_document(request.document, document, normalization_failures, normalization_error))
    {
        report.chain_id = read_string(request.document, "chain_id", "invalid");
        report.document_hash = canonical_json_hash(request.document);
        report.report_id = "report_" + stable_hash_hex(report.document_hash + "invalid");
        report.verdict = chain_verdict_t::unsupported;
        report.proof_level = proof_level_t::none;
        report.failures = normalization_failures;
        report.diagnostics["error"] = normalization_error;
        budget_state_t budget(request.limits);
        seal_report_job(report, request, document, budget);
        return report;
    }

    budget_state_t budget(request.limits);
    cancellation_token_t token = request.cancellation;
    if (m_impl->cancelled.load(std::memory_order_acquire))
        token.cancel();

    report.chain_id = document.chain_id;
    report.document_hash = document.document_hash;
    report.report_id = "report_" + stable_hash_hex(document.document_hash + std::to_string(report.job.started_ms));
    report.proof_level = proof_level_t::p0_schema;
    report.verdict = chain_verdict_t::confirmed;

    if (request.capture_idb_snapshot)
    {
        report.module_snapshot = capture_current_idb_snapshot();
        if (!report.module_snapshot.valid)
        {
            add_failure(report.failures, failure_code_t::extractor_layer_failed);
            report.verdict = combine_verdict(report.verdict, chain_verdict_t::unsupported);
        }
    }

    report.proof_level = proof_level_t::p1_corpus;
    for (const verification_corpus_record_t& corpus : document.corpus)
    {
        if (corpus.chain_critical && !accepted_corpus_availability(corpus.availability))
        {
            add_failure(report.failures, failure_code_t::missing_corpus);
            report.verdict = combine_verdict(report.verdict, chain_verdict_t::unsupported);
        }
    }

    contract_trace_state_t state = make_trace_state(document.initial_facts);
    if (budget.cancelled(token))
    {
        add_failure(report.failures, failure_code_t::resource_exhausted);
        report.verdict = verdict_for_budget(budget.exhaustion());
        report.final_state = state;
        seal_report_job(report, request, document, budget);
        return report;
    }

    report.proof_level = proof_level_t::p2_link_obligations;
    for (size_t i = request.resume.link_index; i < document.links.size(); ++i)
    {
        if (!budget.consume_link() || budget.cancelled(token))
        {
            add_failure(report.failures, failure_code_t::resource_exhausted);
            report.verdict = combine_verdict(report.verdict, verdict_for_budget(budget.exhaustion()));
            break;
        }

        const verification_chain_link_t& link = document.links[i];
        verification_link_report_t link_report;
        link_report.link_id = link.link_id;
        link_report.proof_level = proof_level_t::p2_link_obligations;
        link_report.verdict = chain_verdict_t::confirmed;

        link_report.preconditions = match_contracts(state, link.preconditions, proof_level_t::p3_boundary_contracts);
        link_report.verdict = combine_verdict(link_report.verdict, link_report.preconditions.verdict);
        for (failure_code_t code : failures_from_contract_eval(link_report.preconditions))
            add_failure(link_report.failures, code);

        link_report.solver = m_impl->solver.evaluate_all(link.solver_obligations, budget, token);
        link_report.verdict = combine_verdict(link_report.verdict, link_report.solver.verdict);
        for (failure_code_t code : link_report.solver.failures)
            add_failure(link_report.failures, code);

        link_report.calls = match_contracts(state, link.path_job.call_obligations, proof_level_t::p2_link_obligations);
        link_report.verdict = combine_verdict(link_report.verdict, link_report.calls.verdict);
        for (failure_code_t code : failures_from_contract_eval(link_report.calls))
            add_failure(link_report.failures, code);

        link_report.returns = match_contracts(state, link.path_job.return_obligations, proof_level_t::p2_link_obligations);
        link_report.verdict = combine_verdict(link_report.verdict, link_report.returns.verdict);
        for (failure_code_t code : failures_from_contract_eval(link_report.returns))
            add_failure(link_report.failures, code);

        link_report.side_effects = evaluate_side_effects(state, link, link_report);
        link_report.verdict = combine_verdict(link_report.verdict, link_report.side_effects.verdict);

        if (i > 0)
        {
            verification_boundary_report_t boundary;
            boundary.producer_link = document.links[i - 1].link_id;
            boundary.consumer_link = link.link_id;
            boundary.requirements = link_report.preconditions;
            boundary.verdict = boundary.requirements.verdict;
            report.boundaries.push_back(std::move(boundary));
        }

        for (const chain_fact_t& fact : link.produced_facts)
        {
            if (!budget.consume_fact())
            {
                add_failure(link_report.failures, failure_code_t::resource_exhausted);
                link_report.verdict = combine_verdict(link_report.verdict, chain_verdict_t::timeout);
                break;
            }
            state = append_fact(state, fact);
            link_report.produced_facts.push_back(fact);
        }

        for (failure_code_t code : link_report.failures)
            add_failure(report.failures, code);
        report.verdict = combine_verdict(report.verdict, link_report.verdict);
        report.links.push_back(std::move(link_report));

        report.job.cursor.link_index = i + 1;
        report.job.cursor.document_hash = document.document_hash;
        report.job.cursor.phase = proof_level_str(report.proof_level);
        if (token.requested() || budget.exhaustion() != budget_exhaustion_t::none)
            break;
    }

    if (token.requested() || budget.exhaustion() != budget_exhaustion_t::none)
    {
        add_failure(report.failures, failure_code_t::resource_exhausted);
        report.verdict = combine_verdict(report.verdict, verdict_for_budget(budget.exhaustion()));
        report.final_state = state;
        seal_report_job(report, request, document, budget);
        return report;
    }

    report.proof_level = proof_level_t::p4_objective_semantics;
    for (const state_contract_t& objective : document.objectives)
    {
        verification_objective_report_t objective_report = evaluate_objective(state, objective);
        report.verdict = combine_verdict(report.verdict, objective_report.verdict);
        if (objective_report.failure != failure_code_t::none)
            add_failure(report.failures, objective_report.failure);
        report.objectives.push_back(std::move(objective_report));
    }

    report.final_state = state;
    report.proof_level = report.verdict == chain_verdict_t::confirmed && report.failures.empty()
        ? proof_level_t::p5_complete
        : report.proof_level;
    if (!report.failures.empty() && report.verdict == chain_verdict_t::confirmed)
        report.verdict = chain_verdict_t::inconclusive;
    report.diagnostics["solver_cache_size"] = m_impl->solver.cache_size();
    report.diagnostics["budget"] = to_json(request.limits);
    report.diagnostics["budget_exhaustion"] = budget_exhaustion_str(budget.exhaustion());
    seal_report_job(report, request, document, budget);
    return report;
}

void ChainVerificationEngine::cancel()
{
    m_impl->cancelled.store(true, std::memory_order_release);
}

size_t ChainVerificationEngine::solver_cache_size() const
{
    return m_impl->solver.cache_size();
}

void ChainVerificationEngine::clear_solver_cache()
{
    m_impl->solver.clear_cache();
}

ChainVerificationEngine& engine()
{
    static ChainVerificationEngine g_engine;
    return g_engine;
}

std::vector<nlohmann::json> universal_synthetic_regression_specs()
{
    std::vector<nlohmann::json> specs;
    specs.push_back({
        {"schema", "aida_chain_document_v2"},
        {"chain_id", "synthetic_controlled_copy_confirm"},
        {"target", {{"architecture", "x86_64"}, {"platform", "user_mode"}}},
        {"corpus", {{{"corpus_id", "mod"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "synthetic"}}}, {"trust", "recorded_dynamic"}}}},
        {"facts", {{{"id", "input_control"}, {"kind", "content_fact"}, {"subject", "buf"}, {"predicate", "content"}, {"value", {{"content_class", "controlled"}, {"controlled", true}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}},
        {"links", {
            {{"id", "copy"}, {"preconditions", {{{"id", "need_controlled"}, {"dimension", "content"}, {"subject", "buf"}, {"predicate", "content"}, {"required", {{"controlled", true}}}}}}, {"postconditions", {{{"id", "field_control"}, {"kind", "content_fact"}, {"subject", "obj.field"}, {"predicate", "content"}, {"value", {{"content_class", "controlled"}, {"controlled", true}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}}},
            {{"id", "consume"}, {"preconditions", {{{"id", "consume_controlled"}, {"dimension", "content"}, {"subject", "obj.field"}, {"predicate", "content"}, {"required", {{"controlled", true}}}}}}, {"postconditions", {{{"id", "objective_done"}, {"kind", "objective_fact"}, {"subject", "goal"}, {"predicate", "achieved"}, {"value", {{"achieved", true}}}, {"proof_state", "proven"}, {"criticality", "objective_critical"}}}}}
        }},
        {"objectives", {{{"id", "goal"}, {"dimension", "final_objective"}, {"subject", "goal"}, {"predicate", "achieved"}, {"required", {{"achieved", true}}}}}}
    });
    specs.push_back({
        {"schema", "aida_chain_document_v2"},
        {"chain_id", "synthetic_zero_fill_refutes_control"},
        {"target", {{"architecture", "x86_64"}, {"platform", "user_mode"}}},
        {"corpus", {{{"corpus_id", "mod"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "synthetic"}}}, {"trust", "recorded_dynamic"}}}},
        {"links", {
            {{"id", "zero_fill"}, {"postconditions", {{{"id", "zero_field"}, {"kind", "content_fact"}, {"subject", "obj.ptr"}, {"predicate", "content"}, {"value", {{"content_class", "zero_bytes"}, {"zero", true}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}}},
            {{"id", "consume_pointer"}, {"preconditions", {{{"id", "needs_controlled_pointer"}, {"dimension", "content"}, {"subject", "obj.ptr"}, {"predicate", "content"}, {"required", {{"controlled", true}}}}}}, {"postconditions", {{{"id", "goal_unknown"}, {"kind", "objective_fact"}, {"subject", "goal"}, {"predicate", "achieved"}, {"value", {{"achieved", false}}}, {"proof_state", "refuted"}, {"criticality", "objective_critical"}}}}}
        }},
        {"objectives", {{{"id", "goal"}, {"dimension", "final_objective"}, {"subject", "goal"}, {"predicate", "achieved"}, {"required", {{"achieved", true}}}}}}
    });
    specs.push_back({
        {"schema", "aida_chain_document_v2"},
        {"chain_id", "synthetic_self_reference_required"},
        {"target", {{"architecture", "x86_64"}, {"platform", "user_mode"}}},
        {"corpus", {{{"corpus_id", "mod"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "synthetic"}}}, {"trust", "recorded_dynamic"}}}},
        {"links", {
            {{"id", "hidden_check"}, {"preconditions", {{{"id", "needs_self_ref"}, {"dimension", "alias_set"}, {"subject", "node.flink"}, {"predicate", "self_reference"}, {"required", {{"self_reference", true}}}, {"failure_when_unmet", "self_reference_unproven"}}}}, {"postconditions", {{{"id", "goal_unproven"}, {"kind", "objective_fact"}, {"subject", "goal"}, {"predicate", "achieved"}, {"value", {{"achieved", false}}}, {"proof_state", "unknown"}, {"criticality", "objective_critical"}}}}}
        }},
        {"objectives", {{{"id", "goal"}, {"dimension", "final_objective"}, {"subject", "goal"}, {"predicate", "achieved"}, {"required", {{"achieved", true}}}}}}
    });
    specs.push_back({
        {"schema", "aida_chain_document_v2"},
        {"chain_id", "synthetic_self_reference_positive"},
        {"target", {{"architecture", "x86_64"}, {"platform", "user_mode"}}},
        {"corpus", {{{"corpus_id", "mod"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "synthetic"}}}, {"trust", "recorded_dynamic"}}}},
        {"facts", {{{"id", "self_ref_fact"}, {"kind", "alias_fact"}, {"subject", "node.flink"}, {"predicate", "self_reference"}, {"value", {{"self_reference", true}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}},
        {"links", {
            {{"id", "hidden_check"}, {"preconditions", {{{"id", "needs_self_ref"}, {"dimension", "alias_set"}, {"subject", "node.flink"}, {"predicate", "self_reference"}, {"required", {{"self_reference", true}}}}}}, {"postconditions", {{{"id", "goal_done"}, {"kind", "objective_fact"}, {"subject", "goal"}, {"predicate", "achieved"}, {"value", {{"achieved", true}}}, {"proof_state", "proven"}, {"criticality", "objective_critical"}}}}}
        }},
        {"objectives", {{{"id", "goal"}, {"dimension", "final_objective"}, {"subject", "goal"}, {"predicate", "achieved"}, {"required", {{"achieved", true}}}}}}
    });
    specs.push_back({
        {"schema", "aida_chain_document_v2"},
        {"chain_id", "synthetic_write_through_mismatch"},
        {"target", {{"architecture", "x86_64"}, {"platform", "user_mode"}}},
        {"corpus", {{{"corpus_id", "mod"}, {"kind", "binary"}, {"availability", "recorded_only"}, {"identity", {{"sha256", "synthetic"}}}, {"trust", "recorded_dynamic"}}}},
        {"facts", {{{"id", "slot_points_elsewhere"}, {"kind", "alias_fact"}, {"subject", "surface.slot"}, {"predicate", "points_to"}, {"value", {{"target", "global.manager"}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}},
        {"links", {{{"id", "write_through"}, {"postconditions", {{{"id", "write_done"}, {"kind", "memory_fact"}, {"subject", "global.manager"}, {"predicate", "written"}, {"value", {{"value", "target"}}}, {"proof_state", "proven"}, {"criticality", "chain_critical"}}}}}}},
        {"objectives", {{{"id", "redirect_slot"}, {"dimension", "final_objective"}, {"subject", "surface.slot"}, {"predicate", "written"}, {"required", {{"operation", {{"kind", "write_through"}, {"pointer_slot", "surface.slot"}, {"required_updated_location", "surface.slot"}}}}}}}}
    });
    return specs;
}

nlohmann::json to_json(const verification_corpus_record_t& corpus)
{
    return nlohmann::json{
        {"corpus_id", corpus.corpus_id},
        {"kind", corpus.kind},
        {"identity", corpus.identity},
        {"availability", corpus.availability},
        {"loader_model", corpus.loader_model},
        {"trust", corpus.trust},
        {"chain_critical", corpus.chain_critical}
    };
}

nlohmann::json to_json(const verification_module_snapshot_t& snapshot)
{
    return nlohmann::json{
        {"snapshot_id", snapshot.snapshot_id},
        {"root_filename", snapshot.root_filename},
        {"input_path", snapshot.input_path},
        {"sha256", snapshot.sha256},
        {"image_base", snapshot.image_base},
        {"min_ea", snapshot.min_ea},
        {"max_ea", snapshot.max_ea},
        {"pointer_width_bits", snapshot.pointer_width_bits},
        {"processor", snapshot.processor},
        {"endianness", snapshot.endianness},
        {"dll", snapshot.dll},
        {"kernel_mode", snapshot.kernel_mode},
        {"valid", snapshot.valid},
        {"error", snapshot.error}
    };
}

nlohmann::json to_json(const verification_path_job_t& job)
{
    nlohmann::json branches = nlohmann::json::array();
    for (const auto& item : job.branch_obligations)
        branches.push_back(to_json(item));
    nlohmann::json calls = nlohmann::json::array();
    for (const auto& item : job.call_obligations)
        calls.push_back(to_json(item));
    nlohmann::json returns = nlohmann::json::array();
    for (const auto& item : job.return_obligations)
        returns.push_back(to_json(item));
    nlohmann::json side_effects = nlohmann::json::array();
    for (const auto& item : job.side_effect_obligations)
        side_effects.push_back(to_json(item));
    return nlohmann::json{
        {"job_id", job.job_id},
        {"link_id", job.link_id},
        {"link_index", job.link_index},
        {"branch_obligations", branches},
        {"call_obligations", calls},
        {"return_obligations", returns},
        {"side_effect_obligations", side_effects}
    };
}

nlohmann::json to_json(const verification_chain_link_t& link)
{
    nlohmann::json pre = nlohmann::json::array();
    for (const auto& item : link.preconditions)
        pre.push_back(to_json(item));
    nlohmann::json facts = nlohmann::json::array();
    for (const auto& item : link.produced_facts)
        facts.push_back(to_json(item));
    nlohmann::json solver = nlohmann::json::array();
    for (const auto& item : link.solver_obligations)
        solver.push_back(to_json(item));
    return nlohmann::json{
        {"link_id", link.link_id},
        {"role", link.role},
        {"preconditions", pre},
        {"produced_facts", facts},
        {"solver_obligations", solver},
        {"path_job", to_json(link.path_job)}
    };
}

nlohmann::json to_json(const verification_document_t& document)
{
    nlohmann::json corpus = nlohmann::json::array();
    for (const auto& item : document.corpus)
        corpus.push_back(to_json(item));
    nlohmann::json facts = nlohmann::json::array();
    for (const auto& item : document.initial_facts)
        facts.push_back(to_json(item));
    nlohmann::json links = nlohmann::json::array();
    for (const auto& item : document.links)
        links.push_back(to_json(item));
    nlohmann::json objectives = nlohmann::json::array();
    for (const auto& item : document.objectives)
        objectives.push_back(to_json(item));
    return nlohmann::json{
        {"schema", document.schema},
        {"chain_id", document.chain_id},
        {"title", document.title},
        {"target", document.target},
        {"corpus", corpus},
        {"initial_facts", facts},
        {"links", links},
        {"objectives", objectives},
        {"policies", document.policies},
        {"document_hash", document.document_hash}
    };
}

nlohmann::json to_json(const verification_request_t& request)
{
    return nlohmann::json{
        {"document", request.document},
        {"limits", to_json(request.limits)},
        {"resume", to_json(request.resume)},
        {"capture_idb_snapshot", request.capture_idb_snapshot}
    };
}

nlohmann::json to_json(const verification_link_report_t& report)
{
    nlohmann::json facts = nlohmann::json::array();
    for (const auto& item : report.produced_facts)
        facts.push_back(to_json(item));
    nlohmann::json failures = nlohmann::json::array();
    for (failure_code_t code : report.failures)
        failures.push_back(failure_code_str(code));
    return nlohmann::json{
        {"link_id", report.link_id},
        {"verdict", verdict_str(report.verdict)},
        {"proof_level", proof_level_str(report.proof_level)},
        {"preconditions", to_json(report.preconditions)},
        {"solver", to_json(report.solver)},
        {"calls", to_json(report.calls)},
        {"returns", to_json(report.returns)},
        {"side_effects", to_json(report.side_effects)},
        {"produced_facts", facts},
        {"failures", failures}
    };
}

nlohmann::json to_json(const verification_boundary_report_t& report)
{
    return nlohmann::json{
        {"producer_link", report.producer_link},
        {"consumer_link", report.consumer_link},
        {"verdict", verdict_str(report.verdict)},
        {"requirements", to_json(report.requirements)}
    };
}

nlohmann::json to_json(const verification_objective_report_t& report)
{
    return nlohmann::json{
        {"objective_id", report.objective_id},
        {"verdict", verdict_str(report.verdict)},
        {"match", to_json(report.match)},
        {"failure", failure_code_str(report.failure)},
        {"operation_evidence", report.operation_evidence}
    };
}

nlohmann::json to_json(const verification_report_t& report)
{
    nlohmann::json failures = nlohmann::json::array();
    for (failure_code_t code : report.failures)
        failures.push_back(failure_code_str(code));
    nlohmann::json links = nlohmann::json::array();
    for (const auto& item : report.links)
        links.push_back(to_json(item));
    nlohmann::json boundaries = nlohmann::json::array();
    for (const auto& item : report.boundaries)
        boundaries.push_back(to_json(item));
    nlohmann::json objectives = nlohmann::json::array();
    for (const auto& item : report.objectives)
        objectives.push_back(to_json(item));
    return nlohmann::json{
        {"report_id", report.report_id},
        {"chain_id", report.chain_id},
        {"document_hash", report.document_hash},
        {"verdict", verdict_str(report.verdict)},
        {"proof_level", proof_level_str(report.proof_level)},
        {"job", to_json(report.job)},
        {"module_snapshot", to_json(report.module_snapshot)},
        {"failures", failures},
        {"links", links},
        {"boundaries", boundaries},
        {"objectives", objectives},
        {"final_state", to_json(report.final_state)},
        {"diagnostics", report.diagnostics}
    };
}

}
}
}
