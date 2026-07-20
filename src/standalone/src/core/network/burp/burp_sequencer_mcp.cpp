#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_sequencer_mcp.hpp"
#include "sequencer.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace sequencer_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

std::vector<uint8_t> b64_decode(const std::string& s)
{
    std::vector<uint8_t> out;
    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    int val = 0;
    int valb = -8;
    for (uint8_t c : s) {
        int v = table[c];
        if (v < 0) {
            if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
            return {};
        }
        val = (val << 6) | v;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

json analysis_to_json(const aida::burp::sequencer::analysis_result_t& a)
{
    auto pack_p = [](double v) -> json {
        if (std::isnan(v)) return nullptr;
        return v;
    };
    json out;
    out["collection_id"]        = a.collection_id;
    out["analysis_mode"]        = a.analysis_mode;
    out["samples_count"]        = static_cast<uint64_t>(a.samples_count);
    out["token_length_mode"]    = static_cast<uint64_t>(a.token_length_mode);
    out["min_token_length"]     = static_cast<uint64_t>(a.min_token_length);
    out["max_token_length"]     = static_cast<uint64_t>(a.max_token_length);
    out["alphabet_size"]        = static_cast<uint64_t>(a.alphabet_size);
    out["total_bits"]           = static_cast<uint64_t>(a.total_bits);
    out["shannon_entropy_bits"] = a.shannon_entropy_bits;
    out["min_entropy_bits_per_symbol"] = a.min_entropy_bits_per_symbol;
    out["chi_square"]           = a.chi_square;
    out["chi_square_p_value"]   = pack_p(a.chi_square_p_value);
    out["monobit_p_value"]      = pack_p(a.monobit_p_value);
    out["monobit_ones"]         = static_cast<uint64_t>(a.monobit_ones);
    out["monobit_zeros"]        = static_cast<uint64_t>(a.monobit_zeros);
    out["poker_p_value"]        = pack_p(a.poker_p_value);
    out["runs_p_value"]         = pack_p(a.runs_p_value);
    out["long_run_p_value"]     = pack_p(a.long_run_p_value);
    out["maurer_universal"]     = pack_p(a.maurer_universal);
    out["autocorrelation"]      = pack_p(a.autocorrelation);
    out["serial_correlation"]   = pack_p(a.serial_correlation);
    out["compression_ratio"]    = pack_p(a.compression_ratio);
    out["passes_fips_140_2"]    = a.passes_fips_140_2;
    out["fips_assessment"]      = a.fips_assessment;
    out["nist_sp800_90b_assessment"] = a.nist_sp800_90b_assessment;
    out["confidence_score"]     = a.confidence_score;
    out["confidence_label"]     = a.confidence_label;
    out["valid"]                = a.valid;
    out["verdict"]              = a.verdict;
    out["notes"]                = a.notes;
    json freq = json::array();
    for (size_t i = 0; i < 256; ++i) freq.push_back(static_cast<uint64_t>(a.byte_frequency[i]));
    out["byte_frequency"]       = std::move(freq);
    json bias = json::array();
    for (size_t i = 0; i < 256; ++i) bias.push_back(a.position_bias[i]);
    out["position_bias"]        = std::move(bias);
    json positions = json::array();
    for (const auto& ps : a.position_analysis) {
        json item;
        item["index"] = static_cast<uint64_t>(ps.index);
        item["samples"] = static_cast<uint64_t>(ps.samples);
        item["distinct_symbols"] = static_cast<uint64_t>(ps.distinct_symbols);
        item["most_common_symbol"] = static_cast<uint32_t>(ps.most_common_symbol);
        item["most_common_count"] = static_cast<uint64_t>(ps.most_common_count);
        item["most_common_frequency"] = ps.most_common_frequency;
        item["entropy_bits"] = ps.entropy_bits;
        item["chi_square"] = ps.chi_square;
        item["chi_square_p_value"] = pack_p(ps.chi_square_p_value);
        positions.push_back(std::move(item));
    }
    out["position_analysis"] = std::move(positions);
    return out;
}

json status_to_json(const aida::burp::sequencer::collection_status_t& s)
{
    json j;
    j["id"]             = s.id;
    j["url"]            = s.url;
    j["name"]           = s.name;
    j["collected"]      = static_cast<uint64_t>(s.collected);
    j["target"]         = static_cast<uint64_t>(s.target);
    j["running"]        = s.running;
    j["error"]          = s.error;
    j["error_message"]  = s.error_message;
    j["started_ms"]     = static_cast<uint64_t>(s.started_ms);
    j["last_sample_ms"] = static_cast<uint64_t>(s.last_sample_ms);
    j["instance_revision"] = s.instance_revision;
    j["retained_sample_bytes"] = static_cast<uint64_t>(s.retained_sample_bytes);
    return j;
}

json sequence_ids_json(const std::vector<aida::burp::sequencer::collection_status_t>& collections)
{
    json arr = json::array();
    for (const auto& c : collections) arr.push_back(c.id);
    return arr;
}

json count_or_null(bool available, size_t value)
{
    return available ? json(static_cast<uint64_t>(value)) : json(nullptr);
}

json sequencer_state_to_json(const aida::burp::sequencer::collection_status_t& s)
{
    json j = status_to_json(s);
    j["active"] = s.id != 0 && s.running;
    j["source_url"] = s.url;
    j["token_collection_id"] = s.id;
    j["sample_count"] = static_cast<uint64_t>(s.collected);
    j["collected_count"] = static_cast<uint64_t>(s.collected);
    j["target_count"] = static_cast<uint64_t>(s.target);
    return j;
}

tool_result_t handle_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "sequencer_start url=%s name=%s", p.value("url", std::string()).c_str(), p.value("name", std::string()).c_str());
    aida::burp::sequencer::collection_config_t cfg;
    if (p.contains("url") && p["url"].is_string()) cfg.url = p["url"].get<std::string>();
    if (p.contains("raw_request_b64") && p["raw_request_b64"].is_string()) {
        cfg.raw_request = b64_decode(p["raw_request_b64"].get<std::string>());
    }
    if (p.contains("use_tls") && p["use_tls"].is_boolean()) cfg.use_tls = p["use_tls"].get<bool>();
    if (p.contains("host") && p["host"].is_string()) cfg.host = p["host"].get<std::string>();
    if (p.contains("port") && p["port"].is_number()) cfg.port = static_cast<uint16_t>(p["port"].get<int>());
    if (p.contains("extract_regex") && p["extract_regex"].is_string()) cfg.extract_regex = p["extract_regex"].get<std::string>();
    if (p.contains("capture_group") && p["capture_group"].is_number()) cfg.capture_group = p["capture_group"].get<int>();
    if (p.contains("target_count") && p["target_count"].is_number()) cfg.target_count = p["target_count"].get<size_t>();
    if (p.contains("concurrency") && p["concurrency"].is_number()) cfg.concurrency = p["concurrency"].get<size_t>();
    if (p.contains("throttle_ms") && p["throttle_ms"].is_number()) cfg.throttle_ms = p["throttle_ms"].get<size_t>();
    if (p.contains("name") && p["name"].is_string()) cfg.name = p["name"].get<std::string>();

    uint64_t id = aida::burp::sequencer::start_collection(cfg);
    if (id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_start failed err=%s", aida::burp::sequencer::last_error().c_str());
        return tool_result_t::error("start failed: " + aida::burp::sequencer::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "sequencer_start ok collection_id=%llu target=%zu", static_cast<unsigned long long>(id), cfg.target_count);
    json out;
    out["collection_id"] = id;
    return tool_result_t::ok("collection started id=" + std::to_string(id), out);
}

tool_result_t handle_status(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "sequencer_status entry");
    if (!p.contains("collection_id") || !p["collection_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_status missing collection_id");
        return tool_result_t::error("collection_id required");
    }
    const uint64_t cid = p["collection_id"].get<uint64_t>();
    auto s = aida::burp::sequencer::status(cid);
    if (s.id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_status not_found id=%llu", static_cast<unsigned long long>(cid));
        return tool_result_t::error("collection not found");
    }
    diag::log_tagged_fmt("mcp_burp", "sequencer_status ok id=%llu collected=%zu running=%d", static_cast<unsigned long long>(cid), s.collected, (int)s.running);
    return tool_result_t::ok("collection status id=" + std::to_string(cid) + " collected=" + std::to_string(s.collected) + " target=" + std::to_string(s.target), status_to_json(s));
}

tool_result_t handle_stop(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "sequencer_stop entry");
    if (!p.contains("collection_id") || !p["collection_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_stop missing collection_id");
        return tool_result_t::error("collection_id required");
    }
    const uint64_t cid = p["collection_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "sequencer_stop collection_id=%llu", static_cast<unsigned long long>(cid));
    auto before = aida::burp::sequencer::status(cid);
    auto before_list = aida::burp::sequencer::list_collections();
    bool ok = aida::burp::sequencer::stop_collection(cid);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_stop not_found id=%llu", static_cast<unsigned long long>(cid));
        return tool_result_t::error("collection not found");
    }
    auto after = aida::burp::sequencer::status(cid);
    auto after_list = aida::burp::sequencer::list_collections();
    json out;
    out["collection_id"] = cid;
    out["token_collection_id"] = cid;
    out["source_url"] = before.id != 0 ? before.url : after.url;
    out["name"] = before.id != 0 ? before.name : after.name;
    out["stop_requested"] = true;
    out["stopped"] = after.id != 0 && !after.running;
    out["deleted"] = false;
    out["before_active"] = before.id != 0 && before.running;
    out["after_active"] = after.id != 0 && after.running;
    out["samples_before"] = before.id != 0 ? static_cast<uint64_t>(before.collected) : 0;
    out["samples_after"] = after.id != 0 ? static_cast<uint64_t>(after.collected) : 0;
    out["collected_count_before"] = before.id != 0 ? static_cast<uint64_t>(before.collected) : 0;
    out["collected_count_after"] = after.id != 0 ? static_cast<uint64_t>(after.collected) : 0;
    out["target_count_before"] = before.id != 0 ? static_cast<uint64_t>(before.target) : 0;
    out["target_count_after"] = after.id != 0 ? static_cast<uint64_t>(after.target) : 0;
    out["before_sequence_count"] = static_cast<uint64_t>(before_list.size());
    out["remaining_sequence_count"] = static_cast<uint64_t>(after_list.size());
    out["remaining_ids"] = sequence_ids_json(after_list);
    out["before"] = sequencer_state_to_json(before);
    out["after"] = sequencer_state_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "sequencer_stop ok collection_id=%llu", static_cast<unsigned long long>(cid));
    return tool_result_t::ok("collection stopping", out);
}

tool_result_t handle_samples(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "sequencer_samples entry");
    if (!p.contains("collection_id") || !p["collection_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_samples missing collection_id");
        return tool_result_t::error("collection_id required");
    }
    const uint64_t cid = p["collection_id"].get<uint64_t>();
    size_t max_count = 0;
    if (p.contains("max") && p["max"].is_number()) max_count = p["max"].get<size_t>();
    diag::log_tagged_fmt("mcp_burp", "sequencer_samples collection_id=%llu max=%zu", static_cast<unsigned long long>(cid), max_count);
    auto v = aida::burp::sequencer::samples(cid, max_count);
    json arr = json::array();
    for (const auto& s : v) arr.push_back(s);
    diag::log_tagged_fmt("mcp_burp", "sequencer_samples ok id=%llu returned=%zu", static_cast<unsigned long long>(cid), v.size());
    json out;
    out["samples"] = std::move(arr);
    out["count"]   = static_cast<uint64_t>(v.size());
    return tool_result_t::ok("samples count=" + std::to_string(v.size()), out);
}

tool_result_t handle_analyze(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "sequencer_analyze entry");
    if (!p.contains("collection_id") || !p["collection_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_analyze missing collection_id");
        return tool_result_t::error("collection_id required");
    }
    const uint64_t cid = p["collection_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "sequencer_analyze collection_id=%llu", static_cast<unsigned long long>(cid));
    aida::burp::sequencer::analysis_config_t cfg;
    if (p.contains("mode") && p["mode"].is_string()) cfg.mode = p["mode"].get<std::string>();
    if (p.contains("analysis_mode") && p["analysis_mode"].is_string()) cfg.mode = p["analysis_mode"].get<std::string>();
    if (p.contains("max_positions") && p["max_positions"].is_number_unsigned()) cfg.max_positions = p["max_positions"].get<size_t>();
    auto a = aida::burp::sequencer::analyze(cid, cfg);
    diag::log_tagged_fmt("mcp_burp", "sequencer_analyze ok id=%llu samples=%llu verdict=%s", static_cast<unsigned long long>(cid), static_cast<unsigned long long>(a.samples_count), a.verdict.c_str());
    return tool_result_t::ok("analysis samples=" + std::to_string(a.samples_count) + " verdict=" + a.verdict, analysis_to_json(a));
}

tool_result_t handle_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "sequencer_list entry");
    auto snapshot = aida::burp::sequencer::snapshot_collections();
    json arr = json::array();
    for (const auto& s : snapshot.collections) arr.push_back(status_to_json(s));
    diag::log_tagged_fmt("mcp_burp", "sequencer_list ok count=%zu", snapshot.collections.size());
    json out;
    out["collections"] = std::move(arr);
    out["generation"] = snapshot.generation;
    out["capacity"] = {
        {"collection_count", snapshot.capacity.collection_count},
        {"collection_limit", snapshot.capacity.collection_limit},
        {"retained_sample_bytes", snapshot.capacity.retained_sample_bytes},
        {"retained_sample_limit", snapshot.capacity.retained_sample_limit}
    };
    return tool_result_t::ok("collections count=" + std::to_string(snapshot.collections.size()), out);
}

tool_result_t handle_delete(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "sequencer_delete entry");
    if (!p.contains("collection_id") || !p["collection_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_delete missing collection_id");
        return tool_result_t::error("collection_id required");
    }
    const uint64_t cid = p["collection_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "sequencer_delete collection_id=%llu", static_cast<unsigned long long>(cid));
    auto before = aida::burp::sequencer::status(cid);
    auto before_list = aida::burp::sequencer::list_collections();
    bool ok = aida::burp::sequencer::delete_collection(cid);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "sequencer_delete not_found id=%llu", static_cast<unsigned long long>(cid));
        return tool_result_t::error("collection not found");
    }
    auto after = aida::burp::sequencer::status(cid);
    auto after_list = aida::burp::sequencer::list_collections();
    bool after_available = after.id != 0;
    json out;
    out["collection_id"] = cid;
    out["token_collection_id"] = cid;
    out["source_url"] = before.url;
    out["name"] = before.name;
    out["stop_requested"] = true;
    out["stopped"] = !after_available || !after.running;
    out["deleted"] = true;
    out["before_active"] = before.id != 0 && before.running;
    out["after_active"] = after_available && after.running;
    out["status_available_after"] = after_available;
    out["samples_before"] = before.id != 0 ? static_cast<uint64_t>(before.collected) : 0;
    out["samples_after"] = count_or_null(after_available, after.collected);
    out["collected_count_before"] = before.id != 0 ? static_cast<uint64_t>(before.collected) : 0;
    out["collected_count_after"] = count_or_null(after_available, after.collected);
    out["target_count_before"] = before.id != 0 ? static_cast<uint64_t>(before.target) : 0;
    out["target_count_after"] = count_or_null(after_available, after.target);
    out["before_sequence_count"] = static_cast<uint64_t>(before_list.size());
    out["remaining_sequence_count"] = static_cast<uint64_t>(after_list.size());
    out["remaining_ids"] = sequence_ids_json(after_list);
    out["before"] = sequencer_state_to_json(before);
    out["after"] = after_available ? sequencer_state_to_json(after) : json(nullptr);
    diag::log_tagged_fmt("mcp_burp", "sequencer_delete ok collection_id=%llu", static_cast<unsigned long long>(cid));
    return tool_result_t::ok("collection deleted", out);
}

}

void register_sequencer_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_sequencer_manage", "burp",
        "Manage Sequencer token collection and advanced entropy analysis. Actions: start_collection, status, stop, samples, analyze, list_collections, delete. Analyze supports mode all|bit|byte|character|position and max_positions.",
        {{"action", "string", "start_collection|status|stop|samples|analyze|list_collections|delete", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start_collection") return handle_start(p);
            if (action == "status") return handle_status(p);
            if (action == "stop") return handle_stop(p);
            if (action == "samples") return handle_samples(p);
            if (action == "analyze") return handle_analyze(p);
            if (action == "list_collections") return handle_list(p);
            if (action == "delete") return handle_delete(p);
            return compat_unknown_action("burp_sequencer_manage", action);
        },
        false
    });
}

}
}
}
