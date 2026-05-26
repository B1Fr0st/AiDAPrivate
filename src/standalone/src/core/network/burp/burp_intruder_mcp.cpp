#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_intruder_mcp.hpp"

#include "intruder_engine.hpp"
#include "param_miner.hpp"
#include "h2_editor.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

const char* json_type_name(const json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_null()) return "null";
    return "other";
}

std::string json_shape(const json& j, size_t max_keys = 12)
{
    std::ostringstream oss;
    oss << json_type_name(j);
    if (j.is_object())
    {
        oss << "{";
        size_t n = 0;
        for (auto it = j.begin(); it != j.end() && n < max_keys; ++it, ++n)
        {
            if (n) oss << ",";
            oss << it.key() << ":" << json_type_name(it.value());
        }
        if (j.size() > max_keys) oss << ",...";
        oss << "}";
    }
    else if (j.is_array())
    {
        oss << "[" << j.size() << "]";
    }
    return oss.str();
}

std::vector<uint8_t> b64_decode(const std::string& s)
{
    static const int8_t tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t buf = 0; int bits = 0;
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = tbl[c];
        if (v == -1) return std::vector<uint8_t>();
        if (v == -2) break;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::string b64_encode(const std::vector<uint8_t>& v)
{
    static const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((v.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= v.size()) {
        uint32_t n = (static_cast<uint32_t>(v[i]) << 16) | (static_cast<uint32_t>(v[i + 1]) << 8) | v[i + 2];
        out.push_back(alpha[(n >> 18) & 0x3F]);
        out.push_back(alpha[(n >> 12) & 0x3F]);
        out.push_back(alpha[(n >> 6) & 0x3F]);
        out.push_back(alpha[n & 0x3F]);
        i += 3;
    }
    if (i < v.size()) {
        uint32_t n = static_cast<uint32_t>(v[i]) << 16;
        if (i + 1 < v.size()) n |= static_cast<uint32_t>(v[i + 1]) << 8;
        out.push_back(alpha[(n >> 18) & 0x3F]);
        out.push_back(alpha[(n >> 12) & 0x3F]);
        if (i + 1 < v.size()) out.push_back(alpha[(n >> 6) & 0x3F]);
        else                  out.push_back('=');
        out.push_back('=');
    }
    return out;
}

static tool_result_t burp_intruder_start(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_start host=%s mode=%s",
        params.contains("host") && params["host"].is_string() ? params["host"].get<std::string>().c_str() : "<missing>",
        params.value("attack_mode", std::string("sniper")).c_str());
    intruder::config_t cfg;
    if (!params.contains("host") || !params["host"].is_string()) {
        return tool_result_t::error("host required");
    }
    cfg.host = params["host"].get<std::string>();
    if (params.contains("port") && params["port"].is_number_integer()) {
        cfg.port = static_cast<uint16_t>(params["port"].get<int>());
    } else {
        cfg.port = 443;
    }
    if (params.contains("scheme") && params["scheme"].is_string()) cfg.scheme = params["scheme"].get<std::string>();

    if (params.contains("base_request_b64") && params["base_request_b64"].is_string()) {
        auto dec = b64_decode(params["base_request_b64"].get<std::string>());
        if (dec.empty()) return tool_result_t::error("base_request_b64 invalid");
        cfg.base_request = std::move(dec);
    } else if (params.contains("base_request") && params["base_request"].is_string()) {
        const std::string& s = params["base_request"].get_ref<const std::string&>();
        cfg.base_request.assign(s.begin(), s.end());
    } else {
        return tool_result_t::error("base_request or base_request_b64 required");
    }

    std::string am = params.value("attack_mode", std::string("sniper"));
    if (!intruder::parse_attack_mode(am, cfg.attack_mode)) return tool_result_t::error("invalid attack_mode");
    std::string em = params.value("engine_mode", std::string("http1_pooled"));
    if (!intruder::parse_engine_mode(em, cfg.engine_mode)) return tool_result_t::error("invalid engine_mode");

    if (params.contains("positions") && params["positions"].is_array()) {
        for (auto& it : params["positions"]) {
            if (!it.is_array() || it.size() < 2) continue;
            size_t off = it[0].get<size_t>();
            size_t len = it[1].get<size_t>();
            cfg.positions.push_back({ off, len });
        }
    }
    if (params.contains("payload_sets") && params["payload_sets"].is_array()) {
        for (auto& s : params["payload_sets"]) {
            std::vector<std::string> ps;
            if (s.is_array()) {
                for (auto& p : s) if (p.is_string()) ps.push_back(p.get<std::string>());
            }
            cfg.payload_sets.push_back(std::move(ps));
        }
    }

    cfg.concurrency = params.value("concurrency", static_cast<size_t>(32));
    cfg.requests_per_second_cap = params.value("rps_cap", static_cast<size_t>(0));
    cfg.total_requests_cap = params.value("total_cap", static_cast<size_t>(0));
    cfg.timeout_ms = params.value("timeout_ms", 15000);
    cfg.follow_redirects = params.value("follow_redirects", 0);
    cfg.race_gate_size = params.value("race_gate_size", static_cast<size_t>(30));
    cfg.race_warmup_count = params.value("race_warmup", 0);
    cfg.max_response_body_bytes = params.value("max_body_bytes", static_cast<size_t>(65536));

    uint64_t id = intruder::start(std::move(cfg));
    if (id == 0) {
        diag::log_tagged_fmt("mcp_burp", "intruder_start failed err=%s", intruder::last_error().c_str());
        return tool_result_t::error(std::string("intruder::start failed: ") + intruder::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "intruder_start ok job_id=%llu", static_cast<unsigned long long>(id));
    json r;
    r["job_id"] = id;
    return tool_result_t::ok("intruder job started", r);
}

static tool_result_t burp_intruder_status(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_status job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    intruder::status_t s = intruder::status(id);
    if (s.job_id == 0) { diag::log_tagged_fmt("mcp_burp", "intruder_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    json r;
    r["job_id"] = s.job_id;
    r["total"] = s.total;
    r["sent"] = s.sent;
    r["errors"] = s.errors;
    r["running"] = s.running;
    r["current_rps"] = s.current_rps;
    r["started_unix_ms"] = s.started_unix_ms;
    r["finished_unix_ms"] = s.finished_unix_ms;
    diag::log_tagged_fmt("mcp_burp", "intruder_status ok id=%llu sent=%zu running=%d", static_cast<unsigned long long>(id), s.sent, (int)s.running);
    return tool_result_t::ok(r);
}

static tool_result_t burp_intruder_results(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_results job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    size_t start_idx = params.value("start", static_cast<size_t>(0));
    size_t max_count = params.value("max", static_cast<size_t>(100));
    auto rows = intruder::results(id, start_idx, max_count);
    json arr = json::array();
    for (auto& r : rows) {
        json e;
        e["index"] = r.index;
        e["payloads"] = r.payloads;
        e["status_code"] = r.status_code;
        e["response_size"] = r.response_size;
        e["latency_ms"] = r.latency_ms;
        e["error"] = r.error;
        e["error_msg"] = r.error_msg;
        e["preview"] = r.response_preview.substr(0, 1024);
        e["raw_b64"] = b64_encode(r.response_raw);
        arr.push_back(e);
    }
    json out;
    out["job_id"] = id;
    out["count"] = rows.size();
    out["results"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "intruder_results ok id=%llu count=%zu", static_cast<unsigned long long>(id), rows.size());
    return tool_result_t::ok(out);
}

static tool_result_t burp_intruder_stop(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_stop job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    if (!intruder::stop(id)) { diag::log_tagged_fmt("mcp_burp", "intruder_stop not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    diag::log_tagged_fmt("mcp_burp", "intruder_stop ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("intruder job stopped");
}

static tool_result_t burp_intruder_list_jobs(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "intruder_list_jobs entry");
    auto jobs = intruder::list_jobs();
    json arr = json::array();
    for (auto& s : jobs) {
        json e;
        e["job_id"] = s.job_id;
        e["total"] = s.total;
        e["sent"] = s.sent;
        e["errors"] = s.errors;
        e["running"] = s.running;
        e["current_rps"] = s.current_rps;
        arr.push_back(e);
    }
    json out;
    out["count"] = jobs.size();
    out["jobs"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "intruder_list_jobs ok count=%zu", jobs.size());
    return tool_result_t::ok(out);
}

static tool_result_t burp_intruder_clear(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_clear job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    if (!intruder::clear(id)) { diag::log_tagged_fmt("mcp_burp", "intruder_clear not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    diag::log_tagged_fmt("mcp_burp", "intruder_clear ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("intruder job cleared");
}

static tool_result_t burp_param_miner_start(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_start target=%s loc=%s",
        params.contains("target_url") && params["target_url"].is_string() ? params["target_url"].get<std::string>().c_str() : "<missing>",
        params.value("location", std::string("query")).c_str());
    if (!params.contains("target_url") || !params["target_url"].is_string()) {
        return tool_result_t::error("target_url required");
    }
    aida::burp::param_miner::config_t cfg;
    cfg.target_url = params["target_url"].get<std::string>();
    std::string loc_s = params.value("location", std::string("query"));
    if (!aida::burp::param_miner::parse_location(loc_s, cfg.location)) {
        return tool_result_t::error("invalid location");
    }
    if (params.contains("wordlist_id") && params["wordlist_id"].is_string()) {
        cfg.wordlist_id = params["wordlist_id"].get<std::string>();
    }
    if (params.contains("custom_words") && params["custom_words"].is_array()) {
        for (auto& w : params["custom_words"]) if (w.is_string()) cfg.custom_words.push_back(w.get<std::string>());
    }
    cfg.concurrency = params.value("concurrency", static_cast<size_t>(8));
    cfg.throttle_ms = params.value("throttle_ms", 0);
    cfg.timeout_ms = params.value("timeout_ms", 12000);
    cfg.baseline_count = params.value("baseline_count", static_cast<size_t>(5));
    cfg.diff_sigma_threshold = params.value("diff_sigma_threshold", 3.0);
    cfg.report_as_issues = params.value("report_as_issues", true);

    uint64_t id = aida::burp::param_miner::start(std::move(cfg));
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "param_miner_start failed err=%s", aida::burp::param_miner::last_error().c_str()); return tool_result_t::error(std::string("param_miner::start failed: ") + aida::burp::param_miner::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "param_miner_start ok job_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["job_id"] = id;
    return tool_result_t::ok("param miner started", out);
}

static tool_result_t burp_param_miner_status(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_status id=%llu", params.contains("id") ? static_cast<unsigned long long>(params["id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("id")) return tool_result_t::error("id required");
    uint64_t id = params["id"].get<uint64_t>();
    auto s = aida::burp::param_miner::status(id);
    if (s.job_id == 0) { diag::log_tagged_fmt("mcp_burp", "param_miner_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    json out;
    out["job_id"] = s.job_id;
    out["total"] = s.total;
    out["tried"] = s.tried;
    out["hits"] = s.hits;
    out["running"] = s.running;
    diag::log_tagged_fmt("mcp_burp", "param_miner_status ok id=%llu tried=%zu hits=%zu running=%d", static_cast<unsigned long long>(id), s.tried, s.hits, (int)s.running);
    return tool_result_t::ok(out);
}

static tool_result_t burp_param_miner_results(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_results id=%llu", params.contains("id") ? static_cast<unsigned long long>(params["id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("id")) return tool_result_t::error("id required");
    uint64_t id = params["id"].get<uint64_t>();
    auto hits = aida::burp::param_miner::results(id);
    json arr = json::array();
    for (auto& h : hits) {
        json e;
        e["param"] = h.param_name;
        e["location"] = h.location_label;
        e["status"] = h.status_code;
        e["size"] = h.response_size;
        e["sigma"] = h.size_diff_sigma;
        e["cache_diff"] = h.cache_diff;
        e["echoed"] = h.echoed;
        e["header_echoed"] = h.header_echoed;
        e["evidence"] = h.evidence;
        arr.push_back(e);
    }
    json out;
    out["count"] = hits.size();
    out["hits"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "param_miner_results ok id=%llu count=%zu", static_cast<unsigned long long>(id), hits.size());
    return tool_result_t::ok(out);
}

static tool_result_t burp_param_miner_stop(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_stop id=%llu", params.contains("id") ? static_cast<unsigned long long>(params["id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("id")) return tool_result_t::error("id required");
    uint64_t id = params["id"].get<uint64_t>();
    if (!aida::burp::param_miner::stop(id)) { diag::log_tagged_fmt("mcp_burp", "param_miner_stop not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    diag::log_tagged_fmt("mcp_burp", "param_miner_stop ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("param miner stopped");
}

static tool_result_t burp_h2_send(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "h2_send entry params_shape=%s host=%s port=%d",
        json_shape(params).c_str(),
        params.contains("host") && params["host"].is_string() ? params["host"].get<std::string>().c_str() : "<missing>",
        params.value("port", 443));
    h2_editor::request_t req;
    if (!params.contains("host") || !params["host"].is_string()) {
        diag::log_tagged_fmt("mcp_burp", "h2_send missing_host");
        return tool_result_t::error("host required");
    }
    req.host = params["host"].get<std::string>();
    req.port = static_cast<uint16_t>(params.value("port", 443));
    req.timeout_ms = params.value("timeout_ms", 15000);
    if (params.value("offline_validate", false)) {
        diag::log_tagged_fmt("mcp_burp", "h2_send offline_validate host=%s port=%u timeout_ms=%d",
            req.host.c_str(), static_cast<unsigned>(req.port), req.timeout_ms);
        h2_editor::frame_t settings;
        settings.type = 4;
        settings.flags = 0;
        settings.stream_id = 0;
        std::vector<uint8_t> wire = h2_editor::encode_frame(settings);
        std::vector<h2_editor::frame_t> frames;
        bool decoded = h2_editor::decode_frames(wire, frames);
        json out;
        out["ok"] = decoded && frames.size() == 1 && frames[0].type == 4 && frames[0].stream_id == 0;
        out["offline_validate"] = true;
        out["frames"] = frames.size();
        out["raw_wire_out_b64"] = b64_encode(wire);
        out["body_size"] = 0;
        out["latency_ms"] = 0;
        diag::log_tagged_fmt("mcp_burp", "h2_send offline_validate result ok=%d frames=%zu wire_len=%zu",
            (int)out["ok"].get<bool>(), frames.size(), wire.size());
        return tool_result_t::ok(out);
    }

    if (params.contains("raw_frames_b64") && params["raw_frames_b64"].is_string()) {
        const std::string& raw_b64 = params["raw_frames_b64"].get_ref<const std::string&>();
        auto bytes = b64_decode(raw_b64);
        std::vector<h2_editor::frame_t> frames;
        if (!h2_editor::decode_frames(bytes, frames)) {
            diag::log_tagged_fmt("mcp_burp", "h2_send raw_frames_decode_failed b64_len=%zu bytes=%zu",
                raw_b64.size(), bytes.size());
            return tool_result_t::error("raw_frames_b64 decode failed");
        }
        req.use_raw_frames = true;
        req.raw_frames = std::move(frames);
        diag::log_tagged_fmt("mcp_burp", "h2_send raw_frames mode frames=%zu b64_len=%zu bytes=%zu",
            req.raw_frames.size(), raw_b64.size(), bytes.size());
    } else {
        if (params.contains("pseudo_headers") && params["pseudo_headers"].is_object()) {
            const auto& ph = params["pseudo_headers"];
            if (ph.contains("method")) req.pseudo.method = ph["method"].get<std::string>();
            if (ph.contains("path"))   req.pseudo.path   = ph["path"].get<std::string>();
            if (ph.contains("scheme")) req.pseudo.scheme = ph["scheme"].get<std::string>();
            if (ph.contains("authority")) req.pseudo.authority = ph["authority"].get<std::string>();
        }
        if (params.contains("headers") && params["headers"].is_array()) {
            for (auto& kv : params["headers"]) {
                if (kv.is_array() && kv.size() == 2 && kv[0].is_string() && kv[1].is_string()) {
                    req.headers.push_back({ kv[0].get<std::string>(), kv[1].get<std::string>() });
                }
            }
        }
        if (params.contains("body_b64") && params["body_b64"].is_string()) {
            const std::string& body_b64 = params["body_b64"].get_ref<const std::string&>();
            req.body = b64_decode(body_b64);
            diag::log_tagged_fmt("mcp_burp", "h2_send body_from_b64 b64_len=%zu body_len=%zu", body_b64.size(), req.body.size());
        } else if (params.contains("body") && params["body"].is_string()) {
            const std::string& s = params["body"].get_ref<const std::string&>();
            req.body.assign(s.begin(), s.end());
            diag::log_tagged_fmt("mcp_burp", "h2_send body_from_text body_len=%zu", req.body.size());
        }
        if (params.contains("flags") && params["flags"].is_number_unsigned()) {
            req.flags = params["flags"].get<uint32_t>();
        }
    }
    diag::log_tagged_fmt("mcp_burp", "h2_send dispatch host=%s port=%u method=%s path_len=%zu has_query=%d headers=%zu body_len=%zu use_raw=%d raw_frames=%zu timeout_ms=%d",
        req.host.c_str(), static_cast<unsigned>(req.port), req.pseudo.method.c_str(),
        req.pseudo.path.size(), (int)(req.pseudo.path.find('?') != std::string::npos),
        req.headers.size(), req.body.size(), (int)req.use_raw_frames, req.raw_frames.size(), req.timeout_ms);

    h2_editor::response_t r = h2_editor::send(req);
    json out;
    out["ok"] = r.ok;
    out["status_code"] = r.status_code;
    out["latency_ms"] = r.latency_ms;
    out["error_msg"] = r.error_msg;
    json hdrs = json::array();
    for (auto& h : r.headers) {
        json e = json::array();
        e.push_back(h.first);
        e.push_back(h.second);
        hdrs.push_back(e);
    }
    out["headers"] = std::move(hdrs);
    out["body_b64"] = b64_encode(r.body);
    out["body_size"] = r.body.size();
    out["raw_wire_in_b64"]  = b64_encode(r.raw_wire_in);
    out["raw_wire_out_b64"] = b64_encode(r.raw_wire_out);
    diag::log_tagged_fmt("mcp_burp", "h2_send result ok=%d status=%d latency=%llums err_len=%zu headers=%zu body_len=%zu wire_in=%zu wire_out=%zu",
        (int)r.ok, r.status_code, static_cast<unsigned long long>(r.latency_ms), r.error_msg.size(),
        r.headers.size(), r.body.size(), r.raw_wire_in.size(), r.raw_wire_out.size());
    if (!r.ok) {
        return tool_result_t::error(r.error_msg.empty() ? std::string("h2_send_failed") : r.error_msg);
    }
    return tool_result_t::ok(out);
}

}

void register_intruder_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_intruder_start", "burp_intruder",
        "Start an Intruder/Turbo attack job. Supports sniper, battering_ram, pitchfork, "
        "clusterbomb, turbo, and race attack modes plus http1_serial/pipelined/pooled, "
        "http2_multiplexed, and http2_single_packet (Kettle) engine modes.",
        {
            { "host", "string", "Target host", true },
            { "port", "number", "Target port (defaults 443)", false },
            { "scheme", "string", "'http' or 'https'", false },
            { "base_request", "string", "Raw HTTP/1.1 request as text", false },
            { "base_request_b64", "string", "Raw HTTP/1.1 request, base64 encoded", false },
            { "attack_mode", "string", "sniper|battering_ram|pitchfork|clusterbomb|turbo|race", false },
            { "engine_mode", "string", "http1_serial|http1_pipelined|http1_pooled|http2_multiplexed|http2_single_packet", false },
            { "positions", "array", "Array of [offset, length] pairs into base_request", false },
            { "payload_sets", "array", "Array of arrays of strings, one set per position", false },
            { "concurrency", "number", "Worker count / inflight streams (default 32)", false },
            { "rps_cap", "number", "Requests-per-second cap (0 = unbounded)", false },
            { "total_cap", "number", "Total request cap (0 = exhaust payloads)", false },
            { "timeout_ms", "number", "Per-request timeout in ms (default 15000)", false },
            { "follow_redirects", "number", "Max redirect hops (default 0)", false },
            { "race_gate_size", "number", "Race gate size (default 30)", false },
            { "race_warmup", "number", "Race warmup count (default 0)", false },
            { "max_body_bytes", "number", "Max response body bytes captured per request (default 65536)", false }
        },
        burp_intruder_start, false });

    register_compat(srv, {
        "burp_intruder_status", "burp_intruder",
        "Get the running status of an Intruder job.",
        { { "job_id", "number", "Job id from burp_intruder_start", true } },
        burp_intruder_status, true });

    register_compat(srv, {
        "burp_intruder_results", "burp_intruder",
        "Retrieve Intruder job results.",
        {
            { "job_id", "number", "Job id", true },
            { "start", "number", "Result start index (default 0)", false },
            { "max", "number", "Max results returned (default 100)", false }
        },
        burp_intruder_results, true });

    register_compat(srv, {
        "burp_intruder_stop", "burp_intruder",
        "Cancel a running Intruder job.",
        { { "job_id", "number", "Job id", true } },
        burp_intruder_stop, false });

    register_compat(srv, {
        "burp_intruder_list_jobs", "burp_intruder",
        "Enumerate all Intruder jobs.",
        {},
        burp_intruder_list_jobs, true });

    register_compat(srv, {
        "burp_intruder_clear", "burp_intruder",
        "Forget an Intruder job (cancels if running).",
        { { "job_id", "number", "Job id", true } },
        burp_intruder_clear, false });

    register_compat(srv, {
        "burp_param_miner_start", "burp_param_miner",
        "Start a hidden parameter discovery job over a target URL.",
        {
            { "target_url", "string", "Absolute URL to probe", true },
            { "location", "string", "query|body_form|json_body|header|cookie", false },
            { "wordlist_id", "string", "Payload library wordlist id (e.g. 'params/common')", false },
            { "custom_words", "array", "Optional custom parameter name list", false },
            { "concurrency", "number", "Worker count (default 8, max 16)", false },
            { "throttle_ms", "number", "Per-request delay in ms", false },
            { "timeout_ms", "number", "Per-request timeout (default 12000)", false },
            { "baseline_count", "number", "Baseline sample count (default 5)", false },
            { "diff_sigma_threshold", "number", "Standard-deviation threshold for size diff (default 3.0)", false },
            { "report_as_issues", "boolean", "Emit hits to the issue store (default true)", false }
        },
        burp_param_miner_start, false });

    register_compat(srv, {
        "burp_param_miner_status", "burp_param_miner",
        "Get the status of a param miner job.",
        { { "id", "number", "Job id", true } },
        burp_param_miner_status, true });

    register_compat(srv, {
        "burp_param_miner_results", "burp_param_miner",
        "Retrieve hits from a param miner job.",
        { { "id", "number", "Job id", true } },
        burp_param_miner_results, true });

    register_compat(srv, {
        "burp_param_miner_stop", "burp_param_miner",
        "Cancel a running param miner job.",
        { { "id", "number", "Job id", true } },
        burp_param_miner_stop, false });

    register_compat(srv, {
        "burp_h2_send", "burp_h2",
        "Send a single, fully user-controlled HTTP/2 request. Supports pseudo-header overrides, "
        "explicit stream flags, and a raw frame bytes mode for spec violations.",
        {
            { "host", "string", "Target host", true },
            { "port", "number", "Target port (default 443)", false },
            { "timeout_ms", "number", "Timeout in ms (default 15000)", false },
            { "pseudo_headers", "object", "Object {method, path, scheme, authority}", false },
            { "headers", "array", "Array of [name, value] string pairs", false },
            { "body", "string", "Body text", false },
            { "body_b64", "string", "Body, base64 encoded (preferred for binary)", false },
            { "flags", "number", "Bitfield: 1=END_STREAM 2=END_HEADERS 4=PADDED 8=PRIORITY", false },
            { "raw_frames_b64", "string", "Pre-encoded HTTP/2 frames as base64 (raw mode bypasses HEADERS/DATA construction)", false },
            { "offline_validate", "boolean", "Validate HTTP/2 frame encode/decode without opening a socket", false }
        },
        burp_h2_send, false });

    diag::log_tagged("burp", "intruder_mcp_registered");
}

}
}
