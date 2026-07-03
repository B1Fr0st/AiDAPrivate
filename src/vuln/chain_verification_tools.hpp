#pragma once

#include "../aida_pro.hpp"
#include "../agent_tools.hpp"
#include "../multibinary_index.hpp"
#include "../multibinary_project.hpp"
#include "chain_extraction.hpp"
#include "chain_path_trace.hpp"
#include "chain_verifier.hpp"
#include "verification_engine.hpp"

#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <prodir.h>
#include <segment.hpp>
#include <xref.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida
{
namespace vuln
{
namespace chain_mcp
{
namespace
{

using json = nlohmann::json;

constexpr const char* kRequestSchema = "aida.ida.mcp.manage.v1";
constexpr const char* kResponseSchema = "aida.ida.mcp.response.v1";
constexpr const char* kChainSchema = "aida_chain_document_v2";
constexpr const char* kReportSchema = "chain_verification_report_v2";

struct field_rule_t
{
    std::string name;
    std::string type;
    bool required = false;
    std::vector<std::string> enum_values;
};

struct operation_meta_t
{
    std::string name;
    std::string description;
    bool read_only = true;
    bool destructive = false;
    bool deterministic = true;
    bool job_mode = false;
    std::string cache_policy;
    int default_timeout_ms = 1000;
    int hard_timeout_ms = 30000;
    std::vector<std::string> required_indices;
    std::vector<field_rule_t> fields;
    bool allow_extra = false;
};

struct request_ctx_t
{
    std::string tool;
    std::string operation;
    std::string request_id;
    std::string job_mode;
    std::string idempotency_key;
    std::string cursor;
    int limit = 100;
    json budget = json::object();
    json payload = json::object();
};

struct job_record_t
{
    std::string job_id;
    std::string tool;
    std::string operation;
    std::string state;
    std::string report_id;
    std::string error_code;
    std::string error_message;
    uint64_t created_at_ms = 0;
    uint64_t updated_at_ms = 0;
    double progress = 0.0;
    json request;
    json result;
    json events = json::array();
};

struct report_record_t
{
    std::string report_id;
    std::string job_id;
    std::string chain_id;
    uint64_t created_at_ms = 0;
    std::string content_hash;
    json report;
};

struct index_record_t
{
    std::string index_id;
    std::string status;
    std::string generation;
    uint64_t built_at_ms = 0;
    json coverage = json::object();
};

struct state_t
{
    std::mutex mutex;
    std::unordered_map<std::string, job_record_t> jobs;
    std::unordered_map<std::string, report_record_t> reports;
    std::unordered_map<std::string, index_record_t> indices;
    json corpus_manifest = json::object();
    std::atomic<uint64_t> next_job{1};
    std::atomic<uint64_t> next_report{1};
};

state_t& state()
{
    static state_t s;
    return s;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string hex_lower(const uint8_t* data, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        out.push_back(h[(data[i] >> 4) & 0xf]);
        out.push_back(h[data[i] & 0xf]);
    }
    return out;
}

uint64_t fnv1a64(const std::string& text)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : text)
    {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

std::string hash_text(const std::string& text)
{
    std::ostringstream ss;
    ss << "fnv1a64:" << std::hex << std::setw(16) << std::setfill('0') << fnv1a64(text);
    return ss.str();
}

std::string scalar_to_string(const json& v)
{
    if (v.is_string())
        return v.get<std::string>();
    if (v.is_number_unsigned())
    {
        std::ostringstream ss;
        ss << "0x" << std::hex << v.get<uint64_t>();
        return ss.str();
    }
    if (v.is_number_integer())
    {
        int64_t n = v.get<int64_t>();
        std::ostringstream ss;
        if (n < 0)
            ss << n;
        else
            ss << "0x" << std::hex << static_cast<uint64_t>(n);
        return ss.str();
    }
    if (v.is_number_float())
        return std::to_string(v.get<double>());
    return std::string();
}

std::string basename_of(const std::string& path)
{
    const size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}

std::string lowercase_ascii(std::string value)
{
    for (char& c : value)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    }
    return value;
}

std::string input_path()
{
    char path[4096] = {};
    get_input_file_path(path, sizeof(path));
    return std::string(path[0] ? path : "");
}

std::string idb_path()
{
    const char* p = get_path(PATH_TYPE_IDB);
    return std::string(p ? p : "");
}

std::string input_md5()
{
    uchar md5[16] = {};
    if (!retrieve_input_file_md5(md5))
        return std::string();
    return hex_lower(md5, sizeof(md5));
}

std::string input_sha256()
{
    uchar sha[32] = {};
    if (!retrieve_input_file_sha256(sha))
        return std::string();
    return hex_lower(sha, sizeof(sha));
}

std::string processor_name()
{
    char proc[IDAINFO_PROCNAME_SIZE] = {};
    if (inf_get_procname(proc, sizeof(proc)))
        return proc;
    return std::string();
}

int bitness()
{
    if (inf_is_64bit())
        return 64;
    if (inf_is_32bit_exactly())
        return 32;
    return 16;
}

std::string fmt_ea(ea_t ea)
{
    return agent_tools::helpers::format_address(ea);
}

std::string generation_id()
{
    json g;
    g["input_sha256"] = input_sha256();
    g["imagebase"] = fmt_ea(static_cast<ea_t>(get_imagebase()));
    g["min_ea"] = fmt_ea(inf_get_min_ea());
    g["max_ea"] = fmt_ea(inf_get_max_ea());
    g["functions"] = static_cast<uint64_t>(get_func_qty());
    g["segments"] = get_segm_qty();
    g["auto_ok"] = auto_is_ok();
    return hash_text(g.dump());
}

json module_identity()
{
    aida::vuln::chain::corpus_record_t corpus = aida::vuln::chain::snapshot_current_idb_corpus();
    json m;
    m["module_id"] = corpus.identity.corpus_id;
    m["corpus_id"] = corpus.identity.corpus_id;
    m["canonical_name"] = corpus.identity.canonical_name;
    m["input_file"] = corpus.identity.input_path;
    m["input_path"] = corpus.identity.input_path;
    m["input_basename"] = basename_of(corpus.identity.input_path);
    m["idb_path"] = corpus.identity.idb_path;
    m["input_md5"] = corpus.identity.hashes.md5;
    m["input_sha256"] = corpus.identity.hashes.sha256;
    m["imagebase"] = fmt_ea(static_cast<ea_t>(corpus.identity.image_base));
    m["image_base"] = fmt_ea(static_cast<ea_t>(corpus.identity.image_base));
    m["min_ea"] = fmt_ea(static_cast<ea_t>(corpus.identity.min_ea));
    m["max_ea"] = fmt_ea(static_cast<ea_t>(corpus.identity.max_ea));
    m["processor"] = corpus.identity.processor;
    m["bitness"] = corpus.identity.bitness;
    m["address_model"] = "module_id+rva";
    m["generation"] = generation_id();
    return m;
}

json instance_identity()
{
    json i;
    i["instance_id"] = nullptr;
#ifdef _WIN32
    i["pid"] = static_cast<uint64_t>(GetCurrentProcessId());
#else
    i["pid"] = 0;
#endif
    i["idb_path"] = idb_path();
    i["input_file"] = input_path();
    i["input_basename"] = basename_of(input_path());
    i["input_md5"] = input_md5();
    i["input_sha256"] = input_sha256();
    i["processor"] = processor_name();
    i["bitness"] = bitness();
    i["database_generation"] = generation_id();
    i["auto_analysis_ok"] = auto_is_ok();
    return i;
}

bool is_common_key(const std::string& key)
{
    static const std::set<std::string> keys = {
        "operation", "action", "schema_version", "instance_id", "pid", "request_id",
        "idempotency_key", "job_mode", "cursor", "limit", "budget", "payload"
    };
    return keys.find(key) != keys.end();
}

int clamp_int(int value, int lo, int hi)
{
    return std::max(lo, std::min(hi, value));
}

int int_param(const json& j, const char* key, int def, int lo, int hi)
{
    int value = def;
    if (j.contains(key))
    {
        const json& v = j.at(key);
        if (v.is_number_integer())
            value = v.get<int>();
        else if (v.is_number_unsigned())
            value = static_cast<int>(std::min<uint64_t>(static_cast<uint64_t>(hi), v.get<uint64_t>()));
        else if (v.is_number_float())
            value = static_cast<int>(v.get<double>());
        else if (v.is_string())
        {
            char* endp = nullptr;
            long parsed = std::strtol(v.get_ref<const std::string&>().c_str(), &endp, 0);
            if (endp != v.get_ref<const std::string&>().c_str())
                value = static_cast<int>(parsed);
        }
    }
    return clamp_int(value, lo, hi);
}

json field_schema(const field_rule_t& f)
{
    json s;
    if (f.type == "location")
    {
        s["oneOf"] = json::array({
            json::object({{"type", "string"}}),
            json::object({{"type", "number"}}),
            json::object({{"type", "object"}, {"properties", json::object({
                {"ea", json::object({{"type", "string"}})},
                {"address", json::object({{"type", "string"}})},
                {"rva", json::object({{"type", "string"}})},
                {"module_id", json::object({{"type", "string"}})}
            })}})
        });
        return s;
    }
    s["type"] = f.type;
    if (!f.enum_values.empty())
        s["enum"] = f.enum_values;
    if (f.type == "array")
        s["items"] = json::object({{"type", "object"}});
    return s;
}

json payload_schema(const operation_meta_t& meta)
{
    json props = json::object();
    json req = json::array();
    for (const auto& f : meta.fields)
    {
        props[f.name] = field_schema(f);
        if (f.required)
            req.push_back(f.name);
    }
    json s;
    s["type"] = "object";
    s["properties"] = props;
    s["additionalProperties"] = meta.allow_extra;
    if (!req.empty())
        s["required"] = req;
    return s;
}

json meta_to_json(const operation_meta_t& meta)
{
    json j;
    j["operation"] = meta.name;
    j["description"] = meta.description;
    j["read_only"] = meta.read_only;
    j["destructive"] = meta.destructive;
    j["deterministic"] = meta.deterministic;
    j["job_mode"] = meta.job_mode;
    j["cache_policy"] = meta.cache_policy;
    j["default_timeout_ms"] = meta.default_timeout_ms;
    j["hard_timeout_ms"] = meta.hard_timeout_ms;
    j["required_indices"] = meta.required_indices;
    j["payload_schema"] = payload_schema(meta);
    return j;
}

const operation_meta_t* find_meta(const std::vector<operation_meta_t>& metas, const std::string& op)
{
    for (const auto& m : metas)
    {
        if (m.name == op)
            return &m;
    }
    return nullptr;
}

json operations_json(const std::vector<operation_meta_t>& metas)
{
    json arr = json::array();
    for (const auto& m : metas)
        arr.push_back(meta_to_json(m));
    return arr;
}

std::vector<std::string> operation_names(const std::vector<operation_meta_t>& metas)
{
    std::vector<std::string> names;
    names.reserve(metas.size());
    for (const auto& m : metas)
        names.push_back(m.name);
    return names;
}

std::vector<agent_tools::tool_param_t> common_params(const std::vector<operation_meta_t>& metas)
{
    return {
        {OBFSTR("operation"), OBFSTR("string"), OBFSTR("Manage operation name."), true, operation_names(metas), json()},
        {OBFSTR("schema_version"), OBFSTR("string"), OBFSTR("Request schema version; use aida.ida.mcp.manage.v1."), false},
        {OBFSTR("action"), OBFSTR("string"), OBFSTR("Migration alias for operation."), false, operation_names(metas), json()},
        {OBFSTR("request_id"), OBFSTR("string"), OBFSTR("Optional caller correlation id."), false},
        {OBFSTR("idempotency_key"), OBFSTR("string"), OBFSTR("Optional retry-safe job key."), false},
        {OBFSTR("job_mode"), OBFSTR("string"), OBFSTR("inline, job, or auto."), false, {"inline", "job", "auto"}, json()},
        {OBFSTR("cursor"), OBFSTR("string"), OBFSTR("Opaque pagination cursor returned by a prior page."), false},
        {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Page size limit."), false},
        {OBFSTR("budget"), OBFSTR("object"), OBFSTR("Timeout, byte, item, depth, solver, and partial-result budget."), false},
        {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Operation-specific request payload."), false}
    };
}

bool type_matches(const json& value, const std::string& type)
{
    if (type == "location")
        return value.is_string() || value.is_number() || value.is_object();
    if (type == "string")
        return value.is_string() || value.is_number();
    if (type == "number" || type == "integer")
        return value.is_number() || value.is_string();
    if (type == "boolean")
        return value.is_boolean();
    if (type == "object")
        return value.is_object();
    if (type == "array")
        return value.is_array();
    return true;
}

std::optional<ea_t> parse_location(const json& v)
{
    if (v.is_string() || v.is_number())
        return agent_tools::helpers::parse_address(scalar_to_string(v));
    if (!v.is_object())
        return std::nullopt;
    for (const char* k : {"ea", "address", "addr"})
    {
        if (v.contains(k))
            return agent_tools::helpers::parse_address(scalar_to_string(v.at(k)));
    }
    if (v.contains("rva"))
    {
        auto rva = agent_tools::helpers::parse_address(scalar_to_string(v.at("rva")));
        if (rva)
            return static_cast<ea_t>(get_imagebase()) + *rva;
    }
    return std::nullopt;
}

std::optional<ea_t> payload_location(const json& payload, const char* key)
{
    if (!payload.contains(key))
        return std::nullopt;
    return parse_location(payload.at(key));
}

std::string cursor_for(const std::string& op, const std::string& generation, size_t offset)
{
    std::ostringstream ss;
    ss << "ac1." << op << "." << generation << "." << offset;
    return ss.str();
}

bool parse_cursor(const std::string& cursor, const std::string& op, const std::string& generation, size_t& offset)
{
    offset = 0;
    if (cursor.empty())
        return true;
    const std::string prefix = "ac1." + op + "." + generation + ".";
    if (cursor.rfind(prefix, 0) != 0)
        return false;
    std::string n = cursor.substr(prefix.size());
    if (n.empty())
        return false;
    char* endp = nullptr;
    unsigned long long parsed = _strtoui64(n.c_str(), &endp, 10);
    if (endp == n.c_str() || *endp != '\0')
        return false;
    offset = static_cast<size_t>(parsed);
    return true;
}

json page_json(const std::string& cursor, const std::string& next_cursor, int limit, size_t returned, bool truncated)
{
    json p;
    p["cursor"] = cursor.empty() ? json(nullptr) : json(cursor);
    p["next_cursor"] = next_cursor.empty() ? json(nullptr) : json(next_cursor);
    p["limit"] = limit;
    p["returned"] = returned;
    p["truncated"] = truncated;
    return p;
}

agent_tools::tool_result_t result_from_envelope(const json& envelope, const std::string& message, bool success, const std::string& error_code = std::string())
{
    if (success)
        return agent_tools::tool_result_t::ok(message, envelope);
    agent_tools::tool_result_t r;
    r.success = false;
    r.output = message;
    r.data = envelope;
    r.error_code = error_code;
    return r;
}

json base_envelope(const request_ctx_t& ctx, bool ok)
{
    json e;
    e["ok"] = ok;
    e["schema"] = kResponseSchema;
    e["tool"] = ctx.tool;
    e["operation"] = ctx.operation;
    e["request_id"] = ctx.request_id;
    e["instance"] = instance_identity();
    e["module"] = module_identity();
    e["job"] = nullptr;
    e["page"] = nullptr;
    e["data"] = nullptr;
    e["warnings"] = json::array();
    e["resources"] = json::array();
    e["error"] = nullptr;
    return e;
}

agent_tools::tool_result_t ok_envelope(const request_ctx_t& ctx,
                                       const json& data,
                                       const json& job = json(),
                                       const json& page = json(),
                                       const json& warnings = json::array(),
                                       const json& resources = json::array())
{
    json e = base_envelope(ctx, true);
    e["data"] = data;
    if (!job.is_null() && !job.empty())
        e["job"] = job;
    if (!page.is_null() && !page.empty())
        e["page"] = page;
    e["warnings"] = warnings;
    e["resources"] = resources;
    std::string msg = ctx.tool + "." + ctx.operation + " ok";
    return result_from_envelope(e, msg, true);
}

agent_tools::tool_result_t error_envelope(const request_ctx_t& ctx,
                                          const std::string& code,
                                          const std::string& message,
                                          const json& details = json::object(),
                                          bool retryable = false)
{
    json e = base_envelope(ctx, false);
    e["data"] = nullptr;
    e["error"] = {
        {"code", code},
        {"message", message},
        {"retryable", retryable},
        {"details", details}
    };
    return result_from_envelope(e, ctx.tool + "." + ctx.operation + " " + code + ": " + message, false, code);
}

std::string new_request_id()
{
    static std::atomic<uint64_t> seq{1};
    std::ostringstream ss;
    ss << "req-" << now_ms() << "-" << seq.fetch_add(1);
    return ss.str();
}

request_ctx_t parse_request(const std::string& tool,
                            const json& params,
                            const std::vector<operation_meta_t>& metas,
                            agent_tools::tool_result_t& failure)
{
    request_ctx_t ctx;
    ctx.tool = tool;
    ctx.operation = params.value("operation", params.value("action", std::string()));
    ctx.request_id = params.value("request_id", new_request_id());
    ctx.job_mode = params.value("job_mode", std::string("auto"));
    ctx.idempotency_key = params.value("idempotency_key", std::string());
    ctx.cursor = params.value("cursor", std::string());
    ctx.limit = int_param(params, "limit", 100, 1, 1000);
    ctx.budget = params.contains("budget") && params["budget"].is_object() ? params["budget"] : json::object();
    ctx.payload = params.contains("payload") && params["payload"].is_object() ? params["payload"] : json::object();

    if (ctx.operation.empty())
    {
        ctx.operation = "unknown";
        failure = error_envelope(ctx, "bad_param", "operation is required", {{"field", "operation"}});
        return ctx;
    }

    if (params.contains("schema_version") && params["schema_version"].is_string()
        && params["schema_version"].get<std::string>() != kRequestSchema)
    {
        failure = error_envelope(ctx, "schema_version_unsupported", "schema_version must be aida.ida.mcp.manage.v1",
                                 {{"field", "schema_version"}, {"actual", params["schema_version"]}});
        return ctx;
    }

    const operation_meta_t* meta = find_meta(metas, ctx.operation);
    if (!meta)
    {
        failure = error_envelope(ctx, "unknown_operation", "unsupported operation for " + tool,
                                 {{"operation", ctx.operation}, {"allowed", operation_names(metas)}});
        return ctx;
    }

    if (params.is_object())
    {
        for (auto it = params.begin(); it != params.end(); ++it)
        {
            if (!is_common_key(it.key()) && !ctx.payload.contains(it.key()))
                ctx.payload[it.key()] = it.value();
        }
    }

    std::set<std::string> allowed;
    for (const auto& f : meta->fields)
        allowed.insert(f.name);
    if (!meta->allow_extra)
    {
        for (auto it = ctx.payload.begin(); it != ctx.payload.end(); ++it)
        {
            if (allowed.find(it.key()) == allowed.end())
            {
                failure = error_envelope(ctx, "bad_param", "unexpected payload field",
                                         {{"field", "payload." + it.key()}, {"operation", ctx.operation}});
                return ctx;
            }
        }
    }

    for (const auto& f : meta->fields)
    {
        if (f.required && !ctx.payload.contains(f.name))
        {
            failure = error_envelope(ctx, "bad_param", "required payload field is missing",
                                     {{"field", "payload." + f.name}, {"operation", ctx.operation}});
            return ctx;
        }
        if (ctx.payload.contains(f.name))
        {
            const json& v = ctx.payload.at(f.name);
            if (!type_matches(v, f.type))
            {
                failure = error_envelope(ctx, "bad_param", "payload field has the wrong type",
                                         {{"field", "payload." + f.name}, {"expected", f.type}});
                return ctx;
            }
            if (!f.enum_values.empty() && v.is_string())
            {
                const std::string actual = v.get<std::string>();
                if (std::find(f.enum_values.begin(), f.enum_values.end(), actual) == f.enum_values.end())
                {
                    failure = error_envelope(ctx, "bad_param", "payload field is outside the allowed enum",
                                             {{"field", "payload." + f.name}, {"allowed", f.enum_values}});
                    return ctx;
                }
            }
        }
    }

    failure = agent_tools::tool_result_t{};
    return ctx;
}

json job_to_json(const job_record_t& j)
{
    json out;
    out["job_id"] = j.job_id;
    out["tool"] = j.tool;
    out["operation"] = j.operation;
    out["state"] = j.state;
    out["report_id"] = j.report_id.empty() ? json(nullptr) : json(j.report_id);
    out["created_at_ms"] = j.created_at_ms;
    out["updated_at_ms"] = j.updated_at_ms;
    out["progress"] = j.progress;
    out["error_code"] = j.error_code.empty() ? json(nullptr) : json(j.error_code);
    out["error_message"] = j.error_message.empty() ? json(nullptr) : json(j.error_message);
    out["events"] = j.events;
    return out;
}

std::string create_job(const request_ctx_t& ctx)
{
    auto& s = state();
    const uint64_t id = s.next_job.fetch_add(1);
    std::ostringstream ss;
    ss << "ida-job-" << id;
    job_record_t j;
    j.job_id = ss.str();
    j.tool = ctx.tool;
    j.operation = ctx.operation;
    j.state = "running";
    j.created_at_ms = now_ms();
    j.updated_at_ms = j.created_at_ms;
    j.progress = 0.01;
    j.request = {
        {"tool", ctx.tool},
        {"operation", ctx.operation},
        {"request_id", ctx.request_id},
        {"payload", ctx.payload},
        {"budget", ctx.budget},
        {"job_mode", ctx.job_mode}
    };
    j.events.push_back({{"ts_ms", j.created_at_ms}, {"state", "running"}});
    std::lock_guard<std::mutex> lock(s.mutex);
    s.jobs.emplace(j.job_id, std::move(j));
    return ss.str();
}

void finish_job(const std::string& job_id, const std::string& state_name, const json& result, const std::string& report_id = std::string(), const std::string& err_code = std::string(), const std::string& err_msg = std::string())
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.jobs.find(job_id);
    if (it == s.jobs.end())
        return;
    it->second.state = state_name;
    it->second.updated_at_ms = now_ms();
    it->second.progress = state_name == "completed" ? 1.0 : it->second.progress;
    it->second.result = result;
    it->second.report_id = report_id;
    it->second.error_code = err_code;
    it->second.error_message = err_msg;
    it->second.events.push_back({{"ts_ms", it->second.updated_at_ms}, {"state", state_name}});
}

std::optional<job_record_t> get_job(const std::string& job_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.jobs.find(job_id);
    if (it == s.jobs.end())
        return std::nullopt;
    return it->second;
}

std::string store_report(const std::string& job_id, const std::string& chain_id, const json& report)
{
    auto& s = state();
    const uint64_t id = s.next_report.fetch_add(1);
    std::ostringstream ss;
    ss << "ida-report-" << id;
    report_record_t r;
    r.report_id = ss.str();
    r.job_id = job_id;
    r.chain_id = chain_id;
    r.created_at_ms = now_ms();
    r.report = report;
    r.content_hash = hash_text(report.dump());
    std::lock_guard<std::mutex> lock(s.mutex);
    s.reports.emplace(r.report_id, std::move(r));
    return ss.str();
}

std::optional<report_record_t> get_report_record(const std::string& report_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.reports.find(report_id);
    if (it == s.reports.end())
        return std::nullopt;
    return it->second;
}

json resource_for_report(const report_record_t& r, const std::string& format)
{
    json res;
    res["uri"] = "ida://chain/reports/" + r.report_id + "?format=" + format;
    res["kind"] = "report";
    res["report_id"] = r.report_id;
    res["format"] = format;
    res["content_hash"] = r.content_hash;
    res["available_via"] = "ida_report_manage.export_report";
    return res;
}

json make_capabilities(const std::string& tool, const std::vector<operation_meta_t>& metas)
{
    json d;
    d["schema_version"] = kRequestSchema;
    d["response_schema"] = kResponseSchema;
    d["tool"] = tool;
    d["operations"] = operations_json(metas);
    d["operation_field"] = "operation";
    d["action_alias_accepted"] = true;
    d["routing"] = {
        {"instance_id", "Handled by the existing MCP proxy before this tool executes."},
        {"pid", "Handled by the existing MCP proxy before this tool executes."}
    };
    d["common_error_codes"] = {
        "bad_param", "unsupported_operation", "unknown_operation", "schema_version_unsupported",
        "peer_unavailable", "peer_timeout", "wrong_instance", "idb_unavailable",
        "analysis_not_settled", "hexrays_unavailable", "index_required", "budget_exhausted",
        "result_too_large", "cursor_expired", "job_not_found", "job_conflict", "cancelled",
        "timeout", "stale_generation", "destructive_denied", "license_required", "rate_limited",
        "internal_error"
    };
    d["examples"] = json::array({
        {{"operation", "capabilities"}, {"payload", json::object()}},
        {{"operation", "status"}, {"payload", json::object()}},
        {{"operation", "functions"}, {"limit", 100}, {"payload", {{"filter", ""}}}}
    });
    return d;
}

json segment_json(const segment_t* seg)
{
    json s;
    if (!seg)
        return s;
    qstring name;
    qstring cls;
    get_segm_name(&name, seg);
    get_segm_class(&cls, seg);
    s["name"] = name.c_str();
    s["class"] = cls.c_str();
    s["start_ea"] = fmt_ea(seg->start_ea);
    s["end_ea"] = fmt_ea(seg->end_ea);
    s["size"] = static_cast<uint64_t>(seg->end_ea - seg->start_ea);
    s["type"] = static_cast<int>(segtype(seg->start_ea));
    s["perm"] = seg->perm;
    s["read"] = (seg->perm & SEGPERM_READ) != 0;
    s["write"] = (seg->perm & SEGPERM_WRITE) != 0;
    s["execute"] = (seg->perm & SEGPERM_EXEC) != 0;
    return s;
}

json function_json(func_t* fn, bool include_segment)
{
    json f;
    if (!fn)
        return f;
    qstring name;
    get_func_name(&name, fn->start_ea);
    f["address"] = fmt_ea(fn->start_ea);
    f["rva"] = fmt_ea(fn->start_ea - static_cast<ea_t>(get_imagebase()));
    f["end_address"] = fmt_ea(fn->end_ea);
    f["size"] = static_cast<uint64_t>(fn->end_ea - fn->start_ea);
    f["name"] = name.c_str();
    f["flags"] = fn->flags;
    if (include_segment)
        f["segment"] = segment_json(getseg(fn->start_ea));
    return f;
}

json import_rows(int max_rows)
{
    struct import_state_t
    {
        json rows = json::array();
        int max_rows = 0;
        std::string module;
    } st;
    st.max_rows = max_rows;
    const uint qty = get_import_module_qty();
    for (uint i = 0; i < qty && static_cast<int>(st.rows.size()) < max_rows; ++i)
    {
        qstring mod;
        get_import_module_name(&mod, static_cast<int>(i));
        st.module = mod.c_str();
        enum_import_names(static_cast<int>(i), [](ea_t ea, const char* name, uval_t ordinal, void* ud) -> int {
            auto* s = static_cast<import_state_t*>(ud);
            if (static_cast<int>(s->rows.size()) >= s->max_rows)
                return 0;
            json r;
            r["module"] = s->module;
            r["name"] = name ? name : "";
            r["ea"] = ea == BADADDR ? json(nullptr) : json(fmt_ea(ea));
            r["ordinal"] = static_cast<uint64_t>(ordinal);
            s->rows.push_back(r);
            return 1;
        }, &st);
    }
    return st.rows;
}

json entry_rows(int max_rows)
{
    json rows = json::array();
    const size_t qty = get_entry_qty();
    for (size_t i = 0; i < qty && static_cast<int>(rows.size()) < max_rows; ++i)
    {
        const uval_t ord = get_entry_ordinal(i);
        const ea_t ea = get_entry(ord);
        qstring name;
        qstring fwd;
        get_entry_name(&name, ord);
        get_entry_forwarder(&fwd, ord);
        rows.push_back({
            {"ordinal", static_cast<uint64_t>(ord)},
            {"ea", ea == BADADDR ? json(nullptr) : json(fmt_ea(ea))},
            {"name", name.c_str()},
            {"forwarder", fwd.c_str()}
        });
    }
    return rows;
}

json segment_rows()
{
    json rows = json::array();
    const int qty = get_segm_qty();
    for (int i = 0; i < qty; ++i)
        rows.push_back(segment_json(getnseg(i)));
    return rows;
}

json inventory_json(const json& payload)
{
    const int max_rows = int_param(payload, "max_rows", 256, 1, 5000);
    const bool include_segments = payload.value("include_segments", true);
    const bool include_imports = payload.value("include_imports", true);
    const bool include_entries = payload.value("include_entries", true);
    json inv;
    inv["schema"] = "aida.ida.project.inventory.v1";
    inv["module"] = module_identity();
    inv["instance"] = instance_identity();
    inv["auto_analysis_ok"] = auto_is_ok();
    inv["function_count"] = static_cast<uint64_t>(get_func_qty());
    inv["segment_count"] = get_segm_qty();
    inv["import_module_count"] = get_import_module_qty();
    inv["entry_count"] = static_cast<uint64_t>(get_entry_qty());
    if (include_segments)
        inv["segments"] = segment_rows();
    if (include_imports)
        inv["imports_preview"] = import_rows(max_rows);
    if (include_entries)
        inv["entry_points"] = entry_rows(max_rows);
    return inv;
}

json page_vector(const request_ctx_t& ctx, const std::string& op, const json& full, json& page)
{
    const std::string gen = generation_id();
    size_t offset = 0;
    if (!parse_cursor(ctx.cursor, op, gen, offset))
    {
        page = json::object({{"error", "cursor_expired"}});
        return json::array();
    }
    json out = json::array();
    const size_t total = full.is_array() ? full.size() : 0;
    const size_t end = std::min(total, offset + static_cast<size_t>(ctx.limit));
    for (size_t i = offset; i < end; ++i)
        out.push_back(full.at(i));
    const bool truncated = end < total;
    const std::string next = truncated ? cursor_for(op, gen, end) : std::string();
    page = page_json(ctx.cursor, next, ctx.limit, out.size(), truncated);
    page["total_known"] = total;
    return out;
}

std::string pointer_escape(const std::string& key)
{
    std::string out;
    out.reserve(key.size());
    for (char c : key)
    {
        if (c == '~')
            out += "~0";
        else if (c == '/')
            out += "~1";
        else
            out.push_back(c);
    }
    return out;
}

std::string hex_encode_text(const std::string& text)
{
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() * 2);
    for (unsigned char c : text)
    {
        out.push_back(h[(c >> 4) & 0x0f]);
        out.push_back(h[c & 0x0f]);
    }
    return out;
}

bool hex_decode_text(const std::string& hex, std::string& out)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    if ((hex.size() & 1u) != 0)
        return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

std::string nested_cursor_for(const std::string& op, const std::string& generation, const std::string& path, size_t offset)
{
    return "ac2." + op + "." + generation + "." + std::to_string(offset) + "." + hex_encode_text(path);
}

bool parse_nested_cursor(const std::string& cursor, const std::string& op, const std::string& generation, std::string& path, size_t& offset)
{
    offset = 0;
    path.clear();
    const std::string prefix = "ac2." + op + "." + generation + ".";
    if (cursor.rfind(prefix, 0) != 0)
        return false;
    const std::string rest = cursor.substr(prefix.size());
    const std::size_t dot = rest.find('.');
    if (dot == std::string::npos)
        return false;
    const std::string n = rest.substr(0, dot);
    const std::string encoded = rest.substr(dot + 1);
    char* endp = nullptr;
    unsigned long long parsed = _strtoui64(n.c_str(), &endp, 10);
    if (endp == n.c_str() || *endp != '\0')
        return false;
    offset = static_cast<size_t>(parsed);
    return hex_decode_text(encoded, path);
}

json* json_at_pointer(json& root, const std::string& path)
{
    if (path.empty())
        return nullptr;
    try
    {
        return &root.at(json::json_pointer(path));
    }
    catch (...)
    {
        return nullptr;
    }
}

json page_array_slice(const json& full, size_t offset, size_t limit)
{
    json out = json::array();
    if (!full.is_array())
        return out;
    const size_t total = full.size();
    const size_t end = std::min(total, offset + limit);
    for (size_t i = offset; i < end; ++i)
        out.push_back(full.at(i));
    return out;
}

void cap_nested_arrays(json& node,
                       const std::string& path,
                       size_t limit,
                       const std::string& op,
                       const std::string& generation,
                       json& nested,
                       size_t& capped_count)
{
    if (node.is_array())
    {
        const size_t total = node.size();
        if (total > limit)
        {
            node = page_array_slice(node, 0, limit);
            nested.push_back({{"path", path},
                              {"cursor", nullptr},
                              {"next_cursor", nested_cursor_for(op, generation, path, limit)},
                              {"limit", limit},
                              {"returned", node.size()},
                              {"total_known", total},
                              {"truncated", true}});
            ++capped_count;
        }
        for (size_t i = 0; i < node.size(); ++i)
            cap_nested_arrays(node[i], path + "/" + std::to_string(i), limit, op, generation, nested, capped_count);
        return;
    }
    if (!node.is_object())
        return;
    for (auto it = node.begin(); it != node.end(); ++it)
        cap_nested_arrays(it.value(), path + "/" + pointer_escape(it.key()), limit, op, generation, nested, capped_count);
}

bool apply_nested_pagination(const request_ctx_t& ctx,
                             const std::string& op,
                             json& data,
                             const std::string& default_path,
                             json& page)
{
    const std::string gen = generation_id();
    std::string path = ctx.payload.value("page_path", std::string());
    size_t offset = 0;
    if (!ctx.cursor.empty())
    {
        if (ctx.cursor.rfind("ac2.", 0) == 0)
        {
            if (!parse_nested_cursor(ctx.cursor, op, gen, path, offset))
            {
                page = json::object({{"error", "cursor_expired"}});
                return false;
            }
        }
        else if (!path.empty())
        {
            if (!parse_cursor(ctx.cursor, op, gen, offset))
            {
                page = json::object({{"error", "cursor_expired"}});
                return false;
            }
        }
    }
    if (path.empty())
        path = default_path;
    if (!path.empty())
    {
        json* target = json_at_pointer(data, path);
        if (target == nullptr || !target->is_array())
        {
            page = json::object({{"error", "bad_page_path"}, {"path", path}});
            return false;
        }
        const size_t total = target->size();
        const size_t limit = static_cast<size_t>(ctx.limit);
        *target = page_array_slice(*target, offset, limit);
        const bool truncated = offset + target->size() < total;
        page = page_json(ctx.cursor, truncated ? nested_cursor_for(op, gen, path, offset + target->size()) : std::string(), ctx.limit, target->size(), truncated);
        page["path"] = path;
        page["total_known"] = total;
        return true;
    }
    json nested = json::array();
    size_t capped_count = 0;
    cap_nested_arrays(data, std::string(), static_cast<size_t>(ctx.limit), op, gen, nested, capped_count);
    page = json::object({{"cursor", ctx.cursor.empty() ? json(nullptr) : json(ctx.cursor)},
                         {"next_cursor", nullptr},
                         {"limit", ctx.limit},
                         {"returned", nullptr},
                         {"truncated", !nested.empty()},
                         {"nested", std::move(nested)}});
    return true;
}

agent_tools::tool_result_t invoke_registered(const std::string& tool_name, const json& params)
{
    return agent_tools::ToolRegistry::instance().execute_tool(tool_name, params);
}

json wrapped_tool_result(const std::string& tool_name, const agent_tools::tool_result_t& r)
{
    json d;
    d["legacy_tool"] = tool_name;
    d["success"] = r.success;
    d["message"] = r.output;
    d["error_code"] = r.error_code.empty() ? json(nullptr) : json(r.error_code);
    d["data"] = r.data.is_null() ? json::object() : r.data;
    return d;
}

json verify_link_data(const json& payload, agent_tools::tool_result_t& failure, const request_ctx_t& ctx)
{
    auto source = payload_location(payload, "source");
    auto sink = payload_location(payload, "sink");
    if (!source || !sink)
    {
        failure = error_envelope(ctx, "bad_param", "source and sink locations are required",
                                 json{{"required", json::array({"source", "sink"})}});
        return json::object();
    }
    const int timeout_ms = int_param(payload, "timeout_ms", 5000, 100, 60000);
    json p;
    p["source"] = fmt_ea(*source);
    p["sink"] = fmt_ea(*sink);
    p["timeout_ms"] = timeout_ms;
    auto r = invoke_registered("verify_taint_path", p);
    json out = wrapped_tool_result("verify_taint_path", r);
    if (!r.success)
        out["data"] = json::object({{"verdict", "unsupported"}, {"rationale", r.output}, {"error_code", r.error_code.empty() ? "internal_error" : r.error_code}});
    out["source"] = fmt_ea(*source);
    out["sink"] = fmt_ea(*sink);
    out["link_id"] = payload.value("link_id", std::string("link:" + fmt_ea(*source) + "->" + fmt_ea(*sink)));
    failure = agent_tools::tool_result_t{};
    return out;
}

json boundary_match_data(const json& payload)
{
    json out;
    out["schema"] = "aida.ida.chain.boundary_match.v1";
    out["verdict"] = "inconclusive";
    out["matches"] = json::array();
    out["mismatches"] = json::array();
    out["counterevidence"] = json::array();
    out["unproven"] = json::array();

    const json producer = payload.value("producer", json::object());
    const json consumer = payload.value("consumer", json::object());
    if (producer.is_object() && consumer.is_object())
    {
        if (producer.contains("postconditions") && consumer.contains("preconditions"))
        {
            const std::string pp = producer["postconditions"].dump();
            const std::string cp = consumer["preconditions"].dump();
            if (pp == cp)
                out["matches"].push_back({{"kind", "postcondition_precondition"}, {"hash", hash_text(pp)}});
            else
                out["mismatches"].push_back({{"kind", "postcondition_precondition"}, {"producer_hash", hash_text(pp)}, {"consumer_hash", hash_text(cp)}});
        }
        if (producer.contains("output") && consumer.contains("input"))
        {
            if (producer["output"] == consumer["input"])
                out["matches"].push_back({{"kind", "output_input"}, {"value", producer["output"]}});
            else
                out["mismatches"].push_back({{"kind", "output_input"}, {"producer", producer["output"]}, {"consumer", consumer["input"]}});
        }
    }

    auto source = payload_location(payload, "source");
    auto sink = payload_location(payload, "sink");
    if (sink)
    {
        json p;
        if (source)
            p["source"] = fmt_ea(*source);
        p["sink"] = fmt_ea(*sink);
        p["max_branches"] = int_param(payload, "max_branches", 64, 1, 1024);
        auto r = invoke_registered("extract_wire_path_constraints", p);
        out["wire_constraints"] = wrapped_tool_result("extract_wire_path_constraints", r);
    }

    if (!out["mismatches"].empty())
    {
        out["verdict"] = "refuted";
        out["counterevidence"] = out["mismatches"];
    }
    else if (!out["matches"].empty())
        out["verdict"] = "confirmed";
    else
        out["unproven"].push_back({{"reason", "no comparable producer/consumer facts were supplied"}});
    return out;
}

json call_edges_from_function(func_t* fn, int max_edges)
{
    json edges = json::array();
    if (!fn)
        return edges;
    func_item_iterator_t fii(fn);
    for (bool ok = fii.first(); ok && static_cast<int>(edges.size()) < max_edges; ok = fii.next_head())
    {
        ea_t item = fii.current();
        xrefblk_t xb;
        for (bool xok = xb.first_from(item, XREF_FAR); xok && static_cast<int>(edges.size()) < max_edges; xok = xb.next_from())
        {
            func_t* callee = get_func(xb.to);
            if (!callee)
                continue;
            json e;
            e["call_ea"] = fmt_ea(item);
            e["callee"] = function_json(callee, false);
            e["xref_type"] = xb.type;
            edges.push_back(e);
        }
    }
    return edges;
}

json trigger_confirm_data(const json& payload)
{
    json out;
    out["schema"] = "aida.ida.chain.trigger_confirm.v1";
    out["verdict"] = "inconclusive";
    out["path"] = json::array();
    out["frontier_exhausted"] = false;
    out["unresolved_edges"] = json::array();
    auto entry = payload_location(payload, "entry");
    if (!entry)
        entry = payload_location(payload, "trigger");
    auto target = payload_location(payload, "target");
    if (!target)
        target = payload_location(payload, "sink");
    if (!target)
    {
        out["failure"] = "target or sink is required";
        return out;
    }
    const int max_depth = int_param(payload, "max_depth", 5, 1, 32);
    const int max_functions = int_param(payload, "max_functions", 512, 1, 20000);
    func_t* target_fn = get_func(*target);
    if (!target_fn)
    {
        out["failure"] = "target is not inside a known function";
        out["target"] = fmt_ea(*target);
        return out;
    }
    if (!entry)
    {
        xrefblk_t xb;
        json callers = json::array();
        for (bool ok = xb.first_to(target_fn->start_ea, XREF_FAR); ok && callers.size() < static_cast<size_t>(max_functions); ok = xb.next_to())
        {
            func_t* caller = get_func(xb.from);
            if (caller)
                callers.push_back({{"call_ea", fmt_ea(xb.from)}, {"caller", function_json(caller, false)}});
        }
        out["candidate_callers"] = callers;
        out["verdict"] = callers.empty() ? "inconclusive" : "confirmed";
        out["rationale"] = callers.empty() ? "no static callers found inside the current IDB budget" : "static caller evidence found";
        return out;
    }
    func_t* entry_fn = get_func(*entry);
    if (!entry_fn)
    {
        out["failure"] = "entry is not inside a known function";
        out["entry"] = fmt_ea(*entry);
        return out;
    }
    struct node_t { ea_t fn; std::vector<ea_t> path; int depth; };
    std::vector<node_t> queue;
    std::set<ea_t> seen;
    queue.push_back({entry_fn->start_ea, {entry_fn->start_ea}, 0});
    seen.insert(entry_fn->start_ea);
    size_t head = 0;
    while (head < queue.size() && seen.size() <= static_cast<size_t>(max_functions))
    {
        node_t cur = queue[head++];
        if (cur.fn == target_fn->start_ea)
        {
            out["verdict"] = "confirmed";
            for (ea_t ea : cur.path)
                out["path"].push_back(fmt_ea(ea));
            return out;
        }
        if (cur.depth >= max_depth)
            continue;
        func_t* fn = get_func(cur.fn);
        json edges = call_edges_from_function(fn, max_functions);
        for (const auto& e : edges)
        {
            auto callee_ea = parse_location(e["callee"]["address"]);
            if (!callee_ea || seen.find(*callee_ea) != seen.end())
                continue;
            std::vector<ea_t> np = cur.path;
            np.push_back(*callee_ea);
            queue.push_back({*callee_ea, std::move(np), cur.depth + 1});
            seen.insert(*callee_ea);
        }
    }
    out["frontier_exhausted"] = head >= queue.size();
    out["visited_functions"] = seen.size();
    out["verdict"] = "inconclusive";
    out["rationale"] = "no static call path reached the target inside the supplied budget";
    return out;
}

json chain_validation_data(const json& chain)
{
    json out;
    out["schema"] = "aida.ida.chain.validation.v1";
    out["valid"] = true;
    out["errors"] = json::array();
    out["normalized"] = chain;
    if (!chain.is_object())
    {
        out["valid"] = false;
        out["errors"].push_back({{"field", "chain"}, {"message", "chain must be an object"}});
        return out;
    }
    if (chain.value("schema", std::string(kChainSchema)) != kChainSchema)
    {
        out["valid"] = false;
        out["errors"].push_back({{"field", "chain.schema"}, {"message", "schema must be aida_chain_document_v2"}});
    }
    if (!chain.contains("links") || !chain["links"].is_array())
    {
        out["valid"] = false;
        out["errors"].push_back({{"field", "chain.links"}, {"message", "links array is required"}});
    }
    else
    {
        for (size_t i = 0; i < chain["links"].size(); ++i)
        {
            const json& link = chain["links"].at(i);
            if (!link.is_object())
            {
                out["valid"] = false;
                out["errors"].push_back({{"field", "chain.links[" + std::to_string(i) + "]"}, {"message", "link must be an object"}});
                continue;
            }
            if (!link.contains("source") && !link.contains("entry") && !link.contains("producer"))
            {
                out["valid"] = false;
                out["errors"].push_back({{"field", "chain.links[" + std::to_string(i) + "]"}, {"message", "source, entry, or producer is required"}});
            }
            if (!link.contains("sink") && !link.contains("target") && !link.contains("consumer"))
            {
                out["valid"] = false;
                out["errors"].push_back({{"field", "chain.links[" + std::to_string(i) + "]"}, {"message", "sink, target, or consumer is required"}});
            }
        }
    }
    return out;
}

json build_chain_report(const request_ctx_t& ctx, const std::string& job_id)
{
    json chain = ctx.payload.contains("chain") ? ctx.payload["chain"] : json::object();
    if (chain.empty())
    {
        chain["schema"] = kChainSchema;
        chain["chain_id"] = ctx.payload.value("chain_id", std::string("chain:" + ctx.request_id));
        chain["links"] = json::array({{
            {"link_id", "link:0"},
            {"source", ctx.payload.value("source", json())},
            {"sink", ctx.payload.value("sink", json())}
        }});
    }
    const std::string chain_id = chain.value("chain_id", std::string("chain:" + ctx.request_id));
    json report;
    report["schema"] = kReportSchema;
    report["report_id"] = nullptr;
    report["chain_id"] = chain_id;
    report["job_id"] = job_id;
    report["verdict"] = "inconclusive";
    report["acceptance"] = "not_accepted";
    report["confidence"] = "plausible";
    report["summary"] = "Chain verification completed with current IDA plugin evidence producers.";
    report["first_failure"] = nullptr;
    report["unproven_critical_facts"] = json::array();
    report["corpus"] = json::array({module_identity()});
    report["phase_status"] = json::array();
    report["links"] = json::array();
    report["boundaries"] = json::array();
    report["objectives"] = json::array();
    report["trace_manifest"] = json::object();
    report["fact_manifest"] = json::object();
    report["solver_manifest"] = json::object();
    report["resource_manifest"] = json::array();
    report["generation_manifest"] = json::array({generation_id()});
    report["budget_manifest"] = ctx.budget;
    report["diagnostics"] = json::object({{"auto_analysis_ok", auto_is_ok()}, {"engine", verify::engine().verdict_summary()}});

    json validation = chain_validation_data(chain);
    report["phase_status"].push_back({{"phase", "validate_spec"}, {"ok", validation.value("valid", false)}, {"details", validation}});
    if (!validation.value("valid", false))
    {
        report["verdict"] = "unsupported";
        report["first_failure"] = validation["errors"].empty() ? json(nullptr) : validation["errors"].front();
        report["unproven_critical_facts"] = validation["errors"];
        return report;
    }

    int confirmed = 0;
    int refuted = 0;
    int timeout = 0;
    int unsupported = 0;
    int inconclusive = 0;
    const json& links = chain["links"];
    for (size_t i = 0; i < links.size(); ++i)
    {
        json link_payload = links.at(i);
        if (!link_payload.contains("link_id"))
            link_payload["link_id"] = "link:" + std::to_string(i);
        if (ctx.payload.contains("timeout_ms") && !link_payload.contains("timeout_ms"))
            link_payload["timeout_ms"] = ctx.payload["timeout_ms"];
        if (link_payload.contains("target") && !link_payload.contains("sink"))
            link_payload["sink"] = link_payload["target"];
        agent_tools::tool_result_t failure;
        json link_result;
        if (link_payload.contains("source") && link_payload.contains("sink"))
            link_result = verify_link_data(link_payload, failure, ctx);
        else
        {
            link_result["success"] = false;
            link_result["data"] = json::object({{"verdict", "inconclusive"}, {"rationale", "link lacks source/sink verification endpoints"}});
        }
        json link_report;
        link_report["link_id"] = link_payload.value("link_id", std::string("link:" + std::to_string(i)));
        link_report["role"] = link_payload.value("role", std::string("transition"));
        link_report["verification"] = link_result;
        std::string verdict = "inconclusive";
        if (link_result.contains("data") && link_result["data"].is_object())
        {
            const json& data = link_result["data"];
            if (data.contains("verdict") && data["verdict"].is_string())
                verdict = data["verdict"].get<std::string>();
        }
        link_report["verdict"] = verdict;
        link_report["proof_level"] = verdict == "confirmed" ? "link_path_sat" : "not_confirmed";
        link_report["unproven_facts"] = json::array();
        link_report["refutations"] = json::array();
        if (verdict == "confirmed")
            ++confirmed;
        else if (verdict == "refuted")
        {
            ++refuted;
            link_report["refutations"].push_back(link_result);
        }
        else if (verdict == "timeout")
            ++timeout;
        else if (verdict == "unsupported")
            ++unsupported;
        else
            ++inconclusive;
        if (verdict != "confirmed")
            link_report["unproven_facts"].push_back({{"link_id", link_report["link_id"]}, {"verdict", verdict}, {"acceptance_blocker", true}});
        report["links"].push_back(link_report);
    }

    for (size_t i = 1; i < links.size(); ++i)
    {
        json b_payload;
        b_payload["producer"] = links.at(i - 1);
        b_payload["consumer"] = links.at(i);
        json b = boundary_match_data(b_payload);
        b["producer_link"] = links.at(i - 1).value("link_id", std::string("link:" + std::to_string(i - 1)));
        b["consumer_link"] = links.at(i).value("link_id", std::string("link:" + std::to_string(i)));
        report["boundaries"].push_back(b);
        if (b.value("verdict", std::string()) == "refuted")
            ++refuted;
        else if (b.value("verdict", std::string()) != "confirmed")
            ++inconclusive;
    }

    if (refuted > 0)
    {
        report["verdict"] = "refuted";
        report["acceptance"] = "rejected";
    }
    else if (timeout > 0)
    {
        report["verdict"] = "timeout";
        report["acceptance"] = "not_accepted";
    }
    else if (unsupported > 0)
    {
        report["verdict"] = "unsupported";
        report["acceptance"] = "not_accepted";
    }
    else if (inconclusive > 0 || confirmed == 0)
    {
        report["verdict"] = "inconclusive";
        report["acceptance"] = "not_accepted";
    }
    else
    {
        report["verdict"] = "confirmed";
        report["acceptance"] = "accepted";
        report["confidence"] = "proven";
    }

    for (const auto& l : report["links"])
    {
        if (l.value("verdict", std::string()) != "confirmed")
        {
            report["unproven_critical_facts"].push_back({{"link_id", l["link_id"]}, {"verdict", l["verdict"]}, {"acceptance_blocker", true}});
            if (report["first_failure"].is_null())
                report["first_failure"] = report["unproven_critical_facts"].back();
        }
    }
    if (report["first_failure"].is_null() && report["verdict"] != "confirmed")
        report["first_failure"] = {{"reason", "chain did not reach complete proof acceptance"}};
    return report;
}

std::string markdown_report(const report_record_t& r)
{
    std::ostringstream ss;
    ss << "# AiDA Chain Verification Report\n\n";
    ss << "- Report: `" << r.report_id << "`\n";
    ss << "- Job: `" << r.job_id << "`\n";
    ss << "- Chain: `" << r.chain_id << "`\n";
    ss << "- Verdict: `" << r.report.value("verdict", std::string("inconclusive")) << "`\n";
    ss << "- Acceptance: `" << r.report.value("acceptance", std::string("not_accepted")) << "`\n\n";
    ss << "## Links\n\n";
    if (r.report.contains("links") && r.report["links"].is_array())
    {
        for (const auto& l : r.report["links"])
        {
            ss << "- `" << l.value("link_id", std::string()) << "` verdict `"
               << l.value("verdict", std::string("inconclusive")) << "`\n";
        }
    }
    return ss.str();
}

json sarif_report(const report_record_t& r)
{
    json sarif;
    sarif["version"] = "2.1.0";
    sarif["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";
    json run;
    run["tool"]["driver"]["name"] = "AiDA IDA Chain Verifier";
    run["tool"]["driver"]["informationUri"] = "ida://aida-chain";
    run["results"] = json::array();
    if (r.report.contains("links") && r.report["links"].is_array())
    {
        for (const auto& l : r.report["links"])
        {
            if (l.value("verdict", std::string()) == "confirmed")
                continue;
            json res;
            res["ruleId"] = "AIDA_CHAIN_" + l.value("verdict", std::string("INCONCLUSIVE"));
            res["level"] = l.value("verdict", std::string()) == "refuted" ? "error" : "warning";
            res["message"]["text"] = "Chain link " + l.value("link_id", std::string()) + " verdict: " + l.value("verdict", std::string("inconclusive"));
            run["results"].push_back(res);
        }
    }
    sarif["runs"] = json::array({run});
    return sarif;
}

json export_report_data(const report_record_t& r, const std::string& format)
{
    json d;
    d["report_id"] = r.report_id;
    d["format"] = format;
    d["content_hash"] = r.content_hash;
    d["resource"] = resource_for_report(r, format);
    if (format == "json")
        d["content"] = r.report;
    else if (format == "markdown")
        d["content"] = markdown_report(r);
    else if (format == "sarif")
        d["content"] = sarif_report(r);
    return d;
}

bool json_contains_evidence(const json& node, const std::string& evidence_id, const std::string& address, json& out)
{
    if (node.is_object())
    {
        bool match = false;
        if (!evidence_id.empty())
        {
            for (const char* key : {"evidence_id", "fact_id", "link_id", "report_id", "job_id"})
            {
                if (node.contains(key) && node[key].is_string() && node[key].get<std::string>() == evidence_id)
                    match = true;
            }
        }
        if (!address.empty())
        {
            for (const char* key : {"ea", "address", "source", "sink", "comparison_ea"})
            {
                if (node.contains(key) && node[key].is_string() && node[key].get<std::string>() == address)
                    match = true;
            }
            if (node.contains("cited_eas") && node["cited_eas"].is_array())
            {
                for (const auto& ea : node["cited_eas"])
                {
                    if (ea.is_string() && ea.get<std::string>() == address)
                        match = true;
                }
            }
        }
        if (match)
        {
            out = node;
            return true;
        }
        for (auto it = node.begin(); it != node.end(); ++it)
        {
            if (json_contains_evidence(it.value(), evidence_id, address, out))
                return true;
        }
    }
    else if (node.is_array())
    {
        for (const auto& item : node)
        {
            if (json_contains_evidence(item, evidence_id, address, out))
                return true;
        }
    }
    return false;
}

const std::vector<operation_meta_t>& chain_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return chain verifier operations, payload schemas, examples, metadata, and error codes.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"validate_spec", "Validate and normalize an aida_chain_document_v2 chain specification.", true, false, true, false, "none", 1000, 5000, {}, {{"chain", "object", true, {}}}, false},
        {"submit", "Validate, verify, ledger, and report a chain verification request.", false, false, false, true, "ledger", 120000, 600000, {"taint_engine", "symbolic_engine", "smt_solver"}, {{"chain", "object", false, {}}, {"chain_id", "string", false, {}}, {"source", "location", false, {}}, {"sink", "location", false, {}}, {"timeout_ms", "number", false, {}}}, true},
        {"start", "Alias for submit with job semantics.", false, false, false, true, "ledger", 120000, 600000, {"taint_engine", "symbolic_engine", "smt_solver"}, {{"chain", "object", false, {}}, {"chain_id", "string", false, {}}, {"source", "location", false, {}}, {"sink", "location", false, {}}, {"timeout_ms", "number", false, {}}}, true},
        {"status", "Return verifier engine status or one chain job status.", true, false, false, false, "none", 500, 2000, {}, {{"job_id", "string", false, {}}}, false},
        {"cancel", "Cancel one chain job when job_id is supplied or request global verifier cancellation.", false, false, false, false, "job_state", 500, 2000, {}, {{"job_id", "string", false, {}}}, false},
        {"resume", "Resume a cancelled or failed chain job from its saved request payload.", false, false, false, true, "ledger", 120000, 600000, {"taint_engine", "symbolic_engine", "smt_solver"}, {{"job_id", "string", true, {}}}, false},
        {"export", "Export a chain report by report_id or job_id in json, markdown, or sarif format.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"format", "string", false, {"json", "markdown", "sarif"}}}, false},
        {"verify_link", "Verify a source-to-sink link with the existing SMT-backed verifier.", false, false, false, true, "verdict_cache", 5000, 60000, {"taint_engine", "symbolic_engine", "smt_solver"}, {{"source", "location", true, {}}, {"sink", "location", true, {}}, {"timeout_ms", "number", false, {}}, {"link_id", "string", false, {}}}, false},
        {"boundary_match", "Compare producer and consumer facts and extract wire constraints where source/sink are supplied.", true, false, true, false, "none", 1000, 30000, {"symbolic_engine"}, {{"producer", "object", false, {}}, {"consumer", "object", false, {}}, {"source", "location", false, {}}, {"sink", "location", false, {}}, {"max_branches", "number", false, {}}}, false},
        {"trigger_confirm", "Confirm or refute a bounded static trigger path from entry/trigger to target/sink.", true, false, true, false, "none", 2000, 30000, {"cfg_engine"}, {{"entry", "location", false, {}}, {"trigger", "location", false, {}}, {"target", "location", false, {}}, {"sink", "location", false, {}}, {"max_depth", "number", false, {}}, {"max_functions", "number", false, {}}}, false},
        {"get_report", "Fetch a stored chain verification report.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}}, false},
        {"list", "List stored chain reports and verification jobs.", true, false, false, false, "report", 1000, 10000, {}, {{"verdict", "string", false, {"confirmed", "refuted", "timeout", "inconclusive", "unsupported"}}, {"include_jobs", "boolean", false, {}}}, false},
        {"evidence_fetch", "Fetch cited evidence from a stored report by evidence_id, link_id, fact_id, job_id, report_id, or address.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"evidence_id", "string", false, {}}, {"address", "location", false, {}}}, false},
        {"explain_failure", "Return the first failure, unproven critical facts, refutations, and counterevidence for a report.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}}, false},
        {"diagnostics", "Return chain verifier engine, ledger, job, index, and modal-safety diagnostics.", true, false, false, false, "none", 1000, 10000, {}, {}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& project_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return project, corpus, and index operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"inventory_current", "Return deterministic current-IDB inventory with module identity, hashes, segments, imports, entries, and counts.", true, false, true, false, "none", 500, 5000, {}, {{"include_segments", "boolean", false, {}}, {"include_imports", "boolean", false, {}}, {"include_entries", "boolean", false, {}}, {"max_rows", "number", false, {}}}, false},
        {"inventory_all", "Merge supplied query_all_instances inventory responses when present; otherwise return local inventory plus fail-closed peer_data_missing gaps for live peers that were not supplied.", true, false, false, false, "none", 1000, 30000, {}, {{"include_segments", "boolean", false, {}}, {"include_imports", "boolean", false, {}}, {"include_entries", "boolean", false, {}}, {"max_rows", "number", false, {}}, {"fanout_result", "object", false, {}}, {"inventories", "array", false, {}}}, true},
        {"list", "List durable multibinary projects under the IDA user directory.", true, false, true, false, "project", 500, 5000, {}, {}, false},
        {"load", "Load one durable project manifest and module records.", true, false, true, false, "project", 500, 10000, {}, {{"project_id", "string", true, {}}}, false},
        {"save", "Create or update a durable project from supplied module records or inventory/fanout data.", false, false, false, true, "project", 1000, 60000, {}, {{"project_id", "string", false, {}}, {"modules", "array", false, {}}, {"fanout_result", "object", false, {}}, {"inventories", "array", false, {}}, {"force_lock", "boolean", false, {}}}, true},
        {"delete", "Delete one durable project after explicit confirmation.", false, true, false, false, "project", 1000, 30000, {}, {{"project_id", "string", true, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"status", "Return durable project manifest, cache, generation, stale-state, and cross-edge readiness.", true, false, false, false, "project", 500, 10000, {}, {{"project_id", "string", false, {}}}, false},
        {"corpus_snapshot", "Return a durable project manifest when project_id is supplied, otherwise the current module corpus record.", true, false, true, false, "corpus", 500, 5000, {}, {{"project_id", "string", false, {}}}, false},
        {"corpus_bind", "Bind supplied modules, inventories, fanout responses, and the current module into a durable multibinary project.", false, false, false, false, "corpus", 1000, 60000, {}, {{"modules", "array", false, {}}, {"project_id", "string", false, {}}, {"corpus_id", "string", false, {}}, {"role", "string", false, {}}, {"fanout_result", "object", false, {}}, {"inventories", "array", false, {}}, {"force_lock", "boolean", false, {}}}, true},
        {"corpus_export", "Export a durable project manifest or the current in-memory compatibility corpus manifest.", true, false, true, false, "corpus", 500, 5000, {}, {{"format", "string", false, {"json"}}, {"project_id", "string", false, {}}}, false},
        {"index_build", "Build durable module identity, import/export, function, local-edge, netnode, and cross-edge indexes for the current IDB.", false, false, false, true, "index", 30000, 600000, {}, {{"project_id", "string", false, {}}, {"indices", "array", false, {}}, {"force", "boolean", false, {}}, {"max_functions", "number", false, {}}, {"max_edges", "number", false, {}}, {"max_imports", "number", false, {}}, {"max_exports", "number", false, {}}}, false},
        {"index_status", "Return durable index readiness, generation, stale-state, and cross-edge diagnostics.", true, false, false, false, "index", 500, 5000, {}, {{"project_id", "string", false, {}}, {"indices", "array", false, {}}}, false},
        {"index_page_status", "Return durable page manifests for function, xref, signature, dispatch, callback, global, import/export, summary, and cross-edge indexes.", true, false, false, false, "index", 500, 10000, {}, {{"project_id", "string", false, {}}, {"module_id", "string", false, {}}}, false},
        {"index_page", "Load one durable index page by family/module/page_index or by returned cursor.", true, false, true, false, "index", 500, 30000, {}, {{"project_id", "string", false, {}}, {"module_id", "string", false, {}}, {"family", "string", false, {}}, {"cursor", "string", false, {}}, {"page_index", "number", false, {}}}, false},
        {"resolve_cross_edges", "Resolve and persist the project cross-module import/export/forwarder graph.", false, false, false, true, "index", 1000, 120000, {}, {{"project_id", "string", false, {}}}, false},
        {"resolve_reference", "Resolve one module/name, module/ordinal, import, or module_id+rva reference through the durable project graph.", true, false, true, false, "index", 1000, 30000, {}, {{"project_id", "string", false, {}}, {"reference", "object", true, {}}}, false},
        {"verify_chain", "Verify a chain against durable project modules, normalized addresses, cross edges, and link boundary facts with fail-closed confirmation rules.", true, false, false, true, "project_verifier", 5000, 600000, {}, {{"project_id", "string", false, {}}, {"chain", "object", true, {}}, {"options", "object", false, {}}}, true},
        {"case_study_regressions", "Run source-backed NTFS/AFD/pvScan0 project semantics over supplied chain/source evidence without synthetic passes.", true, false, false, true, "project_verifier", 5000, 600000, {}, {{"project_id", "string", false, {}}, {"chain", "object", false, {}}, {"source_checks", "array", false, {}}, {"options", "object", false, {}}}, true}
    };
    return ops;
}

const std::vector<operation_meta_t>& extract_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return extraction and evidence operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"functions", "List functions with cursor pagination.", true, false, true, false, "none", 1000, 5000, {}, {{"filter", "string", false, {}}, {"include_segments", "boolean", false, {}}}, false},
        {"function", "Fetch normalized function metadata by address.", true, false, true, false, "none", 1000, 5000, {}, {{"address", "location", true, {}}, {"include_xrefs", "boolean", false, {}}}, false},
        {"instructions", "Fetch paginated disassembly rows for a function.", true, false, true, false, "none", 1000, 10000, {}, {{"address", "location", true, {}}}, false},
        {"xrefs", "Fetch code/data xrefs to or from an address.", true, false, true, false, "none", 1000, 10000, {}, {{"address", "location", true, {}}, {"direction", "string", false, {"to", "from", "both"}}, {"kind", "string", false, {"code", "data", "all"}}}, false},
        {"bytes", "Read bytes from the database with max-byte budget.", true, false, true, false, "none", 500, 5000, {}, {{"address", "location", true, {}}, {"size", "number", true, {}}}, false},
        {"decompile", "Return Hex-Rays pseudocode through the existing non-wait decompiler helper.", true, false, false, false, "none", 1000, 30000, {}, {{"address", "location", true, {}}}, false},
        {"imports", "List imports with pagination.", true, false, true, false, "none", 1000, 10000, {}, {}, false},
        {"exports", "List entry/export records with pagination.", true, false, true, false, "none", 1000, 10000, {}, {}, false},
        {"segments", "List IDA segments and permissions.", true, false, true, false, "none", 500, 5000, {}, {}, false},
        {"corpus_snapshot", "Return module and corpus identity adjacent to extraction results.", true, false, true, false, "none", 500, 5000, {}, {}, false},
        {"extract_module_facts", "Return normalized module, segment, entry, import, function index, full mapped-item xref index, resolver index, and cache facts.", true, false, true, false, "extraction_cache", 1000, 30000, {}, {{"layers", "array", false, {}}, {"maturities", "array", false, {}}, {"force_refresh", "boolean", false, {}}, {"max_functions", "number", false, {}}, {"max_module_items", "number", false, {}}, {"max_xrefs_per_address", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_function_facts", "Return normalized raw, CFG, xref, type, ctree, microcode, side-effect, and cache facts for one function.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"address", "location", true, {}}, {"layers", "array", false, {}}, {"maturities", "array", false, {}}, {"force_refresh", "boolean", false, {}}, {"max_instructions", "number", false, {}}, {"max_basic_blocks", "number", false, {}}, {"max_ctree_nodes", "number", false, {}}, {"max_microcode_instructions", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_function_batch", "Return a cancellable bounded batch of normalized function facts.", true, false, true, false, "extraction_cache", 5000, 120000, {}, {{"functions", "array", false, {}}, {"layers", "array", false, {}}, {"maturities", "array", false, {}}, {"force_refresh", "boolean", false, {}}, {"max_functions", "number", false, {}}, {"timeout_ms", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_xref_graph", "Return normalized xref indexes and cross-function/module reachability evidence around a function or address.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"address", "location", true, {}}, {"target", "location", false, {}}, {"layers", "array", false, {}}, {"direction", "string", false, {"to", "from", "both"}}, {"max_depth", "number", false, {}}, {"max_functions", "number", false, {}}, {"modules", "array", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_path_window", "Return a normalized path corridor between entry and target inside one function.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"entry", "location", true, {}}, {"target", "location", true, {}}, {"layers", "array", false, {}}, {"max_blocks", "number", false, {}}, {"max_steps", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_type_facts", "Return normalized function type, stack, local, argument, UDT, enum, and dependency facts.", true, false, true, false, "extraction_cache", 1000, 30000, {}, {{"address", "location", true, {}}, {"force_refresh", "boolean", false, {}}, {"page_path", "string", false, {}}}, true},
        {"resolve_cross_binary", "Resolve a module/RVA, import/export, public symbol, thunk, or controlled target against supplied module fact stores.", true, false, true, false, "extraction_cache", 1000, 30000, {}, {{"reference", "object", true, {}}, {"modules", "array", false, {}}, {"include_current_module", "boolean", false, {}}, {"max_module_items", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"case_study_self_check", "Run source-backed extraction self-checks for NTFS/ETW zero-vs-copy, ETW trigger negative evidence, AFD LIST_ENTRY guard, or pvScan0 self-reference classes.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"case_id", "string", false, {"all", "ntfs_etw_zero_vs_copy", "etw_trigger_negative", "afd_list_entry_guard", "pvscan0_self_reference"}}, {"address", "location", false, {}}, {"entry", "location", false, {}}, {"target", "location", false, {}}, {"modules", "array", false, {}}, {"max_depth", "number", false, {}}, {"max_functions", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extraction_cache_status", "Return extraction cache counters and storage status.", true, false, true, false, "extraction_cache", 500, 5000, {}, {}, false},
        {"invalidate_extraction_cache", "Clear plugin-owned extraction cache storage.", false, true, true, false, "none", 500, 10000, {}, {{"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"evidence_fetch", "Fetch evidence from reports or address-local function/xref context.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"evidence_id", "string", false, {}}, {"address", "location", false, {}}}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& report_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return report and ledger operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"list_reports", "List stored chain verification reports.", true, false, false, false, "report", 1000, 10000, {}, {{"verdict", "string", false, {"confirmed", "refuted", "timeout", "inconclusive", "unsupported"}}}, false},
        {"get_report", "Get a stored report by report_id or job_id.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}}, false},
        {"export_report", "Export a stored report in json, markdown, or sarif.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"format", "string", false, {"json", "markdown", "sarif"}}}, false},
        {"evidence_fetch", "Fetch report evidence by evidence_id or address.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"evidence_id", "string", false, {}}, {"address", "location", false, {}}}, false},
        {"ledger_status", "Return verifier ledger summary.", true, false, false, false, "ledger", 500, 5000, {}, {}, false},
        {"ledger_save", "Persist verifier ledger through the existing netnode-backed engine path.", false, false, false, false, "ledger", 1000, 10000, {}, {}, false},
        {"ledger_load", "Load verifier ledger through the existing netnode-backed engine path.", false, false, false, false, "ledger", 1000, 10000, {}, {}, false},
        {"ledger_clear", "Clear verifier ledger through the existing engine path.", false, false, false, false, "ledger", 1000, 10000, {}, {{"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& job_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return job and diagnostics operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"list", "List plugin-owned jobs.", true, false, false, false, "job_state", 1000, 10000, {}, {{"state", "string", false, {"running", "completed", "cancelled", "failed"}}}, false},
        {"status", "Return one job status.", true, false, false, false, "job_state", 500, 5000, {}, {{"job_id", "string", true, {}}}, false},
        {"result", "Return one job result with report resources.", true, false, true, false, "job_state", 1000, 10000, {}, {{"job_id", "string", true, {}}}, false},
        {"cancel", "Cancel one job and request verifier engine cancellation.", false, false, false, false, "job_state", 500, 5000, {}, {{"job_id", "string", true, {}}}, false},
        {"resume", "Resume a chain job from stored request data.", false, false, false, true, "job_state", 1000, 600000, {}, {{"job_id", "string", true, {}}}, false},
        {"diagnostics", "Return job counts, report counts, engine status, index state, and modal-safety evidence.", true, false, false, false, "diagnostics", 1000, 10000, {}, {}, false},
        {"prune", "Prune completed/cancelled/failed jobs older than a supplied age.", false, false, false, false, "job_state", 1000, 10000, {}, {{"older_than_ms", "number", false, {}}, {"state", "string", false, {"completed", "cancelled", "failed", "all"}}}, false}
    };
    return ops;
}

agent_tools::tool_result_t handle_report_fetch_like(const request_ctx_t& ctx, bool explain_only, bool export_only = false)
{
    std::string report_id = ctx.payload.value("report_id", std::string());
    const std::string job_id = ctx.payload.value("job_id", std::string());
    if (report_id.empty() && !job_id.empty())
    {
        auto job = get_job(job_id);
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        report_id = job->report_id;
    }
    if (report_id.empty())
        return error_envelope(ctx, "bad_param", "report_id or job_id is required", {{"required", json::array({"report_id", "job_id"})}});
    auto rec = get_report_record(report_id);
    if (!rec)
        return error_envelope(ctx, "job_not_found", "report_id was not found", {{"report_id", report_id}});
    json resources = json::array({resource_for_report(*rec, "json"), resource_for_report(*rec, "markdown"), resource_for_report(*rec, "sarif")});
    if (export_only)
    {
        std::string fmt = ctx.payload.value("format", std::string("json"));
        return ok_envelope(ctx, export_report_data(*rec, fmt), json(), json(), json::array(), json::array({resource_for_report(*rec, fmt)}));
    }
    if (explain_only)
    {
        json d;
        d["report_id"] = rec->report_id;
        d["verdict"] = rec->report.value("verdict", std::string("inconclusive"));
        d["acceptance"] = rec->report.value("acceptance", std::string("not_accepted"));
        d["first_failure"] = rec->report.value("first_failure", json(nullptr));
        d["unproven_critical_facts"] = rec->report.value("unproven_critical_facts", json::array());
        d["boundaries"] = rec->report.value("boundaries", json::array());
        d["links"] = rec->report.value("links", json::array());
        return ok_envelope(ctx, d, json(), json(), json::array(), resources);
    }
    json d;
    d["report"] = rec->report;
    d["content_hash"] = rec->content_hash;
    return ok_envelope(ctx, d, json(), json(), json::array(), resources);
}

agent_tools::tool_result_t handle_evidence_fetch(const request_ctx_t& ctx)
{
    std::string report_id = ctx.payload.value("report_id", std::string());
    const std::string job_id = ctx.payload.value("job_id", std::string());
    if (report_id.empty() && !job_id.empty())
    {
        auto job = get_job(job_id);
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        report_id = job->report_id;
    }
    const std::string evidence_id = ctx.payload.value("evidence_id", std::string());
    std::string address;
    if (ctx.payload.contains("address"))
    {
        auto ea = payload_location(ctx.payload, "address");
        if (ea)
            address = fmt_ea(*ea);
        else if (ctx.payload["address"].is_string())
            address = ctx.payload["address"].get<std::string>();
    }
    if (!report_id.empty())
    {
        auto rec = get_report_record(report_id);
        if (!rec)
            return error_envelope(ctx, "job_not_found", "report_id was not found", {{"report_id", report_id}});
        json found;
        if (!json_contains_evidence(rec->report, evidence_id, address, found))
            return error_envelope(ctx, "bad_param", "evidence was not found in report", {{"report_id", report_id}, {"evidence_id", evidence_id}, {"address", address}});
        return ok_envelope(ctx, {{"evidence", found}, {"report_id", report_id}});
    }
    if (!address.empty())
    {
        json d;
        auto ea = agent_tools::helpers::parse_address(address);
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"address", address}});
        d["address"] = fmt_ea(*ea);
        func_t* fn = get_func(*ea);
        d["function"] = fn ? function_json(fn, true) : json(nullptr);
        json xp = {{"address", fmt_ea(*ea)}, {"direction", "both"}, {"kind", "all"}};
        request_ctx_t nested = ctx;
        nested.operation = "xrefs";
        nested.payload = xp;
        d["xrefs"] = json::object();
        xrefblk_t xb;
        json to = json::array();
        for (bool ok = xb.first_to(*ea, XREF_ALL); ok; ok = xb.next_to())
            to.push_back({{"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        json from = json::array();
        for (bool ok = xb.first_from(*ea, XREF_ALL); ok; ok = xb.next_from())
            from.push_back({{"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        d["xrefs"]["to"] = to;
        d["xrefs"]["from"] = from;
        return ok_envelope(ctx, d);
    }
    return error_envelope(ctx, "bad_param", "report_id/job_id plus evidence_id, or address, is required");
}

agent_tools::tool_result_t handle_chain_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_chain_manage", params, chain_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, chain_ops()));
    if (ctx.operation == "validate_spec")
        return ok_envelope(ctx, chain_validation_data(ctx.payload["chain"]));
    if (ctx.operation == "status")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        if (!job_id.empty())
        {
            auto job = get_job(job_id);
            if (!job)
                return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
            return ok_envelope(ctx, {{"job", job_to_json(*job)}, {"result_available", !job->result.is_null() && !job->result.empty()}}, job_to_json(*job));
        }
        return ok_envelope(ctx, {{"engine", verify::engine().verdict_summary()}});
    }
    if (ctx.operation == "cancel")
    {
        verify::engine().cancel();
        const std::string job_id = ctx.payload.value("job_id", std::string());
        if (!job_id.empty())
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            auto it = s.jobs.find(job_id);
            if (it == s.jobs.end())
                return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
            it->second.state = "cancelled";
            it->second.updated_at_ms = now_ms();
            it->second.events.push_back({{"ts_ms", it->second.updated_at_ms}, {"state", "cancelled"}});
            return ok_envelope(ctx, {{"cancelled", true}, {"job", job_to_json(it->second)}}, job_to_json(it->second));
        }
        return ok_envelope(ctx, {{"cancelled", true}, {"in_flight_count", verify::engine().in_flight_count()}});
    }
    if (ctx.operation == "verify_link")
    {
        const std::string job_id = create_job(ctx);
        agent_tools::tool_result_t link_failure;
        json d = verify_link_data(ctx.payload, link_failure, ctx);
        if (!link_failure.output.empty() || !link_failure.data.is_null())
        {
            finish_job(job_id, "failed", link_failure.data, std::string(), "bad_param", link_failure.output);
            return link_failure;
        }
        finish_job(job_id, "completed", d);
        auto job = get_job(job_id);
        return ok_envelope(ctx, d, job ? job_to_json(*job) : json());
    }
    if (ctx.operation == "boundary_match")
        return ok_envelope(ctx, boundary_match_data(ctx.payload));
    if (ctx.operation == "trigger_confirm")
        return ok_envelope(ctx, trigger_confirm_data(ctx.payload));
    if (ctx.operation == "submit" || ctx.operation == "start")
    {
        const std::string job_id = create_job(ctx);
        json report = build_chain_report(ctx, job_id);
        const std::string chain_id = report.value("chain_id", std::string("chain:" + ctx.request_id));
        const std::string report_id = store_report(job_id, chain_id, report);
        auto rec = get_report_record(report_id);
        if (rec)
        {
            rec->report["report_id"] = report_id;
            {
                auto& s = state();
                std::lock_guard<std::mutex> lock(s.mutex);
                auto it = s.reports.find(report_id);
                if (it != s.reports.end())
                {
                    it->second.report["report_id"] = report_id;
                    it->second.content_hash = hash_text(it->second.report.dump());
                }
            }
        }
        json data = get_report_record(report_id)->report;
        finish_job(job_id, "completed", data, report_id);
        auto job = get_job(job_id);
        auto fresh = get_report_record(report_id);
        json resources = fresh ? json::array({resource_for_report(*fresh, "json"), resource_for_report(*fresh, "markdown"), resource_for_report(*fresh, "sarif")}) : json::array();
        return ok_envelope(ctx, {{"report_id", report_id}, {"report", data}}, job ? job_to_json(*job) : json(), json(), json::array(), resources);
    }
    if (ctx.operation == "resume")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id);
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        if (!job->request.contains("payload"))
            return error_envelope(ctx, "job_conflict", "job has no resumable payload", {{"job_id", job_id}});
        json p;
        p["operation"] = "submit";
        p["request_id"] = ctx.request_id;
        p["payload"] = job->request["payload"];
        p["budget"] = job->request.value("budget", json::object());
        return handle_chain_manage(p);
    }
    if (ctx.operation == "export")
        return handle_report_fetch_like(ctx, false, true);
    if (ctx.operation == "get_report")
        return handle_report_fetch_like(ctx, false);
    if (ctx.operation == "evidence_fetch")
        return handle_evidence_fetch(ctx);
    if (ctx.operation == "explain_failure")
        return handle_report_fetch_like(ctx, true);
    if (ctx.operation == "list")
    {
        json arr = json::array();
        const std::string verdict = ctx.payload.value("verdict", std::string());
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.reports)
            {
                const auto& r = kv.second;
                const std::string rv = r.report.value("verdict", std::string("inconclusive"));
                if (!verdict.empty() && rv != verdict)
                    continue;
                arr.push_back({{"report_id", r.report_id}, {"job_id", r.job_id}, {"chain_id", r.chain_id}, {"created_at_ms", r.created_at_ms}, {"verdict", rv}, {"content_hash", r.content_hash}});
            }
        }
        json page;
        json rows = page_vector(ctx, "list", arr, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        json data;
        data["reports"] = rows;
        if (ctx.payload.value("include_jobs", false))
        {
            data["jobs"] = json::array();
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.jobs)
                data["jobs"].push_back(job_to_json(kv.second));
        }
        return ok_envelope(ctx, data, json(), page);
    }
    if (ctx.operation == "diagnostics")
    {
        json d;
        d["engine"] = verify::engine().verdict_summary();
        d["in_flight_count"] = verify::engine().in_flight_count();
        d["auto_analysis_ok"] = auto_is_ok();
        d["modal_safety"] = {{"new_manage_tools_modal_waitbox_api", false}, {"new_manage_tools_ui_cancel_api", false}};
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            d["job_count"] = s.jobs.size();
            d["report_count"] = s.reports.size();
            d["index_count"] = s.indices.size();
        }
        return ok_envelope(ctx, d);
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_project_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_project_manage", params, project_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    auto project_result = [&](const aida::multibinary::project_io_result_t& r) -> agent_tools::tool_result_t {
        if (r.ok)
            return ok_envelope(ctx, r.data);
        return error_envelope(ctx, r.error_code.empty() ? "project_error" : r.error_code,
                              r.error_message.empty() ? "project operation failed" : r.error_message,
                              r.data);
    };
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, project_ops()));
    if (ctx.operation == "inventory_current")
    {
        const int max_rows = int_param(ctx.payload, "max_rows", 256, 1, 100000);
        json inv = aida::multibinary::current_idb_inventory(ctx.payload.value("include_segments", true),
                                                            ctx.payload.value("include_imports", true),
                                                            ctx.payload.value("include_entries", true),
                                                            static_cast<std::size_t>(max_rows));
        return ok_envelope(ctx, inv);
    }
    if (ctx.operation == "inventory_all")
    {
        const int max_rows = int_param(ctx.payload, "max_rows", 256, 1, 100000);
        json local = aida::multibinary::current_idb_inventory(ctx.payload.value("include_segments", true),
                                                             ctx.payload.value("include_imports", true),
                                                             ctx.payload.value("include_entries", true),
                                                             static_cast<std::size_t>(max_rows));
        json supplied = json::object();
        if (ctx.payload.contains("fanout_result"))
            supplied["fanout_result"] = ctx.payload["fanout_result"];
        if (ctx.payload.contains("inventories"))
            supplied["inventories"] = ctx.payload["inventories"];
        json d;
        d["local"] = local;
        d["merged"] = aida::multibinary::merge_inventory_documents(local, supplied);
        std::set<std::string> supplied_instances;
        std::function<void(const json&)> collect_instance_ids = [&](const json& node) {
            if (node.is_object())
            {
                if (node.contains("instance") && node["instance"].is_object())
                {
                    const std::string id = node["instance"].contains("instance_id") && node["instance"]["instance_id"].is_string()
                        ? node["instance"]["instance_id"].get<std::string>()
                        : std::string();
                    if (!id.empty())
                        supplied_instances.insert(id);
                }
                const std::string direct = node.contains("instance_id") && node["instance_id"].is_string()
                    ? node["instance_id"].get<std::string>()
                    : std::string();
                if (!direct.empty())
                    supplied_instances.insert(direct);
                for (auto it = node.begin(); it != node.end(); ++it)
                    collect_instance_ids(it.value());
            }
            else if (node.is_array())
            {
                for (const json& item : node)
                    collect_instance_ids(item);
            }
        };
        collect_instance_ids(local);
        collect_instance_ids(supplied);
        d["peer_data_gaps"] = json::array();
        agent_tools::tool_result_t live_instances = invoke_registered("list_ida_instances", json::object());
        if (live_instances.success && live_instances.data.contains("instances") && live_instances.data["instances"].is_array())
        {
            for (const json& inst : live_instances.data["instances"])
            {
                const std::string id = inst.value("instance_id", std::string());
                if (id.empty() || supplied_instances.find(id) != supplied_instances.end())
                    continue;
                d["peer_data_gaps"].push_back({{"kind", "peer_data_missing"}, {"instance", inst}, {"reason", "query_all_instances inventory result was not supplied to ida_project_manage"}});
            }
        }
        else if (!live_instances.success)
        {
            d["peer_data_gaps"].push_back({{"kind", "peer_registry_unavailable"}, {"error_code", live_instances.error_code}, {"message", live_instances.output}});
        }
        d["fanout"] = {
            {"tool", "query_all_instances"},
            {"arguments", {{"tool", "ida_project_manage"}, {"arguments", {{"operation", "inventory_current"}, {"payload", ctx.payload}}}}},
            {"reason", "query_all_instances owns network peer routing; pass its result back as payload.fanout_result to merge and persist without self-deadlock"}
        };
        d["instances_routing_compatible"] = true;
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "list")
        return project_result(aida::multibinary::list_projects());
    if (ctx.operation == "load")
        return project_result(aida::multibinary::load_project_modules(ctx.payload.value("project_id", std::string())));
    if (ctx.operation == "save")
    {
        if (ctx.payload.contains("modules") && ctx.payload["modules"].is_array())
            return project_result(aida::multibinary::save_or_update_project(ctx.payload.value("project_id", std::string()),
                                                                            ctx.payload["modules"],
                                                                            ctx.payload));
        const int max_rows = int_param(ctx.payload, "max_rows", 100000, 1, 1000000);
        json local = aida::multibinary::current_idb_inventory(true, true, true, static_cast<std::size_t>(max_rows));
        return project_result(aida::multibinary::bind_current_inventory_to_project(ctx.payload.value("project_id", std::string()),
                                                                                  local,
                                                                                  ctx.payload,
                                                                                  ctx.payload));
    }
    if (ctx.operation == "delete")
    {
        if (!ctx.payload.value("confirm_destructive", false) || ctx.payload.value("reason", std::string()).empty())
            return error_envelope(ctx, "destructive_denied", "delete requires confirm_destructive=true and a non-empty reason");
        return project_result(aida::multibinary::delete_project(ctx.payload.value("project_id", std::string())));
    }
    if (ctx.operation == "status")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::index_status(project_id));
    }
    if (ctx.operation == "corpus_snapshot")
    {
        const std::string project_id = ctx.payload.value("project_id", std::string());
        if (!project_id.empty())
            return project_result(aida::multibinary::load_project_manifest(project_id));
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        json d = s.corpus_manifest.empty() ? json::object({{"corpus_id", "current"}, {"modules", json::array({module_identity()})}, {"generation", generation_id()}}) : s.corpus_manifest;
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "corpus_bind")
    {
        const int max_rows = int_param(ctx.payload, "max_rows", 100000, 1, 1000000);
        aida::multibinary::project_io_result_t saved = ctx.payload.contains("modules") && ctx.payload["modules"].is_array()
            ? aida::multibinary::save_or_update_project(ctx.payload.value("project_id", ctx.payload.value("corpus_id", std::string())),
                                                        ctx.payload["modules"],
                                                        ctx.payload)
            : aida::multibinary::bind_current_inventory_to_project(ctx.payload.value("project_id", ctx.payload.value("corpus_id", std::string())),
                                                                   aida::multibinary::current_idb_inventory(true, true, true, static_cast<std::size_t>(max_rows)),
                                                                   ctx.payload,
                                                                   ctx.payload);
        if (!saved.ok)
            return project_result(saved);
        auto loaded = aida::multibinary::load_project_manifest(saved.data.value("project_id", ctx.payload.value("project_id", std::string())));
        auto& s = state();
        {
            std::lock_guard<std::mutex> lock(s.mutex);
            s.corpus_manifest = loaded.ok ? loaded.data["manifest"] : saved.data;
        }
        return ok_envelope(ctx, saved.data);
    }
    if (ctx.operation == "corpus_export")
    {
        const std::string project_id = ctx.payload.value("project_id", std::string());
        if (!project_id.empty())
        {
            auto loaded = aida::multibinary::load_project_manifest(project_id);
            if (!loaded.ok)
                return project_result(loaded);
            return ok_envelope(ctx, {{"format", "json"}, {"manifest", loaded.data["manifest"]}, {"content_hash", aida::multibinary::content_hash_summary(loaded.data["manifest"])}});
        }
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        json manifest = s.corpus_manifest.empty() ? json::object({{"corpus_id", "current"}, {"modules", json::array({module_identity()})}, {"generation", generation_id()}}) : s.corpus_manifest;
        return ok_envelope(ctx, {{"format", "json"}, {"manifest", manifest}, {"content_hash", hash_text(manifest.dump())}});
    }
    if (ctx.operation == "index_build")
    {
        const std::string job_id = create_job(ctx);
        json indices = ctx.payload.contains("indices") && ctx.payload["indices"].is_array() ? ctx.payload["indices"] : json::array({"functions", "segments", "imports", "entries", "verifier"});
        aida::multibinary::index_build_options_t options = aida::multibinary::index_options_from_json(ctx.payload);
        options.force = ctx.payload.value("force", options.force);
        aida::multibinary::project_io_result_t built = aida::multibinary::build_current_module_index(ctx.payload.value("project_id", std::string()), indices, options);
        if (!built.ok)
        {
            finish_job(job_id, "failed", built.data, std::string(), built.error_code, built.error_message);
            return project_result(built);
        }
        json result = built.data;
        finish_job(job_id, "completed", result);
        auto job = get_job(job_id);
        return ok_envelope(ctx, result, job ? job_to_json(*job) : json());
    }
    if (ctx.operation == "index_status")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::index_status(project_id));
    }
    if (ctx.operation == "index_page_status")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::index_page_status(project_id, ctx.payload.value("module_id", std::string())));
    }
    if (ctx.operation == "index_page")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        const std::size_t page_index = static_cast<std::size_t>(int_param(ctx.payload, "page_index", 0, 0, 1000000000));
        return project_result(aida::multibinary::load_index_page(project_id,
                                                                 ctx.payload.value("module_id", std::string()),
                                                                 ctx.payload.value("family", std::string()),
                                                                 ctx.payload.value("cursor", std::string()),
                                                                 page_index));
    }
    if (ctx.operation == "resolve_cross_edges")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::resolve_project_cross_edges(project_id));
    }
    if (ctx.operation == "resolve_reference")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::resolve_project_reference(project_id, ctx.payload.value("reference", json::object())));
    }
    if (ctx.operation == "verify_chain")
    {
        const std::string project_id = ctx.payload.value("project_id", std::string());
        return project_result(aida::vuln::chain_verifier::verify_project_chain(project_id,
                                                                               ctx.payload.value("chain", json::object()),
                                                                               ctx.payload.value("options", json::object())));
    }
    if (ctx.operation == "case_study_regressions")
    {
        const std::string project_id = ctx.payload.value("project_id", std::string());
        return project_result(aida::vuln::chain_verifier::run_case_study_regressions(project_id, ctx.payload));
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

std::vector<std::string> strings_from_array_field(const json& payload, const char* key)
{
    std::vector<std::string> out;
    if (!payload.contains(key) || !payload[key].is_array())
        return out;
    for (const auto& item : payload[key])
    {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
    return out;
}

bool contains_string(const std::vector<std::string>& values, const std::string& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

aida::vuln::chain::extraction_options_t extraction_options_from_ctx(const request_ctx_t& ctx)
{
    aida::vuln::chain::extraction_options_t options;
    const std::vector<std::string> layers = strings_from_array_field(ctx.payload, "layers");
    if (!layers.empty())
    {
        options.include_bytes = contains_string(layers, "raw") || contains_string(layers, "bytes") || contains_string(layers, "instructions") || contains_string(layers, "assembly");
        options.include_xrefs = contains_string(layers, "raw") || contains_string(layers, "xrefs") || contains_string(layers, "xref_graph");
        options.include_xref_indexes = contains_string(layers, "xrefs") || contains_string(layers, "xref_graph");
        options.include_types = contains_string(layers, "types") || contains_string(layers, "type");
        options.include_ctree = contains_string(layers, "ctree") || contains_string(layers, "decompiler") || contains_string(layers, "hexrays");
        options.include_microcode = contains_string(layers, "microcode");
        options.include_effects = contains_string(layers, "effects") || contains_string(layers, "side_effects");
    }
    options.force_refresh = ctx.payload.value("force_refresh", false);
    options.max_instructions = static_cast<std::size_t>(int_param(ctx.payload, "max_instructions", static_cast<int>(options.max_instructions), 1, 200000));
    options.max_basic_blocks = static_cast<std::size_t>(int_param(ctx.payload, "max_basic_blocks", static_cast<int>(options.max_basic_blocks), 1, 50000));
    options.max_xrefs_per_address = static_cast<std::size_t>(int_param(ctx.payload, "max_xrefs_per_address", static_cast<int>(options.max_xrefs_per_address), 1, 10000));
    options.max_ctree_nodes = static_cast<std::size_t>(int_param(ctx.payload, "max_ctree_nodes", static_cast<int>(options.max_ctree_nodes), 1, 200000));
    options.max_microcode_instructions = static_cast<std::size_t>(int_param(ctx.payload, "max_microcode_instructions", static_cast<int>(options.max_microcode_instructions), 1, 200000));
    options.max_pseudocode_lines = static_cast<std::size_t>(int_param(ctx.payload, "max_pseudocode_lines", static_cast<int>(options.max_pseudocode_lines), 1, 50000));
    options.max_batch_functions = static_cast<std::size_t>(int_param(ctx.payload, "max_functions", static_cast<int>(options.max_batch_functions), 1, 20000));
    options.max_module_items = static_cast<std::size_t>(int_param(ctx.payload, "max_module_items", static_cast<int>(options.max_module_items), 1, 1000000));
    if (ctx.payload.contains("timeout_ms") || ctx.budget.contains("timeout_ms"))
        options.timeout_ms = static_cast<std::uint64_t>(int_param(ctx.payload.contains("timeout_ms") ? ctx.payload : ctx.budget, "timeout_ms", 0, 0, 600000));
    std::vector<std::string> maturities = strings_from_array_field(ctx.payload, "maturities");
    if (!maturities.empty())
        options.microcode_maturities = maturities;
    return options;
}

std::vector<ea_t> function_locations_from_payload(const json& payload)
{
    std::vector<ea_t> out;
    if (!payload.contains("functions") || !payload["functions"].is_array())
        return out;
    for (const auto& item : payload["functions"])
    {
        std::optional<ea_t> ea;
        if (item.is_object() && item.contains("address"))
            ea = parse_location(item["address"]);
        else
            ea = parse_location(item);
        if (ea)
            out.push_back(*ea);
    }
    return out;
}

struct function_start_page_t
{
    std::vector<ea_t> starts;
    json page = json::object();
    bool cursor_ok = true;
};

function_start_page_t function_start_page(const request_ctx_t& ctx, std::size_t max_functions)
{
    struct request_t : public exec_request_t
    {
        request_ctx_t ctx;
        std::size_t max_functions = 0;
        function_start_page_t result;
        request_t(const request_ctx_t& c, std::size_t m) : ctx(c), max_functions(m) {}
        ssize_t idaapi execute() override
        {
            size_t offset = 0;
            if (!parse_cursor(ctx.cursor, "extract_function_batch", generation_id(), offset))
            {
                result.cursor_ok = false;
                return 1;
            }
            const std::size_t qty = get_func_qty();
            const std::size_t limit = std::min<std::size_t>(static_cast<std::size_t>(ctx.limit), max_functions);
            const std::size_t end = std::min(qty, offset + limit);
            for (std::size_t i = offset; i < end; ++i)
            {
                func_t* fn = getn_func(i);
                if (fn != nullptr)
                    result.starts.push_back(fn->start_ea);
            }
            const bool truncated = end < qty;
            const std::string next = truncated ? cursor_for("extract_function_batch", generation_id(), end) : std::string();
            result.page = page_json(ctx.cursor, next, static_cast<int>(limit), result.starts.size(), truncated);
            return 1;
        }
    };
    request_t req(ctx, max_functions);
    if (execute_sync(req, MFF_READ) <= 0)
    {
        req.result.cursor_ok = false;
        return req.result;
    }
    return req.result;
}

aida::vuln::chain::path_trace_options_t path_options_from_ctx(const request_ctx_t& ctx)
{
    aida::vuln::chain::path_trace_options_t options;
    options.max_blocks = static_cast<std::size_t>(int_param(ctx.payload, "max_blocks", static_cast<int>(options.max_blocks), 1, 50000));
    options.max_steps = static_cast<std::size_t>(int_param(ctx.payload, "max_steps", static_cast<int>(options.max_steps), 1, 200000));
    options.max_unresolved_edges = static_cast<std::size_t>(int_param(ctx.payload, "max_unresolved_edges", static_cast<int>(options.max_unresolved_edges), 1, 50000));
    return options;
}

json resolver_modules_from_ctx(const request_ctx_t& ctx, const json& current_module = json())
{
    json modules = json::array();
    std::unordered_set<std::string> seen;
    auto module_id_of = [](const json& module) {
        if (module.contains("identity") && module["identity"].is_object())
            return module["identity"].value("module_id", module["identity"].value("corpus_id", std::string()));
        if (module.contains("module") && module["module"].is_object())
            return module["module"].value("module_id", module["module"].value("corpus_id", std::string()));
        return module.value("module_id", module.value("corpus_id", std::string()));
    };
    auto append = [&](const json& module) {
        if (!module.is_object())
            return;
        const std::string id = module_id_of(module);
        const std::string key = id.empty() ? hash_text(module.dump()) : id;
        if (!seen.insert(key).second)
            return;
        modules.push_back(module);
    };
    if (!current_module.is_null() && !current_module.empty())
        append(current_module);
    if (ctx.payload.contains("modules") && ctx.payload["modules"].is_array())
    {
        for (const json& module : ctx.payload["modules"])
            append(module);
    }
    if (modules.empty() || ctx.payload.value("include_current_module", true))
    {
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        options.include_bytes = false;
        options.include_types = false;
        options.include_ctree = false;
        options.include_microcode = false;
        options.include_effects = false;
        options.include_xrefs = true;
        options.include_xref_indexes = true;
        append(aida::vuln::chain::to_json(aida::vuln::chain::extract_module_snapshot(options)));
    }
    return modules;
}

bool target_reference_matches(const json& target_ref, const json& resolved)
{
    if (!target_ref.is_object() || !resolved.is_object() || !resolved.value("resolved", false))
        return false;
    const json target = resolved.value("target", json::object());
    std::string wanted_module = target_ref.value("module_id", target_ref.value("corpus_id", std::string()));
    if (wanted_module.empty() && target_ref.contains("module") && target_ref["module"].is_object())
        wanted_module = target_ref["module"].value("module_id", target_ref["module"].value("corpus_id", std::string()));
    std::string got_module = target.value("module_id", target.value("corpus_id", std::string()));
    if (got_module.empty() && target.contains("module") && target["module"].is_object())
        got_module = target["module"].value("module_id", target["module"].value("corpus_id", std::string()));
    const bool wanted_has_rva = target_ref.contains("rva") && !target_ref["rva"].is_null()
        && (!target_ref["rva"].is_string() || !target_ref["rva"].get<std::string>().empty());
    const bool got_has_rva = target.contains("rva") && !target["rva"].is_null()
        && (!target["rva"].is_string() || !target["rva"].get<std::string>().empty());
    if (!wanted_module.empty() && !got_module.empty() && wanted_module != got_module)
        return false;
    if (wanted_has_rva && got_has_rva)
    {
        auto wanted_rva = agent_tools::helpers::parse_address(scalar_to_string(target_ref["rva"]));
        auto got_rva = agent_tools::helpers::parse_address(scalar_to_string(target["rva"]));
        if (wanted_rva && got_rva && *wanted_rva != *got_rva)
            return false;
    }
    std::string wanted_symbol = target_ref.value("symbol", target_ref.value("name", std::string()));
    std::string got_symbol = target.value("symbol", target.value("name", std::string()));
    if (!wanted_symbol.empty() && !got_symbol.empty() && lowercase_ascii(wanted_symbol) != lowercase_ascii(got_symbol))
        return false;
    return !wanted_module.empty() || wanted_has_rva || !wanted_symbol.empty();
}

json cross_reachability_data(const request_ctx_t& ctx,
                             ea_t entry_ea,
                             const std::optional<ea_t>& local_target,
                             const json& target_ref,
                             const json& resolver_modules)
{
    json out;
    out["schema"] = "aida_chain_cross_reachability_v1";
    out["entry"] = fmt_ea(entry_ea);
    out["target"] = target_ref.is_null() ? json(nullptr) : target_ref;
    out["verdict"] = "incomplete";
    out["reached"] = false;
    out["negative_evidence_complete"] = false;
    out["visited_functions"] = json::array();
    out["visited_modules"] = json::array();
    out["traversed_edges"] = json::array();
    out["unresolved_edges"] = json::array();
    out["cross_binary_resolutions"] = json::array();
    out["cutoff_reason"] = nullptr;
    func_t* entry_fn = get_func(entry_ea);
    if (entry_fn == nullptr)
    {
        out["cutoff_reason"] = "entry_not_in_function";
        return out;
    }
    ea_t target_fn_ea = BADADDR;
    if (local_target)
    {
        func_t* tf = get_func(*local_target);
        target_fn_ea = tf != nullptr ? tf->start_ea : *local_target;
    }
    const std::uint64_t start = now_ms();
    const int max_depth = int_param(ctx.payload, "max_depth", 8, 1, 128);
    const int max_functions = int_param(ctx.payload, "max_functions", 1024, 1, 100000);
    struct node_t
    {
        ea_t fn = BADADDR;
        int depth = 0;
        std::vector<ea_t> path;
    };
    std::deque<node_t> queue;
    std::set<ea_t> seen;
    queue.push_back({entry_fn->start_ea, 0, {entry_fn->start_ea}});
    seen.insert(entry_fn->start_ea);
    bool unresolved = false;
    bool cutoff = false;
    while (!queue.empty())
    {
        if (seen.size() > static_cast<size_t>(max_functions))
        {
            cutoff = true;
            out["cutoff_reason"] = "function_budget_exhausted";
            break;
        }
        if (ctx.budget.contains("timeout_ms") && now_ms() - start >= static_cast<std::uint64_t>(int_param(ctx.budget, "timeout_ms", 0, 0, 600000)))
        {
            cutoff = true;
            out["cutoff_reason"] = "timeout";
            break;
        }
        if (user_cancelled())
        {
            cutoff = true;
            out["cutoff_reason"] = "cancelled";
            break;
        }
        node_t cur = queue.front();
        queue.pop_front();
        out["visited_functions"].push_back(fmt_ea(cur.fn));
        if (cur.fn == target_fn_ea)
        {
            out["verdict"] = "confirmed";
            out["reached"] = true;
            out["path"] = json::array();
            for (ea_t step : cur.path)
                out["path"].push_back(fmt_ea(step));
            return out;
        }
        if (cur.depth >= max_depth)
        {
            cutoff = true;
            out["cutoff_reason"] = "depth_budget_exhausted";
            continue;
        }
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        options.include_bytes = false;
        options.include_types = false;
        options.include_ctree = false;
        options.include_microcode = false;
        options.include_effects = false;
        options.include_xrefs = true;
        options.include_xref_indexes = true;
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(cur.fn, options);
        const std::string module_id = snapshot.identity.start.module.module_id;
        if (!module_id.empty())
            out["visited_modules"].push_back(module_id);
        for (const auto& call : snapshot.calls)
        {
            json edge;
            edge["from_function"] = fmt_ea(cur.fn);
            edge["callsite"] = aida::vuln::chain::to_json(call.callsite);
            edge["kind"] = call.kind;
            edge["callee_name"] = call.callee_name;
            edge["resolution_quality"] = call.resolution_quality;
            if (!call.resolved || call.kind == "indirect")
            {
                unresolved = true;
                out["unresolved_edges"].push_back(edge);
                continue;
            }
            edge["target"] = aida::vuln::chain::to_json(call.target);
            out["traversed_edges"].push_back(edge);
            if (local_target && call.target.ea == static_cast<std::uint64_t>(*local_target))
            {
                out["verdict"] = "confirmed";
                out["reached"] = true;
                out["path"] = json::array();
                for (ea_t step : cur.path)
                    out["path"].push_back(fmt_ea(step));
                out["path"].push_back(fmt_ea(static_cast<ea_t>(call.target.ea)));
                return out;
            }
            json ref;
            ref["address"] = aida::vuln::chain::to_json(call.target);
            ref["symbol"] = call.callee_name;
            json resolved = aida::vuln::chain::resolve_cross_binary_reference(resolver_modules, ref);
            out["cross_binary_resolutions"].push_back(resolved);
            if (target_reference_matches(target_ref, resolved))
            {
                out["verdict"] = "confirmed";
                out["reached"] = true;
                out["path"] = json::array();
                for (ea_t step : cur.path)
                    out["path"].push_back(fmt_ea(step));
                out["path"].push_back(resolved["target"]);
                return out;
            }
            func_t* callee = get_func(static_cast<ea_t>(call.target.ea));
            if (callee == nullptr)
                continue;
            if (!seen.insert(callee->start_ea).second)
                continue;
            std::vector<ea_t> next_path = cur.path;
            next_path.push_back(callee->start_ea);
            queue.push_back({callee->start_ea, cur.depth + 1, std::move(next_path)});
        }
    }
    if (!cutoff && !unresolved)
    {
        out["verdict"] = "refuted";
        out["negative_evidence_complete"] = true;
        out["cutoff_reason"] = nullptr;
    }
    else
    {
        out["verdict"] = "incomplete";
        if (out["cutoff_reason"].is_null())
            out["cutoff_reason"] = unresolved ? "unresolved_indirect_or_external_edges" : "frontier_incomplete";
    }
    out["visited_function_count"] = seen.size();
    return out;
}

json xref_graph_data(const request_ctx_t& ctx, const aida::vuln::chain::function_snapshot_t& snapshot, std::optional<ea_t> target)
{
    json data;
    data["function"] = aida::vuln::chain::to_json(snapshot.identity);
    data["xref_from_index"] = snapshot.xref_from_index;
    data["xref_to_index"] = snapshot.xref_to_index;
    data["calls"] = json::array();
    for (const auto& call : snapshot.calls)
        data["calls"].push_back(aida::vuln::chain::to_json(call));
    data["branches"] = json::array();
    for (const auto& branch : snapshot.branches)
        data["branches"].push_back(aida::vuln::chain::to_json(branch));
    data["reachable_evidence"] = json::object();
    if (target)
    {
        aida::vuln::chain::path_trace_t trace = aida::vuln::chain::trace_path_corridor(snapshot, snapshot.identity.start.ea, static_cast<std::uint64_t>(*target), path_options_from_ctx(ctx));
        data["reachable_evidence"] = aida::vuln::chain::to_json(trace);
        data["reachable_evidence"]["negative_evidence_complete"] = !trace.reached && trace.complete;
    }
    json modules = resolver_modules_from_ctx(ctx);
    data["corpus_reachability"] = cross_reachability_data(ctx,
                                                         static_cast<ea_t>(snapshot.identity.start.ea),
                                                         target,
                                                         ctx.payload.value("target", json(nullptr)),
                                                         modules);
    data["resolver_index"] = aida::vuln::chain::build_cross_binary_resolver_index(modules);
    return data;
}

bool json_text_contains(const json& value, const std::vector<std::string>& needles)
{
    const std::string text = lowercase_ascii(value.dump());
    for (const std::string& needle : needles)
    {
        if (text.find(lowercase_ascii(needle)) != std::string::npos)
            return true;
    }
    return false;
}

json zero_vs_copy_check(const aida::vuln::chain::function_snapshot_t& snapshot)
{
    json out;
    out["case_id"] = "ntfs_etw_zero_vs_copy";
    out["status"] = "unproven";
    out["evidence"] = json::array();
    bool zero_write = false;
    bool copied_write = false;
    for (const auto& effect : snapshot.effects)
    {
        const std::string kind = effect.value("kind", std::string());
        const json source = effect.value("source", json::object());
        const std::string origin = source.value("value_origin", std::string());
        if ((kind == "memory_set" || kind == "write") && origin == "constant_zero")
        {
            zero_write = true;
            out["evidence"].push_back(effect);
        }
        if ((kind == "memory_copy" || kind == "write") && (origin == "copied_from_memory" || origin == "copied_from_input"))
        {
            copied_write = true;
            out["evidence"].push_back(effect);
        }
    }
    out["zero_write_present"] = zero_write;
    out["copied_write_present"] = copied_write;
    if (zero_write && copied_write)
        out["status"] = "passed";
    else
        out["reason"] = "function_facts_do_not_contain_both_constant_zero_and_copied_write_sources";
    return out;
}

json afd_list_entry_guard_check(const aida::vuln::chain::function_snapshot_t& snapshot)
{
    json out;
    out["case_id"] = "afd_list_entry_guard";
    out["status"] = "unproven";
    out["evidence"] = json::array();
    bool has_48 = false;
    bool has_50 = false;
    bool has_branch = false;
    bool has_later_indirect_call = false;
    std::uint64_t first_branch = 0;
    for (const auto& branch : snapshot.branches)
    {
        const json bj = aida::vuln::chain::to_json(branch);
        if (json_text_contains(bj, {"0x48", "+48", " 48h", "list_entry", "flink", "blink"}))
            has_48 = true;
        if (json_text_contains(bj, {"0x50", "+50", " 50h", "list_entry", "flink", "blink"}))
            has_50 = true;
        if (json_text_contains(bj, {"0x48", "+48", "0x50", "+50", "list_entry", "flink", "blink"}))
        {
            has_branch = true;
            if (first_branch == 0)
                first_branch = branch.branch.ea;
            out["evidence"].push_back(bj);
        }
    }
    for (const auto& ins : snapshot.instructions)
    {
        if (!ins.is_indirect || !ins.is_call)
            continue;
        if (first_branch == 0 || ins.location.ea > first_branch)
        {
            has_later_indirect_call = true;
            out["evidence"].push_back(aida::vuln::chain::to_json(ins));
            break;
        }
    }
    if (json_text_contains(snapshot.ctree.memory_facts, {"0x48", "+48", " 48h"}))
        has_48 = true;
    if (json_text_contains(snapshot.ctree.memory_facts, {"0x50", "+50", " 50h"}))
        has_50 = true;
    out["offset_0x48_present"] = has_48;
    out["offset_0x50_present"] = has_50;
    out["branch_before_indirect_call_present"] = has_branch && has_later_indirect_call;
    if (has_48 && has_50 && has_branch && has_later_indirect_call)
        out["status"] = "passed";
    else
        out["reason"] = "source_facts_do_not_prove_list_entry_offsets_and_guard_before_indirect_call";
    return out;
}

json pvscan0_self_reference_check(const aida::vuln::chain::function_snapshot_t& snapshot)
{
    json out;
    out["case_id"] = "pvscan0_self_reference";
    out["status"] = "unproven";
    out["evidence"] = json::array();
    bool found = false;
    bool preserves_destination_and_source = false;
    for (const auto& effect : snapshot.effects)
    {
        const std::string kind = effect.value("kind", std::string());
        const std::string operation = lowercase_ascii(effect.value("operation", std::string()));
        if (operation.find("setbitmapbits") == std::string::npos && !json_text_contains(effect.value("tags", json::array()), {"pvscan0"}))
            continue;
        found = true;
        const json destination = effect.value("destination", json::object());
        const json source = effect.value("source", json::object());
        if (!destination.value("text", std::string()).empty() && (!source.value("text", std::string()).empty() || source.value("controlled_by_input", false)))
            preserves_destination_and_source = true;
        if (kind == "memory_set" || kind == "memory_copy" || kind == "write")
            out["evidence"].push_back(effect);
    }
    out["setbitmapbits_effect_present"] = found;
    out["destination_and_source_preserved"] = preserves_destination_and_source;
    if (found && preserves_destination_and_source)
        out["status"] = "passed";
    else
        out["reason"] = "source_facts_do_not_preserve_setbitmapbits_destination_and_source_expressions";
    return out;
}

json etw_trigger_negative_check(const request_ctx_t& ctx, const json& resolver_modules)
{
    json out;
    out["case_id"] = "etw_trigger_negative";
    out["status"] = "unproven";
    auto entry = payload_location(ctx.payload, "entry");
    std::optional<ea_t> target = payload_location(ctx.payload, "target");
    if (!entry || (!target && !ctx.payload.contains("target")))
    {
        out["reason"] = "entry_and_target_are_required_for_trigger_negative_evidence";
        return out;
    }
    json reach = cross_reachability_data(ctx, *entry, target, ctx.payload.value("target", json(nullptr)), resolver_modules);
    out["evidence"] = reach;
    if (reach.value("negative_evidence_complete", false))
        out["status"] = "passed";
    else
        out["reason"] = reach.value("cutoff_reason", std::string("target_reached_or_evidence_incomplete"));
    return out;
}

json case_study_self_check_data(const request_ctx_t& ctx)
{
    json out;
    out["schema"] = "aida_chain_case_study_self_check_v1";
    out["overall"] = "unproven";
    out["checks"] = json::array();
    const std::string case_id = ctx.payload.value("case_id", std::string("all"));
    aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
    options.include_bytes = true;
    options.include_xrefs = true;
    options.include_xref_indexes = true;
    options.include_types = true;
    options.include_ctree = true;
    options.include_microcode = false;
    options.include_effects = true;
    std::optional<ea_t> address = payload_location(ctx.payload, "address");
    aida::vuln::chain::function_snapshot_t snapshot;
    bool has_snapshot = false;
    if (address)
    {
        snapshot = aida::vuln::chain::extract_function_snapshot(*address, options);
        has_snapshot = snapshot.identity.start.ea != 0;
        out["function"] = aida::vuln::chain::to_json(snapshot.identity);
    }
    if ((case_id == "all" || case_id == "ntfs_etw_zero_vs_copy") && has_snapshot)
        out["checks"].push_back(zero_vs_copy_check(snapshot));
    else if (case_id == "all" || case_id == "ntfs_etw_zero_vs_copy")
        out["checks"].push_back({{"case_id", "ntfs_etw_zero_vs_copy"}, {"status", "unproven"}, {"reason", "address_is_required"}});
    if (case_id == "all" || case_id == "etw_trigger_negative")
        out["checks"].push_back(etw_trigger_negative_check(ctx, resolver_modules_from_ctx(ctx)));
    if ((case_id == "all" || case_id == "afd_list_entry_guard") && has_snapshot)
        out["checks"].push_back(afd_list_entry_guard_check(snapshot));
    else if (case_id == "all" || case_id == "afd_list_entry_guard")
        out["checks"].push_back({{"case_id", "afd_list_entry_guard"}, {"status", "unproven"}, {"reason", "address_is_required"}});
    if ((case_id == "all" || case_id == "pvscan0_self_reference") && has_snapshot)
        out["checks"].push_back(pvscan0_self_reference_check(snapshot));
    else if (case_id == "all" || case_id == "pvscan0_self_reference")
        out["checks"].push_back({{"case_id", "pvscan0_self_reference"}, {"status", "unproven"}, {"reason", "address_is_required"}});
    bool any = false;
    bool all_passed = true;
    for (const auto& check : out["checks"])
    {
        any = true;
        if (check.value("status", std::string()) != "passed")
            all_passed = false;
    }
    if (any && all_passed)
        out["overall"] = "passed";
    return out;
}

agent_tools::tool_result_t handle_extract_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_extract_manage", params, extract_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, extract_ops()));
    if (ctx.operation == "extract_module_facts")
    {
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        aida::vuln::chain::module_snapshot_t snapshot = aida::vuln::chain::extract_module_snapshot(options);
        json data = {{"module_facts", aida::vuln::chain::to_json(snapshot)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_module_facts", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_function_facts")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*ea, options);
        json data = {{"function_facts", aida::vuln::chain::to_json(snapshot)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_function_facts", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_function_batch")
    {
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        std::vector<ea_t> functions = function_locations_from_payload(ctx.payload);
        json page;
        if (functions.empty())
        {
            function_start_page_t starts = function_start_page(ctx, options.max_batch_functions);
            if (!starts.cursor_ok)
                return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
            functions = std::move(starts.starts);
            page = starts.page;
        }
        if (functions.empty())
        {
            json empty_batch;
            empty_batch["schema"] = aida::vuln::chain::k_chain_extraction_schema;
            empty_batch["module"] = module_identity();
            empty_batch["functions"] = json::array();
            empty_batch["statuses"] = json::array();
            empty_batch["complete"] = true;
            empty_batch["cancelled"] = false;
            empty_batch["timeout"] = false;
            empty_batch["reason"] = "empty_page";
            return ok_envelope(ctx, {{"batch", empty_batch}}, json(), page);
        }
        options.max_batch_functions = std::min(options.max_batch_functions, functions.size());
        aida::vuln::chain::function_batch_result_t batch = aida::vuln::chain::extract_function_batch(functions, options);
        json data = {{"batch", aida::vuln::chain::to_json(batch)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_function_batch", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        if (!page.empty())
            nested_page["function_page"] = page;
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_xref_graph")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        if (!ctx.payload.contains("layers"))
        {
            options.include_bytes = false;
            options.include_types = false;
            options.include_ctree = false;
            options.include_microcode = false;
            options.include_effects = false;
            options.include_xrefs = true;
            options.include_xref_indexes = true;
        }
        std::optional<ea_t> target = payload_location(ctx.payload, "target");
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*ea, options);
        json data = {{"xref_graph", xref_graph_data(ctx, snapshot, target)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_xref_graph", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_path_window")
    {
        auto entry = payload_location(ctx.payload, "entry");
        auto target = payload_location(ctx.payload, "target");
        if (!entry || !target)
            return error_envelope(ctx, "bad_param", "entry and target are required", {{"required", json::array({"payload.entry", "payload.target"})}});
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        if (!ctx.payload.contains("layers"))
        {
            options.include_bytes = false;
            options.include_types = false;
            options.include_ctree = false;
            options.include_microcode = false;
            options.include_effects = true;
            options.include_xrefs = true;
            options.include_xref_indexes = true;
        }
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*entry, options);
        aida::vuln::chain::path_trace_t trace = aida::vuln::chain::trace_path_corridor(snapshot, static_cast<std::uint64_t>(*entry), static_cast<std::uint64_t>(*target), path_options_from_ctx(ctx));
        json data = {{"function", aida::vuln::chain::to_json(snapshot.identity)}, {"path", aida::vuln::chain::to_json(trace)}, {"cache", aida::vuln::chain::to_json(snapshot.cache)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_path_window", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_type_facts")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        aida::vuln::chain::extraction_options_t options;
        options.include_bytes = false;
        options.include_xrefs = false;
        options.include_xref_indexes = false;
        options.include_ctree = false;
        options.include_microcode = false;
        options.include_effects = false;
        options.include_types = true;
        options.force_refresh = ctx.payload.value("force_refresh", false);
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*ea, options);
        json statuses = json::array();
        for (const auto& status : snapshot.statuses)
            statuses.push_back(aida::vuln::chain::to_json(status));
        json data = {{"function", aida::vuln::chain::to_json(snapshot.identity)}, {"type", aida::vuln::chain::to_json(snapshot.type)}, {"statuses", statuses}, {"cache", aida::vuln::chain::to_json(snapshot.cache)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_type_facts", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "resolve_cross_binary")
    {
        json modules = resolver_modules_from_ctx(ctx);
        json reference = ctx.payload.value("reference", json::object());
        json data = {{"resolver_index", aida::vuln::chain::build_cross_binary_resolver_index(modules)},
                     {"resolution", aida::vuln::chain::resolve_cross_binary_reference(modules, reference)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "resolve_cross_binary", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "case_study_self_check")
    {
        json data = {{"self_check", case_study_self_check_data(ctx)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "case_study_self_check", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extraction_cache_status")
        return ok_envelope(ctx, {{"cache", aida::vuln::chain::extraction_cache_status()}});
    if (ctx.operation == "invalidate_extraction_cache")
    {
        if (!ctx.payload.value("confirm_destructive", false) || ctx.payload.value("reason", std::string()).empty())
            return error_envelope(ctx, "destructive_denied", "invalidate_extraction_cache requires confirm_destructive=true and a non-empty reason");
        aida::vuln::chain::clear_extraction_cache();
        return ok_envelope(ctx, {{"cleared", true}, {"cache", aida::vuln::chain::extraction_cache_status()}});
    }
    if (ctx.operation == "functions")
    {
        json all = json::array();
        const std::string filter = ctx.payload.value("filter", std::string());
        const bool include_segments = ctx.payload.value("include_segments", false);
        const size_t qty = get_func_qty();
        for (size_t i = 0; i < qty; ++i)
        {
            func_t* fn = getn_func(i);
            if (!fn)
                continue;
            json f = function_json(fn, include_segments);
            if (!filter.empty() && f.value("name", std::string()).find(filter) == std::string::npos)
                continue;
            all.push_back(f);
        }
        json page;
        json rows = page_vector(ctx, "functions", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"functions", rows}, {"total_known", all.size()}}, json(), page);
    }
    if (ctx.operation == "function")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        json d = function_json(fn, true);
        if (ctx.payload.value("include_xrefs", false))
        {
            json xrefs = json::array();
            xrefblk_t xb;
            for (bool ok = xb.first_to(fn->start_ea, XREF_ALL); ok; ok = xb.next_to())
                xrefs.push_back({{"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
            d["xrefs_to_start"] = xrefs;
        }
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "instructions")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        json all = json::array();
        func_item_iterator_t fii(fn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t item = fii.current();
            qstring dis;
            generate_disasm_line(&dis, item, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            all.push_back({{"ea", fmt_ea(item)}, {"rva", fmt_ea(item - static_cast<ea_t>(get_imagebase()))}, {"text", dis.c_str()}});
        }
        json page;
        json rows = page_vector(ctx, "instructions", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"function", function_json(fn, false)}, {"instructions", rows}}, json(), page);
    }
    if (ctx.operation == "xrefs")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        const std::string direction = ctx.payload.value("direction", std::string("both"));
        const std::string kind = ctx.payload.value("kind", std::string("all"));
        const int flags = kind == "code" ? XREF_FAR : (kind == "data" ? XREF_DATA : XREF_ALL);
        json all = json::array();
        xrefblk_t xb;
        if (direction == "to" || direction == "both")
        {
            for (bool ok = xb.first_to(*ea, flags); ok; ok = xb.next_to())
                all.push_back({{"direction", "to"}, {"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        }
        if (direction == "from" || direction == "both")
        {
            for (bool ok = xb.first_from(*ea, flags); ok; ok = xb.next_from())
                all.push_back({{"direction", "from"}, {"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        }
        json page;
        json rows = page_vector(ctx, "xrefs", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"address", fmt_ea(*ea)}, {"xrefs", rows}}, json(), page);
    }
    if (ctx.operation == "bytes")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        int size = int_param(ctx.payload, "size", 16, 1, 1048576);
        int max_bytes = int_param(ctx.budget, "max_bytes", 1048576, 1, 1048576);
        if (size > max_bytes)
            return error_envelope(ctx, "budget_exhausted", "requested size exceeds max_bytes budget", {{"size", size}, {"max_bytes", max_bytes}});
        std::vector<uint8_t> buf(static_cast<size_t>(size));
        ssize_t got = get_bytes(buf.data(), buf.size(), *ea);
        if (got < 0)
            return error_envelope(ctx, "bad_param", "failed to read bytes", {{"address", fmt_ea(*ea)}});
        json bytes = json::array();
        std::ostringstream hex;
        for (ssize_t i = 0; i < got; ++i)
        {
            bytes.push_back(buf[static_cast<size_t>(i)]);
            if (i)
                hex << ' ';
            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[static_cast<size_t>(i)]);
        }
        return ok_envelope(ctx, {{"address", fmt_ea(*ea)}, {"size", got}, {"bytes", bytes}, {"hex", hex.str()}, {"complete", got == size}});
    }
    if (ctx.operation == "decompile")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        json d;
        d["function"] = function_json(fn, true);
        d["pseudocode"] = agent_tools::helpers::get_pseudocode(fn->start_ea);
        d["hexrays_no_wait"] = true;
        d["preview_only"] = false;
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "imports")
    {
        json all = import_rows(1000000);
        json page;
        json rows = page_vector(ctx, "imports", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"imports", rows}, {"total_known", all.size()}}, json(), page);
    }
    if (ctx.operation == "exports")
    {
        json all = entry_rows(1000000);
        json page;
        json rows = page_vector(ctx, "exports", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"exports", rows}, {"total_known", all.size()}}, json(), page);
    }
    if (ctx.operation == "segments")
        return ok_envelope(ctx, {{"segments", segment_rows()}});
    if (ctx.operation == "corpus_snapshot")
        return ok_envelope(ctx, {{"module", module_identity()}, {"instance", instance_identity()}});
    if (ctx.operation == "evidence_fetch")
        return handle_evidence_fetch(ctx);
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_report_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_report_manage", params, report_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, report_ops()));
    if (ctx.operation == "get_report")
        return handle_report_fetch_like(ctx, false);
    if (ctx.operation == "export_report")
        return handle_report_fetch_like(ctx, false, true);
    if (ctx.operation == "evidence_fetch")
        return handle_evidence_fetch(ctx);
    if (ctx.operation == "list_reports")
    {
        json arr = json::array();
        const std::string verdict = ctx.payload.value("verdict", std::string());
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.reports)
            {
                const auto& r = kv.second;
                const std::string rv = r.report.value("verdict", std::string("inconclusive"));
                if (!verdict.empty() && rv != verdict)
                    continue;
                arr.push_back({{"report_id", r.report_id}, {"job_id", r.job_id}, {"chain_id", r.chain_id}, {"created_at_ms", r.created_at_ms}, {"verdict", rv}, {"acceptance", r.report.value("acceptance", std::string("not_accepted"))}, {"content_hash", r.content_hash}});
            }
        }
        json page;
        json rows = page_vector(ctx, "list_reports", arr, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"reports", rows}}, json(), page);
    }
    if (ctx.operation == "ledger_status")
        return ok_envelope(ctx, verify::engine().verdict_summary());
    if (ctx.operation == "ledger_save" || ctx.operation == "ledger_load")
    {
        const std::string action = ctx.operation == "ledger_save" ? "save" : "load";
        return ok_envelope(ctx, verify::engine().persist_ledger(action));
    }
    if (ctx.operation == "ledger_clear")
    {
        if (!ctx.payload.value("confirm_destructive", false) || ctx.payload.value("reason", std::string()).empty())
            return error_envelope(ctx, "destructive_denied", "ledger_clear requires confirm_destructive=true and a non-empty reason");
        return ok_envelope(ctx, verify::engine().persist_ledger("clear"));
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_job_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_job_manage", params, job_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, job_ops()));
    if (ctx.operation == "status")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id);
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        return ok_envelope(ctx, {{"job", job_to_json(*job)}}, job_to_json(*job));
    }
    if (ctx.operation == "result")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id);
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        json resources = json::array();
        if (!job->report_id.empty())
        {
            auto rec = get_report_record(job->report_id);
            if (rec)
                resources = json::array({resource_for_report(*rec, "json"), resource_for_report(*rec, "markdown"), resource_for_report(*rec, "sarif")});
        }
        return ok_envelope(ctx, {{"job", job_to_json(*job)}, {"result", job->result}}, job_to_json(*job), json(), json::array(), resources);
    }
    if (ctx.operation == "list")
    {
        json all = json::array();
        const std::string state_filter = ctx.payload.value("state", std::string());
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.jobs)
            {
                if (!state_filter.empty() && kv.second.state != state_filter)
                    continue;
                all.push_back(job_to_json(kv.second));
            }
        }
        json page;
        json rows = page_vector(ctx, "jobs", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"jobs", rows}}, json(), page);
    }
    if (ctx.operation == "cancel")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        verify::engine().cancel();
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        auto it = s.jobs.find(job_id);
        if (it == s.jobs.end())
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        it->second.state = "cancelled";
        it->second.updated_at_ms = now_ms();
        it->second.events.push_back({{"ts_ms", it->second.updated_at_ms}, {"state", "cancelled"}});
        return ok_envelope(ctx, {{"cancelled", true}, {"job", job_to_json(it->second)}}, job_to_json(it->second));
    }
    if (ctx.operation == "resume")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id);
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        if (job->tool != "ida_chain_manage" || !job->request.contains("payload"))
            return error_envelope(ctx, "job_conflict", "only ida_chain_manage jobs with saved payloads can be resumed", {{"job_id", job_id}, {"tool", job->tool}});
        json p;
        p["operation"] = "submit";
        p["request_id"] = ctx.request_id;
        p["payload"] = job->request["payload"];
        p["budget"] = job->request.value("budget", json::object());
        return handle_chain_manage(p);
    }
    if (ctx.operation == "diagnostics")
    {
        json d;
        d["engine"] = verify::engine().verdict_summary();
        d["in_flight_count"] = verify::engine().in_flight_count();
        d["auto_analysis_ok"] = auto_is_ok();
        d["modal_safety"] = {{"new_manage_tools_modal_waitbox_api", false}, {"new_manage_tools_ui_cancel_api", false}};
        json states = json::object();
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.jobs)
                states[kv.second.state] = states.value(kv.second.state, 0) + 1;
            d["job_count"] = s.jobs.size();
            d["report_count"] = s.reports.size();
            d["index_count"] = s.indices.size();
            d["job_states"] = states;
        }
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "prune")
    {
        const uint64_t age = static_cast<uint64_t>(int_param(ctx.payload, "older_than_ms", 3600000, 0, 2147483647));
        const std::string sf = ctx.payload.value("state", std::string("all"));
        const uint64_t cutoff = now_ms() > age ? now_ms() - age : 0;
        size_t removed = 0;
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        for (auto it = s.jobs.begin(); it != s.jobs.end(); )
        {
            const bool state_ok = sf == "all" || it->second.state == sf;
            if (state_ok && it->second.updated_at_ms < cutoff && it->second.state != "running")
            {
                it = s.jobs.erase(it);
                ++removed;
            }
            else
                ++it;
        }
        return ok_envelope(ctx, {{"removed", removed}});
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

json common_output_schema()
{
    return json::object({
        {"type", "object"},
        {"properties", {
            {"ok", {{"type", "boolean"}}},
            {"schema", {{"type", "string"}}},
            {"tool", {{"type", "string"}}},
            {"operation", {{"type", "string"}}},
            {"request_id", {{"type", "string"}}},
            {"instance", {{"type", "object"}}},
            {"module", {{"type", "object"}}},
            {"job", {{"type", json::array({"object", "null"})}}},
            {"page", {{"type", json::array({"object", "null"})}}},
            {"data", json::object()},
            {"warnings", {{"type", "array"}}},
            {"resources", {{"type", "array"}}},
            {"error", {{"type", json::array({"object", "null"})}}}
        }},
        {"required", json::array({"ok", "schema", "tool", "operation", "request_id", "instance", "module", "data", "warnings", "resources", "error"})},
        {"additionalProperties", true}
    });
}

void register_one(const std::string& name,
                  const std::string& category,
                  const std::string& description,
                  const std::vector<operation_meta_t>& metas,
                  std::function<agent_tools::tool_result_t(const json&)> handler,
                  bool read_only,
                  bool deterministic)
{
    agent_tools::tool_definition_t def;
    def.name = name;
    def.category = category;
    def.description = description;
    def.parameters = common_params(metas);
    def.handler = std::move(handler);
    def.read_only = read_only;
    def.destructive = false;
    def.deterministic = deterministic;
    def.output_schema = common_output_schema();
    def.required_indices = {};
    agent_tools::ToolRegistry::instance().register_tool(def);
}

}

inline void register_manage_tools()
{
    register_one(OBFSTR("ida_chain_manage"),
                 OBFSTR("ida_mcp_manage"),
                 OBFSTR("Consolidated chain-verification MCP surface: validate, submit, start, status, cancel, resume, export, verify links, match boundaries, confirm triggers, list reports, fetch evidence, and diagnose verifier state."),
                 chain_ops(),
                 handle_chain_manage,
                 false,
                 false);
    register_one(OBFSTR("ida_project_manage"),
                 OBFSTR("ida_mcp_manage"),
                 OBFSTR("Consolidated project, corpus, and index MCP surface for module inventory, corpus snapshots, corpus binding, index build/status, and export."),
                 project_ops(),
                 handle_project_manage,
                 false,
                 false);
    register_one(OBFSTR("ida_extract_manage"),
                 OBFSTR("ida_mcp_manage"),
                 OBFSTR("Consolidated extraction and evidence MCP surface for functions, instructions, xrefs, bytes, decompilation, imports, exports, segments, corpus identity, and evidence fetch."),
                 extract_ops(),
                 handle_extract_manage,
                 true,
                 false);
    register_one(OBFSTR("ida_report_manage"),
                 OBFSTR("ida_mcp_manage"),
                 OBFSTR("Consolidated report and ledger MCP surface for report listing, retrieval, export, evidence lookup, and verifier ledger operations."),
                 report_ops(),
                 handle_report_manage,
                 false,
                 false);
    register_one(OBFSTR("ida_job_manage"),
                 OBFSTR("ida_mcp_manage"),
                 OBFSTR("Consolidated diagnostics and job MCP surface for status, result retrieval, cancellation, resume, pruning, and runtime diagnostics."),
                 job_ops(),
                 handle_job_manage,
                 false,
                 false);
}

}
}
}
