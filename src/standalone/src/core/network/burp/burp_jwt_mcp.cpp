#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_jwt_mcp.hpp"
#include "jwt_lab.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

tool_result_t handle_decode(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_decode entry");
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    const std::string token = params["token"].get<std::string>();
    const auto parsed = jwt_lab::decode(token);
    json out;
    out["valid_structure"] = parsed.valid_structure;
    out["alg"] = parsed.alg;
    out["kid"] = parsed.kid;
    out["header"] = parsed.header;
    out["payload"] = parsed.payload;
    out["header_b64"] = parsed.header_b64;
    out["payload_b64"] = parsed.payload_b64;
    out["signature_b64"] = parsed.signature_b64;
    diag::log_tagged_fmt("mcp_burp", "jwt_decode ok alg=%s valid=%d", parsed.alg.c_str(), (int)parsed.valid_structure);
    return tool_result_t::ok(out);
}

tool_result_t handle_forge(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_forge alg=%s", params.value("alg", std::string("HS256")).c_str());
    jwt_lab::jwt_forge_input_t in;
    if (params.contains("header") && params["header"].is_object()) in.header = params["header"];
    else in.header = json::object();
    if (params.contains("payload") && params["payload"].is_object()) in.payload = params["payload"];
    else in.payload = json::object();
    in.alg = params.value("alg", std::string("HS256"));
    in.hmac_secret = params.value("hmac_secret", std::string());
    in.rsa_private_pem = params.value("rsa_private_pem", std::string());
    in.ecdsa_private_pem = params.value("ecdsa_private_pem", std::string());
    const std::string out_token = jwt_lab::forge(in);
    if (out_token.empty()) { diag::log_tagged_fmt("mcp_burp", "jwt_forge failed err=%s", jwt_lab::last_error().c_str()); return tool_result_t::error(std::string("forge failed: ") + jwt_lab::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "jwt_forge ok token_len=%zu", out_token.size());
    json out;
    out["token"] = out_token;
    return tool_result_t::ok(out);
}

tool_result_t handle_verify(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_verify mode=%s", params.value("mode", std::string("auto")).c_str());
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    const std::string token = params["token"].get<std::string>();
    const std::string key = params.value("key", std::string());
    const std::string mode = params.value("mode", std::string("auto"));
    bool ok = false;
    if (mode == "hmac" || mode == "auto") ok = jwt_lab::verify_hmac(token, key);
    if (!ok && (mode == "rsa" || mode == "auto")) ok = jwt_lab::verify_rsa(token, key);
    if (!ok && (mode == "ecdsa" || mode == "auto")) ok = jwt_lab::verify_ecdsa(token, key);
    diag::log_tagged_fmt("mcp_burp", "jwt_verify ok verified=%d mode=%s", (int)ok, mode.c_str());
    json out;
    out["verified"] = ok;
    return tool_result_t::ok(out);
}

tool_result_t handle_crack_start(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_start wordlist=%s concurrency=%d", params.value("wordlist_id", std::string("common_passwords")).c_str(), params.value("concurrency", 8));
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    jwt_lab::crack_config_t cfg;
    cfg.token = params["token"].get<std::string>();
    cfg.wordlist_id = params.value("wordlist_id", std::string("common_passwords"));
    if (params.contains("custom_words") && params["custom_words"].is_array()) {
        for (const auto& w : params["custom_words"]) {
            if (w.is_string()) cfg.custom_words.push_back(w.get<std::string>());
        }
    }
    cfg.concurrency = static_cast<size_t>(params.value("concurrency", 8));
    cfg.max_attempts = static_cast<size_t>(params.value("max_attempts", 1000000));
    const uint64_t id = jwt_lab::start_crack(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "jwt_crack_start failed err=%s", jwt_lab::last_error().c_str()); return tool_result_t::error(std::string("start_crack failed: ") + jwt_lab::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_start ok crack_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["crack_id"] = id;
    return tool_result_t::ok(out);
}

tool_result_t handle_crack_status(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("crack_id", 0));
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_status crack_id=%llu", static_cast<unsigned long long>(id));
    const auto status = jwt_lab::crack_status(id);
    json out;
    out["id"] = status.id;
    out["attempts"] = status.attempts;
    out["running"] = status.running;
    out["secret_found"] = status.secret_found;
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_status ok id=%llu running=%d found=%s attempts=%zu", static_cast<unsigned long long>(id), (int)status.running, status.secret_found.c_str(), status.attempts);
    return tool_result_t::ok(out);
}

tool_result_t handle_crack_stop(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("crack_id", 0));
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_stop crack_id=%llu", static_cast<unsigned long long>(id));
    jwt_lab::crack_stop(id);
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_stop ok id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["stopped"] = true;
    return tool_result_t::ok(out);
}

tool_result_t handle_attack(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_attack attack=%s", params.value("attack", std::string("alg_none")).c_str());
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    const std::string token = params["token"].get<std::string>();
    const std::string attack = params.value("attack", std::string("alg_none"));
    std::vector<std::string> candidates;
    if (attack == "alg_none") candidates = jwt_lab::attack_alg_none(token);
    else if (attack == "alg_confusion") {
        const std::string pub_pem = params.value("rsa_public_pem", std::string());
        if (pub_pem.empty()) return tool_result_t::error("alg_confusion requires rsa_public_pem");
        candidates = jwt_lab::attack_alg_confusion(token, pub_pem);
    }
    else if (attack == "kid_traversal") candidates = jwt_lab::attack_kid_traversal(token);
    else if (attack == "jku_injection") {
        const std::string url = params.value("attacker_jku_url", std::string());
        candidates = jwt_lab::attack_jku_injection(token, url);
    }
    else if (attack == "signature_strip") candidates = jwt_lab::attack_signature_strip(token);
    else return tool_result_t::error("unknown attack");

    diag::log_tagged_fmt("mcp_burp", "jwt_attack ok attack=%s candidates=%zu", attack.c_str(), candidates.size());
    json out;
    out["count"] = candidates.size();
    out["candidates"] = candidates;
    return tool_result_t::ok(out);
}

}

void register_jwt_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "burp_jwt_decode",
        "Decode a JWT token. Returns parsed header, payload, alg, and kid. Validates structure but does not verify signature.",
        {{"token", "string", "JWT token (header.payload.signature)", true}},
        true, handle_decode
    });

    srv.register_tool({
        "burp_jwt_forge",
        "Forge a JWT token. Supports alg values: none, HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512. Returns the encoded token.",
        {{"header", "object", "JWT header object", false},
         {"payload", "object", "JWT payload object", false},
         {"alg", "string", "Signing algorithm", true},
         {"hmac_secret", "string", "HMAC secret (HS*)", false},
         {"rsa_private_pem", "string", "RSA private key PEM (RS*)", false},
         {"ecdsa_private_pem", "string", "ECDSA private key PEM (ES*)", false}},
        false, handle_forge
    });

    srv.register_tool({
        "burp_jwt_verify",
        "Verify a JWT signature. Mode = hmac | rsa | ecdsa | auto. The 'key' is the shared secret for HMAC or the public PEM for RSA/ECDSA.",
        {{"token", "string", "JWT token", true},
         {"key", "string", "Secret or public PEM", true},
         {"mode", "string", "hmac|rsa|ecdsa|auto", false}},
        true, handle_verify
    });

    srv.register_tool({
        "burp_jwt_crack_start",
        "Start a JWT HMAC secret crack using a wordlist. Returns a crack_id for status polling.",
        {{"token", "string", "JWT token (HS256/384/512)", true},
         {"wordlist_id", "string", "Payload library wordlist id", false},
         {"custom_words", "array", "Extra words to test", false},
         {"max_attempts", "number", "Maximum attempts (default 1000000)", false},
         {"concurrency", "number", "Worker thread count (default 8, max 32)", false}},
        false, handle_crack_start
    });

    srv.register_tool({
        "burp_jwt_crack_status",
        "Poll the status of a JWT crack job.",
        {{"crack_id", "number", "Crack job id", true}},
        true, handle_crack_status
    });

    srv.register_tool({
        "burp_jwt_crack_stop",
        "Request a JWT crack job to stop.",
        {{"crack_id", "number", "Crack job id", true}},
        false, handle_crack_stop
    });

    srv.register_tool({
        "burp_jwt_attack",
        "Run a JWT attack and get forged candidate tokens. Attack: alg_none | alg_confusion | kid_traversal | jku_injection | signature_strip.",
        {{"token", "string", "JWT token", true},
         {"attack", "string", "Attack name", true},
         {"rsa_public_pem", "string", "Public PEM (alg_confusion)", false},
         {"attacker_jku_url", "string", "Attacker URL (jku_injection)", false}},
        false, handle_attack
    });
}

}
}
