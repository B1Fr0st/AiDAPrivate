#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string b64url_encode(const std::string& s)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int bits = 0;
    int n = 0;
    for (unsigned char c : s) {
        n = (n << 8) | c;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(tbl[(n >> bits) & 0x3f]);
        }
    }
    if (bits > 0) out.push_back(tbl[(n << (6 - bits)) & 0x3f]);
    return out;
}

std::vector<uint8_t> b64url_decode(const std::string& s)
{
    std::vector<uint8_t> out;
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-' || c == '+') return 62;
        if (c == '_' || c == '/') return 63;
        return -1;
    };
    int bits = 0;
    int n = 0;
    for (char c : s) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        const int v = val(c);
        if (v < 0) return {};
        n = (n << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((n >> bits) & 0xff));
        }
    }
    return out;
}

struct token_t
{
    std::string raw;
    std::string header_b64;
    std::string payload_b64;
    std::string signature_b64;
    nlohmann::json header;
    nlohmann::json payload;
};

std::vector<token_t> find_tokens(const std::string& request)
{
    static const std::regex jwt_re(R"(([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*))");
    std::vector<token_t> out;
    auto begin = std::sregex_iterator(request.begin(), request.end(), jwt_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        token_t tok;
        tok.raw = (*it)[1].str();
        const size_t d1 = tok.raw.find('.');
        const size_t d2 = tok.raw.find('.', d1 + 1);
        if (d1 == std::string::npos || d2 == std::string::npos) continue;
        tok.header_b64 = tok.raw.substr(0, d1);
        tok.payload_b64 = tok.raw.substr(d1 + 1, d2 - d1 - 1);
        tok.signature_b64 = tok.raw.substr(d2 + 1);
        auto header_bytes = b64url_decode(tok.header_b64);
        auto payload_bytes = b64url_decode(tok.payload_b64);
        tok.header = nlohmann::json::parse(std::string(header_bytes.begin(), header_bytes.end()), nullptr, false);
        tok.payload = nlohmann::json::parse(std::string(payload_bytes.begin(), payload_bytes.end()), nullptr, false);
        if (!tok.header.is_discarded() && tok.header.is_object() && !tok.payload.is_discarded() && tok.payload.is_object())
            out.push_back(std::move(tok));
    }
    return out;
}

std::vector<uint8_t> replace_token(const std::string& request, const std::string& old_token, const std::string& new_token)
{
    std::string out = request;
    size_t pos = out.find(old_token);
    if (pos != std::string::npos)
        out.replace(pos, old_token.size(), new_token);
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::string render_token(const token_t& tok, const nlohmann::json& payload)
{
    return tok.header_b64 + "." + b64url_encode(payload.dump()) + ".";
}

bool accepted_like_baseline(const exchange_observed_t& resp, const module_context_t& ctx)
{
    return resp.status_code == ctx.baseline_status_code && resp.status_code >= 200 && resp.status_code < 400;
}

void jwt_null_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    if (ip.kind != "header" || lower_ascii(ip.name) != "host") return;
    const auto tokens = find_tokens(ip.base_request);
    if (tokens.empty()) return;
    static const char* const sensitive_claims[] = {
        "sub", "user_id", "uid", "email", "role", "roles", "scope", "scopes", "permissions", "groups", "tenant", "tenant_id", "org", "organization", "is_admin", "admin"
    };
    for (const auto& tok : tokens) {
        std::vector<std::pair<std::string, nlohmann::json>> variants;
        nlohmann::json null_payload = tok.payload;
        bool mutated_null = false;
        for (const char* claim : sensitive_claims) {
            if (null_payload.contains(claim)) {
                null_payload[claim] = nullptr;
                mutated_null = true;
            }
        }
        if (mutated_null) variants.emplace_back("null-sensitive-claims", std::move(null_payload));
        nlohmann::json empty_payload = tok.payload;
        bool mutated_empty = false;
        for (const char* claim : sensitive_claims) {
            if (!empty_payload.contains(claim)) continue;
            if (empty_payload[claim].is_array()) empty_payload[claim] = nlohmann::json::array();
            else if (empty_payload[claim].is_string()) empty_payload[claim] = "";
            else if (empty_payload[claim].is_boolean()) empty_payload[claim] = false;
            else empty_payload[claim] = nullptr;
            mutated_empty = true;
        }
        if (mutated_empty) variants.emplace_back("empty-sensitive-claims", std::move(empty_payload));
        for (const auto& variant : variants) {
            if (ctx.cancelled && ctx.cancelled()) return;
            const std::string forged = render_token(tok, variant.second);
            probe_t probe;
            probe.payload = forged;
            probe.marker = variant.first;
            probe.variant = variant.first;
            auto resp = send(replace_token(ip.base_request, tok.raw, forged), probe);
            if (!resp.has_value() || !accepted_like_baseline(*resp, ctx)) continue;
            auto iss = make_issue("jwt.null-claim-mutation-accepted",
                                  "JWT null or empty claim mutation accepted",
                                  severity_t::high, confidence_t::firm, ip, probe, *resp, ctx,
                                  std::string("accepted variant=") + variant.first);
            iss.description = "A JWT with authorization-relevant claims changed to null or empty values and an invalidated signature was accepted with a baseline-equivalent response.";
            iss.remediation = "Reject null or empty critical claims, enforce issuer-specific claim schemas, and validate the signature before any authorization decision.";
            iss.cwe.push_back("CWE-345");
            iss.cwe.push_back("CWE-863");
            issue_store::add(std::move(iss));
            return;
        }
    }
}

bool register_self()
{
    module_t m;
    m.id = "jwt-null-claim";
    m.name = "JWT Null Claim Handling";
    m.category = "Authentication";
    m.max_probes_per_point = 3;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = jwt_null_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
