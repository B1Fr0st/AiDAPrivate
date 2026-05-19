#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#ifdef small
#undef small
#endif

#include "auth_lab.hpp"

#include "../../../helpers/diag_log.hpp"

#include <httplib.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#include <zlib.h>

#include <nlohmann/json.hpp>

#pragma comment(lib, "Bcrypt.lib")

namespace aida {
namespace burp {
namespace auth_lab {

namespace {

struct state_t
{
    std::atomic<bool>   initialized{false};
    std::atomic<bool>   legacy_loaded{false};
    std::mutex          err_mtx;
    std::string         last_err;
    OSSL_PROVIDER*      legacy = nullptr;
    OSSL_PROVIDER*      default_p = nullptr;
};

state_t& s()
{
    static state_t st;
    return st;
}

void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}

const char kB64Std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64std_index(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

std::string base64_encode_internal(const uint8_t* data, size_t len)
{
    std::string out;
    if (len == 0) return out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        const uint32_t t = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8) | uint32_t(data[i+2]);
        out.push_back(kB64Std[(t >> 18) & 63]);
        out.push_back(kB64Std[(t >> 12) & 63]);
        out.push_back(kB64Std[(t >> 6) & 63]);
        out.push_back(kB64Std[t & 63]);
        i += 3;
    }
    const size_t rem = len - i;
    if (rem == 1) {
        const uint32_t t = uint32_t(data[i]) << 16;
        out.push_back(kB64Std[(t >> 18) & 63]);
        out.push_back(kB64Std[(t >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t t = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8);
        out.push_back(kB64Std[(t >> 18) & 63]);
        out.push_back(kB64Std[(t >> 12) & 63]);
        out.push_back(kB64Std[(t >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::string base64url_encode_no_pad(const uint8_t* data, size_t len)
{
    std::string out = base64_encode_internal(data, len);
    while (!out.empty() && out.back() == '=') out.pop_back();
    for (auto& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

bool base64_decode_internal(const std::string& in, std::string& out)
{
    out.clear();
    out.reserve((in.size() * 3) / 4 + 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        const int v = b64std_index(c);
        if (v < 0) return false;
        buffer = (buffer << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    return true;
}

std::string url_encode(const std::string& in)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

std::string ascii_lower(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c >= 'A' && c <= 'Z') out.push_back(static_cast<char>(c + 32));
        else                       out.push_back(c);
    }
    return out;
}

std::string trim(const std::string& in)
{
    size_t b = 0;
    while (b < in.size() && (in[b] == ' ' || in[b] == '\t' || in[b] == '\r' || in[b] == '\n')) ++b;
    size_t e = in.size();
    while (e > b && (in[e-1] == ' ' || in[e-1] == '\t' || in[e-1] == '\r' || in[e-1] == '\n')) --e;
    return in.substr(b, e - b);
}

std::string hex_lower(const uint8_t* data, size_t len)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

bool evp_digest(const EVP_MD* md, const std::string& data, std::vector<uint8_t>& out)
{
    out.clear();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, data.data(), data.size()) == 1) {
        out.assign(EVP_MAX_MD_SIZE, 0);
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(ctx, out.data(), &len) == 1) {
            out.resize(len);
            ok = true;
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool evp_digest_bytes(const EVP_MD* md, const uint8_t* data, size_t len_in, std::vector<uint8_t>& out)
{
    out.clear();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, data, len_in) == 1) {
        out.assign(EVP_MAX_MD_SIZE, 0);
        unsigned int olen = 0;
        if (EVP_DigestFinal_ex(ctx, out.data(), &olen) == 1) {
            out.resize(olen);
            ok = true;
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool evp_md4_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
{
    EVP_MD* md4 = EVP_MD_fetch(nullptr, "MD4", nullptr);
    if (!md4) return false;
    bool ok = evp_digest_bytes(md4, data, len, out);
    EVP_MD_free(md4);
    return ok;
}

bool evp_md5_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
{
    return evp_digest_bytes(EVP_md5(), data, len, out);
}

bool hmac_md5_bytes(const uint8_t* key, size_t key_len,
                    const uint8_t* data, size_t data_len,
                    std::vector<uint8_t>& out)
{
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) return false;
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) return false;
    char digest_name[] = "MD5";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    bool ok = false;
    if (EVP_MAC_init(ctx, key, key_len, params) > 0 &&
        EVP_MAC_update(ctx, data, data_len) > 0) {
        out.assign(EVP_MAX_MD_SIZE, 0);
        size_t olen = out.size();
        if (EVP_MAC_final(ctx, out.data(), &olen, out.size()) > 0) {
            out.resize(olen);
            ok = true;
        }
    }
    EVP_MAC_CTX_free(ctx);
    return ok;
}

bool ensure_legacy_provider_loaded()
{
    auto& st = s();
    if (st.legacy_loaded.load(std::memory_order_acquire)) return true;
    OSSL_PROVIDER* def = OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(nullptr, "legacy");
    if (!legacy) {
        if (def) OSSL_PROVIDER_unload(def);
        set_err("legacy provider load failed");
        return false;
    }
    st.legacy = legacy;
    st.default_p = def;
    st.legacy_loaded.store(true, std::memory_order_release);
    return true;
}

std::string parse_quoted_or_token(const std::string& v, size_t& pos)
{
    while (pos < v.size() && (v[pos] == ' ' || v[pos] == '\t')) ++pos;
    if (pos >= v.size()) return std::string();
    if (v[pos] == '"') {
        ++pos;
        std::string out;
        while (pos < v.size() && v[pos] != '"') {
            if (v[pos] == '\\' && pos + 1 < v.size()) { out.push_back(v[pos+1]); pos += 2; continue; }
            out.push_back(v[pos++]);
        }
        if (pos < v.size() && v[pos] == '"') ++pos;
        return out;
    }
    size_t start = pos;
    while (pos < v.size() && v[pos] != ',' && v[pos] != ' ' && v[pos] != '\t') ++pos;
    return v.substr(start, pos - start);
}

std::vector<std::pair<std::string, std::string>> parse_auth_header(const std::string& header)
{
    std::vector<std::pair<std::string, std::string>> out;
    size_t pos = 0;
    while (pos < header.size() && header[pos] != ' ') ++pos;
    while (pos < header.size() && (header[pos] == ' ' || header[pos] == '\t')) ++pos;
    while (pos < header.size()) {
        while (pos < header.size() && (header[pos] == ' ' || header[pos] == '\t' || header[pos] == ',')) ++pos;
        if (pos >= header.size()) break;
        size_t key_start = pos;
        while (pos < header.size() && header[pos] != '=' && header[pos] != ',' && header[pos] != ' ') ++pos;
        std::string key = header.substr(key_start, pos - key_start);
        while (pos < header.size() && (header[pos] == ' ' || header[pos] == '\t')) ++pos;
        if (pos < header.size() && header[pos] == '=') {
            ++pos;
            std::string val = parse_quoted_or_token(header, pos);
            out.emplace_back(ascii_lower(key), val);
        } else {
            out.emplace_back(ascii_lower(key), std::string());
        }
        while (pos < header.size() && header[pos] != ',') ++pos;
        if (pos < header.size() && header[pos] == ',') ++pos;
    }
    return out;
}

std::string get_param(const std::vector<std::pair<std::string, std::string>>& kv, const std::string& key)
{
    for (const auto& p : kv) if (p.first == key) return p.second;
    return std::string();
}

std::vector<uint8_t> random_bytes(size_t n)
{
    std::vector<uint8_t> out(n, 0);
    BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return out;
}

bool http_post_form(const std::string& token_endpoint,
                    const std::vector<std::pair<std::string, std::string>>& form,
                    std::string& body_out)
{
    body_out.clear();
    std::string scheme, host, path;
    uint16_t port = 0;
    bool is_https = false;
    {
        std::string u = token_endpoint;
        size_t schema_end = u.find("://");
        if (schema_end == std::string::npos) {
            set_err("invalid token endpoint");
            return false;
        }
        scheme = ascii_lower(u.substr(0, schema_end));
        is_https = (scheme == "https");
        size_t cursor = schema_end + 3;
        size_t path_start = u.find('/', cursor);
        std::string authority = (path_start == std::string::npos) ? u.substr(cursor) : u.substr(cursor, path_start - cursor);
        size_t colon = authority.find(':');
        if (colon == std::string::npos) {
            host = authority;
            port = is_https ? 443 : 80;
        } else {
            host = authority.substr(0, colon);
            const std::string ps = authority.substr(colon + 1);
            int v = 0;
            for (char c : ps) { if (c < '0' || c > '9') { v = -1; break; } v = v * 10 + (c - '0'); }
            port = (v <= 0 || v > 65535) ? (is_https ? 443 : 80) : static_cast<uint16_t>(v);
        }
        path = (path_start == std::string::npos) ? std::string("/") : u.substr(path_start);
    }

    std::string body;
    for (size_t i = 0; i < form.size(); ++i) {
        if (i > 0) body.push_back('&');
        body.append(url_encode(form[i].first));
        body.push_back('=');
        body.append(url_encode(form[i].second));
    }

    std::string origin = (is_https ? "https://" : "http://") + host + ":" + std::to_string(port);
    httplib::Client cli(origin);
    cli.set_connection_timeout(15, 0);
    cli.set_read_timeout(20, 0);
    cli.set_write_timeout(20, 0);
    cli.enable_server_certificate_verification(true);
    cli.set_follow_location(false);

    httplib::Headers headers = {
        { "Content-Type", "application/x-www-form-urlencoded" },
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-AuthLab/1.0" }
    };
    auto res = cli.Post(path, headers, body, "application/x-www-form-urlencoded");
    if (!res) {
        set_err("http_post_form: no response");
        return false;
    }
    body_out = res->body;
    if (res->status < 200 || res->status >= 300) {
        set_err("http_post_form: HTTP " + std::to_string(res->status));
        return false;
    }
    return true;
}

}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    ensure_legacy_provider_loaded();
    diag::log_tagged("burp", "auth_lab_initialized");
    return true;
}

void shutdown()
{
    auto& st = s();
    if (!st.initialized.exchange(false)) return;
    if (st.legacy) { OSSL_PROVIDER_unload(st.legacy); st.legacy = nullptr; }
    if (st.default_p) { OSSL_PROVIDER_unload(st.default_p); st.default_p = nullptr; }
    st.legacy_loaded.store(false, std::memory_order_release);
}

std::string base64_encode_std(const uint8_t* data, size_t len)
{
    return base64_encode_internal(data, len);
}

bool base64_decode_std(const std::string& in, std::string& out)
{
    return base64_decode_internal(in, out);
}

std::string basic_encode(const std::string& user, const std::string& pass)
{
    std::string raw = user + ":" + pass;
    std::string enc = base64_encode_internal(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    return std::string("Basic ") + enc;
}

bool basic_decode(const std::string& header, std::string& user, std::string& pass)
{
    user.clear();
    pass.clear();
    std::string h = trim(header);
    if (h.size() < 6) return false;
    std::string lo = ascii_lower(h.substr(0, 6));
    if (lo != "basic ") return false;
    std::string b = trim(h.substr(6));
    std::string raw;
    if (!base64_decode_internal(b, raw)) return false;
    size_t colon = raw.find(':');
    if (colon == std::string::npos) return false;
    user = raw.substr(0, colon);
    pass = raw.substr(colon + 1);
    return true;
}

std::string digest_solve(const std::string& method,
                         const std::string& uri,
                         const std::string& body,
                         const std::string& www_auth_header,
                         const std::string& user,
                         const std::string& pass,
                         const std::string& cnonce_in)
{
    auto kv = parse_auth_header(www_auth_header);
    std::string realm = get_param(kv, "realm");
    std::string nonce = get_param(kv, "nonce");
    std::string qop = get_param(kv, "qop");
    std::string opaque = get_param(kv, "opaque");
    std::string algorithm = get_param(kv, "algorithm");
    if (algorithm.empty()) algorithm = "MD5";

    std::string algorithm_up;
    for (char c : algorithm) algorithm_up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    const bool sess = (algorithm_up.find("-SESS") != std::string::npos);
    const EVP_MD* md = EVP_md5();
    if (algorithm_up.find("SHA-512-256") != std::string::npos) md = EVP_sha512_256();
    else if (algorithm_up.find("SHA-256") != std::string::npos) md = EVP_sha256();
    else md = EVP_md5();

    std::string qop_sel;
    {
        std::string lq = ascii_lower(qop);
        if (lq.find("auth-int") != std::string::npos) qop_sel = "auth-int";
        else if (lq.find("auth") != std::string::npos) qop_sel = "auth";
    }

    std::string cnonce = cnonce_in;
    if (cnonce.empty()) {
        const auto rb = random_bytes(16);
        cnonce = hex_lower(rb.data(), rb.size());
    }

    auto hex_md = [&](const std::string& data) -> std::string {
        std::vector<uint8_t> out;
        evp_digest(md, data, out);
        return hex_lower(out.data(), out.size());
    };

    std::string a1 = user + ":" + realm + ":" + pass;
    std::string ha1 = hex_md(a1);
    if (sess) {
        ha1 = hex_md(ha1 + ":" + nonce + ":" + cnonce);
    }

    std::string a2 = method + ":" + uri;
    if (qop_sel == "auth-int") {
        a2 += ":" + hex_md(body);
    }
    std::string ha2 = hex_md(a2);

    std::string nc = "00000001";
    std::string response_input;
    if (qop_sel == "auth" || qop_sel == "auth-int") {
        response_input = ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop_sel + ":" + ha2;
    } else {
        response_input = ha1 + ":" + nonce + ":" + ha2;
    }
    std::string response_hash = hex_md(response_input);

    std::string out = "Digest username=\"" + user + "\"";
    out += ", realm=\"" + realm + "\"";
    out += ", nonce=\"" + nonce + "\"";
    out += ", uri=\"" + uri + "\"";
    out += ", algorithm=" + algorithm;
    if (!qop_sel.empty()) {
        out += ", qop=" + qop_sel;
        out += ", nc=" + nc;
        out += ", cnonce=\"" + cnonce + "\"";
    }
    out += ", response=\"" + response_hash + "\"";
    if (!opaque.empty()) out += ", opaque=\"" + opaque + "\"";
    return out;
}

std::string ntlm_type1(const std::string& domain, const std::string& workstation)
{
    std::vector<uint8_t> msg;
    msg.reserve(64);
    const char sig[] = "NTLMSSP";
    msg.insert(msg.end(), sig, sig + 8);
    auto u32 = [&](uint32_t v) {
        msg.push_back(static_cast<uint8_t>(v & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    auto u16 = [&](uint16_t v) {
        msg.push_back(static_cast<uint8_t>(v & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    u32(1);
    const uint32_t flags = 0x60088207;
    u32(flags);
    u16(static_cast<uint16_t>(domain.size()));
    u16(static_cast<uint16_t>(domain.size()));
    u32(static_cast<uint32_t>(32 + workstation.size()));
    u16(static_cast<uint16_t>(workstation.size()));
    u16(static_cast<uint16_t>(workstation.size()));
    u32(32);
    msg.insert(msg.end(), workstation.begin(), workstation.end());
    msg.insert(msg.end(), domain.begin(), domain.end());
    return base64_encode_internal(msg.data(), msg.size());
}

namespace {

std::vector<uint8_t> utf16le_upper(const std::string& s_in)
{
    std::vector<uint8_t> out;
    out.reserve(s_in.size() * 2);
    for (unsigned char c : s_in) {
        unsigned char up = (c >= 'a' && c <= 'z') ? static_cast<unsigned char>(c - 32) : c;
        out.push_back(up);
        out.push_back(0);
    }
    return out;
}

std::vector<uint8_t> utf16le(const std::string& s_in)
{
    std::vector<uint8_t> out;
    out.reserve(s_in.size() * 2);
    for (unsigned char c : s_in) {
        out.push_back(c);
        out.push_back(0);
    }
    return out;
}

}

std::string ntlm_type3(const std::string& type2_b64,
                       const std::string& user,
                       const std::string& pass,
                       const std::string& domain,
                       const std::string& workstation)
{
    std::string raw_type2;
    if (!base64_decode_internal(type2_b64, raw_type2)) {
        set_err("ntlm_type3: type2 b64 decode failed");
        return std::string();
    }
    if (raw_type2.size() < 48) {
        set_err("ntlm_type3: type2 too short");
        return std::string();
    }
    const uint8_t* t2 = reinterpret_cast<const uint8_t*>(raw_type2.data());
    uint8_t server_challenge[8];
    std::memcpy(server_challenge, t2 + 24, 8);
    const uint16_t target_info_len = static_cast<uint16_t>(t2[40] | (t2[41] << 8));
    const uint32_t target_info_off = static_cast<uint32_t>(t2[44] | (t2[45] << 8) | (t2[46] << 16) | (t2[47] << 24));
    std::vector<uint8_t> target_info;
    if (target_info_off + target_info_len <= raw_type2.size()) {
        target_info.assign(t2 + target_info_off, t2 + target_info_off + target_info_len);
    }

    if (!ensure_legacy_provider_loaded()) {
        set_err("ntlm_type3: legacy provider unavailable for MD4");
        return std::string();
    }

    std::vector<uint8_t> pass_utf16 = utf16le(pass);
    std::vector<uint8_t> ntlm_hash;
    if (!evp_md4_bytes(pass_utf16.data(), pass_utf16.size(), ntlm_hash) || ntlm_hash.size() != 16) {
        set_err("ntlm_type3: md4 failed");
        return std::string();
    }

    std::vector<uint8_t> user_dom_utf16;
    {
        std::vector<uint8_t> ub = utf16le_upper(user);
        std::vector<uint8_t> db = utf16le(domain);
        user_dom_utf16.reserve(ub.size() + db.size());
        user_dom_utf16.insert(user_dom_utf16.end(), ub.begin(), ub.end());
        user_dom_utf16.insert(user_dom_utf16.end(), db.begin(), db.end());
    }
    std::vector<uint8_t> ntlmv2_hash;
    if (!hmac_md5_bytes(ntlm_hash.data(), ntlm_hash.size(),
                        user_dom_utf16.data(), user_dom_utf16.size(), ntlmv2_hash) ||
        ntlmv2_hash.size() != 16) {
        set_err("ntlm_type3: hmac-md5 failed");
        return std::string();
    }

    uint64_t now_filetime_100ns = 0;
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        now_filetime_100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }
    uint8_t client_challenge[8];
    {
        auto rb = random_bytes(8);
        std::memcpy(client_challenge, rb.data(), 8);
    }

    std::vector<uint8_t> blob;
    blob.reserve(28 + target_info.size() + 4);
    blob.push_back(0x01); blob.push_back(0x01);
    blob.push_back(0x00); blob.push_back(0x00);
    blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00);
    for (int i = 0; i < 8; ++i) blob.push_back(static_cast<uint8_t>((now_filetime_100ns >> (i * 8)) & 0xFF));
    blob.insert(blob.end(), client_challenge, client_challenge + 8);
    blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00);
    blob.insert(blob.end(), target_info.begin(), target_info.end());
    blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00);

    std::vector<uint8_t> ntlmv2_data;
    ntlmv2_data.reserve(8 + blob.size());
    ntlmv2_data.insert(ntlmv2_data.end(), server_challenge, server_challenge + 8);
    ntlmv2_data.insert(ntlmv2_data.end(), blob.begin(), blob.end());
    std::vector<uint8_t> nt_proof;
    if (!hmac_md5_bytes(ntlmv2_hash.data(), ntlmv2_hash.size(),
                        ntlmv2_data.data(), ntlmv2_data.size(), nt_proof) ||
        nt_proof.size() != 16) {
        set_err("ntlm_type3: nt proof hmac failed");
        return std::string();
    }
    std::vector<uint8_t> nt_response;
    nt_response.reserve(16 + blob.size());
    nt_response.insert(nt_response.end(), nt_proof.begin(), nt_proof.end());
    nt_response.insert(nt_response.end(), blob.begin(), blob.end());

    std::vector<uint8_t> lm_response(24, 0);
    {
        std::vector<uint8_t> lm_data;
        lm_data.reserve(16);
        lm_data.insert(lm_data.end(), server_challenge, server_challenge + 8);
        lm_data.insert(lm_data.end(), client_challenge, client_challenge + 8);
        std::vector<uint8_t> lm_proof;
        if (hmac_md5_bytes(ntlmv2_hash.data(), ntlmv2_hash.size(),
                           lm_data.data(), lm_data.size(), lm_proof) &&
            lm_proof.size() == 16) {
            lm_response.assign(lm_proof.begin(), lm_proof.end());
            lm_response.insert(lm_response.end(), client_challenge, client_challenge + 8);
        }
    }

    std::vector<uint8_t> user_utf16 = utf16le(user);
    std::vector<uint8_t> domain_utf16 = utf16le(domain);
    std::vector<uint8_t> ws_utf16 = utf16le(workstation);
    std::vector<uint8_t> session_key(16, 0);

    const uint32_t header_size = 64;
    const uint32_t off_domain = header_size;
    const uint32_t off_user = off_domain + static_cast<uint32_t>(domain_utf16.size());
    const uint32_t off_ws = off_user + static_cast<uint32_t>(user_utf16.size());
    const uint32_t off_lm = off_ws + static_cast<uint32_t>(ws_utf16.size());
    const uint32_t off_nt = off_lm + static_cast<uint32_t>(lm_response.size());
    const uint32_t off_sk = off_nt + static_cast<uint32_t>(nt_response.size());
    const uint32_t total = off_sk + static_cast<uint32_t>(session_key.size());

    std::vector<uint8_t> msg(total, 0);
    std::memcpy(msg.data(), "NTLMSSP\0", 8);
    auto put_u32 = [&](uint32_t offset, uint32_t v) {
        msg[offset]     = static_cast<uint8_t>(v & 0xFF);
        msg[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        msg[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        msg[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    };
    auto put_u16 = [&](uint32_t offset, uint16_t v) {
        msg[offset]     = static_cast<uint8_t>(v & 0xFF);
        msg[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    };
    put_u32(8, 3);
    put_u16(12, static_cast<uint16_t>(lm_response.size()));
    put_u16(14, static_cast<uint16_t>(lm_response.size()));
    put_u32(16, off_lm);
    put_u16(20, static_cast<uint16_t>(nt_response.size()));
    put_u16(22, static_cast<uint16_t>(nt_response.size()));
    put_u32(24, off_nt);
    put_u16(28, static_cast<uint16_t>(domain_utf16.size()));
    put_u16(30, static_cast<uint16_t>(domain_utf16.size()));
    put_u32(32, off_domain);
    put_u16(36, static_cast<uint16_t>(user_utf16.size()));
    put_u16(38, static_cast<uint16_t>(user_utf16.size()));
    put_u32(40, off_user);
    put_u16(44, static_cast<uint16_t>(ws_utf16.size()));
    put_u16(46, static_cast<uint16_t>(ws_utf16.size()));
    put_u32(48, off_ws);
    put_u16(52, static_cast<uint16_t>(session_key.size()));
    put_u16(54, static_cast<uint16_t>(session_key.size()));
    put_u32(56, off_sk);
    put_u32(60, 0x60088207);

    std::memcpy(msg.data() + off_domain, domain_utf16.data(), domain_utf16.size());
    std::memcpy(msg.data() + off_user, user_utf16.data(), user_utf16.size());
    std::memcpy(msg.data() + off_ws, ws_utf16.data(), ws_utf16.size());
    std::memcpy(msg.data() + off_lm, lm_response.data(), lm_response.size());
    std::memcpy(msg.data() + off_nt, nt_response.data(), nt_response.size());
    std::memcpy(msg.data() + off_sk, session_key.data(), session_key.size());

    return base64_encode_internal(msg.data(), msg.size());
}

std::string bearer_header(const std::string& token)
{
    return std::string("Bearer ") + token;
}

oauth2_pkce_t generate_pkce_pair()
{
    oauth2_pkce_t out;
    auto rb = random_bytes(32);
    out.verifier = base64url_encode_no_pad(rb.data(), rb.size());
    std::vector<uint8_t> sha;
    evp_digest_bytes(EVP_sha256(),
                     reinterpret_cast<const uint8_t*>(out.verifier.data()),
                     out.verifier.size(), sha);
    out.challenge = base64url_encode_no_pad(sha.data(), sha.size());
    return out;
}

std::string oauth2_build_auth_url(const std::string& authorize_endpoint,
                                  const std::string& client_id,
                                  const std::string& redirect_uri,
                                  const std::string& scope,
                                  const std::string& state,
                                  const std::string& code_challenge)
{
    std::string out = authorize_endpoint;
    out += (authorize_endpoint.find('?') == std::string::npos) ? "?" : "&";
    out += "response_type=code";
    out += "&client_id=" + url_encode(client_id);
    out += "&redirect_uri=" + url_encode(redirect_uri);
    if (!scope.empty()) out += "&scope=" + url_encode(scope);
    if (!state.empty()) out += "&state=" + url_encode(state);
    if (!code_challenge.empty()) {
        out += "&code_challenge=" + url_encode(code_challenge);
        out += "&code_challenge_method=S256";
    }
    return out;
}

bool oauth2_exchange_code(const std::string& token_endpoint,
                          const std::string& client_id,
                          const std::string& code,
                          const std::string& redirect_uri,
                          const std::string& code_verifier,
                          std::string& access_token,
                          std::string& refresh_token,
                          int& expires_in)
{
    access_token.clear();
    refresh_token.clear();
    expires_in = 0;
    std::vector<std::pair<std::string, std::string>> form;
    form.emplace_back("grant_type", "authorization_code");
    form.emplace_back("client_id", client_id);
    form.emplace_back("code", code);
    form.emplace_back("redirect_uri", redirect_uri);
    if (!code_verifier.empty()) form.emplace_back("code_verifier", code_verifier);
    std::string body;
    if (!http_post_form(token_endpoint, form, body)) return false;
    nlohmann::json j;
    try { j = nlohmann::json::parse(body, nullptr, false); } catch (...) { j = {}; }
    if (j.is_discarded() || !j.is_object()) { set_err("token response not JSON"); return false; }
    if (j.contains("access_token") && j["access_token"].is_string()) access_token = j["access_token"].get<std::string>();
    if (j.contains("refresh_token") && j["refresh_token"].is_string()) refresh_token = j["refresh_token"].get<std::string>();
    if (j.contains("expires_in")) {
        if (j["expires_in"].is_number_integer()) expires_in = j["expires_in"].get<int>();
        else if (j["expires_in"].is_number_unsigned()) expires_in = static_cast<int>(j["expires_in"].get<uint64_t>());
    }
    return !access_token.empty();
}

bool oauth2_refresh(const std::string& token_endpoint,
                    const std::string& client_id,
                    const std::string& refresh_token,
                    std::string& access_token,
                    int& expires_in)
{
    access_token.clear();
    expires_in = 0;
    std::vector<std::pair<std::string, std::string>> form;
    form.emplace_back("grant_type", "refresh_token");
    form.emplace_back("client_id", client_id);
    form.emplace_back("refresh_token", refresh_token);
    std::string body;
    if (!http_post_form(token_endpoint, form, body)) return false;
    nlohmann::json j;
    try { j = nlohmann::json::parse(body, nullptr, false); } catch (...) { j = {}; }
    if (j.is_discarded() || !j.is_object()) { set_err("refresh response not JSON"); return false; }
    if (j.contains("access_token") && j["access_token"].is_string()) access_token = j["access_token"].get<std::string>();
    if (j.contains("expires_in")) {
        if (j["expires_in"].is_number_integer()) expires_in = j["expires_in"].get<int>();
        else if (j["expires_in"].is_number_unsigned()) expires_in = static_cast<int>(j["expires_in"].get<uint64_t>());
    }
    return !access_token.empty();
}

namespace {

std::string pretty_xml(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 64);
    int depth = 0;
    std::string buf;
    auto emit_indent = [&]() {
        if (!out.empty() && out.back() != '\n') out.push_back('\n');
        for (int i = 0; i < depth; ++i) out.append("  ");
    };
    size_t i = 0;
    while (i < in.size()) {
        char c = in[i];
        if (c == '<') {
            if (!buf.empty()) {
                std::string t = trim(buf);
                if (!t.empty()) out.append(t);
                buf.clear();
            }
            const bool is_close = (i + 1 < in.size() && in[i + 1] == '/');
            const bool is_decl = (i + 1 < in.size() && (in[i + 1] == '?' || in[i + 1] == '!'));
            std::string tag = "<";
            ++i;
            while (i < in.size() && in[i] != '>') {
                tag.push_back(in[i]);
                ++i;
            }
            if (i < in.size()) tag.push_back('>');
            ++i;
            const bool is_self_close = (tag.size() >= 2 && tag[tag.size() - 2] == '/');
            if (is_decl) {
                emit_indent();
                out.append(tag);
            } else if (is_close) {
                --depth;
                emit_indent();
                out.append(tag);
            } else if (is_self_close) {
                emit_indent();
                out.append(tag);
            } else {
                emit_indent();
                out.append(tag);
                ++depth;
            }
        } else {
            buf.push_back(c);
            ++i;
        }
    }
    if (!buf.empty()) {
        std::string t = trim(buf);
        if (!t.empty()) out.append(t);
    }
    return out;
}

}

std::string saml_decode_request(const std::string& saml_b64)
{
    std::string urldecoded;
    {
        std::string s_in = saml_b64;
        std::string tmp;
        tmp.reserve(s_in.size());
        for (size_t i = 0; i < s_in.size(); ++i) {
            char c = s_in[i];
            if (c == '+') tmp.push_back(' ');
            else if (c == '%' && i + 2 < s_in.size()) {
                int hi = -1, lo = -1;
                char h = s_in[i + 1], l = s_in[i + 2];
                if (h >= '0' && h <= '9') hi = h - '0';
                else if (h >= 'a' && h <= 'f') hi = 10 + h - 'a';
                else if (h >= 'A' && h <= 'F') hi = 10 + h - 'A';
                if (l >= '0' && l <= '9') lo = l - '0';
                else if (l >= 'a' && l <= 'f') lo = 10 + l - 'a';
                else if (l >= 'A' && l <= 'F') lo = 10 + l - 'A';
                if (hi >= 0 && lo >= 0) { tmp.push_back(static_cast<char>((hi << 4) | lo)); i += 2; }
                else tmp.push_back(c);
            } else tmp.push_back(c);
        }
        urldecoded = tmp;
    }
    std::string raw;
    if (!base64_decode_internal(urldecoded, raw)) {
        set_err("saml_decode_request: base64 decode failed");
        return std::string();
    }
    std::vector<uint8_t> inflated;
    inflated.reserve(raw.size() * 4 + 32);
    z_stream strm{};
    if (inflateInit2(&strm, -15) != Z_OK) {
        return pretty_xml(raw);
    }
    strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(raw.data()));
    strm.avail_in = static_cast<uInt>(raw.size());
    uint8_t chunk[8192];
    int ret = Z_OK;
    while (ret == Z_OK) {
        strm.next_out = chunk;
        strm.avail_out = sizeof(chunk);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            return pretty_xml(raw);
        }
        const size_t produced = sizeof(chunk) - strm.avail_out;
        inflated.insert(inflated.end(), chunk, chunk + produced);
        if (ret == Z_STREAM_END) break;
        if (produced == 0) break;
    }
    inflateEnd(&strm);
    std::string xml(reinterpret_cast<const char*>(inflated.data()), inflated.size());
    return pretty_xml(xml);
}

std::string saml_decode_response(const std::string& saml_b64)
{
    std::string raw;
    if (!base64_decode_internal(saml_b64, raw)) {
        set_err("saml_decode_response: base64 decode failed");
        return std::string();
    }
    return pretty_xml(raw);
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    return st.last_err;
}

}
}
}
