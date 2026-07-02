#pragma once

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <mutex>
#include <regex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tls_policy {

enum class certificate_key_type_t {
    rsa_2048,
    ecdsa_p256,
    ecdsa_p384
};

struct certificate_options_t {
    certificate_key_type_t key_type = certificate_key_type_t::rsa_2048;
    std::uint32_t validity_days = 365;
    bool include_wildcard_san = true;
    std::vector<std::string> san_dns;
    std::vector<std::uint8_t> ocsp_response_der;
};

struct host_policy_t {
    std::string name;
    std::string host_regex;
    int min_tls_version = TLS1_2_VERSION;
    int max_tls_version = 0;
    std::string cipher_list;
    std::string ciphersuites;
    std::vector<std::string> alpn_protocols;
    bool ignore_cert_errors = false;
    std::vector<std::string> upstream_cert_sha256_pins;
    certificate_options_t certificate;
};

struct match_result_t {
    bool matched = false;
    host_policy_t policy;
};

inline std::mutex& registry_mutex() {
    static std::mutex m;
    return m;
}

inline std::vector<host_policy_t>& registry() {
    static std::vector<host_policy_t> policies;
    return policies;
}

inline std::atomic<std::uint64_t>& registry_generation() {
    static std::atomic<std::uint64_t> generation{1};
    return generation;
}

inline std::mutex& ctx_data_mutex() {
    static std::mutex m;
    return m;
}

inline std::unordered_map<SSL_CTX*, std::vector<unsigned char>>& ctx_alpn_data() {
    static std::unordered_map<SSL_CTX*, std::vector<unsigned char>> data;
    return data;
}

inline std::unordered_map<SSL_CTX*, std::vector<std::uint8_t>>& ctx_ocsp_data() {
    static std::unordered_map<SSL_CTX*, std::vector<std::uint8_t>> data;
    return data;
}

inline int alpn_select_callback(SSL*, const unsigned char** out, unsigned char* outlen,
                                const unsigned char* in, unsigned int inlen, void* arg) {
    auto* encoded = static_cast<std::vector<unsigned char>*>(arg);
    if (!encoded || encoded->empty())
        return SSL_TLSEXT_ERR_NOACK;
    if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                              encoded->data(), static_cast<unsigned int>(encoded->size()),
                              in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

inline int ocsp_status_callback(SSL* ssl, void* arg) {
    auto* response = static_cast<std::vector<std::uint8_t>*>(arg);
    if (!ssl || !response || response->empty())
        return SSL_TLSEXT_ERR_NOACK;
    auto* copy = static_cast<unsigned char*>(OPENSSL_malloc(response->size()));
    if (!copy)
        return SSL_TLSEXT_ERR_NOACK;
    std::copy(response->begin(), response->end(), copy);
    if (SSL_set_tlsext_status_ocsp_resp(ssl, copy, static_cast<int>(response->size())) != 1) {
        OPENSSL_free(copy);
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

inline int verify_callback(int preverify_ok, X509_STORE_CTX*) {
    return preverify_ok;
}

inline std::vector<unsigned char> encode_alpn_protocols(const std::vector<std::string>& protocols) {
    std::vector<unsigned char> out;
    for (const auto& proto : protocols) {
        if (proto.empty() || proto.size() > 255)
            continue;
        out.push_back(static_cast<unsigned char>(proto.size()));
        out.insert(out.end(), proto.begin(), proto.end());
    }
    return out;
}

inline bool valid_policy(const host_policy_t& policy) {
    if (policy.host_regex.empty())
        return false;
    try {
        std::regex probe(policy.host_regex, std::regex::icase | std::regex::ECMAScript);
        (void)probe;
    } catch (const std::regex_error&) {
        return false;
    }
    if (policy.min_tls_version != 0 && policy.max_tls_version != 0 &&
        policy.min_tls_version > policy.max_tls_version) {
        return false;
    }
    return true;
}

inline bool set_policies(std::vector<host_policy_t> policies) {
    for (const auto& policy : policies) {
        if (!valid_policy(policy))
            return false;
    }
    std::lock_guard<std::mutex> lock(registry_mutex());
    registry() = std::move(policies);
    registry_generation().fetch_add(1, std::memory_order_acq_rel);
    return true;
}

inline bool add_policy(host_policy_t policy) {
    if (!valid_policy(policy))
        return false;
    std::lock_guard<std::mutex> lock(registry_mutex());
    registry().push_back(std::move(policy));
    registry_generation().fetch_add(1, std::memory_order_acq_rel);
    return true;
}

inline void clear_policies() {
    std::lock_guard<std::mutex> lock(registry_mutex());
    registry().clear();
    registry_generation().fetch_add(1, std::memory_order_acq_rel);
}

inline std::vector<host_policy_t> policies() {
    std::lock_guard<std::mutex> lock(registry_mutex());
    return registry();
}

inline match_result_t match_host(const std::string& host) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    for (const auto& policy : registry()) {
        try {
            std::regex re(policy.host_regex, std::regex::icase | std::regex::ECMAScript);
            if (std::regex_match(host, re) || std::regex_search(host, re))
                return { true, policy };
        } catch (const std::regex_error&) {
        }
    }
    return {};
}

inline std::uint64_t generation() {
    return registry_generation().load(std::memory_order_acquire);
}

inline bool apply_tls_versions(SSL_CTX* ctx, const host_policy_t& policy) {
    if (!ctx)
        return false;
    if (policy.min_tls_version != 0 && SSL_CTX_set_min_proto_version(ctx, policy.min_tls_version) != 1)
        return false;
    if (policy.max_tls_version != 0 && SSL_CTX_set_max_proto_version(ctx, policy.max_tls_version) != 1)
        return false;
    return true;
}

inline bool apply_cipher_policy(SSL_CTX* ctx, const host_policy_t& policy) {
    if (!ctx)
        return false;
    if (!policy.cipher_list.empty() && SSL_CTX_set_cipher_list(ctx, policy.cipher_list.c_str()) != 1)
        return false;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (!policy.ciphersuites.empty() && SSL_CTX_set_ciphersuites(ctx, policy.ciphersuites.c_str()) != 1)
        return false;
#else
    if (!policy.ciphersuites.empty())
        return false;
#endif
    return true;
}

inline bool apply_alpn_select(SSL_CTX* ctx, const host_policy_t& policy) {
    if (!ctx || policy.alpn_protocols.empty())
        return true;
    auto encoded = encode_alpn_protocols(policy.alpn_protocols);
    if (encoded.empty())
        return false;
    std::lock_guard<std::mutex> lock(ctx_data_mutex());
    auto& slot = ctx_alpn_data()[ctx];
    slot = std::move(encoded);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, &slot);
    return true;
}

inline bool apply_ocsp_stapling(SSL_CTX* ctx, const std::vector<std::uint8_t>& response_der) {
    if (!ctx || response_der.empty())
        return true;
    std::lock_guard<std::mutex> lock(ctx_data_mutex());
    auto& slot = ctx_ocsp_data()[ctx];
    slot = response_der;
    SSL_CTX_set_tlsext_status_cb(ctx, ocsp_status_callback);
    SSL_CTX_set_tlsext_status_arg(ctx, &slot);
    return true;
}

inline bool apply_server_policy(SSL_CTX* ctx, const match_result_t& match) {
    if (!ctx)
        return false;
    if (!match.matched)
        return SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 1;
    return apply_tls_versions(ctx, match.policy) &&
           apply_cipher_policy(ctx, match.policy) &&
           apply_alpn_select(ctx, match.policy);
}

inline bool apply_client_policy(SSL_CTX* ctx, const match_result_t& match) {
    if (!ctx)
        return false;
    if (!match.matched) {
        if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
            return false;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
        SSL_CTX_set_default_verify_paths(ctx);
        return true;
    }
    if (!apply_tls_versions(ctx, match.policy) || !apply_cipher_policy(ctx, match.policy))
        return false;
    if (match.policy.ignore_cert_errors) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
        SSL_CTX_set_default_verify_paths(ctx);
    }
    return true;
}

inline bool apply_client_alpn(SSL* ssl, const match_result_t& match,
                              const unsigned char* fallback, unsigned int fallback_len) {
    if (!ssl)
        return false;
    if (match.matched && !match.policy.alpn_protocols.empty()) {
        auto encoded = encode_alpn_protocols(match.policy.alpn_protocols);
        if (encoded.empty())
            return false;
        return SSL_set_alpn_protos(ssl, encoded.data(), static_cast<unsigned int>(encoded.size())) == 0;
    }
    if (fallback && fallback_len > 0)
        return SSL_set_alpn_protos(ssl, fallback, fallback_len) == 0;
    return true;
}

inline bool configure_hostname_verification(SSL* ssl, const std::string& host, const match_result_t& match) {
    if (!ssl || host.empty())
        return false;
    if (match.matched && match.policy.ignore_cert_errors)
        return true;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return SSL_set1_host(ssl, host.c_str()) == 1;
#else
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    return param && X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0) == 1;
#endif
}

inline std::string normalize_fingerprint(std::string value) {
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value) {
        if (c == ':' || c == '-' || std::isspace(c))
            continue;
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

inline std::string cert_sha256_fingerprint_hex(X509* cert) {
    if (!cert)
        return {};
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digest_len = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1 || digest_len == 0)
        return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(digest_len) * 2);
    for (unsigned int i = 0; i < digest_len; ++i) {
        out.push_back(hex[(digest[i] >> 4) & 0x0F]);
        out.push_back(hex[digest[i] & 0x0F]);
    }
    return out;
}

inline bool pins_configured(const match_result_t& match) {
    return match.matched && !match.policy.upstream_cert_sha256_pins.empty();
}

inline bool fingerprint_matches_pin(const std::string& fingerprint_hex, const match_result_t& match) {
    if (!pins_configured(match))
        return true;
    const std::string normalized = normalize_fingerprint(fingerprint_hex);
    for (const auto& pin : match.policy.upstream_cert_sha256_pins) {
        if (normalized == normalize_fingerprint(pin))
            return true;
    }
    return false;
}

inline void forget_context(SSL_CTX* ctx) {
    if (!ctx)
        return;
    std::lock_guard<std::mutex> lock(ctx_data_mutex());
    ctx_alpn_data().erase(ctx);
    ctx_ocsp_data().erase(ctx);
}

inline void forget_all_contexts() {
    std::lock_guard<std::mutex> lock(ctx_data_mutex());
    ctx_alpn_data().clear();
    ctx_ocsp_data().clear();
}

inline const char* key_type_name(certificate_key_type_t type) {
    switch (type) {
    case certificate_key_type_t::rsa_2048: return "rsa_2048";
    case certificate_key_type_t::ecdsa_p256: return "ecdsa_p256";
    case certificate_key_type_t::ecdsa_p384: return "ecdsa_p384";
    default: return "unknown";
    }
}

}
