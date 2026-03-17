// net_security_test - Offline verification of net_security crypto and parsing
// Tests HKDF-SHA256, QUIC Initial decryption, TLS SNI extraction, and
// AutoResponder rule matching WITHOUT requiring the kernel driver.

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

// ==================================================================
// Minimal reproduction of the crypto helpers from net_security.cpp
// (keep in sync with the real implementation)
// ==================================================================

static bool hmac_sha256(const std::uint8_t* key, std::size_t key_len,
                        const std::uint8_t* data, std::size_t data_len,
                        std::uint8_t out[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hash_obj_size = 0, cb_data = 0;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return false;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hash_obj_size),
                          sizeof(hash_obj_size), &cb_data, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    std::vector<std::uint8_t> hash_obj(hash_obj_size);
    if (BCryptCreateHash(hAlg, &hHash, hash_obj.data(), hash_obj_size,
                         const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    if (BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0) == 0) {
        if (BCryptFinishHash(hHash, out, 32, 0) == 0)
            ok = true;
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool hkdf_extract(const std::uint8_t* salt, std::size_t salt_len,
                          const std::uint8_t* ikm, std::size_t ikm_len,
                          std::uint8_t prk[32]) {
    if (salt_len == 0) {
        std::uint8_t zero_salt[32] = {};
        return hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    }
    return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static bool hkdf_expand(const std::uint8_t prk[32],
                         const std::uint8_t* info, std::size_t info_len,
                         std::uint8_t* okm, std::size_t okm_len) {
    std::uint8_t t[32] = {};
    std::size_t t_len = 0;
    std::uint8_t counter = 1;
    std::size_t offset = 0;

    while (offset < okm_len) {
        std::vector<std::uint8_t> input;
        input.reserve(t_len + info_len + 1);
        input.insert(input.end(), t, t + t_len);
        input.insert(input.end(), info, info + info_len);
        input.push_back(counter);

        if (!hmac_sha256(prk, 32, input.data(), input.size(), t))
            return false;

        t_len = 32;
        std::size_t to_copy = (32 < okm_len - offset) ? 32 : okm_len - offset;
        std::memcpy(okm + offset, t, to_copy);
        offset += to_copy;
        counter++;
        if (counter == 0) return false;
    }
    return true;
}

static bool hkdf_expand_label(const std::uint8_t prk[32],
                               const char* label, std::size_t label_len,
                               const std::uint8_t* context, std::size_t context_len,
                               std::uint8_t* okm, std::size_t okm_len) {
    const char* prefix = "tls13 ";
    std::size_t prefix_len = 6;
    std::size_t full_label_len = prefix_len + label_len;

    std::vector<std::uint8_t> hkdf_label;
    hkdf_label.push_back(static_cast<std::uint8_t>((okm_len >> 8) & 0xFF));
    hkdf_label.push_back(static_cast<std::uint8_t>(okm_len & 0xFF));
    hkdf_label.push_back(static_cast<std::uint8_t>(full_label_len));
    hkdf_label.insert(hkdf_label.end(),
                       reinterpret_cast<const std::uint8_t*>(prefix),
                       reinterpret_cast<const std::uint8_t*>(prefix) + prefix_len);
    hkdf_label.insert(hkdf_label.end(),
                       reinterpret_cast<const std::uint8_t*>(label),
                       reinterpret_cast<const std::uint8_t*>(label) + label_len);
    hkdf_label.push_back(static_cast<std::uint8_t>(context_len));
    if (context_len > 0)
        hkdf_label.insert(hkdf_label.end(), context, context + context_len);

    return hkdf_expand(prk, hkdf_label.data(), hkdf_label.size(), okm, okm_len);
}

static bool aes_ecb_encrypt(const std::uint8_t key[16],
                             const std::uint8_t in[16],
                             std::uint8_t out[16]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
                          static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_ECB)), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD key_obj_size = 0, cb_data = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PUCHAR>(&key_obj_size), sizeof(key_obj_size), &cb_data, 0);

    std::vector<std::uint8_t> key_obj(key_obj_size);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj.data(), key_obj_size,
                                    const_cast<PUCHAR>(key), 16, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    ULONG result_len = 0;
    std::uint8_t input_copy[16];
    std::memcpy(input_copy, in, 16);
    if (BCryptEncrypt(hKey, input_copy, 16, nullptr, nullptr, 0, out, 16, &result_len, 0) == 0)
        ok = (result_len == 16);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ==================================================================
// QUIC Initial key derivation (same as net_security.cpp)
// ==================================================================

static bool derive_initial_keys(const std::uint8_t* dcid, std::size_t dcid_len,
                                 std::uint32_t version,
                                 std::uint8_t* client_key, std::uint8_t* client_iv, std::uint8_t* client_hp,
                                 std::uint8_t* server_key, std::uint8_t* server_iv, std::uint8_t* server_hp) {
    if (!dcid || dcid_len == 0) return false;

    const std::uint8_t salt_v1[] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    const std::uint8_t salt_v2[] = {
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
    };

    const std::uint8_t* salt;
    std::size_t salt_len;

    if (version == 0x6b3343cf) {
        salt = salt_v2; salt_len = sizeof(salt_v2);
    } else {
        salt = salt_v1; salt_len = sizeof(salt_v1);
    }

    std::uint8_t initial_secret[32];
    if (!hkdf_extract(salt, salt_len, dcid, dcid_len, initial_secret))
        return false;

    std::uint8_t client_secret[32];
    if (!hkdf_expand_label(initial_secret, "client in", 9, nullptr, 0, client_secret, 32))
        return false;

    std::uint8_t server_secret[32];
    if (!hkdf_expand_label(initial_secret, "server in", 9, nullptr, 0, server_secret, 32))
        return false;

    if (!hkdf_expand_label(client_secret, "quic key", 8, nullptr, 0, client_key, 16)) return false;
    if (!hkdf_expand_label(client_secret, "quic iv",  7, nullptr, 0, client_iv,  12)) return false;
    if (!hkdf_expand_label(client_secret, "quic hp",  7, nullptr, 0, client_hp,  16)) return false;

    if (!hkdf_expand_label(server_secret, "quic key", 8, nullptr, 0, server_key, 16)) return false;
    if (!hkdf_expand_label(server_secret, "quic iv",  7, nullptr, 0, server_iv,  12)) return false;
    if (!hkdf_expand_label(server_secret, "quic hp",  7, nullptr, 0, server_hp,  16)) return false;

    SecureZeroMemory(initial_secret, 32);
    SecureZeroMemory(client_secret, 32);
    SecureZeroMemory(server_secret, 32);
    return true;
}

// ==================================================================
// TLS SNI extraction (same as net_security.cpp)
// ==================================================================

static std::string extract_tls_sni(const std::uint8_t* data, std::size_t len) {
    if (len < 44 || data[0] != 0x16) return "";

    std::uint16_t rec_len = (static_cast<std::uint16_t>(data[3]) << 8) | data[4];
    if (static_cast<std::size_t>(5) + rec_len > len) return "";

    if (data[5] != 0x01) return "";

    std::size_t pos = 9;
    if (pos + 34 > len) return "";
    pos += 2;
    pos += 32;

    if (pos >= len) return "";
    std::uint8_t sid_len = data[pos++];
    pos += sid_len;

    if (pos + 2 > len) return "";
    std::uint16_t cs_len = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2 + cs_len;

    if (pos >= len) return "";
    std::uint8_t cm_len = data[pos++];
    pos += cm_len;

    if (pos + 2 > len) return "";
    std::uint16_t ext_total = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;

    std::size_t ext_end = pos + ext_total;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        std::uint16_t ext_type = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        std::uint16_t ext_data_len = (static_cast<std::uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;

        if (ext_type == 0x0000 && ext_data_len >= 5 && pos + ext_data_len <= ext_end) {
            std::size_t sni_pos = pos + 2;
            if (sni_pos < ext_end && data[sni_pos] == 0x00) {
                sni_pos++;
                if (sni_pos + 2 <= ext_end) {
                    std::uint16_t name_len = (static_cast<std::uint16_t>(data[sni_pos]) << 8) | data[sni_pos + 1];
                    sni_pos += 2;
                    if (name_len > 0 && name_len < 256 && sni_pos + name_len <= ext_end) {
                        std::string sni(reinterpret_cast<const char*>(data + sni_pos), name_len);
                        for (auto& c : sni) {
                            if (c < 0x20 || c > 0x7E) return "";
                        }
                        return sni;
                    }
                }
            }
            break;
        }
        pos += ext_data_len;
    }
    return "";
}

// ==================================================================
// AutoResponder matching logic (simplified from net_security.cpp)
// ==================================================================

enum class match_type {
    exact_url, prefix_url, regex_url, method_and_url,
    header_contains, body_contains, sni_contains
};

struct rule_t {
    bool enabled = true;
    match_type mtype = match_type::prefix_url;
    std::string pattern;
    std::string method;
};

static bool match_rule(const rule_t& rule, const std::string& method, const std::string& url,
                       const std::map<std::string, std::string>& headers, const std::string& body) {
    if (!rule.enabled) return false;
    if (!rule.method.empty() && rule.method != method) return false;

    switch (rule.mtype) {
        case match_type::exact_url: return url == rule.pattern;
        case match_type::prefix_url: return url.find(rule.pattern) != std::string::npos;
        case match_type::method_and_url: return method == rule.method && url.find(rule.pattern) != std::string::npos;
        case match_type::header_contains:
            for (const auto& [n, v] : headers)
                if (v.find(rule.pattern) != std::string::npos || n.find(rule.pattern) != std::string::npos) return true;
            return false;
        case match_type::body_contains: return body.find(rule.pattern) != std::string::npos;
        case match_type::sni_contains: {
            std::string lower_url = url, lower_pat = rule.pattern;
            for (auto& c : lower_url) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (auto& c : lower_pat) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return lower_url.find(lower_pat) != std::string::npos;
        }
        default: return false;
    }
}

// ==================================================================
// Test framework
// ==================================================================

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

static std::string bytes_to_hex(const std::uint8_t* data, std::size_t len) {
    std::string out;
    for (std::size_t i = 0; i < len; i++) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    return out;
}

static std::vector<std::uint8_t> hex_to_bytes(const char* hex) {
    std::vector<std::uint8_t> out;
    std::size_t len = std::strlen(hex);
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return 0;
        };
        out.push_back(static_cast<std::uint8_t>((nib(hex[i]) << 4) | nib(hex[i+1])));
    }
    return out;
}

#define TEST(name) \
    { g_tests_run++; \
    const char* _test_name = name; \
    bool _pass = true;

#define EXPECT(cond, msg) \
    if (!(cond)) { \
        printf("  FAIL [%s]: %s\n", _test_name, msg); \
        _pass = false; \
    }

#define END_TEST \
    if (_pass) { g_tests_passed++; printf("  PASS [%s]\n", _test_name); } \
    else { g_tests_failed++; } \
    }

// ==================================================================
// Tests
// ==================================================================

int main() {
    printf("=== net_security offline verification ===\n\n");

    // ---------------------------------------------------------------
    // 1. HKDF-SHA256 - RFC 5869 Test Case 1
    // ---------------------------------------------------------------
    printf("--- HKDF-SHA256 ---\n");

    TEST("HKDF-Extract (RFC 5869 TC1)")
    {
        auto ikm  = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        auto salt = hex_to_bytes("000102030405060708090a0b0c");
        std::uint8_t prk[32] = {};
        bool ok = hkdf_extract(salt.data(), salt.size(), ikm.data(), ikm.size(), prk);
        EXPECT(ok, "hkdf_extract returned false");
        std::string got = bytes_to_hex(prk, 32);
        EXPECT(got == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
               "PRK mismatch");
    }
    END_TEST

    TEST("HKDF-Expand (RFC 5869 TC1)")
    {
        auto prk  = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        auto info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        std::uint8_t okm[42] = {};
        bool ok = hkdf_expand(prk.data(), info.data(), info.size(), okm, 42);
        EXPECT(ok, "hkdf_expand returned false");
        std::string got = bytes_to_hex(okm, 42);
        EXPECT(got == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
               "OKM mismatch");
    }
    END_TEST

    // ---------------------------------------------------------------
    // 2. QUIC Initial Key Derivation - RFC 9001 Section A.1
    // Destination Connection ID: 0x8394c8f03e515708
    // ---------------------------------------------------------------
    printf("\n--- QUIC Initial Key Derivation (RFC 9001 A.1) ---\n");

    TEST("QUIC v1 derive_initial_keys")
    {
        auto dcid = hex_to_bytes("8394c8f03e515708");

        std::uint8_t ck[16], ci[12], ch[16], sk[16], si[12], sh[16];
        bool ok = derive_initial_keys(dcid.data(), dcid.size(), 0x00000001,
                                       ck, ci, ch, sk, si, sh);
        EXPECT(ok, "derive_initial_keys returned false");

        // RFC 9001 A.1 expected values:
        // client initial secret = c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
        // client key  = 1f369613dd76d5467730efcbe3b1a22d
        // client iv   = fa044b2f42a3fd3b46fb255c
        // client hp   = 9f50449e04a0e810283a1e9933adedd2

        std::string ck_hex = bytes_to_hex(ck, 16);
        std::string ci_hex = bytes_to_hex(ci, 12);
        std::string ch_hex = bytes_to_hex(ch, 16);

        EXPECT(ck_hex == "1f369613dd76d5467730efcbe3b1a22d",
               ("client key mismatch: got " + ck_hex).c_str());
        EXPECT(ci_hex == "fa044b2f42a3fd3b46fb255c",
               ("client iv mismatch: got " + ci_hex).c_str());
        EXPECT(ch_hex == "9f50449e04a0e810283a1e9933adedd2",
               ("client hp mismatch: got " + ch_hex).c_str());

        // server key  = cf3a5331653c364c88f0f379b6067e37
        // server iv   = 0ac1493ca1905853b0bba03e
        // server hp   = c206b8d9b9f0f37644430b490eeaa314

        std::string sk_hex = bytes_to_hex(sk, 16);
        std::string si_hex = bytes_to_hex(si, 12);
        std::string sh_hex = bytes_to_hex(sh, 16);

        EXPECT(sk_hex == "cf3a5331653c364c88f0f379b6067e37",
               ("server key mismatch: got " + sk_hex).c_str());
        EXPECT(si_hex == "0ac1493ca1905853b0bba03e",
               ("server iv mismatch: got " + si_hex).c_str());
        EXPECT(sh_hex == "c206b8d9b9f0f37644430b490eeaa314",
               ("server hp mismatch: got " + sh_hex).c_str());
    }
    END_TEST

    // ---------------------------------------------------------------
    // 3. AES-ECB (used for QUIC header protection)
    // ---------------------------------------------------------------
    printf("\n--- AES-ECB (Header Protection) ---\n");

    TEST("AES-128-ECB encrypt")
    {
        // NIST AES-128-ECB test vector
        auto key  = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto pt   = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
        auto expected = hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97");
        std::uint8_t out[16] = {};
        bool ok = aes_ecb_encrypt(key.data(), pt.data(), out);
        EXPECT(ok, "aes_ecb_encrypt failed");
        EXPECT(std::memcmp(out, expected.data(), 16) == 0,
               ("AES-ECB output mismatch: got " + bytes_to_hex(out, 16)).c_str());
    }
    END_TEST

    // ---------------------------------------------------------------
    // 4. TLS SNI Extraction
    // ---------------------------------------------------------------
    printf("\n--- TLS SNI Extraction ---\n");

    TEST("Extract SNI from real TLS Client Hello")
    {
        // Minimal TLS 1.2 Client Hello with SNI = "example.com"
        // Record: 0x16 0x03 0x01 <length> ...
        // Handshake: 0x01 <length> ...
        // Version, Random (32 bytes), Session ID length=0, Cipher Suite length=2,
        // one cipher suite, Compression methods length=1, null compression,
        // Extensions length, SNI extension
        std::vector<std::uint8_t> hello;

        // Build inner handshake first
        std::vector<std::uint8_t> hs;
        // Client version 0x0303 (TLS 1.2)
        hs.push_back(0x03); hs.push_back(0x03);
        // Random (32 bytes)
        for (int i = 0; i < 32; i++) hs.push_back(static_cast<std::uint8_t>(i));
        // Session ID length = 0
        hs.push_back(0x00);
        // Cipher suites length = 2 (1 suite)
        hs.push_back(0x00); hs.push_back(0x02);
        hs.push_back(0x13); hs.push_back(0x01); // TLS_AES_128_GCM_SHA256
        // Compression methods length = 1
        hs.push_back(0x01);
        hs.push_back(0x00); // null compression

        // Extensions
        std::vector<std::uint8_t> ext;
        // SNI extension (type 0x0000)
        const char* sni = "example.com";
        std::size_t sni_len = std::strlen(sni);
        ext.push_back(0x00); ext.push_back(0x00); // extension type
        std::uint16_t sni_ext_data_len = static_cast<std::uint16_t>(2 + 1 + 2 + sni_len);
        ext.push_back(static_cast<std::uint8_t>(sni_ext_data_len >> 8));
        ext.push_back(static_cast<std::uint8_t>(sni_ext_data_len & 0xFF));
        // SNI list length
        std::uint16_t sni_list_len = static_cast<std::uint16_t>(1 + 2 + sni_len);
        ext.push_back(static_cast<std::uint8_t>(sni_list_len >> 8));
        ext.push_back(static_cast<std::uint8_t>(sni_list_len & 0xFF));
        // Host name type
        ext.push_back(0x00);
        // Host name length
        ext.push_back(static_cast<std::uint8_t>(sni_len >> 8));
        ext.push_back(static_cast<std::uint8_t>(sni_len & 0xFF));
        // Host name
        for (std::size_t i = 0; i < sni_len; i++)
            ext.push_back(static_cast<std::uint8_t>(sni[i]));

        // Extensions total length
        std::uint16_t ext_total = static_cast<std::uint16_t>(ext.size());
        hs.push_back(static_cast<std::uint8_t>(ext_total >> 8));
        hs.push_back(static_cast<std::uint8_t>(ext_total & 0xFF));
        hs.insert(hs.end(), ext.begin(), ext.end());

        // Handshake header: type=0x01, length (3 bytes)
        std::vector<std::uint8_t> handshake;
        handshake.push_back(0x01);
        std::uint32_t hs_len = static_cast<std::uint32_t>(hs.size());
        handshake.push_back(static_cast<std::uint8_t>((hs_len >> 16) & 0xFF));
        handshake.push_back(static_cast<std::uint8_t>((hs_len >> 8) & 0xFF));
        handshake.push_back(static_cast<std::uint8_t>(hs_len & 0xFF));
        handshake.insert(handshake.end(), hs.begin(), hs.end());

        // TLS record header: type=0x16, version=0x0301, length
        hello.push_back(0x16);
        hello.push_back(0x03); hello.push_back(0x01);
        std::uint16_t rec_len = static_cast<std::uint16_t>(handshake.size());
        hello.push_back(static_cast<std::uint8_t>(rec_len >> 8));
        hello.push_back(static_cast<std::uint8_t>(rec_len & 0xFF));
        hello.insert(hello.end(), handshake.begin(), handshake.end());

        std::string result = extract_tls_sni(hello.data(), hello.size());
        EXPECT(result == "example.com",
               ("SNI mismatch: got '" + result + "'").c_str());
    }
    END_TEST

    TEST("SNI extraction - non-TLS packet returns empty")
    {
        std::uint8_t http[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        std::string result = extract_tls_sni(http, sizeof(http) - 1);
        EXPECT(result.empty(), "Non-TLS should return empty");
    }
    END_TEST

    TEST("SNI extraction - truncated packet returns empty")
    {
        std::uint8_t trunc[] = { 0x16, 0x03, 0x01, 0x00 };
        std::string result = extract_tls_sni(trunc, sizeof(trunc));
        EXPECT(result.empty(), "Truncated should return empty");
    }
    END_TEST

    // ---------------------------------------------------------------
    // 5. AutoResponder Rule Matching
    // ---------------------------------------------------------------
    printf("\n--- AutoResponder Rule Matching ---\n");

    TEST("exact_url match")
    {
        rule_t r; r.mtype = match_type::exact_url; r.pattern = "http://example.com/api/v1";
        EXPECT(match_rule(r, "GET", "http://example.com/api/v1", {}, ""),
               "Should match exact URL");
        EXPECT(!match_rule(r, "GET", "http://example.com/api/v2", {}, ""),
               "Should NOT match different URL");
    }
    END_TEST

    TEST("prefix_url match")
    {
        rule_t r; r.mtype = match_type::prefix_url; r.pattern = "/api/";
        EXPECT(match_rule(r, "GET", "http://example.com/api/v1", {}, ""),
               "Should match prefix in URL");
        EXPECT(!match_rule(r, "GET", "http://example.com/other", {}, ""),
               "Should NOT match non-matching URL");
    }
    END_TEST

    TEST("sni_contains match (case insensitive)")
    {
        rule_t r; r.mtype = match_type::sni_contains; r.pattern = "google.com";
        EXPECT(match_rule(r, "CONNECT", "https://GOOGLE.COM/", {}, ""),
               "Should match case-insensitive");
        EXPECT(match_rule(r, "CONNECT", "https://www.Google.Com/search", {}, ""),
               "Should match subdomain");
        EXPECT(!match_rule(r, "CONNECT", "https://facebook.com/", {}, ""),
               "Should NOT match different domain");
    }
    END_TEST

    TEST("header_contains match")
    {
        rule_t r; r.mtype = match_type::header_contains; r.pattern = "bearer";
        std::map<std::string, std::string> hdrs = {{"Authorization", "bearer abc123"}};
        EXPECT(match_rule(r, "GET", "/api", hdrs, ""),
               "Should match header value");
    }
    END_TEST

    TEST("body_contains match")
    {
        rule_t r; r.mtype = match_type::body_contains; r.pattern = "malware";
        EXPECT(match_rule(r, "POST", "/upload", {}, "this has malware in body"),
               "Should match body content");
        EXPECT(!match_rule(r, "POST", "/upload", {}, "this is clean"),
               "Should NOT match clean body");
    }
    END_TEST

    TEST("method filter")
    {
        rule_t r; r.mtype = match_type::prefix_url; r.pattern = "/api/"; r.method = "POST";
        EXPECT(!match_rule(r, "GET", "http://x.com/api/v1", {}, ""),
               "GET should be filtered out");
        EXPECT(match_rule(r, "POST", "http://x.com/api/v1", {}, ""),
               "POST should match");
    }
    END_TEST

    TEST("disabled rule never matches")
    {
        rule_t r; r.mtype = match_type::exact_url; r.pattern = "http://x.com/"; r.enabled = false;
        EXPECT(!match_rule(r, "GET", "http://x.com/", {}, ""),
               "Disabled rule should not match");
    }
    END_TEST

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           g_tests_passed, g_tests_failed, g_tests_run);

    return g_tests_failed > 0 ? 1 : 0;
}
