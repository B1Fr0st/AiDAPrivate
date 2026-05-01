#include "tls_exporter.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <openssl/ssl.h>

#pragma comment(lib, "bcrypt.lib")

namespace aida::tls_exporter
{
    static std::string bytes_to_hex(const uint8_t* data, size_t len)
    {
        static const char hex[] = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            out.push_back(hex[data[i] >> 4]);
            out.push_back(hex[data[i] & 0x0F]);
        }
        return out;
    }

    static bool bcrypt_hmac_sha256(const uint8_t* key, size_t key_len,
                                    const uint8_t* data, size_t data_len,
                                    uint8_t out[32]) noexcept
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) return false;

        status = BCryptCreateHash(
            hAlg, &hHash, nullptr, 0,
            const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        status = BCryptHashData(
            hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
        if (status != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        status = BCryptFinishHash(hHash, out, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status == 0;
    }

    std::string compute_header_value_openssl(void* ssl_ctx) noexcept
    {
        if (!ssl_ctx) return {};

        auto* ssl = static_cast<SSL*>(ssl_ctx);

        uint8_t exported[kExporterLen] = {};
        int rc = SSL_export_keying_material(
            ssl,
            exported, kExporterLen,
            kExporterLabel, strlen(kExporterLabel),
            nullptr, 0, 0
        );
        if (rc != 1) return {};

        uint8_t hmac_out[32] = {};
        if (!bcrypt_hmac_sha256(exported, kExporterLen,
                                reinterpret_cast<const uint8_t*>(kExporterLabel),
                                strlen(kExporterLabel), hmac_out))
            return {};

        return bytes_to_hex(hmac_out, 32);
    }

    std::string derive_expected(const std::string& secret_hex) noexcept
    {
        if (secret_hex.size() != kExporterLen * 2) return {};

        uint8_t secret[kExporterLen] = {};
        for (uint32_t i = 0; i < kExporterLen; ++i) {
            auto hi = secret_hex[i * 2];
            auto lo = secret_hex[i * 2 + 1];
            auto nibble = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                return 0;
            };
            secret[i] = (nibble(hi) << 4) | nibble(lo);
        }

        uint8_t hmac_out[32] = {};
        if (!bcrypt_hmac_sha256(secret, kExporterLen,
                                reinterpret_cast<const uint8_t*>(kExporterLabel),
                                strlen(kExporterLabel), hmac_out))
            return {};

        return bytes_to_hex(hmac_out, 32);
    }
}
