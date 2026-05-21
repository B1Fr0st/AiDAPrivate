#include "tls_exporter.hpp"
#include "helpers/diag_log.hpp"

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
        diag::log_tagged_fmt("tls", "bcrypt_hmac_sha256 entry key_len=%zu data_len=%zu", key_len, data_len);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) {
            diag::log_tagged_fmt("tls", "bcrypt_hmac_sha256 BCryptOpenAlgorithmProvider failed status=0x%lx", status);
            return false;
        }

        status = BCryptCreateHash(
            hAlg, &hHash, nullptr, 0,
            const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
        if (status != 0) {
            diag::log_tagged_fmt("tls", "bcrypt_hmac_sha256 BCryptCreateHash failed status=0x%lx", status);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        status = BCryptHashData(
            hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
        if (status != 0) {
            diag::log_tagged_fmt("tls", "bcrypt_hmac_sha256 BCryptHashData failed status=0x%lx", status);
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        status = BCryptFinishHash(hHash, out, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status != 0) {
            diag::log_tagged_fmt("tls", "bcrypt_hmac_sha256 BCryptFinishHash failed status=0x%lx", status);
        } else {
            diag::log_tagged("tls", "bcrypt_hmac_sha256 success");
        }
        return status == 0;
    }

    std::string compute_header_value_openssl(void* ssl_ctx) noexcept
    {
        diag::log_tagged_fmt("tls", "compute_header_value_openssl entry ssl_ctx=%p", ssl_ctx);
        if (!ssl_ctx) {
            diag::log_tagged("tls", "compute_header_value_openssl null ssl_ctx");
            return {};
        }

        auto* ssl = static_cast<SSL*>(ssl_ctx);

        uint8_t exported[kExporterLen] = {};
        int rc = SSL_export_keying_material(
            ssl,
            exported, kExporterLen,
            kExporterLabel, strlen(kExporterLabel),
            nullptr, 0, 0
        );
        diag::log_tagged_fmt("tls", "compute_header_value_openssl SSL_export_keying_material rc=%d label=%s len=%zu", rc, kExporterLabel, kExporterLen);
        if (rc != 1) {
            diag::log_tagged("tls", "compute_header_value_openssl SSL_export_keying_material failed");
            return {};
        }

        uint8_t hmac_out[32] = {};
        bool hmac_ok = bcrypt_hmac_sha256(exported, kExporterLen,
                                reinterpret_cast<const uint8_t*>(kExporterLabel),
                                strlen(kExporterLabel), hmac_out);
        diag::log_tagged_fmt("tls", "compute_header_value_openssl hmac_ok=%d", (int)hmac_ok);
        if (!hmac_ok)
            return {};

        std::string result = bytes_to_hex(hmac_out, 32);
        diag::log_tagged_fmt("tls", "compute_header_value_openssl success result_len=%zu", result.size());
        return result;
    }

    std::string derive_expected(const std::string& secret_hex) noexcept
    {
        diag::log_tagged_fmt("tls", "derive_expected entry secret_hex_len=%zu expected=%zu", secret_hex.size(), kExporterLen * 2);
        if (secret_hex.size() != kExporterLen * 2) {
            diag::log_tagged_fmt("tls", "derive_expected invalid secret_hex size got=%zu expected=%zu", secret_hex.size(), kExporterLen * 2);
            return {};
        }

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
        diag::log_tagged_fmt("tls", "derive_expected hex decoded %zu bytes", kExporterLen);

        uint8_t hmac_out[32] = {};
        bool hmac_ok = bcrypt_hmac_sha256(secret, kExporterLen,
                                reinterpret_cast<const uint8_t*>(kExporterLabel),
                                strlen(kExporterLabel), hmac_out);
        diag::log_tagged_fmt("tls", "derive_expected hmac_ok=%d", (int)hmac_ok);
        if (!hmac_ok)
            return {};

        std::string result = bytes_to_hex(hmac_out, 32);
        diag::log_tagged_fmt("tls", "derive_expected success result_len=%zu", result.size());
        return result;
    }
}
