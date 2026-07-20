#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "decoy_call_graph.hpp"
#include "decoy_core.hpp"
#include "state.hpp"
#include "webhook.hpp"
#include "key_pipeline.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../runtime/standalone_license.hpp"
#include "../runtime/reason_ids.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../../../../libs/nlohmann/json.hpp"
#include "../../../../../libs/cpp-httplib/httplib.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

#ifndef STATUS_GUARD_PAGE_VIOLATION
#define STATUS_GUARD_PAGE_VIOLATION ((DWORD)0x80000001L)
#endif

namespace anti_tamper::honeypot {

    enum class canary_status_t : uint8_t {
        CANARY_INTACT     = 0,
        CANARY_CORRUPTION = 1,
        CANARY_PATCHED    = 2,
    };

    enum class patch_type_t : uint8_t {
        CRC_INVALID_CORRUPTION = 0,
        CRC_VALID_PATCH        = 1,
    };

    struct canary_t {
        uint8_t  magic[16];
        uint8_t  signature[16];
        uint8_t  nonce[16];
        uint32_t crc32;
    };
    static_assert(sizeof(canary_t) == 52, "canary_t must be 52 bytes with CRC32");

    struct decoy_license_meta_t {
        uint64_t fn_addr;
        uint64_t canary_addr;
        uint64_t orig_crc;
        uint8_t  orig_canary[48];
        uint32_t fn_id;
        uint32_t canary_len;
        uint32_t check_interval_ms;
        uint8_t  patched;
        uint8_t  _pad[3];
    };
    static_assert(sizeof(decoy_license_meta_t) == 88, "decoy_license_meta_t layout");

    inline decoy_license_meta_t g_decoy_metas[5] = {};

    struct honeypot_string_access_t {
        std::atomic<uint64_t> string_addr{0};
        std::atomic<uint32_t> access_count{0};
        std::atomic<uint32_t> last_access_ms{0};
    };
    static_assert(sizeof(honeypot_string_access_t) == 16, "honeypot_string_access_t layout");

    inline honeypot_string_access_t g_string_access[20] = {};

    constexpr uint32_t HONEYPOT_BUGCHECK_STRING_ACCESS = 0xA1DA0001u;
    constexpr uint32_t HONEYPOT_BUGCHECK_CANARY_PATCH   = 0xA1DA0002u;
    constexpr uint32_t HONEYPOT_CHECK_INTERVAL_MS       = 30000;
    constexpr unsigned int HONEYPOT_FAST_FAIL_KEY_DERIVATION = 0xA1DA0A11u;

    __forceinline uint32_t crc32_ieee(const uint8_t* data, size_t len)
    {
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < len; ++i)
        {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j)
            {
                uint32_t mask = 0u - (crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
        return ~crc;
    }

    alignas(16) static volatile uint8_t s_canary_v1[52] = {
        0xCF, 0xBF, 0x48, 0x23, 0xDB, 0x74, 0x6F, 0xB3,
        0x15, 0xF2, 0x53, 0x95, 0xDE, 0x3B, 0x9E, 0x0B,
        0x4F, 0xA1, 0xA8, 0x86, 0x57, 0x74, 0x2A, 0x55,
        0x65, 0xFB, 0xD1, 0x43, 0x7D, 0x21, 0x7B, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xCE, 0x0F, 0x2D, 0x69
    };

    alignas(16) static volatile uint8_t s_canary_v2[52] = {
        0x99, 0x15, 0x63, 0x8E, 0xD3, 0x96, 0x0F, 0x8F,
        0xB8, 0x94, 0x59, 0x6D, 0xB0, 0xCB, 0xC0, 0x4A,
        0x95, 0x53, 0x56, 0x61, 0xA5, 0xBC, 0xAA, 0x84,
        0x67, 0x36, 0x48, 0x2F, 0xAD, 0x7A, 0x3E, 0xC7,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xED, 0x85, 0xB9, 0xD3
    };

    alignas(16) static volatile uint8_t s_canary_v3[52] = {
        0x90, 0xCF, 0xD2, 0x77, 0x6B, 0xE8, 0xEB, 0x15,
        0x1C, 0x0E, 0xFB, 0x4A, 0x4F, 0x73, 0x4B, 0x21,
        0x55, 0x6E, 0x52, 0x79, 0x28, 0x11, 0x4A, 0x5A,
        0xAA, 0xDD, 0xD0, 0x20, 0x2B, 0x92, 0xEC, 0xA5,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE9, 0xC2, 0x8A, 0xCC
    };

    alignas(16) static volatile uint8_t s_canary_v4[52] = {
        0xB1, 0x09, 0x8E, 0x28, 0xC8, 0xC0, 0xF0, 0x41,
        0xE9, 0x5B, 0xE4, 0xDE, 0x51, 0xB6, 0x40, 0x76,
        0x90, 0x44, 0xEE, 0x71, 0xF3, 0x94, 0x06, 0x78,
        0x3B, 0xAD, 0x78, 0x2F, 0x29, 0xD6, 0x41, 0x7F,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE9, 0x68, 0xF2, 0xD5
    };

    alignas(16) static volatile uint8_t s_canary_v5[52] = {
        0x33, 0xC8, 0xE3, 0xA5, 0x04, 0x6F, 0x22, 0x73,
        0x7E, 0xC3, 0x38, 0xC6, 0x40, 0x52, 0xCC, 0x8E,
        0x16, 0xA5, 0x03, 0x48, 0x5C, 0x61, 0x3E, 0xB2,
        0x13, 0x9F, 0x66, 0x38, 0x25, 0x59, 0xE1, 0x61,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0xFC, 0xD5, 0x61
    };

    static volatile uint8_t* s_canary_table[5] = {
        s_canary_v1, s_canary_v2, s_canary_v3, s_canary_v4, s_canary_v5
    };

    __forceinline canary_status_t check_canary(uint32_t decoy_id,
        const volatile uint8_t* canary, size_t len)
    {
        if (decoy_id >= 5 || len < 52) return canary_status_t::CANARY_CORRUPTION;

        uint8_t buf[52];
        memcpy(buf, (const void*)canary, 52);

        uint32_t stored_crc;
        memcpy(&stored_crc, buf + 48, 4);
        uint32_t computed_crc = crc32_ieee(buf, 48);

        if (computed_crc != stored_crc)
            return canary_status_t::CANARY_CORRUPTION;

        if (memcmp(buf, g_decoy_metas[decoy_id].orig_canary, 48) != 0)
            return canary_status_t::CANARY_PATCHED;

        return canary_status_t::CANARY_INTACT;
    }

    __forceinline void refresh_canary_from_backup(uint32_t decoy_id)
    {
        if (decoy_id >= 5) return;

        uint8_t nonce_buf[16] = {};
        uint32_t id = decoy_id;
        if (!key_pipeline::derive("aida.honeypot.canary.nonce",
            reinterpret_cast<const uint8_t*>(&id), sizeof(id), nonce_buf, 16))
        {
            __fastfail(HONEYPOT_FAST_FAIL_KEY_DERIVATION);
        }

        volatile uint8_t* canary = s_canary_table[decoy_id];
        for (int i = 0; i < 16; ++i)
            canary[32 + i] = nonce_buf[i];

        uint8_t raw[48];
        memcpy(raw, (const void*)canary, 48);
        uint32_t crc = crc32_ieee(raw, 48);
        canary[48] = (uint8_t)(crc & 0xFF);
        canary[49] = (uint8_t)((crc >> 8) & 0xFF);
        canary[50] = (uint8_t)((crc >> 16) & 0xFF);
        canary[51] = (uint8_t)((crc >> 24) & 0xFF);

        memcpy(g_decoy_metas[decoy_id].orig_canary, raw, 48);
        g_decoy_metas[decoy_id].orig_crc = crc;

        SecureZeroMemory(nonce_buf, sizeof(nonce_buf));
        SecureZeroMemory(raw, sizeof(raw));
    }

    __forceinline void trigger_immediate_bsod(uint32_t bug_code, uint32_t decoy_id)
    {
        if (decoy_id >= 5) return;

        diag::log_tagged_critical_fmt("honeypot",
            "trigger_immediate_bsod bug_code=0x%08X decoy_id=%u fn_addr=0x%016llX canary_addr=0x%016llX",
            bug_code, decoy_id,
            static_cast<unsigned long long>(g_decoy_metas[decoy_id].fn_addr),
            static_cast<unsigned long long>(g_decoy_metas[decoy_id].canary_addr));

        driver_bridge::trigger_kernel_bsod(bug_code,
            g_decoy_metas[decoy_id].fn_addr);
    }

    __forceinline void report_patch(uint32_t decoy_id, canary_status_t status)
    {
        if (decoy_id >= 5) return;

        char patch_location[64];
        _snprintf_s(patch_location, sizeof(patch_location), _TRUNCATE,
            "decoy_%u_addr=0x%llX", decoy_id,
            static_cast<unsigned long long>(g_decoy_metas[decoy_id].fn_addr));

        uint8_t raw[48];
        memcpy(raw, (const void*)s_canary_table[decoy_id], 48);
        uint32_t computed = crc32_ieee(raw, 48);
        uint32_t stored;
        memcpy(&stored, (const void*)(s_canary_table[decoy_id] + 48), 4);

        char patch_bytes[64];
        _snprintf_s(patch_bytes, sizeof(patch_bytes), _TRUNCATE,
            "computed_crc=0x%08X stored_crc=0x%08X", computed, stored);

        patch_type_t ptype = (status == canary_status_t::CANARY_PATCHED)
            ? patch_type_t::CRC_VALID_PATCH
            : patch_type_t::CRC_INVALID_CORRUPTION;

        nlohmann::json payload;
        payload["type"] = "patch_attempt";
        payload["patch_type"] = static_cast<uint8_t>(ptype);
        payload["hwid"] = webhook::get_computer_name();
        payload["license_key"] = standalone_license::get_session_token();
        payload["watermark"] = "aida_standalone";
        payload["patch_location"] = patch_location;
        payload["patch_bytes"] = patch_bytes;
        payload["decoy_id"] = decoy_id;
        payload["bug_code"] = static_cast<uint32_t>(HONEYPOT_BUGCHECK_CANARY_PATCH);

        webhook::write_log("honeypot",
            (std::string("patch_detected decoy_id=") + std::to_string(decoy_id) +
             " location=" + patch_location + " patch_type=" +
             std::to_string(static_cast<uint8_t>(ptype))).c_str());

        try {
            std::string host =
#ifdef AIDA_LOCAL_LICENSE_SERVER
                "http://localhost:3001";
#else
                "https://aidapro.net";
#endif
            httplib::Client cli(host);
            cli.set_connection_timeout(3);
            cli.set_read_timeout(3);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            cli.enable_server_certificate_verification(true);
#endif

            nlohmann::json body;
            body["hwid"] = webhook::get_computer_name();
            body["license_key"] = standalone_license::get_session_token();
            body["watermark"] = "aida_standalone";
            body["patch_location"] = patch_location;
            body["patch_bytes"] = patch_bytes;
            body["decoy_id"] = decoy_id;
            body["bug_code"] = static_cast<uint32_t>(HONEYPOT_BUGCHECK_CANARY_PATCH);
            body["patch_type"] = static_cast<uint8_t>(ptype);
            body["computed_crc"] = computed;
            body["stored_crc"] = stored;

            std::string body_str = body.dump();
            cli.Post("/api/honeypot/patch-attempt", body_str, "application/json");
        } catch (...) {}

        SecureZeroMemory(raw, sizeof(raw));
    }

    __forceinline void on_canary_patched(uint32_t decoy_id)
    {
        if (decoy_id >= 5) return;
        g_decoy_metas[decoy_id].patched = 1;
        report_patch(decoy_id, canary_status_t::CANARY_PATCHED);
        trigger_immediate_bsod(HONEYPOT_BUGCHECK_CANARY_PATCH, decoy_id);
    }

    __forceinline void periodic_canary_check()
    {
        for (uint32_t i = 0; i < 5; ++i)
        {
            auto& meta = g_decoy_metas[i];
            if (meta.fn_addr == 0) continue;

            canary_status_t status = check_canary(i,
                reinterpret_cast<const volatile uint8_t*>(meta.canary_addr),
                meta.canary_len);

            if (status == canary_status_t::CANARY_CORRUPTION)
            {
                auto& rt = state::get();
                rt.decoy_honeypot_count.fetch_add(1, std::memory_order_relaxed);
                webhook::write_log("honeypot",
                    ("canary_corruption_not_patch decoy_id=" + std::to_string(i)).c_str());
                refresh_canary_from_backup(i);
                continue;
            }

            if (status == canary_status_t::CANARY_PATCHED)
            {
                on_canary_patched(i);
            }
        }
    }

    __forceinline void track_string_access(uint32_t string_idx)
    {
        if (string_idx >= 20) return;
        auto& entry = g_string_access[string_idx];
        entry.access_count.fetch_add(1, std::memory_order_relaxed);
        entry.last_access_ms.store(
            static_cast<uint32_t>(state::monotonic_ms() & 0xFFFFFFFF),
            std::memory_order_release);

        if (entry.access_count.load(std::memory_order_acquire) == 1)
        {
            webhook::write_log("honeypot",
                ("honeypot_string_accessed idx=" + std::to_string(string_idx)).c_str());
        }
    }

#pragma section(".hpot", read)
__declspec(allocate(".hpot"))
inline volatile const char* g_license_honeypot_strings[] = {
    "https://api.aidapro.net/v2/license/bypass",
    "https://api.aidapro.net/v2/license/offline_activate",
    "https://api.aidapro.net/internal/admin/force_valid",
    "sk_license_4eC39HqLyjWDarjtT1zdp7dc",
    "sk_license_b3F82aK9mP5vW8jF3bY5hT6dA1cE0gN",
    "License validation passed: method=offline_bypass",
    "License validation passed: method=server_emulation",
    "License bypass token: %016llx",
    "allow_offline_mode=true",
    "skip_hwid_check=true",
    "bypass_gate_validation=1",
    "AIDA_OFFLINE_LICENSE_KEY=VALID",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\AiDA\\BypassKey",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\AiDA\\OfflineMode",
    "POST /api/v2/license/force_validate HTTP/1.1\r\nX-Bypass: true\r\n",
    "X-License-Bypass: %016llx\r\nX-Offline-Token: %016llx",
    "SELECT license_key, hwid FROM licenses WHERE bypass=1",
    "wss://relay.aidapro.net/v2/bypass?token=%s",
    "license_emulator_enabled=true",
    "decoy_validation_passed: function=validate_v1",
};

    __declspec(noinline) static bool __cdecl decoy_license_validate_v1(
        uint64_t key_hash, uint64_t hwid_hash, uint64_t session_token_hash)
    {
        anti_tamper::decoy::work::capture_or_check_crc(27,
            reinterpret_cast<const void*>(&decoy_license_validate_v1), 32);

        uint8_t blob[24];
        std::memcpy(blob, &key_hash, 8);
        std::memcpy(blob + 8, &hwid_hash, 8);
        std::memcpy(blob + 16, &session_token_hash, 8);
        uint8_t hash[32] = {};
        anti_tamper::decoy::work::sha256(blob, sizeof(blob), hash);
        std::memcpy(anti_tamper::decoy::work::s_tls_sink_buf, hash, 32);

        anti_tamper::decoy::work::touch_real_globals();

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);

        HKEY hKey = nullptr;
        __try {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AiDA",
                0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                WCHAR val[256] = {};
                DWORD sz = sizeof(val);
                RegQueryValueExW(hKey, L"LicenseMode", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(val), &sz);
                RegCloseKey(hKey);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (hKey) RegCloseKey(hKey);
        }

        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 0);
        uint64_t hw_mix = static_cast<uint64_t>(cpuid_buf[0]) ^
                         static_cast<uint64_t>(cpuid_buf[1]) ^
                         __rdtsc();
        anti_tamper::decoy::work::s_tls_sink_a ^= hw_mix;

        uint64_t alloc_h = anti_tamper::decoy::work::real_alloc_free_round(64);
        anti_tamper::decoy::work::s_tls_sink_b ^= alloc_h;

        volatile uint8_t canary_read = s_canary_v1[0];
        (void)canary_read;

        if (anti_tamper::decoy::opaque_false(__rdtsc()))
            return false;

        track_string_access(0);
        return true;
    }

    __declspec(noinline) static bool __cdecl decoy_license_validate_v2(
        uint64_t nonce, uint64_t server_proof, uint64_t arc_token)
    {
        anti_tamper::decoy::work::capture_or_check_crc(28,
            reinterpret_cast<const void*>(&decoy_license_validate_v2), 32);

        uint8_t blob[24];
        std::memcpy(blob, &nonce, 8);
        std::memcpy(blob + 8, &server_proof, 8);
        std::memcpy(blob + 16, &arc_token, 8);
        uint8_t hash[32] = {};
        anti_tamper::decoy::work::sha256(blob, sizeof(blob), hash);
        std::memcpy(anti_tamper::decoy::work::s_tls_sink_buf, hash, 32);

        anti_tamper::decoy::work::touch_real_globals();

        HINTERNET hInet = WinHttpOpen(L"AiDAStandalone/4.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (hInet)
        {
            DWORD timeout = 1000;
            WinHttpSetTimeouts(hInet, timeout, timeout, timeout, timeout);
            HINTERNET hConn = WinHttpConnect(hInet, L"127.0.0.1",
                INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (hConn)
            {
                HINTERNET hReq = WinHttpOpenRequest(hConn, L"HEAD",
                    L"/license", nullptr, WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (hReq)
                {
                    WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
                    WinHttpCloseHandle(hReq);
                }
                WinHttpCloseHandle(hConn);
            }
            WinHttpCloseHandle(hInet);
        }

        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 1);
        volatile uint64_t tsc = __rdtsc();
        anti_tamper::decoy::work::s_tls_sink_a ^= tsc ^ static_cast<uint64_t>(cpuid_buf[0]);

        uint64_t alloc_h = anti_tamper::decoy::work::real_alloc_free_round(128);
        anti_tamper::decoy::work::s_tls_sink_b ^= alloc_h;

        volatile uint8_t canary_read = s_canary_v2[0];
        (void)canary_read;

        if (anti_tamper::decoy::opaque_false(__rdtsc()))
            return false;

        track_string_access(1);
        return true;
    }

    __declspec(noinline) static double __cdecl decoy_license_proof_v3(
        uint64_t gate_slot, uint64_t token, uint64_t challenge)
    {
        anti_tamper::decoy::work::capture_or_check_crc(29,
            reinterpret_cast<const void*>(&decoy_license_proof_v3), 32);

        uint8_t blob[24];
        std::memcpy(blob, &gate_slot, 8);
        std::memcpy(blob + 8, &token, 8);
        std::memcpy(blob + 16, &challenge, 8);
        uint8_t hash[32] = {};
        anti_tamper::decoy::work::sha256(blob, sizeof(blob), hash);
        std::memcpy(anti_tamper::decoy::work::s_tls_sink_buf, hash, 32);

        anti_tamper::decoy::work::touch_real_globals();

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER ui;
        ui.LowPart = ft.dwLowDateTime;
        ui.HighPart = ft.dwHighDateTime;
        volatile uint64_t ts = ui.QuadPart / 10000ULL;
        anti_tamper::decoy::work::s_tls_sink_a ^= ts;

        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0)
        {
            BCRYPT_HASH_HANDLE h = nullptr;
            if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0)
            {
                BCryptHashData(h, reinterpret_cast<PUCHAR>(blob), sizeof(blob), 0);
                uint8_t out[32] = {};
                BCryptFinishHash(h, out, 32, 0);
                BCryptDestroyHash(h);
                std::memcpy(anti_tamper::decoy::work::s_tls_sink_buf, out, 32);
            }
            BCryptCloseAlgorithmProvider(alg, 0);
        }

        uint64_t alloc_h = anti_tamper::decoy::work::real_alloc_free_round(64);
        anti_tamper::decoy::work::s_tls_sink_b ^= alloc_h;

        volatile uint8_t canary_read = s_canary_v3[0];
        (void)canary_read;

        double proof = 1.0;
        if (anti_tamper::decoy::opaque_false(__rdtsc()))
            proof = 0.0;

        track_string_access(2);
        return proof;
    }

    __declspec(noinline) static bool __cdecl decoy_license_entitlement_v4(
        uint64_t feature_mask, uint64_t tier_hash, uint64_t hwid_hash)
    {
        anti_tamper::decoy::work::capture_or_check_crc(30,
            reinterpret_cast<const void*>(&decoy_license_entitlement_v4), 32);

        uint8_t blob[24];
        std::memcpy(blob, &feature_mask, 8);
        std::memcpy(blob + 8, &tier_hash, 8);
        std::memcpy(blob + 16, &hwid_hash, 8);
        uint8_t hash[32] = {};
        anti_tamper::decoy::work::sha256(blob, sizeof(blob), hash);
        std::memcpy(anti_tamper::decoy::work::s_tls_sink_buf, hash, 32);

        anti_tamper::decoy::work::touch_real_globals();

        __try {
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AiDA",
                0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                WCHAR val[256] = {};
                DWORD sz = sizeof(val);
                RegQueryValueExW(hKey, L"EntitlementTier", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(val), &sz);
                RegCloseKey(hKey);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 0x80000001);
        volatile uint64_t hw = static_cast<uint64_t>(cpuid_buf[2]) ^ __rdtsc();
        anti_tamper::decoy::work::s_tls_sink_a ^= hw;

        uint64_t alloc_h = anti_tamper::decoy::work::real_alloc_free_round(96);
        anti_tamper::decoy::work::s_tls_sink_b ^= alloc_h;

        volatile uint8_t canary_read = s_canary_v4[0];
        (void)canary_read;

        if (anti_tamper::decoy::opaque_false(__rdtsc()))
            return false;

        track_string_access(3);
        return true;
    }

    __declspec(noinline) static bool __cdecl decoy_license_integrity_v5(
        uint64_t code_hash, uint64_t server_nonce, uint64_t session_epoch)
    {
        anti_tamper::decoy::work::capture_or_check_crc(31,
            reinterpret_cast<const void*>(&decoy_license_integrity_v5), 32);

        uint8_t blob[24];
        std::memcpy(blob, &code_hash, 8);
        std::memcpy(blob + 8, &server_nonce, 8);
        std::memcpy(blob + 16, &session_epoch, 8);
        uint8_t hash[32] = {};
        anti_tamper::decoy::work::sha256(blob, sizeof(blob), hash);
        std::memcpy(anti_tamper::decoy::work::s_tls_sink_buf, hash, 32);

        anti_tamper::decoy::work::touch_real_globals();

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);

        uint64_t alloc_h = anti_tamper::decoy::work::real_alloc_free_round(64);
        anti_tamper::decoy::work::s_tls_sink_b ^= alloc_h;

        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 1);
        volatile uint64_t mix = static_cast<uint64_t>(cpuid_buf[0]) ^
            static_cast<uint64_t>(cpuid_buf[3]) ^ __rdtsc();
        anti_tamper::decoy::work::s_tls_sink_a ^= mix;

        volatile uint8_t canary_read = s_canary_v5[0];
        (void)canary_read;

        if (anti_tamper::decoy::opaque_false(__rdtsc()))
            return false;

        track_string_access(4);
        return true;
    }

    __declspec(noinline) static bool __cdecl fake_path_license_init(
        uint64_t session_key, uint64_t hwid)
    {
        volatile bool r1 = decoy_license_validate_v1(session_key, hwid, __rdtsc());
        volatile bool r2 = decoy_license_validate_v2(__rdtsc(), session_key, hwid);
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r1 && r2;
    }

    __declspec(noinline) static bool __cdecl fake_path_gate_check(
        uint32_t slot, uint64_t token)
    {
        volatile double proof = decoy_license_proof_v3(slot, token, __rdtsc());
        volatile bool r = proof >= 0.5;
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r;
    }

    __declspec(noinline) static bool __cdecl fake_path_heartbeat_validate(
        uint64_t server_nonce, uint64_t code_hash)
    {
        volatile bool r = decoy_license_integrity_v5(code_hash, server_nonce, __rdtsc());
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r;
    }

    __declspec(noinline) static bool __cdecl fake_path_arc_activation(
        uint64_t arc_token, uint64_t hwid_hash)
    {
        volatile bool r = decoy_license_entitlement_v4(arc_token, 0, hwid_hash);
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r;
    }

    __declspec(noinline) static bool __cdecl fake_path_subscription_check(
        uint64_t feature_mask, uint64_t tier)
    {
        volatile bool r = decoy_license_entitlement_v4(feature_mask, tier, __rdtsc());
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r;
    }

    __declspec(noinline) static bool __cdecl fake_path_session_integrity(
        uint64_t session_epoch, uint64_t server_nonce)
    {
        volatile bool r = decoy_license_integrity_v5(__rdtsc(), server_nonce, session_epoch);
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r;
    }

    __declspec(noinline) static bool __cdecl fake_path_hwid_binding(
        uint64_t hwid_hash, uint64_t expected_hash)
    {
        volatile bool r = decoy_license_validate_v1(hwid_hash, expected_hash, __rdtsc());
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r;
    }

    __declspec(noinline) static bool __cdecl fake_path_offline_cache(
        uint64_t cached_token, uint64_t cached_epoch)
    {
        volatile bool r = decoy_license_validate_v2(cached_token, cached_epoch, __rdtsc());
        anti_tamper::decoy::work::touch_real_globals();
        if (anti_tamper::decoy::opaque_false(__rdtsc())) return false;
        return r;
    }

    constexpr int HONEYPOT_FAKE_IMPORT_COUNT = 8;

    struct honeypot_fake_iat_entry_t {
        const char* name;
        void*       addr;
    };

    inline volatile honeypot_fake_iat_entry_t g_honeypot_fake_imports[] = {
        {"NtValidateLicenseSession",  (void*)&fake_path_license_init},
        {"NtCheckGateToken",          (void*)&fake_path_gate_check},
        {"NtVerifyHeartbeat",         (void*)&fake_path_heartbeat_validate},
        {"NtActivateArc",             (void*)&fake_path_arc_activation},
        {"NtCheckSubscriptionTier",   (void*)&fake_path_subscription_check},
        {"NtVerifySessionIntegrity",  (void*)&fake_path_session_integrity},
        {"NtBindHwid",                (void*)&fake_path_hwid_binding},
        {"NtValidateOfflineCache",    (void*)&fake_path_offline_cache},
    };

    __declspec(noinline) static void __cdecl anchor_honeypot_graph()
    {
        volatile uintptr_t sink = 0;
        sink += reinterpret_cast<uintptr_t>(&decoy_license_validate_v1);
        sink += reinterpret_cast<uintptr_t>(&decoy_license_validate_v2);
        sink += reinterpret_cast<uintptr_t>(&decoy_license_proof_v3);
        sink += reinterpret_cast<uintptr_t>(&decoy_license_entitlement_v4);
        sink += reinterpret_cast<uintptr_t>(&decoy_license_integrity_v5);
        sink += reinterpret_cast<uintptr_t>(&fake_path_license_init);
        sink += reinterpret_cast<uintptr_t>(&fake_path_gate_check);
        sink += reinterpret_cast<uintptr_t>(&fake_path_heartbeat_validate);
        sink += reinterpret_cast<uintptr_t>(&fake_path_arc_activation);
        sink += reinterpret_cast<uintptr_t>(&fake_path_subscription_check);
        sink += reinterpret_cast<uintptr_t>(&fake_path_session_integrity);
        sink += reinterpret_cast<uintptr_t>(&fake_path_hwid_binding);
        sink += reinterpret_cast<uintptr_t>(&fake_path_offline_cache);

        for (int i = 0; i < 20; ++i)
            sink += reinterpret_cast<uintptr_t>(g_license_honeypot_strings[i]);

        for (int i = 0; i < 5; ++i)
            sink += reinterpret_cast<uintptr_t>(s_canary_table[i]);

        (void)sink;
    }

    struct module_range_t {
        uint64_t base;
        uint64_t size;
    };

    inline module_range_t g_aida_module_range = {};
    inline DWORD g_honeypot_page_size = 4096;

    struct honeypot_string_range_t {
        uint64_t addr;
        uint64_t length;
    };

    inline honeypot_string_range_t g_honeypot_ranges[20] = {};
    inline void* g_honeypot_guard_pages[64] = {};
    inline uint32_t g_honeypot_guard_page_count = 0;
    inline PVOID g_honeypot_veh_handle = nullptr;

    __declspec(noinline) static DWORD post_honeypot_access_winhttp_seh(
        const char* body, DWORD body_size)
    {
        HINTERNET h_session = nullptr;
        HINTERNET h_connect = nullptr;
        HINTERNET h_request = nullptr;
        DWORD observed_seh_code = ERROR_SUCCESS;

        __try
        {
            h_session = WinHttpOpen(L"AiDAStandalone/4.0",
                WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS, 0);
            if (h_session)
            {
                DWORD timeout = 3000;
                WinHttpSetTimeouts(h_session, timeout, timeout, timeout, timeout);

                const wchar_t* host = L"aidapro.net";
                INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
                DWORD flags = WINHTTP_FLAG_SECURE;

#ifdef AIDA_LOCAL_LICENSE_SERVER
                host = L"localhost";
                port = 3001;
                flags = 0;
#endif
                h_connect = WinHttpConnect(h_session, host, port, 0);
                if (h_connect)
                {
                    h_request = WinHttpOpenRequest(h_connect, L"POST",
                        L"/api/honeypot/honeypot-access", nullptr,
                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
                    if (h_request)
                    {
                        wchar_t headers[] = L"Content-Type: application/json\r\n";
                        if (WinHttpSendRequest(h_request, headers,
                            static_cast<DWORD>(_countof(headers) - 1),
                            const_cast<char*>(body), body_size, body_size, 0))
                        {
                            WinHttpReceiveResponse(h_request, nullptr);
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            observed_seh_code = GetExceptionCode();
        }

        if (h_request) WinHttpCloseHandle(h_request);
        if (h_connect) WinHttpCloseHandle(h_connect);
        if (h_session) WinHttpCloseHandle(h_session);
        return observed_seh_code;
    }

    __forceinline void report_honeypot_access(uint64_t accessed_addr, uint64_t rip, uint32_t pid)
    {
        char log_buf[160];
        _snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
            "honeypot_string_access addr=0x%016llX rip=0x%016llX pid=%u",
            static_cast<unsigned long long>(accessed_addr),
            static_cast<unsigned long long>(rip),
            pid);
        webhook::write_log("honeypot", log_buf);

        nlohmann::json body;
        body["accessed_addr"] = static_cast<unsigned long long>(accessed_addr);
        body["rip"] = static_cast<unsigned long long>(rip);
        body["pid"] = pid;
        body["hwid"] = webhook::get_computer_name();
        body["license_key"] = standalone_license::get_session_token();
        body["watermark"] = "aida_standalone";
        body["bug_code"] = static_cast<uint32_t>(HONEYPOT_BUGCHECK_STRING_ACCESS);
        std::string body_str = body.dump();
        const DWORD observed_seh_code = post_honeypot_access_winhttp_seh(
            body_str.data(), static_cast<DWORD>(body_str.size()));
        if (observed_seh_code != ERROR_SUCCESS)
        {
            webhook::write_log_critical_fmt("honeypot",
                "honeypot_access_post_seh code=0x%08X", observed_seh_code);
        }
    }

    __declspec(noinline) static LONG WINAPI honeypot_guard_page_handler(EXCEPTION_POINTERS* ep)
    {
        if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;

        thread_local int recursion_guard = 0;
        if (recursion_guard > 0)
        {
            DWORD old_protect = 0;
            uintptr_t page_base = static_cast<uintptr_t>(
                ep->ExceptionRecord->ExceptionInformation[1]) &
                ~static_cast<uintptr_t>(g_honeypot_page_size - 1);
            VirtualProtect(reinterpret_cast<LPVOID>(page_base),
                g_honeypot_page_size, PAGE_READONLY | PAGE_GUARD, &old_protect);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        ++recursion_guard;

        uint64_t fault_addr = static_cast<uint64_t>(
            ep->ExceptionRecord->ExceptionInformation[1]);

        bool in_honeypot = false;
        for (uint32_t i = 0; i < 20; ++i)
        {
            if (g_honeypot_ranges[i].addr == 0 || g_honeypot_ranges[i].length == 0)
                continue;
            if (fault_addr >= g_honeypot_ranges[i].addr &&
                fault_addr < g_honeypot_ranges[i].addr + g_honeypot_ranges[i].length)
            {
                in_honeypot = true;
                break;
            }
        }

        if (!in_honeypot)
        {
            DWORD old_protect = 0;
            uintptr_t page_base = static_cast<uintptr_t>(fault_addr) &
                ~static_cast<uintptr_t>(g_honeypot_page_size - 1);
            VirtualProtect(reinterpret_cast<LPVOID>(page_base),
                g_honeypot_page_size, PAGE_READONLY | PAGE_GUARD, &old_protect);
            --recursion_guard;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        uint64_t rip = ep->ContextRecord->Rip;
        uint32_t pid = GetCurrentProcessId();

        bool external = false;
        if (g_aida_module_range.base != 0 && g_aida_module_range.size != 0)
        {
            if (rip < g_aida_module_range.base ||
                rip >= g_aida_module_range.base + g_aida_module_range.size)
                external = true;
        }

        diag::log_tagged_critical_fmt("honeypot",
            "guard_page_violation addr=0x%016llX rip=0x%016llX pid=%u external=%d",
            static_cast<unsigned long long>(fault_addr),
            static_cast<unsigned long long>(rip),
            pid, external ? 1 : 0);

        report_honeypot_access(fault_addr, rip, pid);

        if (external)
        {
            driver_bridge::trigger_kernel_bsod(
                HONEYPOT_BUGCHECK_STRING_ACCESS, fault_addr);
        }

        DWORD old_protect = 0;
        uintptr_t page_base = static_cast<uintptr_t>(fault_addr) &
            ~static_cast<uintptr_t>(g_honeypot_page_size - 1);
        VirtualProtect(reinterpret_cast<LPVOID>(page_base),
            g_honeypot_page_size, PAGE_READONLY | PAGE_GUARD, &old_protect);

        --recursion_guard;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    __forceinline void install_honeypot_guard_pages()
    {
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);
        g_honeypot_page_size = si.dwPageSize;
        if (g_honeypot_page_size == 0)
            g_honeypot_page_size = 4096;

        HMODULE hMod = GetModuleHandleW(nullptr);
        if (hMod)
        {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE)
            {
                auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                {
                    g_aida_module_range.base = reinterpret_cast<uint64_t>(hMod);
                    g_aida_module_range.size = nt->OptionalHeader.SizeOfImage;
                }
            }
        }

        g_honeypot_guard_page_count = 0;

        for (uint32_t i = 0; i < 20; ++i)
        {
            const char* str = const_cast<const char*>(g_license_honeypot_strings[i]);
            if (!str) continue;

            uint64_t addr = reinterpret_cast<uint64_t>(str);
            uint64_t len = std::strlen(str);
            if (len == 0)
            {
                g_honeypot_ranges[i].addr = 0;
                g_honeypot_ranges[i].length = 0;
                continue;
            }

            g_honeypot_ranges[i].addr = addr;
            g_honeypot_ranges[i].length = len;

            uint64_t start_page = addr & ~static_cast<uint64_t>(g_honeypot_page_size - 1);
            uint64_t end_page = (addr + len - 1) & ~static_cast<uint64_t>(g_honeypot_page_size - 1);

            for (uint64_t page = start_page; page <= end_page; page += g_honeypot_page_size)
            {
                bool already = false;
                for (uint32_t j = 0; j < g_honeypot_guard_page_count; ++j)
                {
                    if (reinterpret_cast<uint64_t>(g_honeypot_guard_pages[j]) == page)
                    {
                        already = true;
                        break;
                    }
                }
                if (!already && g_honeypot_guard_page_count < 64)
                {
                    DWORD old_protect = 0;
                    if (VirtualProtect(reinterpret_cast<LPVOID>(static_cast<uintptr_t>(page)),
                        g_honeypot_page_size, PAGE_READONLY | PAGE_GUARD, &old_protect))
                    {
                        g_honeypot_guard_pages[g_honeypot_guard_page_count++] =
                            reinterpret_cast<void*>(static_cast<uintptr_t>(page));
                    }
                }
            }
        }

        g_honeypot_veh_handle = AddVectoredExceptionHandler(1,
            reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(honeypot_guard_page_handler));

        char log_buf[160];
        _snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
            "guard_pages_installed count=%u module_base=0x%016llX module_size=0x%08X veh=%p",
            g_honeypot_guard_page_count,
            static_cast<unsigned long long>(g_aida_module_range.base),
            static_cast<uint32_t>(g_aida_module_range.size),
            g_honeypot_veh_handle);
        webhook::write_log("honeypot", log_buf);
    }

    __declspec(noinline) static DWORD register_canary_seh(
        volatile uint8_t* canary, size_t size, BOOL* registered)
    {
        if (registered) *registered = FALSE;
        DWORD observed_seh_code = ERROR_SUCCESS;
        __try
        {
            const bool ok = driver_bridge::canary_register(
                static_cast<void*>(const_cast<uint8_t*>(canary)), size);
            if (registered) *registered = ok ? TRUE : FALSE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            observed_seh_code = GetExceptionCode();
        }
        return observed_seh_code;
    }

    inline void initialize()
    {
        anchor_honeypot_graph();

        volatile uintptr_t hp_sink = 0;
        for (int i = 0; i < HONEYPOT_FAKE_IMPORT_COUNT; ++i)
            hp_sink += reinterpret_cast<uintptr_t>(g_honeypot_fake_imports[i].addr);
        (void)hp_sink;

        for (uint32_t i = 0; i < 20; ++i)
        {
            g_string_access[i].string_addr.store(
                reinterpret_cast<uint64_t>(g_license_honeypot_strings[i]),
                std::memory_order_release);
        }

        for (uint32_t i = 0; i < 5; ++i)
        {
            uint8_t nonce_buf[16] = {};
            uint32_t id = i;
            if (!key_pipeline::derive("aida.honeypot.canary.nonce",
                reinterpret_cast<const uint8_t*>(&id), sizeof(id), nonce_buf, 16))
            {
                __fastfail(HONEYPOT_FAST_FAIL_KEY_DERIVATION);
            }

            volatile uint8_t* canary = s_canary_table[i];
            for (int j = 0; j < 16; ++j)
                canary[32 + j] = nonce_buf[j];

            uint8_t raw[48];
            memcpy(raw, (const void*)canary, 48);
            uint32_t crc = crc32_ieee(raw, 48);
            canary[48] = (uint8_t)(crc & 0xFF);
            canary[49] = (uint8_t)((crc >> 8) & 0xFF);
            canary[50] = (uint8_t)((crc >> 16) & 0xFF);
            canary[51] = (uint8_t)((crc >> 24) & 0xFF);

            auto& meta = g_decoy_metas[i];
            meta.fn_id = i;
            meta.canary_len = 52;
            meta.check_interval_ms = HONEYPOT_CHECK_INTERVAL_MS;
            meta.patched = 0;
            meta.fn_addr = reinterpret_cast<uint64_t>(
                i == 0 ? reinterpret_cast<void*>(&decoy_license_validate_v1) :
                i == 1 ? reinterpret_cast<void*>(&decoy_license_validate_v2) :
                i == 2 ? reinterpret_cast<void*>(&decoy_license_proof_v3) :
                i == 3 ? reinterpret_cast<void*>(&decoy_license_entitlement_v4) :
                         reinterpret_cast<void*>(&decoy_license_integrity_v5));
            meta.canary_addr = reinterpret_cast<uint64_t>(canary);
            meta.orig_crc = crc;
            memcpy(meta.orig_canary, raw, 48);

            SecureZeroMemory(nonce_buf, sizeof(nonce_buf));
            SecureZeroMemory(raw, sizeof(raw));

            BOOL registered = FALSE;
            const DWORD observed_seh_code = register_canary_seh(canary, 52, &registered);
            if (observed_seh_code != ERROR_SUCCESS)
            {
                char register_log[128];
                _snprintf_s(register_log, sizeof(register_log), _TRUNCATE,
                    "canary_register_seh_exception decoy_id=%u code=0x%08X",
                    i, observed_seh_code);
                webhook::write_log("honeypot", register_log);
            }
        }

        install_honeypot_guard_pages();

        webhook::write_log("honeypot", "honeypot_initialize_complete");
    }

}

#define HONEYPOT_LICENSE_WEAVE(tag)                                              \
    do {                                                                         \
        constexpr uint64_t _hl_seed_##tag =                                      \
            (uint64_t)__LINE__ * 0x9E3779B97F4A7C15ULL;                          \
        if (anti_tamper::decoy::runtime_gate(_hl_seed_##tag)) {                  \
            volatile bool _hl_r1_##tag =                                         \
                anti_tamper::honeypot::fake_path_gate_check(                     \
                    static_cast<uint32_t>(__LINE__ & 0xFF),                      \
                    _hl_seed_##tag ^ __rdtsc());                                 \
            volatile bool _hl_r2_##tag =                                         \
                anti_tamper::honeypot::fake_path_session_integrity(              \
                    _hl_seed_##tag, __rdtsc());                                  \
            (void)_hl_r1_##tag;                                                  \
            (void)_hl_r2_##tag;                                                  \
            anti_tamper::decoy::g_decoy_sink ^= _hl_seed_##tag;                  \
        }                                                                        \
    } while (0)
