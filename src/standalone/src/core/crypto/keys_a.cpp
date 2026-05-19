#include "keys.hpp"
#include "share_self_check.hpp"

#include <Windows.h>
#include <cstdint>
#include <cstring>

#pragma section(".aidashr", read)

namespace
{
    volatile uint8_t k_share_a[aida::pubkeys::kid_count][32] = {
        {
            0x04, 0x9E, 0xD7, 0x4A, 0x6F, 0x0E, 0x19, 0x69,
            0x8F, 0x75, 0x9C, 0xC0, 0x63, 0xBB, 0xE0, 0xBC,
            0xA0, 0xA9, 0xF7, 0xF7, 0x3C, 0x81, 0x8A, 0xDB,
            0x81, 0x4E, 0x9B, 0xE8, 0xBE, 0x03, 0xA6, 0x48
        },
        {
            0xBE, 0x7B, 0xA7, 0x4A, 0xA9, 0xB8, 0xA2, 0x30,
            0xD6, 0x61, 0x4D, 0x8D, 0x0C, 0x78, 0xE0, 0xE5,
            0x33, 0xAD, 0xFA, 0x2A, 0xBD, 0xC3, 0xD6, 0x32,
            0x84, 0x38, 0xC3, 0x78, 0x07, 0x7A, 0xDC, 0x90
        },
        {
            0xAE, 0x7B, 0xA7, 0x4A, 0xA9, 0xB8, 0xA2, 0x30,
            0xD6, 0x61, 0x4D, 0x8D, 0x0C, 0x78, 0xE0, 0xE5,
            0x33, 0xAD, 0xFA, 0x2A, 0xBD, 0xC3, 0xD6, 0x32,
            0x84, 0x38, 0xC3, 0x78, 0x07, 0x7A, 0xDC, 0x90
        },
        {
            0xBE, 0x7B, 0xA7, 0x4A, 0xA9, 0xB8, 0xA2, 0x30,
            0xD6, 0x61, 0x4D, 0x8D, 0x0C, 0x78, 0xE0, 0xE5,
            0x33, 0xAD, 0xFA, 0x2A, 0xBD, 0xC3, 0xD6, 0x32,
            0x84, 0x38, 0xC3, 0x78, 0x07, 0x7A, 0xDC, 0x90
        }
    };

    constexpr uint32_t k_fingerprint_offset_a = 0u;
    constexpr uint32_t k_fingerprint_length_a = 256u;

    SRWLOCK s_share_a_lock = SRWLOCK_INIT;
    bool s_share_a_validated = false;
}

extern "C" __declspec(dllexport) __declspec(allocate(".aidashr"))
volatile const uint8_t k_expected_fingerprint_a[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#pragma code_seg(push, ".text$ska")

extern "C" __declspec(dllexport) __declspec(noinline) uint32_t aida_share_anchor_a()
{
    volatile uint32_t marker = 0xA1DA5A01u;
    return marker;
}

namespace aida::pubkeys::detail
{
    __declspec(noinline) bool load_share_a(uint8_t kid_index, uint8_t out[32])
    {
        AcquireSRWLockExclusive(&s_share_a_lock);
        if (!s_share_a_validated)
        {
            if (share_self_check::sentinel_is_zero(k_expected_fingerprint_a, 32u))
            {
                s_share_a_validated = true;
            }
            else
            {
                uint8_t actual[32] = {};
                uintptr_t code_addr = reinterpret_cast<uintptr_t>(&aida_share_anchor_a) + static_cast<uintptr_t>(k_fingerprint_offset_a);
                bool fp_ok = share_self_check::compute_self_fingerprint(code_addr, k_fingerprint_length_a, actual);
                uint8_t expected_copy[32];
                for (size_t i = 0; i < 32; ++i) expected_copy[i] = k_expected_fingerprint_a[i];
                bool match = fp_ok && share_self_check::constant_time_equal(actual, expected_copy, 32u);
                SecureZeroMemory(actual, sizeof(actual));
                SecureZeroMemory(expected_copy, sizeof(expected_copy));
                if (!match)
                {
                    ReleaseSRWLockExclusive(&s_share_a_lock);
                    __fastfail(0xA1DA5A01u);
                }
                s_share_a_validated = true;
            }
        }
        ReleaseSRWLockExclusive(&s_share_a_lock);
        if (out == nullptr) return false;
        if (kid_index >= aida::pubkeys::kid_count) return false;
        for (int i = 0; i < 32; ++i)
        {
            out[i] = static_cast<uint8_t>(k_share_a[kid_index][i]);
        }
        return true;
    }
}

#pragma code_seg(pop)

namespace aida::pubkeys
{
    bool load_pubkey(kid_e kid, uint8_t out[32], std::string& last_error)
    {
        if (out == nullptr)
        {
            last_error = "load_pubkey_null_out";
            return false;
        }
        if (kid < kid_license_1 || kid > kid_arc_2)
        {
            last_error = "load_pubkey_bad_kid";
            return false;
        }
        uint8_t kid_index = static_cast<uint8_t>(static_cast<uint8_t>(kid) - 1u);
        alignas(32) uint8_t a[32];
        alignas(32) uint8_t b[32];
        alignas(32) uint8_t c[32];
        alignas(32) uint8_t d[32];
        bool ok = true;
        if (!detail::load_share_a(kid_index, a)) { last_error = "share_a"; ok = false; }
        if (ok && !detail::load_share_b(kid_index, b)) { last_error = "share_b"; ok = false; }
        if (ok && !detail::load_share_c(kid_index, c)) { last_error = "share_c"; ok = false; }
        if (ok && !detail::load_share_d(kid_index, d)) { last_error = "share_d"; ok = false; }
        if (ok)
        {
            for (int i = 0; i < 32; ++i)
            {
                out[i] = static_cast<uint8_t>(a[i] ^ b[i] ^ c[i] ^ d[i]);
            }
        }
        SecureZeroMemory(a, 32);
        SecureZeroMemory(b, 32);
        SecureZeroMemory(c, 32);
        SecureZeroMemory(d, 32);
        return ok;
    }

    bool load_pubkey_spki_der(kid_e kid, uint8_t out_der[44], std::string& last_error)
    {
        if (out_der == nullptr)
        {
            last_error = "load_pubkey_spki_der_null_out";
            return false;
        }
        alignas(32) uint8_t raw[32];
        if (!load_pubkey(kid, raw, last_error)) return false;
        for (int i = 0; i < 12; ++i) out_der[i] = ed25519_spki_prefix[i];
        for (int i = 0; i < 32; ++i) out_der[12 + i] = raw[i];
        SecureZeroMemory(raw, 32);
        return true;
    }
}
