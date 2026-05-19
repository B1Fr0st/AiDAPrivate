#include "keys.hpp"
#include "share_self_check.hpp"

#include <Windows.h>
#include <cstdint>
#include <cstring>

#pragma section(".aidashr", read)

namespace
{
    volatile uint8_t k_share_d[aida::pubkeys::kid_count][32] = {
        {
            0xEE, 0x4C, 0x9A, 0x49, 0x9D, 0x25, 0x61, 0x17,
            0x70, 0xE6, 0xFA, 0xE9, 0x5C, 0xA3, 0xD8, 0x5B,
            0x5C, 0x1C, 0x09, 0x5E, 0x00, 0xCB, 0xBD, 0x0B,
            0x51, 0x5A, 0xCF, 0xD5, 0x73, 0x56, 0xBD, 0xA5
        },
        {
            0x4C, 0x2E, 0xC5, 0xDC, 0xED, 0xE3, 0x11, 0x1A,
            0x92, 0xE6, 0xB7, 0x2C, 0xC0, 0x81, 0x74, 0x98,
            0x05, 0xD6, 0x9E, 0x57, 0xD0, 0x97, 0x7E, 0x15,
            0xE4, 0xB6, 0xBC, 0xFB, 0xBB, 0x7F, 0x7D, 0xA6
        },
        {
            0x4C, 0x3E, 0xD5, 0xDC, 0xED, 0xE3, 0x11, 0x1A,
            0x92, 0xE6, 0xB7, 0x2C, 0xC0, 0x81, 0x74, 0x98,
            0x05, 0xD6, 0x9E, 0x57, 0xD0, 0x97, 0x7E, 0x15,
            0xE4, 0xB6, 0xBC, 0xFB, 0xBB, 0x7F, 0x7D, 0xA6
        },
        {
            0x4C, 0x2E, 0xC5, 0xDC, 0xED, 0xE3, 0x11, 0x1A,
            0x92, 0xE6, 0xB7, 0x2C, 0xC0, 0x81, 0x74, 0x98,
            0x05, 0xD6, 0x9E, 0x57, 0xD0, 0x97, 0x7E, 0x15,
            0xE4, 0xB6, 0xBC, 0xFB, 0xBB, 0x7F, 0x7D, 0xA6
        }
    };

    constexpr uint32_t k_fingerprint_offset_d = 24u;
    constexpr uint32_t k_fingerprint_length_d = 272u;

    SRWLOCK s_share_d_lock = SRWLOCK_INIT;
    bool s_share_d_validated = false;
}

extern "C" __declspec(dllexport) __declspec(allocate(".aidashr"))
volatile const uint8_t k_expected_fingerprint_d[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#pragma code_seg(push, ".text$skd")

extern "C" __declspec(dllexport) __declspec(noinline) uint32_t aida_share_anchor_d()
{
    volatile uint32_t marker = 0xA1DA5A04u;
    return marker;
}

namespace aida::pubkeys::detail
{
    __declspec(noinline) bool load_share_d(uint8_t kid_index, uint8_t out[32])
    {
        AcquireSRWLockExclusive(&s_share_d_lock);
        if (!s_share_d_validated)
        {
            if (share_self_check::sentinel_is_zero(k_expected_fingerprint_d, 32u))
            {
                s_share_d_validated = true;
            }
            else
            {
                uint8_t actual[32] = {};
                uintptr_t code_addr = reinterpret_cast<uintptr_t>(&aida_share_anchor_d) + static_cast<uintptr_t>(k_fingerprint_offset_d);
                bool fp_ok = share_self_check::compute_self_fingerprint(code_addr, k_fingerprint_length_d, actual);
                uint8_t expected_copy[32];
                for (size_t i = 0; i < 32; ++i) expected_copy[i] = k_expected_fingerprint_d[i];
                bool match = fp_ok && share_self_check::constant_time_equal(actual, expected_copy, 32u);
                SecureZeroMemory(actual, sizeof(actual));
                SecureZeroMemory(expected_copy, sizeof(expected_copy));
                if (!match)
                {
                    ReleaseSRWLockExclusive(&s_share_d_lock);
                    __fastfail(0xA1DA5A04u);
                }
                s_share_d_validated = true;
            }
        }
        ReleaseSRWLockExclusive(&s_share_d_lock);
        if (out == nullptr) return false;
        if (kid_index >= aida::pubkeys::kid_count) return false;
        for (int i = 0; i < 32; ++i)
        {
            out[i] = static_cast<uint8_t>(k_share_d[kid_index][i]);
        }
        return true;
    }
}

#pragma code_seg(pop)
