#pragma once

#include <cstdint>
#include <string>

namespace aida::pubkeys
{
    enum kid_e : uint8_t
    {
        kid_license_1 = 1,
        kid_license_2 = 2,
        kid_arc_1     = 3,
        kid_arc_2     = 4
    };

    constexpr uint8_t kid_count = 4;

    constexpr uint8_t ed25519_spki_prefix[12] = {
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    bool load_pubkey(kid_e kid, uint8_t out[32], std::string& last_error);

    bool load_pubkey_spki_der(kid_e kid, uint8_t out_der[44], std::string& last_error);

    namespace detail
    {
        bool load_share_a(uint8_t kid_index, uint8_t out[32]);
        bool load_share_b(uint8_t kid_index, uint8_t out[32]);
        bool load_share_c(uint8_t kid_index, uint8_t out[32]);
        bool load_share_d(uint8_t kid_index, uint8_t out[32]);
    }
}
