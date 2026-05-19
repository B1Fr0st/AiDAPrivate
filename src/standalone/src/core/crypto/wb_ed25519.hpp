#pragma once

#include <cstddef>
#include <cstdint>

namespace aida::wb_ed25519
{
    bool verify(const uint8_t* msg,
                size_t msg_len,
                const uint8_t* sig_64bytes,
                const uint8_t* pubkey_32bytes) noexcept;

    const char* last_error() noexcept;
}
