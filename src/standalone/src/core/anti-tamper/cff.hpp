#pragma once
//
// Control Flow Flattening (CFF) — anti_tamper::cff
//
// Transforms linear control flow into a state-machine dispatch loop.
// Each basic block is a numbered state; the dispatcher selects the next
// state via an encrypted switch variable. Static analysis tools (IDA,
// Ghidra, angr, Binary Ninja) see a flat switch-case with no recoverable
// CFG edges because the state variable is updated through opaque
// arithmetic at runtime.
//
// Usage:
//   CFF_BEGIN(tag)          — opens a flattened region
//   CFF_STATE(tag, N)       — labels state N
//   CFF_GOTO(tag, N)        — transitions to state N (encrypted)
//   CFF_END(tag)            — closes the region
//   CFF_FLATTEN_FUNC(...)   — wraps an entire function body
//

#include <cstdint>
#include <intrin.h>

namespace anti_tamper {
namespace cff {

namespace detail {

    // Compile-time FNV-1a for generating per-site encryption keys from tags.
    constexpr uint64_t fnv1a_seed = 0xCBF29CE484222325ULL;
    constexpr uint64_t fnv1a_prime = 0x100000001B3ULL;

    constexpr uint64_t ct_fnv1a(const char* s, uint64_t h = fnv1a_seed)
    {
        return *s ? ct_fnv1a(s + 1, (h ^ static_cast<uint64_t>(*s)) * fnv1a_prime) : h;
    }

    // State variable encryption: state = (real_state ^ key) * scramble + noise
    // The key, scramble, and noise are derived from the tag hash + rdtsc at
    // region entry, so every execution produces different intermediate values.
    struct cff_ctx_t
    {
        uint64_t key;        // XOR key
        uint64_t scramble;   // multiplicative scramble (odd, so invertible mod 2^64)
        uint64_t noise;      // additive noise
        uint64_t inv_scramble; // modular inverse of scramble
    };

    // Extended Euclidean to compute modular inverse mod 2^64
    // (scramble is always odd, so inverse exists)
    constexpr uint64_t mod_inverse_64(uint64_t a)
    {
        uint64_t x = a;  // a * x ≡ 1 (mod 2^64) via Newton's method
        for (int i = 0; i < 6; ++i)
            x *= 2 - a * x;
        return x;
    }

    __forceinline cff_ctx_t init_ctx(uint64_t tag_hash)
    {
        cff_ctx_t ctx{};
        uint64_t entropy = __rdtsc() ^ tag_hash;

        // splitmix64 to derive key material
        entropy += 0x9E3779B97F4A7C15ULL;
        uint64_t z = entropy;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        ctx.key = z ^ (z >> 31);

        entropy += 0x9E3779B97F4A7C15ULL;
        z = entropy;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        ctx.scramble = (z ^ (z >> 31)) | 1ULL; // ensure odd

        entropy += 0x9E3779B97F4A7C15ULL;
        z = entropy;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        ctx.noise = z ^ (z >> 31);

        ctx.inv_scramble = mod_inverse_64(ctx.scramble);
        return ctx;
    }

    __forceinline uint64_t encrypt_state(const cff_ctx_t& ctx, uint64_t real_state)
    {
        return ((real_state ^ ctx.key) * ctx.scramble) + ctx.noise;
    }

    __forceinline uint64_t decrypt_state(const cff_ctx_t& ctx, uint64_t enc_state)
    {
        return ((enc_state - ctx.noise) * ctx.inv_scramble) ^ ctx.key;
    }

} // namespace detail

} // namespace cff
} // namespace anti_tamper

// ── CFF Macros ──────────────────────────────────────────────────────
//
// These are designed to wrap arbitrary code blocks. The compiler sees
// a while-switch dispatch loop; the state variable is always encrypted.
//
// CFF_BEGIN / CFF_END create the dispatch skeleton.
// CFF_STATE labels a basic block inside the skeleton.
// CFF_GOTO transitions to a new state (encrypting on the fly).
//

#define CFF_TAG_HASH_(tag) (::anti_tamper::cff::detail::ct_fnv1a(#tag))

#define CFF_BEGIN(tag)                                                           \
    {                                                                            \
        auto _cff_ctx_##tag = ::anti_tamper::cff::detail::init_ctx(              \
            CFF_TAG_HASH_(tag));                                                 \
        volatile uint64_t _cff_sv_##tag =                                        \
            ::anti_tamper::cff::detail::encrypt_state(_cff_ctx_##tag, 0);        \
        volatile bool _cff_run_##tag = true;                                     \
        while (_cff_run_##tag) {                                                 \
            uint64_t _cff_dec_##tag =                                            \
                ::anti_tamper::cff::detail::decrypt_state(                       \
                    _cff_ctx_##tag, _cff_sv_##tag);                              \
            switch (_cff_dec_##tag) {

#define CFF_STATE(tag, N)                                                        \
            break;                                                               \
            case static_cast<uint64_t>(N):

#define CFF_GOTO(tag, N)                                                         \
            _cff_sv_##tag = ::anti_tamper::cff::detail::encrypt_state(           \
                _cff_ctx_##tag, static_cast<uint64_t>(N));                       \
            continue

#define CFF_END(tag)                                                             \
            break;                                                               \
            default:                                                             \
                _cff_run_##tag = false;                                           \
                break;                                                           \
            }                                                                    \
        }                                                                        \
    }

// Convenience: flatten an entire function body.
// States 0..N are the basic blocks, state 0xFFFF is the exit.
#define CFF_EXIT(tag)                                                            \
            _cff_run_##tag = false;                                              \
            break
