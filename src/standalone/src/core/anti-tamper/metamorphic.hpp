#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "integrity.hpp"
#include "anti_symbolic.hpp"
#include "webhook.hpp"

namespace anti_tamper {
namespace metamorphic {

namespace detail {

    struct register_map_t
    {
        uint8_t logical_to_physical[16];
        uint8_t physical_to_logical[16];
        uint64_t session_key;
    };

    inline register_map_t& get_regmap()
    {
        static register_map_t m{};
        return m;
    }

    inline void generate_register_map(uint64_t seed)
    {
        auto& m = get_regmap();
        m.session_key = seed;
        for (int i = 0; i < 16; ++i)
            m.logical_to_physical[i] = static_cast<uint8_t>(i);

        uint64_t state = seed;
        for (int i = 15; i > 0; --i)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            int j = static_cast<int>(state % (i + 1));
            uint8_t tmp = m.logical_to_physical[i];
            m.logical_to_physical[i] = m.logical_to_physical[j];
            m.logical_to_physical[j] = tmp;
        }

        for (int i = 0; i < 16; ++i)
            m.physical_to_logical[m.logical_to_physical[i]] = static_cast<uint8_t>(i);
    }

    inline uint8_t map_reg(uint8_t logical)
    {
        return get_regmap().logical_to_physical[logical & 0x0F];
    }

}

namespace mba {

    __forceinline uint64_t keyed_xor(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t noise = entropy * 0x100000001B3ULL;
        uint64_t mask = (noise & 0xF);
        switch (mask)
        {
        case 0: return (a | b) - (a & b);
        case 1: return (a + b) - 2 * (a & b);
        case 2: {
            uint64_t t = ~a;
            return (t & b) | (a & ~b);
        }
        case 3: {
            uint64_t or_ab = a + b - (a & b);
            uint64_t and_ab = (a + b - (a ^ b)) >> 1;
            return or_ab - and_ab;
        }
        case 4: return (a | b) & ~(a & b);
        case 5: return (~a & b) + (a & ~b);
        case 6: return (((a << 1) + (b << 1) - (a & b) * 2) >> 1)
                       - ((a + b - (a ^ b)) >> 1);
        case 7: {
            volatile uint64_t va = a;
            volatile uint64_t vb = b;
            uint64_t nand_ab = ~(va & vb);
            return ~(~va | ~vb) ^ nand_ab ^ ~(va | vb) ^ ~nand_ab;
        }
        case 8: {
            uint64_t not_a = ~a;
            uint64_t not_b = ~b;
            uint64_t nand_notab = ~(not_a & not_b);
            uint64_t nand_ab = ~(a & b);
            return nand_notab & nand_ab;
        }
        case 9: return (a - (a & b)) + (b - (a & b));
        case 10: return ~(~a ^ ~b) ^ 0xFFFFFFFFFFFFFFFFULL;
        case 11: {
            uint64_t t = a ^ b;
            return (t & 0xAAAAAAAAAAAAAAAAULL) | (t & 0x5555555555555555ULL);
        }
        case 12: return (a + b) ^ ((a & b) << 1);
        case 13: return (~(a & b)) & (a | b);
        case 14: {
            volatile uint64_t va = a;
            volatile uint64_t vb = b;
            uint64_t p = (~va & vb);
            uint64_t q = (va & ~vb);
            uint64_t r = p | q;
            uint64_t guard = (va | vb) - (va & vb);
            return r & guard | r & ~guard | guard & ~r ^ r;
        }
        default: {
            uint64_t c = a ^ b;
            uint64_t d = _rotl64(c, 13);
            return _rotr64(d, 13);
        }
        }
    }

    __forceinline uint64_t keyed_add(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t noise = entropy ^ _rotl64(entropy, 23);
        uint64_t mask = (noise & 0xF);
        switch (mask)
        {
        case 0: return (a ^ b) + 2 * (a & b);
        case 1: {
            uint64_t neg_b = (~b) + 1;
            return a - neg_b;
        }
        case 2: return (a | b) + (a & b);
        case 3: {
            uint64_t t = a ^ b;
            uint64_t c = (a & b) << 1;
            return t + c;
        }
        case 4: return a - (~b) - 1;
        case 5: return (a | b) + (a & b);
        case 6: {
            volatile uint64_t va = a;
            volatile uint64_t vb = b;
            uint64_t xor_ab = va ^ vb;
            uint64_t carry = (va & vb) << 1;
            return xor_ab + carry;
        }
        case 7: return ((a << 1) | (b << 1)) - (a ^ b);
        case 8: {
            uint64_t not_a = ~a;
            return ~(not_a - b);
        }
        case 9: {
            uint64_t carry = a & b;
            uint64_t sum = a ^ b;
            while (carry) { uint64_t c2 = sum & (carry << 1); sum ^= (carry << 1); carry = c2; }
            return sum;
        }
        case 10: return ~(~a - b);
        case 11: return (a - (0 - b));
        case 12: {
            volatile uint64_t va = a;
            volatile uint64_t vb = b;
            uint64_t or_ab = va | vb;
            uint64_t and_ab = va & vb;
            return or_ab + and_ab;
        }
        case 13: {
            uint64_t r = a + b;
            uint64_t check = _rotl64(r, 17);
            return _rotr64(check, 17);
        }
        case 14: return ((a ^ b) | ((a & b) << 1)) + ((a ^ b) & ((a & b) << 1));
        default: {
            volatile uint64_t va = a;
            volatile uint64_t vb = b;
            return va + vb;
        }
        }
    }

    __forceinline uint64_t keyed_and(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t noise = _rotr64(entropy, 17) * 0x9E3779B97F4A7C15ULL;
        uint64_t mask = (noise & 0xF);
        switch (mask)
        {
        case 0: return (a + b - (a ^ b)) >> 1;
        case 1: return ~(~a | ~b);
        case 2: return a - (a & ~b);
        case 3: return ((a | b) - (a ^ b));
        case 4: return a & b;
        case 5: return ~(~a | ~b) + 0;
        case 6: return (a | b) ^ (a ^ b);
        case 7: return ((a + b) - (a | b));
        case 8: {
            uint64_t t = a ^ b;
            return (a | b) - t;
        }
        case 9: return b - (~a & b);
        case 10: return a - (a ^ (a & b));
        case 11: return (a | b) & ~(~a & ~b) & ~(a ^ b) | (a & b);
        case 12: return _rotl64(a & b, 0);
        case 13: {
            uint64_t nand_ab = ~(a & b);
            return ~nand_ab;
        }
        case 14: return (a + b + (a ^ b)) >> 1;
        default: return (a & b) ^ 0 ^ 0;
        }
    }

    __forceinline uint64_t keyed_or(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t noise = entropy ^ (entropy >> 31);
        uint64_t mask = (noise & 0xF);
        switch (mask)
        {
        case 0: return (a ^ b) + (a & b);
        case 1: return a + b - (a & b);
        case 2: return ~(~a & ~b);
        case 3: {
            uint64_t t = keyed_xor(a, b, entropy + 1);
            uint64_t u = keyed_and(a, b, entropy + 2);
            return t + u;
        }
        case 4: return (a | b) + 0;
        case 5: return a | b;
        case 6: return (a ^ b) | (a & b);
        case 7: return ~(~a & ~b) ^ 0;
        case 8: return ((a + b) - ((a + b - (a ^ b)) >> 1));
        case 9: return a + (~a & b);
        case 10: return b + (a & ~b);
        case 11: {
            uint64_t nor = ~(a | b);
            return ~nor;
        }
        case 12: return _rotl64(a | b, 0);
        case 13: return (a & ~b) | b;
        case 14: return (a | b) & 0xFFFFFFFFFFFFFFFFULL;
        default: return (~(~a) | ~(~b));
        }
    }

    __forceinline uint64_t keyed_not(uint64_t a, uint64_t entropy)
    {
        uint64_t noise = entropy * 0xBF58476D1CE4E5B9ULL;
        if (noise & 1)
            return static_cast<uint64_t>(-static_cast<int64_t>(a)) - 1;
        else
            return a ^ 0xFFFFFFFFFFFFFFFFULL;
    }

    __forceinline uint64_t keyed_neg(uint64_t a, uint64_t entropy)
    {
        uint64_t noise = _rotl64(entropy, 11);
        if (noise & 1)
            return (~a) + 1;
        else
            return keyed_not(a, entropy) + 1;
    }

    inline uint64_t generate_chain_xor(uint64_t a, uint64_t b, int depth, uint64_t entropy)
    {
        if (depth <= 0)
            return a ^ b;

        uint64_t or_result = keyed_or(a, b, entropy);
        uint64_t and_result = keyed_and(a, b, entropy + depth);
        return or_result - and_result;
    }

    inline uint64_t generate_chain_add(uint64_t a, uint64_t b, int depth, uint64_t entropy)
    {
        if (depth <= 0)
            return a + b;

        uint64_t xor_result = generate_chain_xor(a, b, depth - 1, entropy);
        uint64_t and_result = keyed_and(a, b, entropy + depth);
        return xor_result + 2 * and_result;
    }

    inline uint64_t obfuscate_constant(uint64_t val, uint64_t entropy)
    {
        uint64_t k0 = detail::get_regmap().session_key;
        uint64_t k1 = entropy ^ k0;
        uint8_t buf[16];
        memcpy(buf, &val, 8);
        memcpy(buf + 8, &k1, 8);
        uint64_t hash = integrity::siphash::hash(buf, 16, k0, k1);
        return val ^ (hash - hash);
    }

    inline uint64_t obfuscate_comparison(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t diff = keyed_xor(a, b, entropy);
        uint64_t neg = keyed_neg(diff, entropy);
        return (diff | neg) >> 63;
    }

    __forceinline uint64_t dynamic_coefficient(uint64_t seed, uint32_t round)
    {
        uint64_t s = seed ^ (static_cast<uint64_t>(round) * 0x9E3779B97F4A7C15ULL);
        s ^= s >> 30;
        s *= 0xBF58476D1CE4E5B9ULL;
        s ^= s >> 27;
        s *= 0x94D049BB133111EBULL;
        s ^= s >> 31;
        return s | 1;
    }

    __forceinline uint64_t keyed_add_dynamic(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t c0 = dynamic_coefficient(entropy, 0);
        uint64_t c1 = dynamic_coefficient(entropy, 1);
        uint64_t t = keyed_xor(a * c0, b * c1, entropy);
        uint64_t carry = keyed_and(a * c0, b * c1, entropy) << 1;
        uint64_t raw = t + carry;
        return raw * dynamic_coefficient(entropy, 2);
    }

    __forceinline uint64_t keyed_xor_dynamic(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t c = dynamic_coefficient(entropy, 3);
        uint64_t rot_a = _rotl64(a, static_cast<int>(c & 0x3F));
        uint64_t rot_b = _rotr64(b, static_cast<int>((c >> 6) & 0x3F));
        uint64_t r = keyed_xor(rot_a, rot_b, entropy);
        return _rotr64(r, static_cast<int>(c & 0x3F)) ^ _rotl64(r, static_cast<int>((c >> 6) & 0x3F)) ^ (a ^ b);
    }

    __forceinline uint64_t keyed_and_dynamic(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t c0 = dynamic_coefficient(entropy, 4);
        uint64_t c1 = dynamic_coefficient(entropy, 5);
        uint64_t c2 = dynamic_coefficient(entropy, 6);
        uint64_t rot_a = _rotl64(a ^ c0, static_cast<int>(c1 & 0x3F));
        uint64_t rot_b = _rotr64(b ^ c1, static_cast<int>((c0 >> 6) & 0x3F));
        uint64_t base = keyed_and(rot_a, rot_b, entropy ^ c2);
        uint64_t mba = (rot_a + rot_b) - (rot_a | rot_b);
        return (base ^ mba) * c2;
    }

    __forceinline uint64_t mba_add_plain(uint64_t a, uint64_t b)
    {
        return (a ^ b) + 2 * (a & b);
    }

    __forceinline uint64_t mba_xor_plain(uint64_t a, uint64_t b)
    {
        return (a | b) - (a & b);
    }

    __forceinline uint64_t mba_and_plain(uint64_t a, uint64_t b)
    {
        return (a + b) - (a | b);
    }

    __forceinline uint64_t mba_or_plain(uint64_t a, uint64_t b)
    {
        return (a + b) - (a & b);
    }

    __forceinline uint64_t mba_not_plain(uint64_t a)
    {
        return a ^ 0xFFFFFFFFFFFFFFFFULL;
    }

    __forceinline uint64_t mba_neg_plain(uint64_t a)
    {
        return (~a) + 1;
    }

    __forceinline uint64_t environmental_mba_chain(
        uint64_t input,
        const anti_symbolic::env_bundle_t& env)
    {
        uint64_t layer1 = mba_xor_plain(input, env.server_hmac);
        uint64_t ka_rotated = _rotl64(env.kernel_attestation, 23);
        uint64_t layer2 = mba_add_plain(layer1, ka_rotated);
        uint64_t layer3 = mba_and_plain(layer2, env.rdtsc_delta);
        uint64_t layer4 = mba_xor_plain(layer3, env.process_state);
        return layer4;
    }

    __forceinline uint64_t deep_mba_nest(uint64_t x, uint64_t env_val)
    {
        uint64_t layer1 = (x ^ (x - 1)) + ((~x & (x - 1)) | (x & ~(x - 1)));
        uint64_t layer2 = mba_xor_plain(layer1, env_val);
        uint64_t not_env = mba_not_plain(env_val);
        uint64_t layer3 = mba_add_plain(layer2, not_env);
        uint64_t or_val = mba_or_plain(layer2, env_val);
        uint64_t layer4 = mba_and_plain(layer3, or_val);
        return layer4;
    }

    __forceinline uint64_t fs_hash_mba(uint64_t input, uint64_t fs_hash)
    {
        uint64_t step1 = mba_xor_plain(input, fs_hash);
        uint64_t step2 = mba_add_plain(step1, mba_not_plain(fs_hash));
        uint64_t step3 = mba_and_plain(step2, _rotl64(fs_hash, 17));
        uint64_t step4 = mba_xor_plain(step3, input);
        return step4;
    }

    struct mba_test_pair_t
    {
        uint64_t a;
        uint64_t b;
        uint64_t add;
        uint64_t xor_;
        uint64_t and_;
        uint64_t or_;
        uint64_t neg_a;
        uint64_t neg_b;
    };

    static const mba_test_pair_t s_mba_test_vectors[1000] = {
#include "mba_test_vectors.inc"
    };

    static const uint64_t s_keyed_entropy_values[42] = {
        0x0000000000000000ULL, 0x08D12E6B76C84D11ULL,
        0x1715609F7C746C69ULL, 0x2344B9ADDB213444ULL,
        0x2E2AC13EF8E8D8D2ULL, 0x33500733FC7D6606ULL,
        0x35E2AA2E7E47ACA0ULL, 0x3C6EF372FE94F82AULL,
        0x454021DE755D453BULL, 0x4E115049EC25924CULL,
        0x538454127B096493ULL, 0x56E27EB562EDDF5DULL,
        0x5C55827DF1D1B1A4ULL, 0x6526B0E96899FEB5ULL,
        0x6A99B4B1F77DD0FCULL, 0x74E4409BFEA6EB64ULL,
        0x76C90DC0562A98D7ULL, 0x78DDE6E5FD29F054ULL,
        0x7B7089E07EF436EEULL, 0x81AF155173F23D65ULL,
        0x8FF34785799E5CBDULL, 0x9285EA7FFB68A357ULL,
        0x95188D7A7D32E9F1ULL, 0x97AB3074FEFD308BULL,
        0x98C475F0F066A9CEULL, 0x9E3779B97F4A7C15ULL,
        0xA708A824F612C926ULL, 0xB54CDA58FBBEE87EULL,
        0xBA72204DFF5375B2ULL, 0xC6EF372FE94F82A0ULL,
        0xCC623AF8783354E7ULL, 0xCFC0659B6017CFB1ULL,
        0xD41A23E7FD9228B5ULL, 0xD5336963EEFBA1F8ULL,
        0xD6ACC6E27F5C6F4FULL, 0xDAA66D2C7DDF743FULL,
        0xDD391026FFA9BAD9ULL, 0xDE0497CF65C3EF09ULL,
        0xE3779B97F4A7C150ULL, 0xEC5B24327F181D62ULL,
        0xF1BBCDCBFA53E0A8ULL, 0xF6E113C0FDE86DDCULL,
    };

    inline uint32_t verify_mba_correctness()
    {
        uint32_t fail_count = 0;

        for (int i = 0; i < 1000; ++i)
        {
            uint64_t a = s_mba_test_vectors[i].a;
            uint64_t b = s_mba_test_vectors[i].b;

            if (s_mba_test_vectors[i].add != (a + b))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail vector_add idx=%d a=0x%016llX b=0x%016llX expected=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b,
                        (unsigned long long)s_mba_test_vectors[i].add);
            }
            if (s_mba_test_vectors[i].xor_ != (a ^ b))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail vector_xor idx=%d a=0x%016llX b=0x%016llX expected=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b,
                        (unsigned long long)s_mba_test_vectors[i].xor_);
            }
            if (s_mba_test_vectors[i].and_ != (a & b))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail vector_and idx=%d a=0x%016llX b=0x%016llX expected=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b,
                        (unsigned long long)s_mba_test_vectors[i].and_);
            }
            if (s_mba_test_vectors[i].or_ != (a | b))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail vector_or idx=%d a=0x%016llX b=0x%016llX expected=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b,
                        (unsigned long long)s_mba_test_vectors[i].or_);
            }
            if (s_mba_test_vectors[i].neg_a != (0ULL - a))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail vector_neg_a idx=%d a=0x%016llX expected=0x%016llX",
                        i, (unsigned long long)a,
                        (unsigned long long)s_mba_test_vectors[i].neg_a);
            }
            if (s_mba_test_vectors[i].neg_b != (0ULL - b))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail vector_neg_b idx=%d b=0x%016llX expected=0x%016llX",
                        i, (unsigned long long)b,
                        (unsigned long long)s_mba_test_vectors[i].neg_b);
            }
            if (mba_add_plain(a, b) != s_mba_test_vectors[i].add)
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_add idx=%d a=0x%016llX b=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b);
            }
            if (mba_xor_plain(a, b) != s_mba_test_vectors[i].xor_)
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_xor idx=%d a=0x%016llX b=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b);
            }
            if (mba_and_plain(a, b) != s_mba_test_vectors[i].and_)
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_and idx=%d a=0x%016llX b=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b);
            }
            if (mba_or_plain(a, b) != s_mba_test_vectors[i].or_)
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_or idx=%d a=0x%016llX b=0x%016llX",
                        i, (unsigned long long)a, (unsigned long long)b);
            }
            if (mba_neg_plain(a) != s_mba_test_vectors[i].neg_a)
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_neg_a idx=%d a=0x%016llX",
                        i, (unsigned long long)a);
            }
            if (mba_neg_plain(b) != s_mba_test_vectors[i].neg_b)
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_neg_b idx=%d b=0x%016llX",
                        i, (unsigned long long)b);
            }
            if (mba_not_plain(a) != (~s_mba_test_vectors[i].a))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_not_a idx=%d a=0x%016llX",
                        i, (unsigned long long)a);
            }
            if (mba_not_plain(b) != (~s_mba_test_vectors[i].b))
            {
                ++fail_count;
                if (fail_count <= 4)
                    webhook::write_log_critical_fmt("metamorphic",
                        "mba_verify_fail plain_not_b idx=%d b=0x%016llX",
                        i, (unsigned long long)b);
            }
        }

        for (int e = 0; e < 42; ++e)
        {
            uint64_t ent = s_keyed_entropy_values[e];
            for (int i = 0; i < 1000; ++i)
            {
                uint64_t a = s_mba_test_vectors[i].a;
                uint64_t b = s_mba_test_vectors[i].b;

                if (keyed_xor(a, b, ent) != s_mba_test_vectors[i].xor_)
                {
                    ++fail_count;
                    if (fail_count <= 4)
                        webhook::write_log_critical_fmt("metamorphic",
                            "mba_verify_fail keyed_xor ent_idx=%d vec_idx=%d "
                            "ent=0x%016llX a=0x%016llX b=0x%016llX",
                            e, i, (unsigned long long)ent,
                            (unsigned long long)a, (unsigned long long)b);
                }
                if (keyed_add(a, b, ent) != s_mba_test_vectors[i].add)
                {
                    ++fail_count;
                    if (fail_count <= 4)
                        webhook::write_log_critical_fmt("metamorphic",
                            "mba_verify_fail keyed_add ent_idx=%d vec_idx=%d "
                            "ent=0x%016llX a=0x%016llX b=0x%016llX",
                            e, i, (unsigned long long)ent,
                            (unsigned long long)a, (unsigned long long)b);
                }
                if (keyed_and(a, b, ent) != s_mba_test_vectors[i].and_)
                {
                    ++fail_count;
                    if (fail_count <= 4)
                        webhook::write_log_critical_fmt("metamorphic",
                            "mba_verify_fail keyed_and ent_idx=%d vec_idx=%d "
                            "ent=0x%016llX a=0x%016llX b=0x%016llX",
                            e, i, (unsigned long long)ent,
                            (unsigned long long)a, (unsigned long long)b);
                }
                if (keyed_or(a, b, ent) != s_mba_test_vectors[i].or_)
                {
                    ++fail_count;
                    if (fail_count <= 4)
                        webhook::write_log_critical_fmt("metamorphic",
                            "mba_verify_fail keyed_or ent_idx=%d vec_idx=%d "
                            "ent=0x%016llX a=0x%016llX b=0x%016llX",
                            e, i, (unsigned long long)ent,
                            (unsigned long long)a, (unsigned long long)b);
                }
                if (keyed_not(a, ent) != (~s_mba_test_vectors[i].a))
                {
                    ++fail_count;
                    if (fail_count <= 4)
                        webhook::write_log_critical_fmt("metamorphic",
                            "mba_verify_fail keyed_not ent_idx=%d vec_idx=%d "
                            "ent=0x%016llX a=0x%016llX",
                            e, i, (unsigned long long)ent,
                            (unsigned long long)a);
                }
                if (keyed_neg(a, ent) != (0ULL - s_mba_test_vectors[i].a))
                {
                    ++fail_count;
                    if (fail_count <= 4)
                        webhook::write_log_critical_fmt("metamorphic",
                            "mba_verify_fail keyed_neg ent_idx=%d vec_idx=%d "
                            "ent=0x%016llX a=0x%016llX",
                            e, i, (unsigned long long)ent,
                            (unsigned long long)a);
                }
            }
        }

        if (fail_count > 0)
        {
            webhook::write_log_critical_fmt("metamorphic",
                "mba_verify_complete failures=%u total_tests=%d",
                fail_count, 14000 + 42 * 6000);
        }
        else
        {
            webhook::write_log("metamorphic", "mba_verify_ok all_primitives_correct");
        }

        return fail_count;
    }

}

struct decryptor_stub_t
{
    void* code;
    uint32_t code_size;
    uint64_t key;
    uint64_t target_addr;
    uint32_t target_size;
};

namespace jit {

    inline void emit_byte(std::vector<uint8_t>& buf, uint8_t b)
    {
        buf.push_back(b);
    }

    inline void emit_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len)
    {
        buf.insert(buf.end(), data, data + len);
    }

    inline void emit_mov_reg_imm64(std::vector<uint8_t>& buf, uint8_t reg, uint64_t imm)
    {
        uint8_t rex = 0x48 | ((reg >> 3) & 1);
        buf.push_back(rex);
        buf.push_back(0xB8 | (reg & 7));
        uint8_t bytes[8];
        memcpy(bytes, &imm, 8);
        emit_bytes(buf, bytes, 8);
    }

    inline void emit_xor_reg_reg(std::vector<uint8_t>& buf, uint8_t dst, uint8_t src)
    {
        uint8_t rex = 0x48;
        if (dst > 7) rex |= 0x01;
        if (src > 7) rex |= 0x04;
        buf.push_back(rex);
        buf.push_back(0x31);
        buf.push_back(0xC0 | ((src & 7) << 3) | (dst & 7));
    }

    inline void emit_nop_sled(std::vector<uint8_t>& buf, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            int type = static_cast<int>(__rdtsc() % 4);
            switch (type)
            {
            case 0: buf.push_back(0x90); break;
            case 1: buf.push_back(0x48); buf.push_back(0x87); buf.push_back(0xC0); break;
            case 2: buf.push_back(0x48); buf.push_back(0x8D); buf.push_back(0x00); break;
            case 3: buf.push_back(0x66); buf.push_back(0x90); break;
            }
        }
    }

    inline void emit_ret(std::vector<uint8_t>& buf)
    {
        buf.push_back(0xC3);
    }

    inline decryptor_stub_t generate_decryptor(uint64_t key, uint64_t target_addr, uint32_t size)
    {
        std::vector<uint8_t> code;
        code.reserve(64);

        emit_nop_sled(code, 2);

        uint64_t part1 = key ^ 0xDEADC0DEULL;
        uint64_t part2 = 0xDEADC0DEULL;

        code.push_back(0x49); code.push_back(0xB8);
        uint8_t imm8[8];
        memcpy(imm8, &part1, 8);
        code.insert(code.end(), imm8, imm8 + 8);

        code.push_back(0x49); code.push_back(0xB9);
        memcpy(imm8, &part2, 8);
        code.insert(code.end(), imm8, imm8 + 8);

        code.push_back(0x4D); code.push_back(0x31); code.push_back(0xC8);

        code.push_back(0x48); code.push_back(0xB9);
        memcpy(imm8, &target_addr, 8);
        code.insert(code.end(), imm8, imm8 + 8);

        uint64_t count = static_cast<uint64_t>(size / 8);
        code.push_back(0x48); code.push_back(0xBA);
        memcpy(imm8, &count, 8);
        code.insert(code.end(), imm8, imm8 + 8);

        code.push_back(0x48); code.push_back(0x85); code.push_back(0xD2);
        size_t jz_pos = code.size();
        code.push_back(0x74); code.push_back(0x00);

        size_t loop_start = code.size();

        code.push_back(0x4C); code.push_back(0x31); code.push_back(0x01);
        code.push_back(0x48); code.push_back(0x83); code.push_back(0xC1); code.push_back(0x08);
        code.push_back(0x48); code.push_back(0x83); code.push_back(0xEA); code.push_back(0x01);

        int back = static_cast<int>(loop_start) - static_cast<int>(code.size() + 2);
        code.push_back(0x75); code.push_back(static_cast<uint8_t>(static_cast<int8_t>(back)));

        size_t after_loop = code.size();
        code[jz_pos + 1] = static_cast<uint8_t>(static_cast<int8_t>(static_cast<int>(after_loop) - static_cast<int>(jz_pos + 2)));

        emit_nop_sled(code, 1);
        emit_ret(code);

        void* exec_mem = VirtualAlloc(nullptr, code.size(),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        decryptor_stub_t stub{};
        if (exec_mem)
        {
            memcpy(exec_mem, code.data(), code.size());
            FlushInstructionCache(GetCurrentProcess(), exec_mem, code.size());
            stub.code = exec_mem;
            stub.code_size = static_cast<uint32_t>(code.size());
            stub.key = key;
            stub.target_addr = target_addr;
            stub.target_size = size;
        }
        return stub;
    }

    inline void destroy_stub(decryptor_stub_t& stub)
    {
        if (stub.code)
        {
            volatile uint8_t* p = static_cast<volatile uint8_t*>(stub.code);
            for (uint32_t i = 0; i < stub.code_size; ++i)
                p[i] = 0xCC;
            VirtualFree(stub.code, 0, MEM_RELEASE);
            stub.code = nullptr;
        }
    }

}

namespace instruction_sub {

    inline void emit_bt_setc_antitaint(std::vector<uint8_t>& buf, uint8_t reg, uint8_t bit)
    {
        buf.push_back(0x48 | ((reg >> 3) & 1));
        buf.push_back(0x0F);
        buf.push_back(0xBA);
        buf.push_back(0xE0 | (reg & 7));
        buf.push_back(bit & 0x3F);

        buf.push_back(0x0F);
        buf.push_back(0x92);
        buf.push_back(0xC0 | (reg & 7));
    }

    inline void emit_rcl_antitaint(std::vector<uint8_t>& buf, uint8_t reg, uint8_t count)
    {
        buf.push_back(0x48 | ((reg >> 3) & 1));
        buf.push_back(0xC1);
        buf.push_back(0xD0 | (reg & 7));
        buf.push_back(count & 0x3F);
    }

    inline void emit_rcr_antitaint(std::vector<uint8_t>& buf, uint8_t reg, uint8_t count)
    {
        buf.push_back(0x48 | ((reg >> 3) & 1));
        buf.push_back(0xC1);
        buf.push_back(0xD8 | (reg & 7));
        buf.push_back(count & 0x3F);
    }

    inline void emit_antitaint_sled(std::vector<uint8_t>& buf, uint8_t scratch_reg)
    {
        uint8_t bit = static_cast<uint8_t>(__rdtsc() & 0x3F);
        emit_bt_setc_antitaint(buf, scratch_reg, bit);
        emit_rcl_antitaint(buf, scratch_reg, 1);
        emit_rcr_antitaint(buf, scratch_reg, 1);
        jit::emit_xor_reg_reg(buf, scratch_reg, scratch_reg);
    }

    inline void substitute_mov_imm(std::vector<uint8_t>& buf, uint8_t reg, uint64_t imm)
    {
        uint32_t lo = static_cast<uint32_t>(imm);
        uint32_t hi = static_cast<uint32_t>(imm >> 32);

        jit::emit_xor_reg_reg(buf, reg, reg);

        uint8_t rex = 0x48 | ((reg >> 3) & 1);
        buf.push_back(rex);
        buf.push_back(0x81);
        buf.push_back(0xC0 | (reg & 7));
        uint8_t lo_bytes[4];
        memcpy(lo_bytes, &lo, 4);
        jit::emit_bytes(buf, lo_bytes, 4);

        if (hi != 0)
        {
            uint8_t tmp = (reg == 0) ? 1 : 0;
            jit::emit_mov_reg_imm64(buf, tmp, static_cast<uint64_t>(hi) << 32);
            rex = 0x48;
            if (reg > 7) rex |= 0x01;
            if (tmp > 7) rex |= 0x04;
            buf.push_back(rex);
            buf.push_back(0x09);
            buf.push_back(0xC0 | ((tmp & 7) << 3) | (reg & 7));
        }
    }

}

inline void initialize()
{
    uint64_t seed = __rdtsc() ^ GetCurrentProcessId() ^ reinterpret_cast<uint64_t>(&detail::get_regmap);
    detail::generate_register_map(seed);
    mba::verify_mba_correctness();
}

}
}
