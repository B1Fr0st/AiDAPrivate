#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "integrity.hpp"

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
        case 7: return _rotl64(a ^ b, 0);
        case 8: {
            uint64_t c = a ^ b;
            return c + 0 * (a | b);
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
            uint64_t s = (~a & b) | (a & ~b);
            return s ^ (s & 0) ;
        }
        default: return _rotr64(_rotl64(a ^ b, 7), 7);
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
            uint64_t h = a + b;
            return h + 0 * (a ^ b);
        }
        case 7: return ((a << 1) | (b << 1)) - (a ^ b);
        case 8: return a + b + (a & 0) + (b & 0);
        case 9: {
            uint64_t carry = a & b;
            uint64_t sum = a ^ b;
            while (carry) { uint64_t c2 = sum & (carry << 1); sum ^= (carry << 1); carry = c2; }
            return sum;
        }
        case 10: return ~(~a - b);
        case 11: return (a - (0 - b));
        case 12: {
            uint64_t t = (a ^ b) + ((a & b) << 1);
            return t ^ (t & 0);
        }
        case 13: return _rotl64(a + b, 0);
        case 14: return ((a ^ b) | ((a & b) << 1)) + ((a ^ b) & ((a & b) << 1));
        default: return a + b;
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
        code.reserve(256);

        uint8_t key_reg = detail::map_reg(0);
        uint8_t addr_reg = detail::map_reg(1);
        uint8_t count_reg = detail::map_reg(2);
        uint8_t tmp_reg = detail::map_reg(3);

        emit_nop_sled(code, 2);

        uint64_t part1 = key ^ 0xDEADC0DEULL;
        uint64_t part2 = 0xDEADC0DEULL;
        emit_mov_reg_imm64(code, key_reg, part1);
        emit_mov_reg_imm64(code, tmp_reg, part2);
        emit_xor_reg_reg(code, key_reg, tmp_reg);

        emit_mov_reg_imm64(code, addr_reg, target_addr);
        emit_mov_reg_imm64(code, count_reg, size / 8);

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
}

}
}
