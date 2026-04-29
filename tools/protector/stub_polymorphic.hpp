#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <array>
#include <algorithm>
#include <random>
#include <asmjit/asmjit.h>
#include "stub.hpp"
#include "payload_blob.hpp"

namespace stub_poly {

using stub::stub_config_t;
using stub::generated_stub_t;

struct poly_rng_t {
    uint64_t s;
    explicit poly_rng_t(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next() {
        uint64_t x = s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s = x;
        return x;
    }
    uint32_t next32() { return static_cast<uint32_t>(next()); }
    uint8_t  next8()  { return static_cast<uint8_t>(next() & 0xFFu); }
    uint32_t range(uint32_t n) { return n == 0u ? 0u : (next32() % n); }
};

inline uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    x = x ^ (x >> 31);
    return x;
}

inline uint64_t derive_build_nonce(uint64_t cfg_seed) {
    if (cfg_seed != 0u) {
        return splitmix64(cfg_seed ^ 0x3A4B5C6D7E8F9A0BULL);
    }
    uint64_t t = static_cast<uint64_t>(__rdtsc());
    std::random_device rd;
    uint64_t r = (static_cast<uint64_t>(rd()) << 32) ^ static_cast<uint64_t>(rd());
    return splitmix64(t ^ r ^ 0x12345678ABCDEF01ULL);
}

inline uint32_t crc32_ieee(const uint8_t* data, size_t len) {
    uint32_t tbl[256];
    for (uint32_t i = 0; i < 256u; ++i) {
        uint32_t c = i;
        for (uint32_t j = 0; j < 8u; ++j) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        tbl[i] = c;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc = tbl[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

inline asmjit::x86::Gp gp64_from_id(uint32_t id) {
    using namespace asmjit;
    switch (id) {
        case 0:  return x86::rax;
        case 1:  return x86::rcx;
        case 2:  return x86::rdx;
        case 3:  return x86::rbx;
        case 4:  return x86::rsp;
        case 5:  return x86::rbp;
        case 6:  return x86::rsi;
        case 7:  return x86::rdi;
        case 8:  return x86::r8;
        case 9:  return x86::r9;
        case 10: return x86::r10;
        case 11: return x86::r11;
        case 12: return x86::r12;
        case 13: return x86::r13;
        case 14: return x86::r14;
        default: return x86::r15;
    }
}

inline asmjit::x86::Gp gp8_from_id(uint32_t id) {
    using namespace asmjit;
    switch (id) {
        case 0:  return x86::al;
        case 1:  return x86::cl;
        case 2:  return x86::dl;
        case 3:  return x86::bl;
        case 6:  return x86::sil;
        case 7:  return x86::dil;
        case 8:  return x86::r8b;
        case 9:  return x86::r9b;
        case 10: return x86::r10b;
        case 11: return x86::r11b;
        case 12: return x86::r12b;
        case 13: return x86::r13b;
        case 14: return x86::r14b;
        case 15: return x86::r15b;
        default: return x86::al;
    }
}

inline void emit_mba_const(asmjit::x86::Assembler& a,
                            asmjit::x86::Gp dst,
                            uint64_t value,
                            poly_rng_t& rng) {
    using namespace asmjit;
    uint32_t form = rng.range(3u);
    uint64_t k = rng.next() & 0x7FFFFFFFULL;
    if (k == 0u) { k = 0x5A5A5A5AULL; }
    switch (form) {
        case 0: {
            a.mov(dst, static_cast<int64_t>(value ^ k));
            a.xor_(dst, static_cast<int64_t>(k));
            a.xor_(dst, static_cast<int64_t>(0ULL));
            break;
        }
        case 1: {
            a.mov(dst, static_cast<int64_t>(value + k));
            a.sub(dst, static_cast<int64_t>(k));
            break;
        }
        default: {
            uint64_t k2 = rng.next() & 0x7FFFFFFFULL;
            if (k2 == 0u) { k2 = 0x3A3A3A3AULL; }
            a.mov(dst, static_cast<int64_t>(value ^ k));
            a.xor_(dst, static_cast<int64_t>(k ^ k2));
            a.xor_(dst, static_cast<int64_t>(k2));
            break;
        }
    }
}

inline void emit_opaque_predicate(asmjit::x86::Assembler& a,
                                    asmjit::x86::Gp scratch,
                                    poly_rng_t& rng) {
    using namespace asmjit;
    Label lSkip = a.new_label();
    uint32_t kind = rng.range(8u);
    std::array<uint8_t, 16> junk{};
    uint32_t junk_len = 4u + rng.range(8u);
    for (uint32_t i = 0; i < junk_len; ++i) { junk[i] = rng.next8(); }

    switch (kind) {
        case 0: {
            a.mov(scratch, static_cast<int64_t>(rng.next() | 1ULL));
            a.or_(scratch, 1);
            a.test(scratch, scratch);
            a.jne(lSkip);
            break;
        }
        case 1: {
            a.mov(scratch, static_cast<int64_t>(rng.next()));
            a.xor_(scratch, scratch);
            a.jz(lSkip);
            break;
        }
        case 2: {
            a.mov(scratch, static_cast<int64_t>(rng.next()));
            a.sub(scratch, scratch);
            a.test(scratch, scratch);
            a.jz(lSkip);
            break;
        }
        case 3: {
            a.mov(scratch, 0);
            a.cmp(scratch, -1);
            a.jne(lSkip);
            break;
        }
        case 4: {
            a.push(x86::rax);
            a.push(x86::rdx);
            a.rdtsc();
            a.mov(scratch, x86::rax);
            a.rdtsc();
            a.cmp(x86::rax, scratch);
            a.pop(x86::rdx);
            a.pop(x86::rax);
            a.jae(lSkip);
            a.mov(scratch, 1);
            a.test(scratch, scratch);
            a.jne(lSkip);
            break;
        }
        case 5: {
            a.push(x86::rax);
            a.push(x86::rbx);
            a.push(x86::rcx);
            a.push(x86::rdx);
            a.xor_(x86::eax, x86::eax);
            a.cpuid();
            a.test(x86::ebx, x86::ebx);
            a.pop(x86::rdx);
            a.pop(x86::rcx);
            a.pop(x86::rbx);
            a.pop(x86::rax);
            a.jne(lSkip);
            break;
        }
        case 6: {
            a.mov(scratch, 8);
            Label lLoop = a.new_label();
            a.bind(lLoop);
            a.dec(scratch);
            a.jne(lLoop);
            a.test(scratch, scratch);
            a.jz(lSkip);
            break;
        }
        default: {
            a.mov(scratch, static_cast<int64_t>(rng.next() | 0x1000ULL));
            a.imul(scratch, scratch);
            a.or_(scratch, 1);
            a.test(scratch, scratch);
            a.jne(lSkip);
            break;
        }
    }

    a.embed(junk.data(), junk_len);
    a.bind(lSkip);
}

inline generated_stub_t generate(const stub_config_t& cfg) {
    using namespace asmjit;

    generated_stub_t out{};
    out.main_stub_entry_offset = 0u;
    out.tls_stub_entry_offset = 0u;

    uint64_t nonce = derive_build_nonce(cfg.seed);
    out.build_nonce = nonce;

    uint64_t master_seed = cfg.seed ^ nonce ^ 0xC3A5C85C97CB3127ULL;
    if (master_seed == 0u) { master_seed = 0xD1B54A32D192ED03ULL; }
    poly_rng_t rng(master_seed);

    std::array<uint8_t, 256> key{};
    {
        uint64_t ks = master_seed ^ 0x9AE16A3B2F90404FULL;
        for (size_t i = 0; i < 256; ++i) {
            ks = splitmix64(ks + i);
            key[i] = static_cast<uint8_t>((ks >> ((i & 7u) * 8u)) & 0xFFu);
        }
    }

    std::vector<uint8_t> masked_blob(aida_payload::kBlobSize);
    for (size_t i = 0; i < aida_payload::kBlobSize; ++i) {
        masked_blob[i] = aida_payload::kAidaUnpackBlob[i] ^ key[i & 0xFFu];
    }

    static const uint32_t kBaseCandidates[] = { 3, 1, 2, 6, 7, 8, 12, 13, 14 };
    static constexpr size_t kBaseCount = sizeof(kBaseCandidates) / sizeof(kBaseCandidates[0]);
    uint32_t base_reg_id = kBaseCandidates[rng.range(static_cast<uint32_t>(kBaseCount))];

    static const uint32_t kSavedRegs[] = { 1, 2, 3, 5, 6, 7, 8, 9, 12, 13, 14, 15 };
    std::array<uint32_t, 12> push_order{};
    for (size_t i = 0; i < push_order.size(); ++i) { push_order[i] = kSavedRegs[i]; }
    for (size_t i = push_order.size() - 1; i > 0; --i) {
        uint32_t j = rng.range(static_cast<uint32_t>(i + 1));
        std::swap(push_order[i], push_order[j]);
    }

    static const uint32_t kScratchSet[] = { 10, 11 };
    uint32_t scratch1_id = kScratchSet[rng.range(2u)];
    uint32_t scratch2_id = kScratchSet[(scratch1_id == 10u) ? 1u : 0u];

    x86::Gp rBase = gp64_from_id(base_reg_id);
    x86::Gp rTmp1 = gp64_from_id(scratch1_id);
    x86::Gp rTmp2 = gp64_from_id(scratch2_id);

    CodeHolder code;
    Environment env;
    env.set_arch(Arch::kX64);
    (void)code.init(env);
    x86::Assembler a(&code);

    Label lKey = a.new_label();
    Label lAfterKey = a.new_label();
    Label lPayload = a.new_label();
    Label lSlot = a.new_label();

    uint32_t opaque_pre = 2u + rng.range(3u);
    for (uint32_t i = 0; i < opaque_pre; ++i) {
        emit_opaque_predicate(a, rTmp1, rng);
    }

    for (size_t i = 0; i < push_order.size(); ++i) {
        a.push(gp64_from_id(push_order[i]));
    }
    a.sub(x86::rsp, 0x28);

    emit_opaque_predicate(a, rTmp1, rng);

    emit_mba_const(a, rTmp1, 0x60ULL, rng);
    x86::Mem peb_mem = x86::qword_ptr(rTmp1);
    peb_mem.set_segment(x86::gs);
    a.mov(rBase, peb_mem);

    emit_opaque_predicate(a, rTmp2, rng);

    emit_mba_const(a, rTmp1, 0x10ULL, rng);
    a.mov(rBase, x86::qword_ptr(rBase, rTmp1));

    a.mov(x86::qword_ptr(x86::rsp, 0x20), rBase);

    emit_opaque_predicate(a, rTmp2, rng);

    a.jmp(lAfterKey);
    a.bind(lKey);
    a.embed(key.data(), key.size());
    a.bind(lAfterKey);

    x86::Gp rKey = rBase;
    x86::Gp rPay = rTmp1;
    x86::Gp rCount = rTmp2;
    x86::Gp rIdx = gp64_from_id(0);

    a.lea(rKey, x86::ptr(lKey));
    a.lea(rPay, x86::ptr(lPayload));
    a.mov(rCount, static_cast<int64_t>(aida_payload::kBlobSize));

    emit_opaque_predicate(a, rIdx, rng);

    Label lLoop = a.new_label();
    a.bind(lLoop);
    a.dec(rCount);
    a.mov(rIdx, rCount);
    a.and_(rIdx, 0xFF);
    a.mov(x86::r9b, x86::byte_ptr(rKey, rIdx));
    a.xor_(x86::byte_ptr(rPay, rCount), x86::r9b);
    a.test(rCount, rCount);
    a.jne(lLoop);

    emit_opaque_predicate(a, rIdx, rng);

    a.mov(x86::rcx, x86::qword_ptr(x86::rsp, 0x20));
    a.lea(x86::rax, x86::ptr(lPayload));
    a.add(x86::rax, static_cast<int32_t>(aida_payload::kEntryOffset));
    a.call(x86::rax);

    a.mov(rBase, x86::qword_ptr(x86::rsp, 0x20));
    a.lea(x86::rax, x86::ptr(rBase, static_cast<int32_t>(cfg.original_entry_rva)));

    uint32_t tail_variant = rng.range(4u);
    if (tail_variant == 1u || tail_variant == 3u) {
        a.mov(x86::qword_ptr(lSlot), x86::rax);
    }

    emit_opaque_predicate(a, rTmp2, rng);

    a.add(x86::rsp, 0x28);
    for (size_t i = push_order.size(); i > 0; --i) {
        a.pop(gp64_from_id(push_order[i - 1]));
    }

    switch (tail_variant) {
        case 0: {
            a.push(x86::rax);
            a.ret();
            break;
        }
        case 1: {
            a.jmp(x86::qword_ptr(lSlot));
            break;
        }
        case 2: {
            a.jmp(x86::rax);
            break;
        }
        default: {
            uint64_t k = rng.next();
            if (k == 0u) { k = 0xC6BC279692B5C323ULL; }
            a.mov(x86::rax, x86::qword_ptr(lSlot));
            a.mov(rTmp1, static_cast<int64_t>(k));
            a.xor_(x86::rax, rTmp1);
            a.xor_(x86::rax, rTmp1);
            a.jmp(x86::rax);
            break;
        }
    }

    a.int3();
    while (((code.text_section()->buffer_size()) & 7u) != 0u) {
        a.int3();
    }
    a.bind(lSlot);
    a.embed_uint64(0);

    a.bind(lPayload);
    a.embed(masked_blob.data(), masked_blob.size());

    (void)code.flatten();
    (void)code.resolve_cross_section_fixups();

    size_t sz = code.code_size();
    out.main_stub.resize(sz, 0);
    (void)code.copy_flattened_data(out.main_stub.data(), sz, CopySectionFlags::kNone);

    out.stub_signature_tag = crc32_ieee(out.main_stub.data(), out.main_stub.size());

    if (!cfg.has_existing_tls) {
        CodeHolder tcode;
        Environment tenv;
        tenv.set_arch(Arch::kX64);
        (void)tcode.init(tenv);
        x86::Assembler ta(&tcode);

        ta.push(x86::rbp);
        ta.mov(x86::rbp, x86::rsp);
        ta.sub(x86::rsp, 0x28);

        x86::Mem pebm = x86::qword_ptr(x86::rax);
        pebm.set_segment(x86::gs);
        ta.mov(x86::rax, 0x60);
        ta.mov(x86::rax, pebm);

        Label lTlsOk = ta.new_label();
        ta.cmp(x86::byte_ptr(x86::rax, 2), 0);
        ta.je(lTlsOk);
        Label lSpin = ta.new_label();
        ta.bind(lSpin);
        ta.jmp(lSpin);
        ta.bind(lTlsOk);

        ta.add(x86::rsp, 0x28);
        ta.pop(x86::rbp);
        ta.ret();

        (void)tcode.flatten();
        (void)tcode.resolve_cross_section_fixups();
        size_t tsz = tcode.code_size();
        out.tls_stub.resize(tsz, 0);
        (void)tcode.copy_flattened_data(out.tls_stub.data(), tsz, CopySectionFlags::kNone);
    }

    (void)cfg.packed_section_rva;
    (void)cfg.section_count;
    (void)cfg.import_count;
    (void)cfg.string_fixup_count;
    (void)cfg.resource_fixup_count;
    (void)cfg.is_dll;
    (void)cfg.exception_dir_rva;
    (void)cfg.exception_dir_size;
    (void)cfg.reloc_dir_rva;
    (void)cfg.reloc_dir_size;
    (void)cfg.preferred_image_base;
    (void)cfg.original_timestamp;
    (void)cfg.original_size_of_code;
    (void)cfg.section_table_offset;
    (void)cfg.import_table_offset;
    (void)cfg.string_table_offset;
    (void)cfg.resource_table_offset;
    (void)cfg.master_key_offset;

    return out;
}

}
