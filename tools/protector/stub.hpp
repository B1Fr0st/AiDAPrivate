#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <array>
#include <algorithm>

namespace stub {

struct rng_t {
    uint64_t state;
    explicit rng_t(uint64_t seed) : state(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next() {
        uint64_t x = state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state = x;
        return x;
    }
    uint32_t next32() { return static_cast<uint32_t>(next()); }
    uint8_t  next8()  { return static_cast<uint8_t>(next() & 0xFFu); }
};

struct payload_blob_view_t {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
    std::uint32_t entry_offset = 0;
    const char* profile = "";
};

struct stub_config_t {
    uint32_t packed_section_rva;
    uint32_t original_entry_rva;
    uint32_t section_count;
    uint32_t import_count;
    uint32_t string_fixup_count;
    uint32_t resource_fixup_count;
    bool     is_dll;
    bool     has_existing_tls;
    uint32_t exception_dir_rva;
    uint32_t exception_dir_size;
    uint32_t reloc_dir_rva;
    uint32_t reloc_dir_size;
    uint64_t preferred_image_base;
    uint8_t  obfuscated_master_key[32];
    uint8_t  key_obfuscation_mask[32];
    uint32_t original_timestamp;
    uint32_t original_size_of_code;
    uint32_t section_table_offset;
    uint32_t import_table_offset;
    uint32_t string_table_offset;
    uint32_t resource_table_offset;
    uint32_t master_key_offset;
    uint32_t stub_code_offset;
    uint64_t seed;
    bool     polymorphic = false;
    payload_blob_view_t payload;
};

struct generated_stub_t {
    std::vector<uint8_t> main_stub;
    std::vector<uint8_t> tls_stub;
    uint32_t main_stub_entry_offset;
    uint32_t tls_stub_entry_offset;
    uint64_t build_nonce = 0;
    uint32_t stub_signature_tag = 0;
};

inline void validate_payload(const stub_config_t& cfg) {
    if (cfg.payload.data == nullptr || cfg.payload.size == 0u || cfg.payload.entry_offset >= cfg.payload.size) {
        throw std::runtime_error("invalid payload blob");
    }
}

namespace reg {
    constexpr uint8_t RAX = 0;
    constexpr uint8_t RCX = 1;
    constexpr uint8_t RDX = 2;
    constexpr uint8_t RBX = 3;
    constexpr uint8_t RSP = 4;
    constexpr uint8_t RBP = 5;
    constexpr uint8_t RSI = 6;
    constexpr uint8_t RDI = 7;
    constexpr uint8_t R8  = 8;
    constexpr uint8_t R9  = 9;
    constexpr uint8_t R10 = 10;
    constexpr uint8_t R11 = 11;
    constexpr uint8_t R12 = 12;
    constexpr uint8_t R13 = 13;
    constexpr uint8_t R14 = 14;
    constexpr uint8_t R15 = 15;
}

namespace emit {

inline void raw(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

inline void put_u8(std::vector<uint8_t>& buf, uint8_t v) {
    buf.push_back(v);
}

inline void put_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}

inline void put_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

inline void put_u64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFFu));
    }
}

inline void push_reg(std::vector<uint8_t>& buf, uint8_t r) {
    if (r >= 8) {
        buf.push_back(0x41);
        buf.push_back(static_cast<uint8_t>(0x50u + (r - 8u)));
    } else {
        buf.push_back(static_cast<uint8_t>(0x50u + r));
    }
}

inline void pop_reg(std::vector<uint8_t>& buf, uint8_t r) {
    if (r >= 8) {
        buf.push_back(0x41);
        buf.push_back(static_cast<uint8_t>(0x58u + (r - 8u)));
    } else {
        buf.push_back(static_cast<uint8_t>(0x58u + r));
    }
}

inline void mov_reg_imm64(std::vector<uint8_t>& buf, uint8_t r, uint64_t imm) {
    uint8_t rex = 0x48u;
    if (r >= 8) { rex |= 0x01u; }
    buf.push_back(rex);
    buf.push_back(static_cast<uint8_t>(0xB8u + (r & 7u)));
    put_u64(buf, imm);
}

inline void mov_reg_imm32(std::vector<uint8_t>& buf, uint8_t r, uint32_t imm) {
    if (r >= 8) { buf.push_back(0x41); }
    buf.push_back(static_cast<uint8_t>(0xB8u + (r & 7u)));
    put_u32(buf, imm);
}

inline void emit_rex_rr(std::vector<uint8_t>& buf, bool w, uint8_t src, uint8_t dst) {
    uint8_t rex = 0;
    if (w) { rex |= 0x48u; }
    if (src >= 8) { rex |= 0x44u; }
    if (dst >= 8) { rex |= 0x41u; }
    if (rex != 0) { buf.push_back(rex); }
}

inline void mov_reg_reg(std::vector<uint8_t>& buf, uint8_t dst, uint8_t src) {
    emit_rex_rr(buf, true, src, dst);
    buf.push_back(0x89);
    buf.push_back(static_cast<uint8_t>(0xC0u | ((src & 7u) << 3) | (dst & 7u)));
}

inline void xor_reg_reg(std::vector<uint8_t>& buf, uint8_t dst, uint8_t src) {
    emit_rex_rr(buf, true, src, dst);
    buf.push_back(0x31);
    buf.push_back(static_cast<uint8_t>(0xC0u | ((src & 7u) << 3) | (dst & 7u)));
}

inline void add_reg_reg(std::vector<uint8_t>& buf, uint8_t dst, uint8_t src) {
    emit_rex_rr(buf, true, src, dst);
    buf.push_back(0x01);
    buf.push_back(static_cast<uint8_t>(0xC0u | ((src & 7u) << 3) | (dst & 7u)));
}

inline void sub_reg_reg(std::vector<uint8_t>& buf, uint8_t dst, uint8_t src) {
    emit_rex_rr(buf, true, src, dst);
    buf.push_back(0x29);
    buf.push_back(static_cast<uint8_t>(0xC0u | ((src & 7u) << 3) | (dst & 7u)));
}

inline void lea_rip_relative(std::vector<uint8_t>& buf, uint8_t r, int32_t disp) {
    uint8_t rex = 0x48u;
    if (r >= 8) { rex |= 0x04u; }
    buf.push_back(rex);
    buf.push_back(0x8D);
    buf.push_back(static_cast<uint8_t>(0x05u | ((r & 7u) << 3)));
    put_u32(buf, static_cast<uint32_t>(disp));
}

inline void call_reg(std::vector<uint8_t>& buf, uint8_t r) {
    if (r >= 8) { buf.push_back(0x41); }
    buf.push_back(0xFF);
    buf.push_back(static_cast<uint8_t>(0xD0u | (r & 7u)));
}

inline void jmp_reg(std::vector<uint8_t>& buf, uint8_t r) {
    if (r >= 8) { buf.push_back(0x41); }
    buf.push_back(0xFF);
    buf.push_back(static_cast<uint8_t>(0xE0u | (r & 7u)));
}

inline void jmp_rel32(std::vector<uint8_t>& buf, int32_t disp) {
    buf.push_back(0xE9);
    put_u32(buf, static_cast<uint32_t>(disp));
}

inline void ret(std::vector<uint8_t>& buf) {
    buf.push_back(0xC3);
}

inline void nop(std::vector<uint8_t>& buf, uint32_t n) {
    static constexpr uint8_t kNop1[] = { 0x90 };
    static constexpr uint8_t kNop2[] = { 0x66, 0x90 };
    static constexpr uint8_t kNop3[] = { 0x0F, 0x1F, 0x00 };
    static constexpr uint8_t kNop4[] = { 0x0F, 0x1F, 0x40, 0x00 };
    static constexpr uint8_t kNop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    static constexpr uint8_t kNop6[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    static constexpr uint8_t kNop7[] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
    static constexpr uint8_t kNop8[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static constexpr uint8_t kNop9[] = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
    while (n > 0) {
        uint32_t take = (n >= 9u) ? 9u : n;
        switch (take) {
            case 1: raw(buf, kNop1, 1); break;
            case 2: raw(buf, kNop2, 2); break;
            case 3: raw(buf, kNop3, 3); break;
            case 4: raw(buf, kNop4, 4); break;
            case 5: raw(buf, kNop5, 5); break;
            case 6: raw(buf, kNop6, 6); break;
            case 7: raw(buf, kNop7, 7); break;
            case 8: raw(buf, kNop8, 8); break;
            default: raw(buf, kNop9, 9); break;
        }
        n -= take;
    }
}

inline void sub_rsp_imm32(std::vector<uint8_t>& buf, uint32_t imm) {
    static constexpr uint8_t kPrefix[] = { 0x48, 0x81, 0xEC };
    raw(buf, kPrefix, 3);
    put_u32(buf, imm);
}

inline void add_rsp_imm32(std::vector<uint8_t>& buf, uint32_t imm) {
    static constexpr uint8_t kPrefix[] = { 0x48, 0x81, 0xC4 };
    raw(buf, kPrefix, 3);
    put_u32(buf, imm);
}

inline void opaque_jz_jnz(std::vector<uint8_t>& buf, rng_t& rng) {
    static constexpr uint8_t kXorSelf[] = { 0x48, 0x33, 0xC0 };
    raw(buf, kXorSelf, 3);
    static constexpr uint8_t kJz[] = { 0x74, 0x05 };
    raw(buf, kJz, 2);
    for (int i = 0; i < 5; ++i) { buf.push_back(rng.next8()); }
    static constexpr uint8_t kCmpRaxRax[] = { 0x48, 0x39, 0xC0 };
    raw(buf, kCmpRaxRax, 3);
    static constexpr uint8_t kJz2[] = { 0x74, 0x05 };
    raw(buf, kJz2, 2);
    for (int i = 0; i < 5; ++i) { buf.push_back(rng.next8()); }
}

inline void fake_branch_over_junk(std::vector<uint8_t>& buf, rng_t& rng) {
    static constexpr uint8_t kStcJc[] = { 0xF9, 0x72, 0x07 };
    raw(buf, kStcJc, 3);
    for (int i = 0; i < 7; ++i) { buf.push_back(rng.next8()); }
}

}

namespace internal {

static constexpr uint8_t kPrologueBlob[] = {
    0x55,
    0x48, 0x89, 0xE5,
    0x53,
    0x56,
    0x57,
    0x41, 0x54,
    0x41, 0x55,
    0x41, 0x56,
    0x41, 0x57
};

static constexpr uint8_t kEpilogueRestoreBlob[] = {
    0x41, 0x5F,
    0x41, 0x5E,
    0x41, 0x5D,
    0x41, 0x5C,
    0x5F,
    0x5E,
    0x5B,
    0x48, 0x89, 0xEC,
    0x5D
};

static constexpr uint8_t kGsPebImageBaseBlob[] = {
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
    0x4C, 0x8B, 0x60, 0x10
};

}

inline void emit_prologue(std::vector<uint8_t>& buf) {
    emit::raw(buf, internal::kPrologueBlob, sizeof(internal::kPrologueBlob));
    emit::sub_rsp_imm32(buf, 0x1C8u);
}

inline void emit_epilogue_and_jmp_oep(std::vector<uint8_t>& buf, uint32_t original_entry_rva, uint32_t packed_section_rva, uint32_t stub_code_offset) {
    emit::add_rsp_imm32(buf, 0x1C8u);
    emit::raw(buf, internal::kEpilogueRestoreBlob, sizeof(internal::kEpilogueRestoreBlob));
    const size_t base_lea_pos = buf.size();
    emit::lea_rip_relative(buf, reg::RCX, 0);
    emit::mov_reg_imm64(buf, reg::RAX, static_cast<uint64_t>(packed_section_rva) + stub_code_offset + static_cast<uint32_t>(base_lea_pos + 7u));
    emit::sub_reg_reg(buf, reg::RCX, reg::RAX);
    emit::mov_reg_imm32(buf, reg::RAX, original_entry_rva);
    emit::add_reg_reg(buf, reg::RAX, reg::RCX);
    emit::jmp_reg(buf, reg::RAX);
}

inline void emit_locate_image_base(std::vector<uint8_t>& buf, uint32_t packed_section_rva, uint32_t stub_code_offset) {
    const size_t base_lea_pos = buf.size();
    emit::lea_rip_relative(buf, reg::R12, 0);
    emit::mov_reg_imm64(buf, reg::RAX, static_cast<uint64_t>(packed_section_rva) + stub_code_offset + static_cast<uint32_t>(base_lea_pos + 7u));
    emit::sub_reg_reg(buf, reg::R12, reg::RAX);
}

inline void emit_tls_body(std::vector<uint8_t>& buf) {
    static constexpr uint8_t kTlsBody[] = {
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        0x80, 0x78, 0x02, 0x00,
        0x74, 0x02,
        0xEB, 0xFE,
        0x48, 0x83, 0xFA, 0x01,
        0x75, 0x02,
        0x90, 0x90,
        0xC3
    };
    emit::raw(buf, kTlsBody, sizeof(kTlsBody));
}

inline generated_stub_t generate_legacy(const stub_config_t& cfg) {
    validate_payload(cfg);

    generated_stub_t out{};
    out.main_stub_entry_offset = 0u;
    out.tls_stub_entry_offset = 0u;

    rng_t rng(cfg.seed ? cfg.seed : 0xA5A5A5A5A5A5A5A5ULL);

    std::vector<uint8_t>& m = out.main_stub;
    m.reserve(8192u + cfg.payload.size);

    emit_prologue(m);
    emit::opaque_jz_jnz(m, rng);

    emit_locate_image_base(m, cfg.packed_section_rva, cfg.stub_code_offset);

    static constexpr uint8_t kMovRcxR12[] = { 0x4C, 0x89, 0xE1 };
    emit::raw(m, kMovRcxR12, 3);

    emit::fake_branch_over_junk(m, rng);

    size_t lea_pos = m.size();
    emit::lea_rip_relative(m, reg::RAX, 0);
    static constexpr uint8_t kAddRaxImm32[] = { 0x48, 0x05 };
    emit::raw(m, kAddRaxImm32, 2);
    emit::put_u32(m, cfg.payload.entry_offset);
    emit::call_reg(m, reg::RAX);

    size_t jmp_pos = m.size();
    emit::jmp_rel32(m, 0);

    while ((m.size() & 0x0Fu) != 0u) {
        emit::nop(m, 1);
    }

    size_t payload_start = m.size();
    int32_t lea_disp = static_cast<int32_t>(payload_start - (lea_pos + 7));
    std::memcpy(m.data() + lea_pos + 3, &lea_disp, 4);

    emit::raw(m, cfg.payload.data, cfg.payload.size);

    size_t after_blob = m.size();
    int32_t jmp_disp = static_cast<int32_t>(after_blob - (jmp_pos + 5));
    std::memcpy(m.data() + jmp_pos + 1, &jmp_disp, 4);

    emit::opaque_jz_jnz(m, rng);

    emit_epilogue_and_jmp_oep(m, cfg.original_entry_rva, cfg.packed_section_rva, cfg.stub_code_offset);

    {
        uint32_t pad = 16u - (static_cast<uint32_t>(m.size()) & 0x0Fu);
        if (pad != 16u) {
            emit::nop(m, pad);
        }
    }

    if (!cfg.has_existing_tls) {
        std::vector<uint8_t>& t = out.tls_stub;
        t.reserve(128);
        emit::push_reg(t, reg::RBP);
        static constexpr uint8_t kTlsPrologueFrame[] = { 0x48, 0x89, 0xE5 };
        emit::raw(t, kTlsPrologueFrame, 3);
        emit::sub_rsp_imm32(t, 0x28u);
        emit_tls_body(t);
        emit::add_rsp_imm32(t, 0x28u);
        emit::pop_reg(t, reg::RBP);
        emit::ret(t);
    } else {
        out.tls_stub.clear();
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
    (void)cfg.stub_code_offset;

    return out;
}

}

#ifndef AIDA_PROTECTOR_LEGACY_STUB
#include "stub_polymorphic.hpp"
#endif

namespace stub {

inline generated_stub_t generate(const stub_config_t& cfg) {
    validate_payload(cfg);
#ifndef AIDA_PROTECTOR_LEGACY_STUB
    if (cfg.polymorphic) {
        return stub_poly::generate(cfg);
    }
#endif
    return generate_legacy(cfg);
}

}
