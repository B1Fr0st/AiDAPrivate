#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "../../src/standalone/src/core/anti-tamper/wbaes.hpp"

#pragma comment(lib, "bcrypt.lib")

extern "C" {
int aes128_wbaes_decrypt_ctr_payload(const uint8_t* tbl_blob, uint32_t tbl_size,
                                      const uint8_t iv[16], const uint8_t* in,
                                      uint8_t* out, uint32_t len);
}

namespace {

constexpr uint8_t k_sbox_ref[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

constexpr uint8_t k_rcon_ref[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint32_t ref_sub_word(uint32_t w) {
    return (static_cast<uint32_t>(k_sbox_ref[(w >> 24) & 0xFFu]) << 24) |
           (static_cast<uint32_t>(k_sbox_ref[(w >> 16) & 0xFFu]) << 16) |
           (static_cast<uint32_t>(k_sbox_ref[(w >> 8) & 0xFFu]) << 8) |
            static_cast<uint32_t>(k_sbox_ref[w & 0xFFu]);
}

uint32_t ref_rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

void ref_key_expansion(const uint8_t key[16], uint32_t rk[44]) {
    for (int i = 0; i < 4; ++i) {
        rk[i] = (static_cast<uint32_t>(key[4 * i]) << 24) |
                (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
                 static_cast<uint32_t>(key[4 * i + 3]);
    }
    for (int i = 4; i < 44; ++i) {
        uint32_t t = rk[i - 1];
        if ((i % 4) == 0) {
            t = ref_sub_word(ref_rot_word(t)) ^ (static_cast<uint32_t>(k_rcon_ref[i / 4]) << 24);
        }
        rk[i] = rk[i - 4] ^ t;
    }
}

uint8_t ref_gf_mul2(uint8_t a) {
    return static_cast<uint8_t>((a << 1) ^ (((a >> 7) & 1u) * 0x1Bu));
}

uint8_t ref_gf_mul3(uint8_t a) {
    return static_cast<uint8_t>(ref_gf_mul2(a) ^ a);
}

void ref_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint32_t rk[44];
    ref_key_expansion(key, rk);

    uint8_t s[4][4];
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            s[r][c] = in[r + 4 * c];
        }
    }
    for (int c = 0; c < 4; ++c) {
        uint32_t k = rk[c];
        s[0][c] ^= static_cast<uint8_t>((k >> 24) & 0xFFu);
        s[1][c] ^= static_cast<uint8_t>((k >> 16) & 0xFFu);
        s[2][c] ^= static_cast<uint8_t>((k >> 8) & 0xFFu);
        s[3][c] ^= static_cast<uint8_t>(k & 0xFFu);
    }
    for (int round = 1; round <= 10; ++round) {
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                s[r][c] = k_sbox_ref[s[r][c]];
            }
        }
        uint8_t t;
        t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
        t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;
        t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;
        t = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = s[3][0]; s[3][0] = t;
        if (round < 10) {
            for (int c = 0; c < 4; ++c) {
                uint8_t s0 = s[0][c], s1 = s[1][c], s2 = s[2][c], s3 = s[3][c];
                s[0][c] = static_cast<uint8_t>(ref_gf_mul2(s0) ^ ref_gf_mul3(s1) ^ s2 ^ s3);
                s[1][c] = static_cast<uint8_t>(s0 ^ ref_gf_mul2(s1) ^ ref_gf_mul3(s2) ^ s3);
                s[2][c] = static_cast<uint8_t>(s0 ^ s1 ^ ref_gf_mul2(s2) ^ ref_gf_mul3(s3));
                s[3][c] = static_cast<uint8_t>(ref_gf_mul3(s0) ^ s1 ^ s2 ^ ref_gf_mul2(s3));
            }
        }
        const uint32_t* krk = &rk[round * 4];
        for (int c = 0; c < 4; ++c) {
            s[0][c] ^= static_cast<uint8_t>((krk[c] >> 24) & 0xFFu);
            s[1][c] ^= static_cast<uint8_t>((krk[c] >> 16) & 0xFFu);
            s[2][c] ^= static_cast<uint8_t>((krk[c] >> 8) & 0xFFu);
            s[3][c] ^= static_cast<uint8_t>(krk[c] & 0xFFu);
        }
    }
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            out[r + 4 * c] = s[r][c];
        }
    }
}

void ref_aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                    const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    size_t off = 0;
    while (off < len) {
        uint8_t ks[16];
        ref_aes128_encrypt_block(key, counter, ks);
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
        size_t bl = (len - off > 16) ? 16 : (len - off);
        for (size_t i = 0; i < bl; ++i) {
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

bool generate_random_bytes(uint8_t* buf, size_t len) {
    NTSTATUS s = BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return s == 0;
}

bool memcontains(const uint8_t* haystack, size_t haystack_len,
                  const uint8_t* needle, size_t needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) return false;
    size_t limit = haystack_len - needle_len;
    for (size_t i = 0; i <= limit; ++i) {
        if (std::memcmp(haystack + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

void hex_print(const char* label, const uint8_t* data, size_t len) {
    std::printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
    std::printf("\n");
}

bool test_known_answer() {
    static const uint8_t kat_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t kat_pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t kat_ct[16] = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
    };

    uint8_t ref_ct[16];
    ref_aes128_encrypt_block(kat_key, kat_pt, ref_ct);
    if (std::memcmp(ref_ct, kat_ct, 16) != 0) {
        std::printf("REFERENCE_AES_FAILED_KAT\n");
        hex_print("ref_ct", ref_ct, 16);
        hex_print("kat_ct", kat_ct, 16);
        return false;
    }

    anti_tamper::wbaes::white_box_table_t* tbl =
        static_cast<anti_tamper::wbaes::white_box_table_t*>(
            std::malloc(sizeof(anti_tamper::wbaes::white_box_table_t)));
    if (!tbl) {
        std::printf("KAT_ALLOC_FAILED\n");
        return false;
    }
    if (!anti_tamper::wbaes::generate_tables(kat_key, 0xDEADBEEFCAFEBABEULL, *tbl)) {
        std::printf("KAT_GENERATE_TABLES_FAILED: %s\n", anti_tamper::wbaes::last_error());
        std::free(tbl);
        return false;
    }
    uint8_t wb_ct[16];
    anti_tamper::wbaes::encrypt_block(*tbl, kat_pt, wb_ct);
    if (std::memcmp(wb_ct, kat_ct, 16) != 0) {
        std::printf("WBAES_KAT_MISMATCH\n");
        hex_print("wb_ct", wb_ct, 16);
        hex_print("kat_ct", kat_ct, 16);
        std::free(tbl);
        return false;
    }
    std::free(tbl);
    return true;
}

bool test_random_match() {
    uint8_t key[16];
    if (!generate_random_bytes(key, sizeof(key))) {
        std::printf("RANDOM_KEY_GEN_FAILED\n");
        return false;
    }

    anti_tamper::wbaes::white_box_table_t* tbl =
        static_cast<anti_tamper::wbaes::white_box_table_t*>(
            std::malloc(sizeof(anti_tamper::wbaes::white_box_table_t)));
    if (!tbl) {
        std::printf("RANDOM_ALLOC_FAILED\n");
        return false;
    }

    uint64_t entropy_seed = 0;
    if (!generate_random_bytes(reinterpret_cast<uint8_t*>(&entropy_seed), sizeof(entropy_seed))) {
        std::printf("RANDOM_SEED_GEN_FAILED\n");
        std::free(tbl);
        return false;
    }

    if (!anti_tamper::wbaes::generate_tables(key, entropy_seed, *tbl)) {
        std::printf("RANDOM_GENERATE_TABLES_FAILED: %s\n", anti_tamper::wbaes::last_error());
        std::free(tbl);
        return false;
    }

    for (int trial = 0; trial < 16; ++trial) {
        uint8_t pt[16];
        if (!generate_random_bytes(pt, sizeof(pt))) {
            std::printf("RANDOM_PT_GEN_FAILED\n");
            std::free(tbl);
            return false;
        }
        uint8_t ct_ref[16];
        uint8_t ct_wb[16];
        ref_aes128_encrypt_block(key, pt, ct_ref);
        anti_tamper::wbaes::encrypt_block(*tbl, pt, ct_wb);
        if (std::memcmp(ct_ref, ct_wb, 16) != 0) {
            std::printf("RANDOM_TRIAL_%d_MISMATCH\n", trial);
            hex_print("key", key, 16);
            hex_print("pt", pt, 16);
            hex_print("ref_ct", ct_ref, 16);
            hex_print("wb_ct", ct_wb, 16);
            std::free(tbl);
            return false;
        }
    }

    std::free(tbl);
    return true;
}

bool test_ctr_round_trip() {
    uint8_t key[16];
    if (!generate_random_bytes(key, sizeof(key))) {
        std::printf("CTR_RANDOM_KEY_FAILED\n");
        return false;
    }
    uint8_t iv[16];
    if (!generate_random_bytes(iv, sizeof(iv))) {
        std::printf("CTR_RANDOM_IV_FAILED\n");
        return false;
    }

    constexpr uint32_t kLen = 4097;
    uint8_t* pt = static_cast<uint8_t*>(std::malloc(kLen));
    uint8_t* ct = static_cast<uint8_t*>(std::malloc(kLen));
    uint8_t* dec = static_cast<uint8_t*>(std::malloc(kLen));
    uint8_t* ref_ct = static_cast<uint8_t*>(std::malloc(kLen));
    if (!pt || !ct || !dec || !ref_ct) {
        std::printf("CTR_BUFFER_ALLOC_FAILED\n");
        if (pt) std::free(pt);
        if (ct) std::free(ct);
        if (dec) std::free(dec);
        if (ref_ct) std::free(ref_ct);
        return false;
    }
    if (!generate_random_bytes(pt, kLen)) {
        std::printf("CTR_PT_GEN_FAILED\n");
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct);
        return false;
    }

    anti_tamper::wbaes::white_box_table_t* tbl =
        static_cast<anti_tamper::wbaes::white_box_table_t*>(
            std::malloc(sizeof(anti_tamper::wbaes::white_box_table_t)));
    if (!tbl) {
        std::printf("CTR_TBL_ALLOC_FAILED\n");
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct);
        return false;
    }

    uint64_t seed = 0;
    if (!generate_random_bytes(reinterpret_cast<uint8_t*>(&seed), sizeof(seed))) {
        std::printf("CTR_SEED_GEN_FAILED\n");
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct); std::free(tbl);
        return false;
    }

    if (!anti_tamper::wbaes::generate_tables(key, seed, *tbl)) {
        std::printf("CTR_GENERATE_TABLES_FAILED: %s\n", anti_tamper::wbaes::last_error());
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct); std::free(tbl);
        return false;
    }

    if (!anti_tamper::wbaes::encrypt_ctr(*tbl, iv, pt, ct, kLen)) {
        std::printf("CTR_WBAES_ENCRYPT_FAILED: %s\n", anti_tamper::wbaes::last_error());
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct); std::free(tbl);
        return false;
    }

    ref_aes128_ctr(key, iv, pt, ref_ct, kLen);
    if (std::memcmp(ct, ref_ct, kLen) != 0) {
        std::printf("CTR_WBAES_VS_REF_MISMATCH\n");
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct); std::free(tbl);
        return false;
    }

    int dec_ok = aes128_wbaes_decrypt_ctr_payload(
        reinterpret_cast<const uint8_t*>(tbl),
        static_cast<uint32_t>(sizeof(anti_tamper::wbaes::white_box_table_t)),
        iv, ct, dec, kLen);
    if (!dec_ok) {
        std::printf("CTR_PAYLOAD_DECRYPT_RETURNED_ZERO\n");
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct); std::free(tbl);
        return false;
    }

    if (std::memcmp(pt, dec, kLen) != 0) {
        std::printf("CTR_PAYLOAD_DECRYPT_MISMATCH\n");
        std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct); std::free(tbl);
        return false;
    }

    std::free(pt); std::free(ct); std::free(dec); std::free(ref_ct); std::free(tbl);
    return true;
}

bool test_no_key_in_memory() {
    uint8_t key[16];
    if (!generate_random_bytes(key, sizeof(key))) {
        std::printf("LEAK_RANDOM_KEY_FAILED\n");
        return false;
    }

    anti_tamper::wbaes::white_box_table_t* tbl =
        static_cast<anti_tamper::wbaes::white_box_table_t*>(
            std::malloc(sizeof(anti_tamper::wbaes::white_box_table_t)));
    if (!tbl) {
        std::printf("LEAK_ALLOC_FAILED\n");
        return false;
    }

    uint64_t seed = 0xA1DAA1DAA1DAA1DAULL;
    if (!anti_tamper::wbaes::generate_tables(key, seed, *tbl)) {
        std::printf("LEAK_GENERATE_TABLES_FAILED: %s\n", anti_tamper::wbaes::last_error());
        std::free(tbl);
        return false;
    }

    const uint8_t* tbl_bytes = reinterpret_cast<const uint8_t*>(tbl);
    size_t tbl_len = sizeof(anti_tamper::wbaes::white_box_table_t);

    if (memcontains(tbl_bytes, tbl_len, key, 16)) {
        std::printf("LEAK_KEY_FOUND_IN_TABLE\n");
        hex_print("key_leaked", key, 16);
        std::free(tbl);
        return false;
    }

    std::printf("table_size_bytes: %zu\n", tbl_len);
    std::printf("table_size_kb: %zu\n", tbl_len / 1024);

    std::free(tbl);
    return true;
}

bool test_deterministic_generation() {
    uint8_t key[16];
    if (!generate_random_bytes(key, sizeof(key))) {
        std::printf("DET_RANDOM_KEY_FAILED\n");
        return false;
    }
    uint64_t seed = 0x123456789ABCDEF0ULL;

    anti_tamper::wbaes::white_box_table_t* tbl_a =
        static_cast<anti_tamper::wbaes::white_box_table_t*>(
            std::malloc(sizeof(anti_tamper::wbaes::white_box_table_t)));
    anti_tamper::wbaes::white_box_table_t* tbl_b =
        static_cast<anti_tamper::wbaes::white_box_table_t*>(
            std::malloc(sizeof(anti_tamper::wbaes::white_box_table_t)));
    if (!tbl_a || !tbl_b) {
        std::printf("DET_ALLOC_FAILED\n");
        if (tbl_a) std::free(tbl_a);
        if (tbl_b) std::free(tbl_b);
        return false;
    }
    if (!anti_tamper::wbaes::generate_tables(key, seed, *tbl_a)) {
        std::printf("DET_GENERATE_A_FAILED\n");
        std::free(tbl_a); std::free(tbl_b);
        return false;
    }
    if (!anti_tamper::wbaes::generate_tables(key, seed, *tbl_b)) {
        std::printf("DET_GENERATE_B_FAILED\n");
        std::free(tbl_a); std::free(tbl_b);
        return false;
    }
    if (std::memcmp(tbl_a, tbl_b, sizeof(anti_tamper::wbaes::white_box_table_t)) != 0) {
        std::printf("DET_NOT_DETERMINISTIC\n");
        std::free(tbl_a); std::free(tbl_b);
        return false;
    }
    std::free(tbl_a); std::free(tbl_b);
    return true;
}

}

int main() {
    std::printf("Starting WBAES tests...\n");
    std::printf("white_box_table_t size: %zu bytes (%zu KB)\n",
        sizeof(anti_tamper::wbaes::white_box_table_t),
        sizeof(anti_tamper::wbaes::white_box_table_t) / 1024);

    if (!test_known_answer()) {
        std::printf("FAIL: known_answer\n");
        return 1;
    }
    std::printf("PASS: known_answer\n");

    if (!test_random_match()) {
        std::printf("FAIL: random_match\n");
        return 1;
    }
    std::printf("PASS: random_match (16 random PT/key trials matched standard AES bit-for-bit)\n");

    if (!test_ctr_round_trip()) {
        std::printf("FAIL: ctr_round_trip\n");
        return 1;
    }
    std::printf("PASS: ctr_round_trip (4097-byte buffer encrypted via wbaes CTR, decrypted via payload.c routine)\n");

    if (!test_deterministic_generation()) {
        std::printf("FAIL: deterministic_generation\n");
        return 1;
    }
    std::printf("PASS: deterministic_generation (same key+seed produces identical tables)\n");

    if (!test_no_key_in_memory()) {
        std::printf("FAIL: no_key_in_memory\n");
        return 1;
    }
    std::printf("PASS: no_key_in_memory (16-byte AES key not present as contiguous substring in table blob)\n");

    std::printf("WBAES_TEST_PASSED\n");
    return 0;
}
