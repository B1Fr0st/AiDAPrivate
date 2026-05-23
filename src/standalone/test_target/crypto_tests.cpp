#include "crypto_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace test_target {
namespace crypto {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[CRYPTO] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static const uint8_t kAesSbox[256] = {
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
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
};

static const uint8_t kAesInvSbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D,
};

static const uint8_t kAesRcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

static void aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i)
        state[i] = kAesSbox[state[i]];
}

static void aes_inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i)
        state[i] = kAesInvSbox[state[i]];
}

static void aes_shift_rows(uint8_t state[16]) {
    uint8_t tmp;
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;
}

static void aes_inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp;
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
}

static uint8_t gf_mul2(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
}

static uint8_t gf_mul3(uint8_t a) {
    return gf_mul2(a) ^ a;
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t hi_bit;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

static void aes_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        state[i]   = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3;
        state[i+1] = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3;
        state[i+2] = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3);
        state[i+3] = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3);
    }
}

static void aes_inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        state[i]   = gf_mul(a0,0x0E) ^ gf_mul(a1,0x0B) ^ gf_mul(a2,0x0D) ^ gf_mul(a3,0x09);
        state[i+1] = gf_mul(a0,0x09) ^ gf_mul(a1,0x0E) ^ gf_mul(a2,0x0B) ^ gf_mul(a3,0x0D);
        state[i+2] = gf_mul(a0,0x0D) ^ gf_mul(a1,0x09) ^ gf_mul(a2,0x0E) ^ gf_mul(a3,0x0B);
        state[i+3] = gf_mul(a0,0x0B) ^ gf_mul(a1,0x0D) ^ gf_mul(a2,0x09) ^ gf_mul(a3,0x0E);
    }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t* round_key) {
    for (int i = 0; i < 16; ++i)
        state[i] ^= round_key[i];
}

static void aes128_key_expansion(const uint8_t key[16], uint8_t round_keys[176]) {
    memcpy(round_keys, key, 16);
    for (int i = 4; i < 44; ++i) {
        uint8_t temp[4];
        memcpy(temp, &round_keys[(i - 1) * 4], 4);
        if (i % 4 == 0) {
            uint8_t t = temp[0];
            temp[0] = kAesSbox[temp[1]] ^ kAesRcon[i / 4];
            temp[1] = kAesSbox[temp[2]];
            temp[2] = kAesSbox[temp[3]];
            temp[3] = kAesSbox[t];
        }
        for (int j = 0; j < 4; ++j)
            round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j];
    }
}

static void aes128_ecb_encrypt_block(const uint8_t plaintext[16], const uint8_t round_keys[176], uint8_t ciphertext[16]) {
    uint8_t state[16];
    memcpy(state, plaintext, 16);

    aes_add_round_key(state, &round_keys[0]);

    for (int round = 1; round <= 9; ++round) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &round_keys[round * 16]);
    }

    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &round_keys[160]);

    memcpy(ciphertext, state, 16);
}

static void aes128_ecb_decrypt_block(const uint8_t ciphertext[16], const uint8_t round_keys[176], uint8_t plaintext[16]) {
    uint8_t state[16];
    memcpy(state, ciphertext, 16);

    aes_add_round_key(state, &round_keys[160]);

    for (int round = 9; round >= 1; --round) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, &round_keys[round * 16]);
        aes_inv_mix_columns(state);
    }

    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, &round_keys[0]);

    memcpy(plaintext, state, 16);
}

static const uint32_t kSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static const uint32_t kSha256H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static uint32_t sha256_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t sha256_sigma0(uint32_t x) { return sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22); }
static uint32_t sha256_sigma1(uint32_t x) { return sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25); }
static uint32_t sha256_gamma0(uint32_t x) { return sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3); }
static uint32_t sha256_gamma1(uint32_t x) { return sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10); }

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = sha256_gamma1(w[i-2]) + w[i-7] + sha256_gamma0(w[i-15]) + w[i-16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + sha256_sigma1(e) + sha256_ch(e, f, g) + kSha256K[i] + w[i];
        uint32_t t2 = sha256_sigma0(a) + sha256_maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_hash(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t state[8];
    memcpy(state, kSha256H0, sizeof(state));

    size_t full_blocks = len / 64;
    for (size_t i = 0; i < full_blocks; ++i) {
        sha256_transform(state, data + i * 64);
    }

    uint8_t last_block[128];
    memset(last_block, 0, sizeof(last_block));
    size_t remaining = len % 64;
    memcpy(last_block, data + full_blocks * 64, remaining);
    last_block[remaining] = 0x80;

    int pad_blocks = (remaining < 56) ? 1 : 2;
    uint64_t bit_len = (uint64_t)len * 8;
    int end = pad_blocks * 64 - 8;
    last_block[end]   = (uint8_t)(bit_len >> 56);
    last_block[end+1] = (uint8_t)(bit_len >> 48);
    last_block[end+2] = (uint8_t)(bit_len >> 40);
    last_block[end+3] = (uint8_t)(bit_len >> 32);
    last_block[end+4] = (uint8_t)(bit_len >> 24);
    last_block[end+5] = (uint8_t)(bit_len >> 16);
    last_block[end+6] = (uint8_t)(bit_len >> 8);
    last_block[end+7] = (uint8_t)(bit_len);

    for (int i = 0; i < pad_blocks; ++i) {
        sha256_transform(state, last_block + i * 64);
    }

    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (uint8_t)(state[i] >> 24);
        out[i*4+1] = (uint8_t)(state[i] >> 16);
        out[i*4+2] = (uint8_t)(state[i] >> 8);
        out[i*4+3] = (uint8_t)(state[i]);
    }
}

struct rc4_state_t {
    uint8_t S[256];
    uint8_t i, j;
};

static void rc4_init(rc4_state_t* st, const uint8_t* key, int key_len) {
    for (int i = 0; i < 256; ++i) st->S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = j + st->S[i] + key[i % key_len];
        uint8_t tmp = st->S[i]; st->S[i] = st->S[j]; st->S[j] = tmp;
    }
    st->i = 0;
    st->j = 0;
}

static void rc4_crypt(rc4_state_t* st, const uint8_t* in, uint8_t* out, int len) {
    for (int n = 0; n < len; ++n) {
        st->i++;
        st->j += st->S[st->i];
        uint8_t tmp = st->S[st->i]; st->S[st->i] = st->S[st->j]; st->S[st->j] = tmp;
        uint8_t k = st->S[(uint8_t)(st->S[st->i] + st->S[st->j])];
        out[n] = in[n] ^ k;
    }
}

static const uint8_t kXorKey = 0x5A;

struct xor_string_t {
    uint8_t  encoded[32];
    int      len;
};

static const xor_string_t kXorStrings[12] = {
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x6B }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x68 }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x69 }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x6E }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x6F }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x6C }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x6D }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x62 }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x63 }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x19,0x3C,0x3F,0x3A,0x38,0x35,0x05,0x1E,0x35,0x33,0x35,0x34,0x35,0x34,0x05,0x6B,0x6A }, 22},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x29,0x35,0x33,0x3C,0x35,0x38,0x05,0x11,0x35,0x3F,0x05,0x1B,0x36,0x3A,0x32,0x3B }, 21},
    {{ 0x1B,0x33,0x1E,0x1B,0x05,0x29,0x35,0x33,0x3C,0x35,0x38,0x05,0x11,0x35,0x3F,0x05,0x15,0x37,0x35,0x37,0x3B }, 21},
};

static void xor_decode(const uint8_t* encoded, int len, char* out) {
    for (int i = 0; i < len; ++i)
        out[i] = (char)(encoded[i] ^ kXorKey);
    out[len] = '\0';
}

static const char kBase64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t* data, int len, char* out, int out_max) {
    int o = 0;
    for (int i = 0; i < len; i += 3) {
        if (o + 4 >= out_max) break;
        uint32_t n = (uint32_t)data[i] << 16;
        if (i + 1 < len) n |= (uint32_t)data[i+1] << 8;
        if (i + 2 < len) n |= (uint32_t)data[i+2];

        out[o++] = kBase64Table[(n >> 18) & 0x3F];
        out[o++] = kBase64Table[(n >> 12) & 0x3F];
        out[o++] = (i + 1 < len) ? kBase64Table[(n >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < len) ? kBase64Table[n & 0x3F] : '=';
    }
    out[o] = '\0';
    return o;
}

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_decode(const char* data, int len, uint8_t* out, int out_max) {
    int o = 0;
    for (int i = 0; i < len; i += 4) {
        if (o + 3 > out_max) break;
        int a = base64_decode_char(data[i]);
        int b = (i+1 < len) ? base64_decode_char(data[i+1]) : 0;
        int c = (i+2 < len) ? base64_decode_char(data[i+2]) : 0;
        int d = (i+3 < len) ? base64_decode_char(data[i+3]) : 0;
        if (a < 0) a = 0;
        if (b < 0) b = 0;
        if (c < 0) c = 0;
        if (d < 0) d = 0;

        uint32_t n = (a << 18) | (b << 12) | (c << 6) | d;
        out[o++] = (uint8_t)(n >> 16);
        if (i+2 < len && data[i+2] != '=') out[o++] = (uint8_t)(n >> 8);
        if (i+3 < len && data[i+3] != '=') out[o++] = (uint8_t)n;
    }
    return o;
}

static const uint32_t kCrc32Table[256] = {
    0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
    0x0EDB8832,0x79DCB8A4,0xE0D5E91B,0x97D2D988,0x09B64C2B,0x7EB17CBB,0xE7B82D09,0x90BF1D9F,
    0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
    0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
    0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
    0x35B5A8FA,0x42B2986C,0xDBBBB9D6,0xACBCB9C0,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
    0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F6B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
    0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
    0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
    0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0D6B,0x086D3D2D,0x91646C97,0xE6635C01,
    0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
    0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
    0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
    0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7822,
    0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
    0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
    0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
    0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5ACE,0xEE0E363C,0x990FD1E6,0x06CA6351,0x270241AA,
    0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,0x5EDEF90E,0x29D9C998,
    0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,
    0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,
    0x0D6D6A3E,0x7A6A5ACE,0xEE0E363C,0x990FD1E6,0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,
    0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,
    0xDF60EFC3,0xA8670955,0x31680E28,0x466906BE,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,
    0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,
    0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
    0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,
    0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,0x68DDB3F6,0x1FDA836E,
    0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,0xFF0F6B70,0x66063BCA,0x11010B5C,
    0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,
    0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,
    0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,
};

static uint32_t crc32_compute(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return crc ^ 0xFFFFFFFF;
}

static int __declspec(noinline) constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0 ? 1 : 0;
}

static void tea_encrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = 0;
    for (int i = 0; i < 32; ++i) {
        sum += delta;
        v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
    }
    v[0] = v0;
    v[1] = v1;
}

static void tea_decrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * 32;
    for (int i = 0; i < 32; ++i) {
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}

struct crypto_context_t {
    uint8_t  aes_key[16];
    uint8_t  aes_iv[16];
    uint8_t  aes_round_keys[176];
    uint8_t  sha256_digest[32];
    rc4_state_t rc4;
    uint32_t tea_key[4];
    uint32_t crc32_accum;
    uint8_t  hmac_pad[64];
    uint8_t  derived_key[32];
    uint64_t nonce;
    uint32_t counter;
    uint8_t  state_buffer[256];
};

static volatile crypto_context_t s_crypto_ctx{};

#pragma optimize("", off)

void __declspec(noinline) test_aes128_ecb(const config_t& cfg) {
    log("AES-128-ECB test starting...");
    log("S-box table at %p (256 bytes)", (const void*)kAesSbox);
    log("Inverse S-box table at %p (256 bytes)", (const void*)kAesInvSbox);

    uint8_t key[16] = { 0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C };
    uint8_t plaintext[16] = { 0x32,0x43,0xF6,0xA8,0x88,0x5A,0x30,0x8D,0x31,0x31,0x98,0xA2,0xE0,0x37,0x07,0x34 };
    uint8_t expected_ct[16] = { 0x39,0x25,0x84,0x1D,0x02,0xDC,0x09,0xFB,0xDC,0x11,0x85,0x97,0x19,0x6A,0x0B,0x32 };

    uint8_t round_keys[176];
    aes128_key_expansion(key, round_keys);

    uint8_t ciphertext[16];
    aes128_ecb_encrypt_block(plaintext, round_keys, ciphertext);

    char hex_ct[64] = {0};
    for (int i = 0; i < 16; ++i) sprintf_s(hex_ct + i*2, 3, "%02X", ciphertext[i]);
    log("AES-128-ECB encrypt: %s", hex_ct);

    int match = constant_time_compare(ciphertext, expected_ct, 16);
    log("AES-128-ECB NIST KAT: %s", match ? "PASS" : "FAIL");

    uint8_t decrypted[16];
    aes128_ecb_decrypt_block(ciphertext, round_keys, decrypted);

    int dec_match = constant_time_compare(decrypted, plaintext, 16);
    log("AES-128-ECB decrypt roundtrip: %s", dec_match ? "PASS" : "FAIL");

    uint8_t multi_pt[64];
    uint8_t multi_ct[64];
    for (int i = 0; i < 64; ++i) multi_pt[i] = (uint8_t)(i * 7 + 3);
    for (int b = 0; b < 4; ++b)
        aes128_ecb_encrypt_block(multi_pt + b*16, round_keys, multi_ct + b*16);
    log("AES-128-ECB encrypted 4 blocks (64 bytes)");

    log("AES-128-ECB test complete");
}

void __declspec(noinline) test_sha256(const config_t& cfg) {
    log("SHA-256 test starting...");
    log("SHA-256 K constants at %p (64 x uint32)", (const void*)kSha256K);
    log("SHA-256 H0 initial values at %p (8 x uint32)", (const void*)kSha256H0);

    uint8_t hash[32];
    sha256_hash((const uint8_t*)"", 0, hash);
    char hex[65] = {0};
    for (int i = 0; i < 32; ++i) sprintf_s(hex + i*2, 3, "%02x", hash[i]);
    log("SHA-256(\"\") = %s", hex);

    const char* expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    log("SHA-256 empty string KAT: %s", strcmp(hex, expected_empty) == 0 ? "PASS" : "FAIL");

    sha256_hash((const uint8_t*)"abc", 3, hash);
    for (int i = 0; i < 32; ++i) sprintf_s(hex + i*2, 3, "%02x", hash[i]);
    log("SHA-256(\"abc\") = %s", hex);

    const char* expected_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    log("SHA-256 'abc' KAT: %s", strcmp(hex, expected_abc) == 0 ? "PASS" : "FAIL");

    sha256_hash((const uint8_t*)"AiDA_TestTarget", 15, hash);
    for (int i = 0; i < 32; ++i) sprintf_s(hex + i*2, 3, "%02x", hash[i]);
    log("SHA-256(\"AiDA_TestTarget\") = %s", hex);

    uint8_t big_buf[1024];
    for (int i = 0; i < 1024; ++i) big_buf[i] = (uint8_t)(i & 0xFF);
    sha256_hash(big_buf, 1024, hash);
    for (int i = 0; i < 32; ++i) sprintf_s(hex + i*2, 3, "%02x", hash[i]);
    log("SHA-256(1024-byte pattern) = %s", hex);

    log("SHA-256 test complete");
}

void __declspec(noinline) test_rc4(const config_t& cfg) {
    log("RC4 test starting...");

    const uint8_t rc4_key[] = { 'K','e','y' };
    const uint8_t rc4_pt[] = { 'P','l','a','i','n','t','e','x','t' };
    uint8_t rc4_ct[9];
    uint8_t rc4_dec[9];

    rc4_state_t st;
    rc4_init(&st, rc4_key, 3);
    rc4_crypt(&st, rc4_pt, rc4_ct, 9);

    char hex[32] = {0};
    for (int i = 0; i < 9; ++i) sprintf_s(hex + i*2, 3, "%02X", rc4_ct[i]);
    log("RC4(\"Key\", \"Plaintext\") = %s", hex);

    rc4_init(&st, rc4_key, 3);
    rc4_crypt(&st, rc4_ct, rc4_dec, 9);
    int match = (memcmp(rc4_dec, rc4_pt, 9) == 0);
    log("RC4 decrypt roundtrip: %s", match ? "PASS" : "FAIL");

    uint8_t key16[16] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10 };
    uint8_t data256[256], enc256[256], dec256[256];
    for (int i = 0; i < 256; ++i) data256[i] = (uint8_t)i;

    rc4_init(&st, key16, 16);
    rc4_crypt(&st, data256, enc256, 256);

    rc4_init(&st, key16, 16);
    rc4_crypt(&st, enc256, dec256, 256);

    int match256 = (memcmp(dec256, data256, 256) == 0);
    log("RC4 256-byte roundtrip (16-byte key): %s", match256 ? "PASS" : "FAIL");

    log("RC4 test complete");
}

void __declspec(noinline) test_xor_strings(const config_t& cfg) {
    log("XOR-encoded string test starting...");
    log("XOR key: 0x%02X", kXorKey);

    for (int i = 0; i < 12; ++i) {
        char decoded[64] = {0};
        xor_decode(kXorStrings[i].encoded, kXorStrings[i].len, decoded);
        log("XOR string %2d decoded: \"%s\" (len=%d)", i + 1, decoded, kXorStrings[i].len);
    }

    log("XOR-encoded string test complete");
}

void __declspec(noinline) test_base64(const config_t& cfg) {
    log("Base64 test starting...");

    const char* input = "AiDA_TestTarget_Base64";
    char encoded[128] = {0};
    int enc_len = base64_encode((const uint8_t*)input, (int)strlen(input), encoded, sizeof(encoded));
    log("Base64 encode(\"%s\") = \"%s\" (len=%d)", input, encoded, enc_len);

    uint8_t decoded[128] = {0};
    int dec_len = base64_decode(encoded, enc_len, decoded, sizeof(decoded));
    decoded[dec_len] = '\0';
    log("Base64 decode = \"%s\" (len=%d)", (char*)decoded, dec_len);
    log("Base64 roundtrip: %s", (strcmp((char*)decoded, input) == 0) ? "PASS" : "FAIL");

    uint8_t bin_data[32];
    for (int i = 0; i < 32; ++i) bin_data[i] = (uint8_t)(i * 8 + 1);
    char bin_enc[128] = {0};
    base64_encode(bin_data, 32, bin_enc, sizeof(bin_enc));
    log("Base64 encode(32 binary bytes) = \"%s\"", bin_enc);

    base64_encode((const uint8_t*)"A", 1, encoded, sizeof(encoded));
    log("Base64 encode(\"A\") = \"%s\"", encoded);
    base64_encode((const uint8_t*)"AB", 2, encoded, sizeof(encoded));
    log("Base64 encode(\"AB\") = \"%s\"", encoded);
    base64_encode((const uint8_t*)"ABC", 3, encoded, sizeof(encoded));
    log("Base64 encode(\"ABC\") = \"%s\"", encoded);

    log("Base64 test complete");
}

void __declspec(noinline) test_crc32(const config_t& cfg) {
    log("CRC32 test starting...");
    log("CRC32 lookup table at %p (256 x uint32)", (const void*)kCrc32Table);

    uint32_t crc_empty = crc32_compute((const uint8_t*)"", 0);
    log("CRC32(\"\") = 0x%08X", crc_empty);

    uint32_t crc_test = crc32_compute((const uint8_t*)"123456789", 9);
    log("CRC32(\"123456789\") = 0x%08X (expected 0xCBF43926)", crc_test);
    log("CRC32 standard KAT: %s", crc_test == 0xCBF43926u ? "PASS" : "FAIL");

    uint32_t crc_aida = crc32_compute((const uint8_t*)"AiDA_TestTarget", 15);
    log("CRC32(\"AiDA_TestTarget\") = 0x%08X", crc_aida);

    uint8_t pattern[4096];
    for (int i = 0; i < 4096; ++i) pattern[i] = (uint8_t)(i & 0xFF);
    uint32_t crc_big = crc32_compute(pattern, 4096);
    log("CRC32(4096-byte pattern) = 0x%08X", crc_big);

    log("CRC32 test complete");
}

void __declspec(noinline) test_constant_time_compare(const config_t& cfg) {
    log("Constant-time compare test starting...");

    uint8_t a[32] = {0}, b[32] = {0};
    for (int i = 0; i < 32; ++i) { a[i] = (uint8_t)i; b[i] = (uint8_t)i; }

    int eq = constant_time_compare(a, b, 32);
    log("Equal buffers: %s (result=%d)", eq ? "PASS" : "FAIL", eq);

    b[15] ^= 0x01;
    int neq = constant_time_compare(a, b, 32);
    log("Different buffers (bit flip at [15]): %s (result=%d)", neq == 0 ? "PASS" : "FAIL", neq);

    b[15] = a[15];
    b[31] ^= 0x80;
    neq = constant_time_compare(a, b, 32);
    log("Different buffers (bit flip at [31]): %s (result=%d)", neq == 0 ? "PASS" : "FAIL", neq);

    log("Constant-time compare test complete");
}

void __declspec(noinline) test_tea(const config_t& cfg) {
    log("TEA test starting...");

    uint32_t key[4] = { 0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0 };
    uint32_t data[2] = { 0x01234567, 0x89ABCDEF };
    uint32_t original[2] = { data[0], data[1] };

    log("TEA plaintext:  0x%08X 0x%08X", data[0], data[1]);

    tea_encrypt(data, key);
    log("TEA ciphertext: 0x%08X 0x%08X", data[0], data[1]);

    tea_decrypt(data, key);
    log("TEA decrypted:  0x%08X 0x%08X", data[0], data[1]);

    int match = (data[0] == original[0] && data[1] == original[1]);
    log("TEA roundtrip: %s", match ? "PASS" : "FAIL");

    for (int i = 0; i < 8; ++i) {
        uint32_t blk[2] = { (uint32_t)(i * 111), (uint32_t)(i * 222 + 333) };
        tea_encrypt(blk, key);
        log("TEA block %d: enc(0x%08X,0x%08X) = (0x%08X,0x%08X)", i, (uint32_t)(i*111), (uint32_t)(i*222+333), blk[0], blk[1]);
    }

    log("TEA test complete");
}

void __declspec(noinline) test_crypto_context(const config_t& cfg) {
    log("Crypto context persistence test starting...");

    volatile crypto_context_t* ctx = &s_crypto_ctx;

    for (int i = 0; i < 16; ++i) {
        ctx->aes_key[i] = (uint8_t)(0x2B + i * 3);
        ctx->aes_iv[i] = (uint8_t)(0xF0 - i * 7);
    }

    aes128_key_expansion((const uint8_t*)ctx->aes_key, (uint8_t*)ctx->aes_round_keys);
    log("Crypto context: AES key expanded (%d bytes round keys)", 176);

    sha256_hash((const uint8_t*)"AiDA_CryptoContext_Seed", 23, (uint8_t*)ctx->sha256_digest);
    log("Crypto context: SHA-256 digest computed");

    rc4_init((rc4_state_t*)&ctx->rc4, (const uint8_t*)ctx->aes_key, 16);
    log("Crypto context: RC4 state initialized");

    ctx->tea_key[0] = 0xA5A5A5A5;
    ctx->tea_key[1] = 0x5A5A5A5A;
    ctx->tea_key[2] = 0xDEADC0DE;
    ctx->tea_key[3] = 0xFEEDF00D;
    log("Crypto context: TEA key set");

    uint8_t seed[48];
    memcpy(seed, (const void*)ctx->aes_key, 16);
    memcpy(seed + 16, (const void*)ctx->sha256_digest, 32);
    sha256_hash(seed, 48, (uint8_t*)ctx->derived_key);
    log("Crypto context: Derived key computed");

    for (int i = 0; i < 64; ++i)
        ctx->hmac_pad[i] = (uint8_t)((i < 16 ? ctx->aes_key[i] : 0x00) ^ 0x36);
    log("Crypto context: HMAC ipad filled");

    ctx->nonce = 0xFEDCBA9876543210ULL;
    ctx->counter = 1;
    ctx->crc32_accum = crc32_compute((const uint8_t*)ctx->aes_key, 16);

    for (int i = 0; i < 256; ++i)
        ctx->state_buffer[i] = (uint8_t)(kAesSbox[i] ^ (uint8_t)(i * 3 + 17));

    log("Crypto context at %p (sizeof=%zu)", (const void*)&s_crypto_ctx, sizeof(crypto_context_t));
    log("  aes_key at offset 0, aes_iv at offset 16");
    log("  round_keys at offset 32, sha256_digest at offset 208");
    log("  nonce=0x%016llX, counter=%u, crc32=0x%08X",
        ctx->nonce, ctx->counter, ctx->crc32_accum);

    log("Crypto context persistence test complete");
}

#pragma optimize("", on)

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Crypto tests starting ===");

    test_aes128_ecb(cfg);
    test_sha256(cfg);
    test_rc4(cfg);
    test_xor_strings(cfg);
    test_base64(cfg);
    test_crc32(cfg);
    test_constant_time_compare(cfg);
    test_tea(cfg);
    test_crypto_context(cfg);

    log("=== Crypto tests complete ===");
}

}
}
