#include "memory_tests.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace test_target {
namespace memory {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[MEM] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

#pragma optimize("", off)

static volatile int s_side_effect = 0;

static int __cdecl callable_add(int a, int b) {
    return a + b;
}

static int __cdecl callable_mul(int a, int b) {
    return a * b;
}

static int __cdecl callable_xor(int a, int b) {
    return a ^ b;
}

static int __cdecl callable_sub(int a, int b) {
    return a - b;
}

#pragma optimize("", on)

static const uint8_t kAesSbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

static const uint8_t kAesInvSbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

static const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint8_t kRc4TestKey[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static const uint64_t kBlowfishPi[18] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B,
};

void test_aob_markers(const config_t& cfg) {
    log("AOB marker test starting...");

    volatile uint8_t* marker1 = (volatile uint8_t*)VirtualAlloc(
        nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (marker1) {
        const char pattern1[] = "AIDA_TEST_MARKER";
        for (int i = 0; i < (int)sizeof(pattern1) - 1; ++i)
            marker1[i] = pattern1[i];

        const uint8_t sig1[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
        for (int i = 0; i < 8; ++i)
            marker1[64 + i] = sig1[i];

        const uint8_t sig2[] = { 0x41, 0x69, 0x44, 0x41, 0x5F, 0x53, 0x49, 0x47 };
        for (int i = 0; i < 8; ++i)
            marker1[128 + i] = sig2[i];

        log("AOB marker 1 at %p: 'AIDA_TEST_MARKER'", (void*)marker1);
        log("AOB marker 2 at %p: DEADBEEF CAFEBABE", (void*)(marker1 + 64));
        log("AOB marker 3 at %p: AiDA_SIG", (void*)(marker1 + 128));
    }

    volatile uint8_t* marker2 = (volatile uint8_t*)VirtualAlloc(
        nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (marker2) {
        const char pattern2[] = "AIDA_SCAN_TARGET_SECONDARY";
        for (int i = 0; i < (int)sizeof(pattern2) - 1; ++i)
            marker2[i] = pattern2[i];

        for (int i = 0; i < 256; ++i)
            marker2[256 + i] = (uint8_t)(i ^ 0xAA);

        log("AOB marker 4 at %p: 'AIDA_SCAN_TARGET_SECONDARY'", (void*)marker2);
        log("AOB marker 5 at %p: XOR pattern (256 bytes)", (void*)(marker2 + 256));
    }

    volatile uint8_t* marker3 = (volatile uint8_t*)VirtualAlloc(
        nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (marker3) {
        for (int i = 0; i < 16; ++i) {
            marker3[i * 16] = 0x90;
            marker3[i * 16 + 1] = 0x90;
            marker3[i * 16 + 2] = 0xCC;
            marker3[i * 16 + 3] = 0xCC;
            marker3[i * 16 + 4] = 0xEB;
            marker3[i * 16 + 5] = 0xFE;
            for (int j = 6; j < 16; ++j)
                marker3[i * 16 + j] = (uint8_t)(i * 16 + j);
        }
        log("AOB marker 6 at %p: repeating NOP/INT3/JMP pattern", (void*)marker3);
    }

    log("AOB marker test complete (buffers kept alive)");
}

void test_signature_patterns(const config_t& cfg) {
    log("Signature pattern test starting...");

    void* buf1 = VirtualAlloc(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf1) {
        uint8_t* p = (uint8_t*)buf1;

        p[0] = 0x4D; p[1] = 0x5A;
        p[60] = 0x80; p[61] = 0x00; p[62] = 0x00; p[63] = 0x00;
        p[0x80] = 0x50; p[0x81] = 0x45; p[0x82] = 0x00; p[0x83] = 0x00;

        log("Signature pattern 1 at %p: PE header stub", buf1);
    }

    void* buf2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf2) {
        uint8_t* p = (uint8_t*)buf2;

        p[0] = 0x48; p[1] = 0x89; p[2] = 0x5C; p[3] = 0x24; p[4] = 0x08;

        p[16] = 0x48; p[17] = 0x83; p[18] = 0xEC; p[19] = 0x20;

        p[32] = 0x48; p[33] = 0x8D; p[34] = 0x0D;

        p[48] = 0xFF; p[49] = 0x15;

        p[64] = 0xC3;

        p[80] = 0xCC;
        p[81] = 0xCC;
        p[82] = 0xCC;

        log("Signature pattern 2 at %p: x64 prologue/epilogue stubs", buf2);
    }

    void* buf3 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf3) {
        uint8_t* p = (uint8_t*)buf3;
        for (int i = 0; i < 4096; ++i)
            p[i] = (uint8_t)((i * 7 + 13) ^ (i >> 3));

        log("Signature pattern 3 at %p: pseudo-random fill (4096 bytes)", buf3);
    }

    log("Signature pattern test complete");
}

void test_protection_flags(const config_t& cfg) {
    log("Memory protection flags test starting...");

    void* read_only = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    if (read_only) {
        log("Allocated PAGE_READONLY at %p", read_only);
    }

    void* rw = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (rw) {
        memset(rw, 0x41, 4096);
        log("Allocated PAGE_READWRITE at %p", rw);
    }

    void* rwx = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (rwx) {
        uint8_t* code = (uint8_t*)rwx;
        code[0] = 0xB8;
        code[1] = 0x2A;
        code[2] = 0x00;
        code[3] = 0x00;
        code[4] = 0x00;
        code[5] = 0xC3;
        log("Allocated PAGE_EXECUTE_READWRITE at %p (mov eax, 42; ret)", rwx);

        typedef int(*fn_t)();
        fn_t fn = (fn_t)rwx;
        int result = fn();
        log("RWX code execution result: %d (expected 42)", result);
    }

    void* rx = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (rx) {
        uint8_t* code = (uint8_t*)rx;
        code[0] = 0x48; code[1] = 0xC7; code[2] = 0xC0;
        code[3] = 0x63; code[4] = 0x00; code[5] = 0x00; code[6] = 0x00;
        code[7] = 0xC3;

        DWORD old_protect;
        VirtualProtect(rx, 4096, PAGE_EXECUTE_READ, &old_protect);
        log("Allocated PAGE_EXECUTE_READ at %p (via VirtualProtect from RW)", rx);

        typedef int(*fn_t)();
        fn_t fn = (fn_t)rx;
        int result = fn();
        log("RX code execution result: %d (expected 99)", result);
    }

    void* noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    if (noaccess) {
        log("Allocated PAGE_NOACCESS at %p", noaccess);
    }

    void* guard = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_GUARD);
    if (guard) {
        log("Allocated PAGE_READWRITE|PAGE_GUARD at %p", guard);
    }

    log("Memory protection flags test complete (allocations kept alive)");
}

void test_function_pointers(const config_t& cfg) {
    log("Function pointer test starting...");

    typedef int(__cdecl* arith_fn)(int, int);
    arith_fn fns[] = { callable_add, callable_mul, callable_xor, callable_sub };
    const char* names[] = { "add", "mul", "xor", "sub" };

    for (int i = 0; i < 4; ++i) {
        int result = fns[i](10, 3);
        log("Function pointer %s(10, 3) = %d at %p", names[i], result, (void*)fns[i]);
    }

    arith_fn* heap_table = (arith_fn*)VirtualAlloc(
        nullptr, sizeof(arith_fn) * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (heap_table) {
        heap_table[0] = callable_add;
        heap_table[1] = callable_mul;
        heap_table[2] = callable_xor;
        heap_table[3] = callable_sub;

        for (int i = 0; i < 4; ++i) {
            int result = heap_table[i](7, 5);
            log("Heap vtable[%d] %s(7, 5) = %d", i, names[i], result);
        }
    }

    void* trampoline_buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (trampoline_buf) {
        uint8_t* code = (uint8_t*)trampoline_buf;

        code[0] = 0x8D; code[1] = 0x04; code[2] = 0x11;
        code[3] = 0xC3;

        typedef int(*add_fn)(int, int);
        add_fn dynamic_add = (add_fn)trampoline_buf;
        int result = dynamic_add(100, 23);
        log("Dynamic trampoline add(100, 23) = %d at %p", result, trampoline_buf);
    }

    log("Function pointer test complete");
}

void test_crypto_patterns(const config_t& cfg) {
    log("Crypto pattern test starting...");

    volatile uint8_t sbox_check = 0;
    for (int i = 0; i < 256; ++i)
        sbox_check ^= kAesSbox[i];
    log("AES S-box at %p (256 bytes, xor check: 0x%02X)", (const void*)kAesSbox, sbox_check);

    volatile uint8_t inv_check = 0;
    for (int i = 0; i < 256; ++i)
        inv_check ^= kAesInvSbox[i];
    log("AES Inverse S-box at %p (256 bytes, xor check: 0x%02X)", (const void*)kAesInvSbox, inv_check);

    volatile uint32_t k_check = 0;
    for (int i = 0; i < 64; ++i)
        k_check ^= kSha256K[i];
    log("SHA-256 round constants at %p (64 x uint32, xor check: 0x%08X)", (const void*)kSha256K, k_check);

    volatile uint8_t rc4_check = 0;
    for (int i = 0; i < 16; ++i)
        rc4_check ^= kRc4TestKey[i];
    log("RC4 test key at %p (16 bytes, xor check: 0x%02X)", (const void*)kRc4TestKey, rc4_check);

    volatile uint64_t bf_check = 0;
    for (int i = 0; i < 18; ++i)
        bf_check ^= kBlowfishPi[i];
    log("Blowfish P-array at %p (18 x uint64, xor check: 0x%016llX)", (const void*)kBlowfishPi, bf_check);

    void* heap_sbox = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (heap_sbox) {
        memcpy(heap_sbox, kAesSbox, 256);
        memcpy((uint8_t*)heap_sbox + 256, kAesInvSbox, 256);
        memcpy((uint8_t*)heap_sbox + 512, kSha256K, sizeof(kSha256K));
        log("Heap crypto patterns at %p (S-box + InvS-box + SHA256K)", heap_sbox);
    }

    log("Crypto pattern test complete");
}

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Memory tests starting ===");

    test_aob_markers(cfg);
    test_signature_patterns(cfg);
    test_protection_flags(cfg);
    test_function_pointers(cfg);
    test_crypto_patterns(cfg);

    log("=== Memory tests complete ===");
}

}
}
