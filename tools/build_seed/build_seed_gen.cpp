#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace {

constexpr size_t k_seed_bytes = 32;

bool gather_entropy(unsigned char* out_buffer, size_t out_size) {
    NTSTATUS status = ::BCryptGenRandom(
        nullptr,
        out_buffer,
        static_cast<ULONG>(out_size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status == STATUS_SUCCESS;
}

void to_hex(const unsigned char* src, size_t src_size, char* dst, size_t dst_size) {
    static const char k_hex[] = "0123456789abcdef";
    if (dst_size < src_size * 2u + 1u) {
        return;
    }
    for (size_t idx = 0; idx < src_size; ++idx) {
        dst[idx * 2u] = k_hex[(src[idx] >> 4) & 0x0F];
        dst[idx * 2u + 1u] = k_hex[src[idx] & 0x0F];
    }
    dst[src_size * 2u] = '\0';
}

bool write_seed_file(const char* path, const char* hex_seed) {
    HANDLE handle = ::CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    DWORD length = static_cast<DWORD>(std::strlen(hex_seed));
    BOOL ok = ::WriteFile(handle, hex_seed, length, &written, nullptr);
    ::CloseHandle(handle);
    return ok != FALSE && written == length;
}

}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: aida_build_seed_gen <output_path>\n");
        return 1;
    }
    unsigned char raw_seed[k_seed_bytes] = {};
    if (!gather_entropy(raw_seed, k_seed_bytes)) {
        std::fprintf(stderr, "aida_build_seed_gen: BCryptGenRandom failed\n");
        return 2;
    }
    char hex_seed[k_seed_bytes * 2u + 1u] = {};
    to_hex(raw_seed, k_seed_bytes, hex_seed, sizeof(hex_seed));
    if (!write_seed_file(argv[1], hex_seed)) {
        std::fprintf(stderr, "aida_build_seed_gen: failed to write seed file\n");
        return 3;
    }
    std::printf("%s\n", hex_seed);
    return 0;
}
