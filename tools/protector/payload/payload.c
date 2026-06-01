#include <stdint.h>
#include <stddef.h>
#include <intrin.h>
#include <wmmintrin.h>
#include <emmintrin.h>

#pragma warning(disable: 4330)
#pragma section(".payload", read, write, execute)
#pragma code_seg(".payload")

__declspec(allocate(".payload")) uintptr_t __security_cookie = 0xBB40E64EAA56C2BFULL;
__declspec(allocate(".payload")) uintptr_t __security_cookie_complement = ~0xBB40E64EAA56C2BFULL;

void __cdecl __security_check_cookie(uintptr_t cookie) {
    if (cookie != __security_cookie) {
        __fastfail(2);
    }
}

void __cdecl __GSHandlerCheck(void) {
}

void __cdecl __report_rangecheckfailure(void) {
    __fastfail(8);
}

typedef struct unicode_string_s {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t pad;
    uint16_t* Buffer;
} unicode_string_t;

typedef struct list_entry_s {
    struct list_entry_s* Flink;
    struct list_entry_s* Blink;
} list_entry_t;

static int resolve_apiset_host(const char* name, size_t name_len,
                               char* out, size_t out_cap, size_t* out_len);

typedef struct ldr_entry_s {
    list_entry_t InLoadOrderLinks;
    list_entry_t InMemoryOrderLinks;
    list_entry_t InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    uint32_t SizeOfImage;
    uint32_t pad0;
    unicode_string_t FullDllName;
    unicode_string_t BaseDllName;
} ldr_entry_t;

typedef struct peb_ldr_data_s {
    uint8_t pad0[16];
    list_entry_t InLoadOrderModuleList;
} peb_ldr_data_t;

typedef struct peb_s {
    uint8_t pad0[24];
    peb_ldr_data_t* Ldr;
} peb_t;

typedef long (__stdcall *nt_protect_t)(void*, void**, size_t*, uint32_t, uint32_t*);
typedef long (__stdcall *nt_alloc_t)(void*, void**, size_t, size_t*, uint32_t, uint32_t);
typedef long (__stdcall *nt_free_t)(void*, void**, size_t*, uint32_t);
typedef uint32_t (__stdcall *rtl_add_func_t)(void*, uint32_t, uint64_t);
typedef long (__stdcall *ldr_load_t)(uint16_t*, uint32_t*, unicode_string_t*, void**);
typedef int (__stdcall *vp_t)(void*, size_t, uint32_t, uint32_t*);
typedef void* (__stdcall *ll_t)(const char*);
typedef void* (__stdcall *gpa_t)(void*, const char*);

typedef struct resolved_s {
    void* ntdll;
    void* kernel32;
    void* kernelbase;
    nt_protect_t NtProtectVirtualMemory;
    nt_alloc_t NtAllocateVirtualMemory;
    nt_free_t NtFreeVirtualMemory;
    rtl_add_func_t RtlAddFunctionTable;
    ldr_load_t LdrLoadDll;
    vp_t VirtualProtect;
    ll_t LoadLibraryA;
    gpa_t GetProcAddress;
} resolved_t;

typedef struct packed_header_s {
    uint32_t magic;
    uint32_t version;
    uint32_t section_count;
    uint32_t import_count;
    uint32_t string_fixup_count;
    uint32_t resource_fixup_count;
    uint32_t section_table_offset;
    uint32_t import_table_offset;
    uint32_t string_table_offset;
    uint32_t resource_table_offset;
    uint32_t master_key_offset;
    uint32_t stub_code_offset;
    uint32_t master_key_pe_timestamp;
    uint32_t master_key_pe_size_of_code;
    uint32_t bind_flags;
    uint32_t aux_offset;
    uint32_t aux_size;
    uint8_t  bind_salt[16];
    uint32_t reserved[3];
} packed_header_t;

typedef struct section_descriptor_s {
    uint32_t original_rva;
    uint32_t original_virtual_size;
    uint32_t original_characteristics;
    uint32_t blob_offset;
    uint32_t compressed_size;
    uint32_t encrypted_size;
    uint32_t original_crc32;
    uint32_t section_index;
    uint8_t  layer1_iv[16];
    uint8_t  layer2_nonce[12];
    uint8_t  layer3_iv[8];
    uint32_t layers_applied;
} section_descriptor_t;

typedef struct import_entry_s {
    uint64_t dll_hash;
    uint64_t func_hash;
    uint32_t iat_rva;
    uint16_t ordinal;
    uint16_t flags;
} import_entry_t;

typedef struct string_fixup_s {
    uint32_t rva;
    uint32_t length;
    uint8_t  xor_key;
    uint8_t  is_wide;
    uint16_t reserved;
} string_fixup_t;

#pragma pack(push, 1)
typedef struct resource_fixup_s {
    uint32_t rva;
    uint32_t size;
    uint64_t rolling_key;
} resource_fixup_t;
#pragma pack(pop)

#define HASH_NTDLL          0x9b1856bd6172a2bbULL
#define HASH_KERNEL32       0x7d52b10b2b6fca23ULL
#define HASH_KERNELBASE     0x8d2f00dde5462eb7ULL
#define HASH_NTPROTECT      0x6f6da37809aecd66ULL
#define HASH_NTALLOC        0x4fe232be2dca3638ULL
#define HASH_NTFREE         0xa95b7a6b57337d87ULL
#define HASH_RTLADDFUNC     0x4e6baa688effc928ULL
#define HASH_LDRLOAD        0x34223840c85e30dfULL
#define HASH_VIRTUALPROTECT 0xed1006223abbbd53ULL
#define HASH_LOADLIBRARYA   0x69d265fe6b1c110fULL
#define HASH_GETPROCADDR    0x578960f1fc7fff25ULL
#define HASH_NTQUERYINFOPROC 0x32ca9e4b50ffedaaULL
#define HASH_NTGETCONTEXTTHREAD 0x60b61d0af197a950ULL
#define HASH_NTQUERYSYSINFO 0xcac033026619e14aULL
#define HASH_CHECKREMOTEDBG 0xe3549a1b1e8d41e1ULL
#define HASH_SLEEP          0x503cbccd6a5cdea8ULL

#define IMG_MAGIC           0x41504B44u
#define IMG_VERSION_LEGACY  0x00020000u
#define IMG_VERSION_MATRYO  0x00030000u
#define IMG_NT_SIGNATURE    0x00004550u
#define IMG_OPT64_MAGIC     0x020Bu
#define IMG_AUX_BLOCK_SIZE  368u
#define IMG_MAX_SECTIONS    512u
#define IMG_MAX_IMPORTS     65536u
#define IMG_MAX_FIXUPS      262144u
#define MATRYOSHKA_LAYERS_LEGACY 1u
#define MATRYOSHKA_LAYERS_FULL   3u
#define MEM_COMMIT_RESERVE  0x3000u
#define PAGE_RW             0x04u
#define PAGE_EX_RWX         0x40u
#define PAGE_EX_R           0x20u
#define PAGE_EX             0x10u
#define PAGE_R              0x02u
#define PAGE_NA             0x01u
#define MEM_RELEASE         0x8000u

#define IMG_SCN_EXEC        0x20000000u
#define IMG_SCN_READ        0x40000000u
#define IMG_SCN_WRITE       0x80000000u

static void mem_copy(void* d, const void* s, size_t n) {
    uint8_t* dd = (uint8_t*)d;
    const uint8_t* ss = (const uint8_t*)s;
    for (size_t i = 0; i < n; ++i) {
        dd[i] = ss[i];
    }
}

static void mem_set(void* d, uint8_t v, size_t n) {
    uint8_t* dd = (uint8_t*)d;
    for (size_t i = 0; i < n; ++i) {
        dd[i] = v;
    }
}

static int mem_eq(const void* a, const void* b, size_t n) {
    const uint8_t* aa = (const uint8_t*)a;
    const uint8_t* bb = (const uint8_t*)b;
    for (size_t i = 0; i < n; ++i) {
        if (aa[i] != bb[i]) {
            return 0;
        }
    }
    return 1;
}

static int range_u32_ok(uint32_t off, uint64_t len, uint32_t limit) {
    uint64_t end = (uint64_t)off + len;
    return off <= limit && end <= (uint64_t)limit;
}

static uint32_t image_size_from_headers(uint8_t* image_base) {
    if (image_base == 0) {
        return 0;
    }
    uint16_t mz = 0;
    mem_copy(&mz, image_base, 2);
    if (mz != 0x5A4Du) {
        return 0;
    }
    uint32_t e_lfanew = 0;
    mem_copy(&e_lfanew, image_base + 0x3C, 4);
    if (e_lfanew < 64u || e_lfanew > 0x10000u) {
        return 0;
    }
    uint8_t* nt = image_base + e_lfanew;
    uint32_t sig = 0;
    mem_copy(&sig, nt, 4);
    if (sig != IMG_NT_SIGNATURE) {
        return 0;
    }
    uint16_t opt_magic = 0;
    mem_copy(&opt_magic, nt + 0x18, 2);
    if (opt_magic != IMG_OPT64_MAGIC) {
        return 0;
    }
    uint32_t size_of_image = 0;
    mem_copy(&size_of_image, nt + 0x18 + 56, 4);
    return size_of_image;
}

static int validate_counted_table(uint8_t* packed_base, uint32_t packed_size,
                                  uint32_t offset, uint32_t expected_count,
                                  uint32_t elem_size, uint32_t max_count,
                                  uint32_t image_size) {
    if (expected_count == 0u && offset == 0u) {
        return 1;
    }
    if (offset == 0u || expected_count > max_count) {
        return 0;
    }
    if (!range_u32_ok(offset, 4u, packed_size)) {
        return 0;
    }
    uint32_t stored_count = 0;
    mem_copy(&stored_count, packed_base + offset, 4);
    if (stored_count != expected_count || stored_count > max_count) {
        return 0;
    }
    uint64_t bytes = 4ull + (uint64_t)stored_count * (uint64_t)elem_size;
    if (!range_u32_ok(offset, bytes, packed_size)) {
        return 0;
    }
    if (image_size != 0u && stored_count != 0u) {
        uint8_t* entries = packed_base + offset + 4u;
        if (elem_size == sizeof(string_fixup_t)) {
            for (uint32_t i = 0; i < stored_count; ++i) {
                string_fixup_t* sf = (string_fixup_t*)(entries + (size_t)i * sizeof(string_fixup_t));
                if (sf->length == 0u || !range_u32_ok(sf->rva, sf->length, image_size)) {
                    return 0;
                }
            }
        } else if (elem_size == sizeof(resource_fixup_t)) {
            for (uint32_t i = 0; i < stored_count; ++i) {
                resource_fixup_t* rf = (resource_fixup_t*)(entries + (size_t)i * sizeof(resource_fixup_t));
                if (rf->size == 0u || !range_u32_ok(rf->rva, rf->size, image_size)) {
                    return 0;
                }
            }
        }
    }
    return 1;
}

static int validate_import_table(uint8_t* packed_base, uint32_t packed_size,
                                 uint32_t offset, uint32_t expected_count,
                                 uint32_t image_size) {
    if (expected_count == 0u && offset == 0u) {
        return 1;
    }
    if (offset == 0u || expected_count > IMG_MAX_IMPORTS) {
        return 0;
    }
    if (!range_u32_ok(offset, 8u, packed_size)) {
        return 0;
    }
    uint32_t stored_count = 0;
    mem_copy(&stored_count, packed_base + offset, 4);
    if (stored_count != expected_count || stored_count > IMG_MAX_IMPORTS) {
        return 0;
    }
    uint64_t pool_field = (uint64_t)offset + 4ull + (uint64_t)stored_count * (uint64_t)sizeof(import_entry_t);
    if (pool_field + 4ull > (uint64_t)packed_size) {
        return 0;
    }
    uint32_t pool_size = 0;
    mem_copy(&pool_size, packed_base + (uint32_t)pool_field, 4);
    uint64_t bytes = 4ull + (uint64_t)stored_count * (uint64_t)sizeof(import_entry_t) + 4ull + (uint64_t)pool_size;
    if (!range_u32_ok(offset, bytes, packed_size)) {
        return 0;
    }
    if (image_size != 0u && stored_count != 0u) {
        import_entry_t* entries = (import_entry_t*)(packed_base + offset + 4u);
        for (uint32_t i = 0; i < stored_count; ++i) {
            if (!range_u32_ok(entries[i].iat_rva, 8u, image_size)) {
                return 0;
            }
        }
    }
    return 1;
}

static int validate_section_table(uint8_t* image_base, uint8_t* packed_base,
                                  uint32_t packed_size, uint32_t image_size,
                                  const packed_header_t* hdr) {
    if (hdr->section_count == 0u) {
        return range_u32_ok(hdr->section_table_offset, 0u, packed_size);
    }
    if (hdr->section_count > IMG_MAX_SECTIONS) {
        return 0;
    }
    uint64_t table_bytes = (uint64_t)hdr->section_count * (uint64_t)sizeof(section_descriptor_t);
    if (!range_u32_ok(hdr->section_table_offset, table_bytes, packed_size)) {
        return 0;
    }
    (void)image_base;
    section_descriptor_t* descs = (section_descriptor_t*)(packed_base + hdr->section_table_offset);
    for (uint32_t i = 0; i < hdr->section_count; ++i) {
        section_descriptor_t* d = &descs[i];
        if (d->original_rva == 0u || d->original_virtual_size == 0u) {
            return 0;
        }
        if (d->encrypted_size == 0u || d->compressed_size == 0u || d->compressed_size > d->encrypted_size) {
            return 0;
        }
        if (!range_u32_ok(d->blob_offset, d->encrypted_size, packed_size)) {
            return 0;
        }
        if (d->layers_applied != MATRYOSHKA_LAYERS_LEGACY && d->layers_applied != MATRYOSHKA_LAYERS_FULL) {
            return 0;
        }
        if (image_size != 0u && !range_u32_ok(d->original_rva, d->original_virtual_size, image_size)) {
            return 0;
        }
    }
    return 1;
}

static int validate_packed_header(uint8_t* image_base, uint8_t* packed_base,
                                  uint32_t packed_size, const packed_header_t* hdr) {
    if (packed_base == 0 || hdr == 0 || packed_size < sizeof(packed_header_t)) {
        return 0;
    }
    if (hdr->magic != IMG_MAGIC) {
        return 0;
    }
    if (hdr->version != IMG_VERSION_LEGACY && hdr->version != IMG_VERSION_MATRYO) {
        return 0;
    }
    uint32_t image_size = image_size_from_headers(image_base);
    if (image_size == 0u) {
        return 0;
    }
    if (!validate_section_table(image_base, packed_base, packed_size, image_size, hdr)) {
        return 0;
    }
    if (!validate_import_table(packed_base, packed_size, hdr->import_table_offset, hdr->import_count, image_size)) {
        return 0;
    }
    if (!validate_counted_table(packed_base, packed_size, hdr->string_table_offset,
                                hdr->string_fixup_count, sizeof(string_fixup_t), IMG_MAX_FIXUPS, image_size)) {
        return 0;
    }
    if (!validate_counted_table(packed_base, packed_size, hdr->resource_table_offset,
                                hdr->resource_fixup_count, sizeof(resource_fixup_t), IMG_MAX_FIXUPS, image_size)) {
        return 0;
    }
    if (!range_u32_ok(hdr->master_key_offset, 64u, packed_size)) {
        return 0;
    }
    if (hdr->stub_code_offset == 0u || !range_u32_ok(hdr->stub_code_offset, 1u, packed_size)) {
        return 0;
    }
    if (hdr->version == IMG_VERSION_MATRYO) {
        if (hdr->aux_offset == 0u || hdr->aux_size != IMG_AUX_BLOCK_SIZE) {
            return 0;
        }
        if (!range_u32_ok(hdr->aux_offset, hdr->aux_size, packed_size)) {
            return 0;
        }
    } else if (hdr->aux_size != 0u && !range_u32_ok(hdr->aux_offset, hdr->aux_size, packed_size)) {
        return 0;
    }
    return 1;
}

static size_t a_strlen(const char* s) {
    size_t n = 0;
    while (s[n] != 0) {
        ++n;
    }
    return n;
}

static uint8_t to_upper_a(uint8_t c) {
    if (c >= 'a' && c <= 'z') {
        return (uint8_t)(c - 32);
    }
    return c;
}

static uint64_t fnv1a64_bytes(const uint8_t* d, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= (uint64_t)d[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uint64_t fnv1a64_w_upper(const uint16_t* w, size_t wchars) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < wchars; ++i) {
        uint16_t c = w[i];
        if (c >= 'a' && c <= 'z') {
            c = (uint16_t)(c - 32);
        }
        h ^= (uint64_t)(uint8_t)(c & 0xFFu);
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uint64_t fnv1a64_a_upper(const char* s, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= (uint64_t)to_upper_a((uint8_t)s[i]);
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64u - n));
}

static uint64_t siphash_2_4(const uint8_t* data, size_t len, uint64_t k0, uint64_t k1) {
    uint64_t v0 = k0 ^ 0x736F6D6570736575ULL;
    uint64_t v1 = k1 ^ 0x646F72616E646F6DULL;
    uint64_t v2 = k0 ^ 0x6C7967656E657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    size_t blocks = len / 8u;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t m;
        mem_copy(&m, data + i * 8u, 8u);
        v3 ^= m;
        for (int r = 0; r < 2; ++r) {
            v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
            v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
        }
        v0 ^= m;
    }
    uint64_t last = (uint64_t)(len & 0xFFu) << 56;
    const uint8_t* tail = data + blocks * 8u;
    size_t rem = len & 7u;
    if (rem >= 7) last |= (uint64_t)tail[6] << 48;
    if (rem >= 6) last |= (uint64_t)tail[5] << 40;
    if (rem >= 5) last |= (uint64_t)tail[4] << 32;
    if (rem >= 4) last |= (uint64_t)tail[3] << 24;
    if (rem >= 3) last |= (uint64_t)tail[2] << 16;
    if (rem >= 2) last |= (uint64_t)tail[1] << 8;
    if (rem >= 1) last |= (uint64_t)tail[0];
    v3 ^= last;
    for (int r = 0; r < 2; ++r) {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    }
    v0 ^= last;
    v2 ^= 0xFFu;
    for (int r = 0; r < 4; ++r) {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    }
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t siphash_3u64(uint64_t key, uint64_t d0, uint64_t d1) {
    uint8_t buf[16];
    mem_copy(buf, &d0, 8);
    mem_copy(buf + 8, &d1, 8);
    return siphash_2_4(buf, 16, key, key ^ 0xA5A5A5A5A5A5A5A5ULL);
}

static void derive_pe_mask(uint32_t ts, uint32_t soc, uint8_t out[32]) {
    uint64_t h = siphash_3u64(0x4149444150524F54ULL, (uint64_t)ts, (uint64_t)soc);
    for (unsigned i = 0; i < 4u; ++i) {
        unsigned n = i * 17u;
        uint64_t rot = (n == 0u) ? h : rotl64(h, n);
        mem_copy(out + i * 8u, &rot, 8u);
    }
}

static void derive_section_key(const uint8_t master[32], uint32_t section_rva,
                               uint32_t section_index, uint8_t out_key[32], uint8_t out_iv[16]) {
    uint64_t m0, m1, m2, m3;
    mem_copy(&m0, master + 0, 8);
    mem_copy(&m1, master + 8, 8);
    mem_copy(&m2, master + 16, 8);
    mem_copy(&m3, master + 24, 8);
    uint64_t rva64 = (uint64_t)section_rva;
    uint64_t idx64 = (uint64_t)section_index;
    uint64_t k0 = siphash_3u64(m0, rva64, idx64);
    uint64_t k1 = siphash_3u64(m1, rva64 ^ k0, idx64);
    uint64_t k2 = siphash_3u64(m2, k0 ^ k1, idx64);
    uint64_t k3 = siphash_3u64(m3, k1 ^ k2, idx64);
    mem_copy(out_key + 0, &k0, 8);
    mem_copy(out_key + 8, &k1, 8);
    mem_copy(out_key + 16, &k2, 8);
    mem_copy(out_key + 24, &k3, 8);
    uint64_t n0 = siphash_3u64(0xDEADC0DEDEADC0DEULL, k0 ^ k3, k1 ^ k2);
    uint64_t n1 = siphash_3u64(0xCAFEBABECAFEBABEULL, k2 ^ k0, k3 ^ k1);
    mem_copy(out_iv + 0, &n0, 8);
    mem_copy(out_iv + 8, &n1, 8);
}

static __m128i aes_assist1(__m128i a, __m128i b) {
    b = _mm_shuffle_epi32(b, 0xFF);
    __m128i t = _mm_slli_si128(a, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    return _mm_xor_si128(a, b);
}

static __m128i aes_assist2(__m128i a, __m128i b) {
    __m128i t = _mm_aeskeygenassist_si128(a, 0);
    __m128i x = _mm_shuffle_epi32(t, 0xAA);
    __m128i u = _mm_slli_si128(b, 4);
    b = _mm_xor_si128(b, u);
    u = _mm_slli_si128(u, 4);
    b = _mm_xor_si128(b, u);
    u = _mm_slli_si128(u, 4);
    b = _mm_xor_si128(b, u);
    return _mm_xor_si128(b, x);
}

static void aes256_expand(const uint8_t key[32], __m128i rk[15]) {
    __m128i a = _mm_loadu_si128((const __m128i*)(key + 0));
    __m128i b = _mm_loadu_si128((const __m128i*)(key + 16));
    rk[0] = a;
    rk[1] = b;
    a = aes_assist1(a, _mm_aeskeygenassist_si128(b, 0x01)); rk[2] = a;
    b = aes_assist2(a, b); rk[3] = b;
    a = aes_assist1(a, _mm_aeskeygenassist_si128(b, 0x02)); rk[4] = a;
    b = aes_assist2(a, b); rk[5] = b;
    a = aes_assist1(a, _mm_aeskeygenassist_si128(b, 0x04)); rk[6] = a;
    b = aes_assist2(a, b); rk[7] = b;
    a = aes_assist1(a, _mm_aeskeygenassist_si128(b, 0x08)); rk[8] = a;
    b = aes_assist2(a, b); rk[9] = b;
    a = aes_assist1(a, _mm_aeskeygenassist_si128(b, 0x10)); rk[10] = a;
    b = aes_assist2(a, b); rk[11] = b;
    a = aes_assist1(a, _mm_aeskeygenassist_si128(b, 0x20)); rk[12] = a;
    b = aes_assist2(a, b); rk[13] = b;
    a = aes_assist1(a, _mm_aeskeygenassist_si128(b, 0x40)); rk[14] = a;
}

static __m128i aes256_enc(__m128i blk, const __m128i rk[15]) {
    blk = _mm_xor_si128(blk, rk[0]);
    blk = _mm_aesenc_si128(blk, rk[1]);
    blk = _mm_aesenc_si128(blk, rk[2]);
    blk = _mm_aesenc_si128(blk, rk[3]);
    blk = _mm_aesenc_si128(blk, rk[4]);
    blk = _mm_aesenc_si128(blk, rk[5]);
    blk = _mm_aesenc_si128(blk, rk[6]);
    blk = _mm_aesenc_si128(blk, rk[7]);
    blk = _mm_aesenc_si128(blk, rk[8]);
    blk = _mm_aesenc_si128(blk, rk[9]);
    blk = _mm_aesenc_si128(blk, rk[10]);
    blk = _mm_aesenc_si128(blk, rk[11]);
    blk = _mm_aesenc_si128(blk, rk[12]);
    blk = _mm_aesenc_si128(blk, rk[13]);
    blk = _mm_aesenclast_si128(blk, rk[14]);
    return blk;
}

static void aes256_ctr_xor(const uint8_t key[32], const uint8_t iv[16],
                           uint8_t* buf, size_t len) {
    __m128i rk[15];
    aes256_expand(key, rk);
    uint8_t counter[16];
    mem_copy(counter, iv, 16);
    size_t off = 0;
    while (off < len) {
        __m128i ctr = _mm_loadu_si128((const __m128i*)counter);
        __m128i ks = aes256_enc(ctr, rk);
        uint8_t ksb[16];
        _mm_storeu_si128((__m128i*)ksb, ks);
        for (int i = 15; i >= 0; --i) {
            counter[i] = (uint8_t)(counter[i] + 1u);
            if (counter[i] != 0) {
                break;
            }
        }
        size_t bl = (len - off < 16u) ? (len - off) : 16u;
        for (size_t i = 0; i < bl; ++i) {
            buf[off + i] = (uint8_t)(buf[off + i] ^ ksb[i]);
        }
        off += bl;
    }
}

static __m128i aes128_assist(__m128i a, __m128i b) {
    b = _mm_shuffle_epi32(b, 0xFF);
    __m128i t = _mm_slli_si128(a, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    return _mm_xor_si128(a, b);
}

static void aes128_expand(const uint8_t key[16], __m128i rk[11]) {
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    rk[1]  = aes128_assist(rk[0],  _mm_aeskeygenassist_si128(rk[0],  0x01));
    rk[2]  = aes128_assist(rk[1],  _mm_aeskeygenassist_si128(rk[1],  0x02));
    rk[3]  = aes128_assist(rk[2],  _mm_aeskeygenassist_si128(rk[2],  0x04));
    rk[4]  = aes128_assist(rk[3],  _mm_aeskeygenassist_si128(rk[3],  0x08));
    rk[5]  = aes128_assist(rk[4],  _mm_aeskeygenassist_si128(rk[4],  0x10));
    rk[6]  = aes128_assist(rk[5],  _mm_aeskeygenassist_si128(rk[5],  0x20));
    rk[7]  = aes128_assist(rk[6],  _mm_aeskeygenassist_si128(rk[6],  0x40));
    rk[8]  = aes128_assist(rk[7],  _mm_aeskeygenassist_si128(rk[7],  0x80));
    rk[9]  = aes128_assist(rk[8],  _mm_aeskeygenassist_si128(rk[8],  0x1B));
    rk[10] = aes128_assist(rk[9],  _mm_aeskeygenassist_si128(rk[9],  0x36));
}

static __m128i aes128_enc(__m128i blk, const __m128i rk[11]) {
    blk = _mm_xor_si128(blk, rk[0]);
    blk = _mm_aesenc_si128(blk, rk[1]);
    blk = _mm_aesenc_si128(blk, rk[2]);
    blk = _mm_aesenc_si128(blk, rk[3]);
    blk = _mm_aesenc_si128(blk, rk[4]);
    blk = _mm_aesenc_si128(blk, rk[5]);
    blk = _mm_aesenc_si128(blk, rk[6]);
    blk = _mm_aesenc_si128(blk, rk[7]);
    blk = _mm_aesenc_si128(blk, rk[8]);
    blk = _mm_aesenc_si128(blk, rk[9]);
    blk = _mm_aesenclast_si128(blk, rk[10]);
    return blk;
}

static void aes128_ctr_xor(const uint8_t key[16], const uint8_t iv[16],
                           uint8_t* buf, size_t len) {
    __m128i rk[11];
    aes128_expand(key, rk);
    uint8_t counter[16];
    mem_copy(counter, iv, 16);
    size_t off = 0;
    while (off < len) {
        __m128i ctr = _mm_loadu_si128((const __m128i*)counter);
        __m128i ks = aes128_enc(ctr, rk);
        uint8_t ksb[16];
        _mm_storeu_si128((__m128i*)ksb, ks);
        for (int i = 15; i >= 0; --i) {
            counter[i] = (uint8_t)(counter[i] + 1u);
            if (counter[i] != 0) {
                break;
            }
        }
        size_t bl = (len - off < 16u) ? (len - off) : 16u;
        for (size_t i = 0; i < bl; ++i) {
            buf[off + i] = (uint8_t)(buf[off + i] ^ ksb[i]);
        }
        off += bl;
    }
}

static uint32_t cc20_rotl32(uint32_t a, unsigned b) {
    return (a << b) | (a >> (32u - b));
}

static void cc20_qr(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = cc20_rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = cc20_rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = cc20_rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = cc20_rotl32(*b, 7);
}

static void cc20_block(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) { x[i] = state[i]; }
    for (int i = 0; i < 10; ++i) {
        cc20_qr(&x[0], &x[4], &x[8],  &x[12]);
        cc20_qr(&x[1], &x[5], &x[9],  &x[13]);
        cc20_qr(&x[2], &x[6], &x[10], &x[14]);
        cc20_qr(&x[3], &x[7], &x[11], &x[15]);
        cc20_qr(&x[0], &x[5], &x[10], &x[15]);
        cc20_qr(&x[1], &x[6], &x[11], &x[12]);
        cc20_qr(&x[2], &x[7], &x[8],  &x[13]);
        cc20_qr(&x[3], &x[4], &x[9],  &x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + state[i];
        out[4 * i + 0] = (uint8_t)(v & 0xFFu);
        out[4 * i + 1] = (uint8_t)((v >> 8) & 0xFFu);
        out[4 * i + 2] = (uint8_t)((v >> 16) & 0xFFu);
        out[4 * i + 3] = (uint8_t)((v >> 24) & 0xFFu);
    }
}

static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                         uint8_t* buf, size_t len) {
    uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = (uint32_t)key[4 * i] |
                       ((uint32_t)key[4 * i + 1] << 8) |
                       ((uint32_t)key[4 * i + 2] << 16) |
                       ((uint32_t)key[4 * i + 3] << 24);
    }
    state[12] = 1u;
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = (uint32_t)nonce[4 * i] |
                        ((uint32_t)nonce[4 * i + 1] << 8) |
                        ((uint32_t)nonce[4 * i + 2] << 16) |
                        ((uint32_t)nonce[4 * i + 3] << 24);
    }
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        cc20_block(state, ks);
        ++state[12];
        size_t bl = (len - off < 64u) ? (len - off) : 64u;
        for (size_t i = 0; i < bl; ++i) {
            buf[off + i] = (uint8_t)(buf[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

static void xtea_block_encrypt(const uint32_t key[4], uint32_t* v0p, uint32_t* v1p) {
    uint32_t v0 = *v0p;
    uint32_t v1 = *v1p;
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 64; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3u]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3u]);
    }
    *v0p = v0;
    *v1p = v1;
}

static void xtea_ctr_xor(const uint8_t key[16], const uint8_t iv[8],
                         uint8_t* buf, size_t len) {
    uint32_t kw[4];
    for (int i = 0; i < 4; ++i) {
        kw[i] = (uint32_t)key[4 * i] |
                ((uint32_t)key[4 * i + 1] << 8) |
                ((uint32_t)key[4 * i + 2] << 16) |
                ((uint32_t)key[4 * i + 3] << 24);
    }
    uint8_t counter[8];
    mem_copy(counter, iv, 8);
    size_t off = 0;
    while (off < len) {
        uint32_t v0 = (uint32_t)counter[0] |
                      ((uint32_t)counter[1] << 8) |
                      ((uint32_t)counter[2] << 16) |
                      ((uint32_t)counter[3] << 24);
        uint32_t v1 = (uint32_t)counter[4] |
                      ((uint32_t)counter[5] << 8) |
                      ((uint32_t)counter[6] << 16) |
                      ((uint32_t)counter[7] << 24);
        xtea_block_encrypt(kw, &v0, &v1);
        uint8_t ks[8];
        ks[0] = (uint8_t)(v0 & 0xFFu);
        ks[1] = (uint8_t)((v0 >> 8) & 0xFFu);
        ks[2] = (uint8_t)((v0 >> 16) & 0xFFu);
        ks[3] = (uint8_t)((v0 >> 24) & 0xFFu);
        ks[4] = (uint8_t)(v1 & 0xFFu);
        ks[5] = (uint8_t)((v1 >> 8) & 0xFFu);
        ks[6] = (uint8_t)((v1 >> 16) & 0xFFu);
        ks[7] = (uint8_t)((v1 >> 24) & 0xFFu);
        for (int i = 0; i < 8; ++i) {
            counter[i] = (uint8_t)(counter[i] + 1u);
            if (counter[i] != 0) {
                break;
            }
        }
        size_t bl = (len - off < 8u) ? (len - off) : 8u;
        for (size_t i = 0; i < bl; ++i) {
            buf[off + i] = (uint8_t)(buf[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

static uint32_t sha_rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static void sha256_compress_pl(uint32_t H[8], const uint8_t block[64]) {
    uint32_t k0  = 0x428a2f98u; uint32_t k1  = 0x71374491u; uint32_t k2  = 0xb5c0fbcfu; uint32_t k3  = 0xe9b5dba5u;
    uint32_t k4  = 0x3956c25bu; uint32_t k5  = 0x59f111f1u; uint32_t k6  = 0x923f82a4u; uint32_t k7  = 0xab1c5ed5u;
    uint32_t k8  = 0xd807aa98u; uint32_t k9  = 0x12835b01u; uint32_t k10 = 0x243185beu; uint32_t k11 = 0x550c7dc3u;
    uint32_t k12 = 0x72be5d74u; uint32_t k13 = 0x80deb1feu; uint32_t k14 = 0x9bdc06a7u; uint32_t k15 = 0xc19bf174u;
    uint32_t k16 = 0xe49b69c1u; uint32_t k17 = 0xefbe4786u; uint32_t k18 = 0x0fc19dc6u; uint32_t k19 = 0x240ca1ccu;
    uint32_t k20 = 0x2de92c6fu; uint32_t k21 = 0x4a7484aau; uint32_t k22 = 0x5cb0a9dcu; uint32_t k23 = 0x76f988dau;
    uint32_t k24 = 0x983e5152u; uint32_t k25 = 0xa831c66du; uint32_t k26 = 0xb00327c8u; uint32_t k27 = 0xbf597fc7u;
    uint32_t k28 = 0xc6e00bf3u; uint32_t k29 = 0xd5a79147u; uint32_t k30 = 0x06ca6351u; uint32_t k31 = 0x14292967u;
    uint32_t k32 = 0x27b70a85u; uint32_t k33 = 0x2e1b2138u; uint32_t k34 = 0x4d2c6dfcu; uint32_t k35 = 0x53380d13u;
    uint32_t k36 = 0x650a7354u; uint32_t k37 = 0x766a0abbu; uint32_t k38 = 0x81c2c92eu; uint32_t k39 = 0x92722c85u;
    uint32_t k40 = 0xa2bfe8a1u; uint32_t k41 = 0xa81a664bu; uint32_t k42 = 0xc24b8b70u; uint32_t k43 = 0xc76c51a3u;
    uint32_t k44 = 0xd192e819u; uint32_t k45 = 0xd6990624u; uint32_t k46 = 0xf40e3585u; uint32_t k47 = 0x106aa070u;
    uint32_t k48 = 0x19a4c116u; uint32_t k49 = 0x1e376c08u; uint32_t k50 = 0x2748774cu; uint32_t k51 = 0x34b0bcb5u;
    uint32_t k52 = 0x391c0cb3u; uint32_t k53 = 0x4ed8aa4au; uint32_t k54 = 0x5b9cca4fu; uint32_t k55 = 0x682e6ff3u;
    uint32_t k56 = 0x748f82eeu; uint32_t k57 = 0x78a5636fu; uint32_t k58 = 0x84c87814u; uint32_t k59 = 0x8cc70208u;
    uint32_t k60 = 0x90befffau; uint32_t k61 = 0xa4506cebu; uint32_t k62 = 0xbef9a3f7u; uint32_t k63 = 0xc67178f2u;
    uint32_t K[64];
    K[0]=k0;K[1]=k1;K[2]=k2;K[3]=k3;K[4]=k4;K[5]=k5;K[6]=k6;K[7]=k7;
    K[8]=k8;K[9]=k9;K[10]=k10;K[11]=k11;K[12]=k12;K[13]=k13;K[14]=k14;K[15]=k15;
    K[16]=k16;K[17]=k17;K[18]=k18;K[19]=k19;K[20]=k20;K[21]=k21;K[22]=k22;K[23]=k23;
    K[24]=k24;K[25]=k25;K[26]=k26;K[27]=k27;K[28]=k28;K[29]=k29;K[30]=k30;K[31]=k31;
    K[32]=k32;K[33]=k33;K[34]=k34;K[35]=k35;K[36]=k36;K[37]=k37;K[38]=k38;K[39]=k39;
    K[40]=k40;K[41]=k41;K[42]=k42;K[43]=k43;K[44]=k44;K[45]=k45;K[46]=k46;K[47]=k47;
    K[48]=k48;K[49]=k49;K[50]=k50;K[51]=k51;K[52]=k52;K[53]=k53;K[54]=k54;K[55]=k55;
    K[56]=k56;K[57]=k57;K[58]=k58;K[59]=k59;K[60]=k60;K[61]=k61;K[62]=k62;K[63]=k63;
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = ((uint32_t)block[4 * i + 0] << 24) |
               ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) |
                (uint32_t)block[4 * i + 3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = sha_rotr32(W[i - 15], 7) ^ sha_rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = sha_rotr32(W[i - 2], 17) ^ sha_rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = sha_rotr32(e, 6) ^ sha_rotr32(e, 11) ^ sha_rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = sha_rotr32(a, 2) ^ sha_rotr32(a, 13) ^ sha_rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

static void sha256_compute(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t H[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t bitlen = (uint64_t)len * 8ull;
    size_t off = 0;
    while (len - off >= 64) {
        sha256_compress_pl(H, data + off);
        off += 64;
    }
    uint8_t block[64];
    size_t rem = len - off;
    if (rem > 0) {
        mem_copy(block, data + off, rem);
    }
    block[rem] = 0x80;
    if (rem + 1 > 56) {
        mem_set(block + rem + 1, 0, 64 - rem - 1);
        sha256_compress_pl(H, block);
        mem_set(block, 0, 56);
    } else {
        mem_set(block + rem + 1, 0, 56 - rem - 1);
    }
    for (int i = 0; i < 8; ++i) {
        block[56 + i] = (uint8_t)((bitlen >> (56 - 8 * i)) & 0xFFull);
    }
    sha256_compress_pl(H, block);
    for (int i = 0; i < 8; ++i) {
        out[4 * i + 0] = (uint8_t)((H[i] >> 24) & 0xFFu);
        out[4 * i + 1] = (uint8_t)((H[i] >> 16) & 0xFFu);
        out[4 * i + 2] = (uint8_t)((H[i] >> 8) & 0xFFu);
        out[4 * i + 3] = (uint8_t)(H[i] & 0xFFu);
    }
}

static void hmac_sha256_compute(const uint8_t* key, size_t key_len,
                                const uint8_t* data, size_t data_len,
                                uint8_t out[32]) {
    uint8_t k[64];
    if (key_len > 64) {
        sha256_compute(key, key_len, k);
        mem_set(k + 32, 0, 32);
    } else {
        if (key_len > 0) {
            mem_copy(k, key, key_len);
        }
        mem_set(k + key_len, 0, 64 - key_len);
    }
    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36u);
        opad[i] = (uint8_t)(k[i] ^ 0x5Cu);
    }
    uint8_t inner[256];
    if (64u + data_len > sizeof(inner)) {
        return;
    }
    mem_copy(inner, ipad, 64);
    if (data_len > 0) {
        mem_copy(inner + 64, data, data_len);
    }
    uint8_t inner_hash[32];
    sha256_compute(inner, 64u + data_len, inner_hash);
    uint8_t outer[96];
    mem_copy(outer, opad, 64);
    mem_copy(outer + 64, inner_hash, 32);
    sha256_compute(outer, 96, out);
}

static void hkdf_extract_pl(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            uint8_t prk[32]) {
    if (salt_len == 0) {
        uint8_t zero_salt[32];
        mem_set(zero_salt, 0, 32);
        hmac_sha256_compute(zero_salt, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256_compute(salt, salt_len, ikm, ikm_len, prk);
    }
}

static void hkdf_expand_pl(const uint8_t prk[32],
                           const uint8_t* info, size_t info_len,
                           uint8_t* out, size_t out_len) {
    uint8_t t[32];
    size_t t_len = 0;
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < out_len) {
        uint8_t buf[256];
        if (t_len + info_len + 1u > sizeof(buf)) {
            return;
        }
        size_t pos = 0;
        if (t_len > 0) {
            mem_copy(buf, t, t_len);
            pos += t_len;
        }
        if (info_len > 0) {
            mem_copy(buf + pos, info, info_len);
            pos += info_len;
        }
        buf[pos] = counter;
        pos += 1u;
        hmac_sha256_compute(prk, 32, buf, pos, t);
        t_len = 32;
        size_t copy = (out_len - produced < 32u) ? (out_len - produced) : 32u;
        mem_copy(out + produced, t, copy);
        produced += copy;
        ++counter;
    }
}

static void hkdf_sha256_pl(const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* salt, size_t salt_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out, size_t out_len) {
    uint8_t prk[32];
    hkdf_extract_pl(salt, salt_len, ikm, ikm_len, prk);
    hkdf_expand_pl(prk, info, info_len, out, out_len);
}

static void compute_hwid_anchor(uint8_t out[32]) {
    uint8_t a[25];
    a[ 0]='a'; a[ 1]='i'; a[ 2]='d'; a[ 3]='a'; a[ 4]='-';
    a[ 5]='b'; a[ 6]='u'; a[ 7]='i'; a[ 8]='l'; a[ 9]='d';
    a[10]='-'; a[11]='h'; a[12]='w'; a[13]='i'; a[14]='d';
    a[15]='-'; a[16]='a'; a[17]='n'; a[18]='c'; a[19]='h';
    a[20]='o'; a[21]='r'; a[22]='-'; a[23]='v'; a[24]='1';
    sha256_compute(a, 25, out);
}

static void compute_tpm_anchor(uint8_t out[32]) {
    uint8_t a[24];
    a[ 0]='a'; a[ 1]='i'; a[ 2]='d'; a[ 3]='a'; a[ 4]='-';
    a[ 5]='b'; a[ 6]='u'; a[ 7]='i'; a[ 8]='l'; a[ 9]='d';
    a[10]='-'; a[11]='t'; a[12]='p'; a[13]='m'; a[14]='-';
    a[15]='a'; a[16]='n'; a[17]='c'; a[18]='h'; a[19]='o';
    a[20]='r'; a[21]='-'; a[22]='v'; a[23]='1';
    sha256_compute(a, 24, out);
}

static void compute_server_anchor(uint8_t out[32]) {
    uint8_t a[34];
    a[ 0]='a'; a[ 1]='i'; a[ 2]='d'; a[ 3]='a'; a[ 4]='-';
    a[ 5]='b'; a[ 6]='u'; a[ 7]='i'; a[ 8]='l'; a[ 9]='d';
    a[10]='-'; a[11]='s'; a[12]='r'; a[13]='v'; a[14]='-';
    a[15]='h'; a[16]='e'; a[17]='a'; a[18]='r'; a[19]='t';
    a[20]='b'; a[21]='e'; a[22]='a'; a[23]='t'; a[24]='-';
    a[25]='a'; a[26]='n'; a[27]='c'; a[28]='h'; a[29]='o';
    a[30]='r'; a[31]='-'; a[32]='v'; a[33]='1';
    sha256_compute(a, 34, out);
}

static void derive_build_seed_from_master(const uint8_t master[32], uint8_t out[32]) {
    uint8_t info[29];
    info[ 0]='a'; info[ 1]='i'; info[ 2]='d'; info[ 3]='a'; info[ 4]='-';
    info[ 5]='m'; info[ 6]='a'; info[ 7]='t'; info[ 8]='r'; info[ 9]='y';
    info[10]='o'; info[11]='s'; info[12]='h'; info[13]='k'; info[14]='a';
    info[15]='-'; info[16]='b'; info[17]='u'; info[18]='i'; info[19]='l';
    info[20]='d'; info[21]='-'; info[22]='s'; info[23]='e'; info[24]='e';
    info[25]='d'; info[26]='-'; info[27]='v'; info[28]='1';
    hkdf_sha256_pl(master, 32, 0, 0, info, 29, out, 32);
}

static void mat_append_section_bytes(uint8_t* out, size_t* pos,
                                     uint32_t section_rva, uint32_t section_index) {
    size_t p = *pos;
    out[p++] = (uint8_t)(section_rva & 0xFFu);
    out[p++] = (uint8_t)((section_rva >> 8) & 0xFFu);
    out[p++] = (uint8_t)((section_rva >> 16) & 0xFFu);
    out[p++] = (uint8_t)((section_rva >> 24) & 0xFFu);
    out[p++] = (uint8_t)(section_index & 0xFFu);
    out[p++] = (uint8_t)((section_index >> 8) & 0xFFu);
    out[p++] = (uint8_t)((section_index >> 16) & 0xFFu);
    out[p++] = (uint8_t)((section_index >> 24) & 0xFFu);
    *pos = p;
}

static void derive_layer1_key(const uint8_t hwid[32], const uint8_t build_seed[32],
                              uint32_t section_rva, uint32_t section_index,
                              uint8_t out_key[16]) {
    uint8_t ikm[64];
    mem_copy(ikm, hwid, 32);
    mem_copy(ikm + 32, build_seed, 32);
    uint8_t info[64];
    size_t pos = 0;
    info[pos++]='m'; info[pos++]='a'; info[pos++]='t'; info[pos++]='r';
    info[pos++]='y'; info[pos++]='o'; info[pos++]='s'; info[pos++]='h';
    info[pos++]='k'; info[pos++]='a'; info[pos++]='-'; info[pos++]='l';
    info[pos++]='1'; info[pos++]='-'; info[pos++]='h'; info[pos++]='w';
    info[pos++]='i'; info[pos++]='d';
    mat_append_section_bytes(info, &pos, section_rva, section_index);
    hkdf_sha256_pl(ikm, 64, 0, 0, info, pos, out_key, 16);
}

static void derive_layer2_key(const uint8_t tpm[32], const uint8_t build_seed[32],
                              uint32_t section_rva, uint32_t section_index,
                              uint8_t out_key[32]) {
    uint8_t ikm[64];
    mem_copy(ikm, tpm, 32);
    mem_copy(ikm + 32, build_seed, 32);
    uint8_t info[64];
    size_t pos = 0;
    info[pos++]='m'; info[pos++]='a'; info[pos++]='t'; info[pos++]='r';
    info[pos++]='y'; info[pos++]='o'; info[pos++]='s'; info[pos++]='h';
    info[pos++]='k'; info[pos++]='a'; info[pos++]='-'; info[pos++]='l';
    info[pos++]='2'; info[pos++]='-'; info[pos++]='t'; info[pos++]='p';
    info[pos++]='m';
    mat_append_section_bytes(info, &pos, section_rva, section_index);
    hkdf_sha256_pl(ikm, 64, 0, 0, info, pos, out_key, 32);
}

static void derive_layer3_key(const uint8_t srv[32], const uint8_t build_seed[32],
                              uint32_t section_rva, uint32_t section_index,
                              uint8_t out_key[16]) {
    uint8_t ikm[64];
    mem_copy(ikm, srv, 32);
    mem_copy(ikm + 32, build_seed, 32);
    uint8_t info[64];
    size_t pos = 0;
    info[pos++]='m'; info[pos++]='a'; info[pos++]='t'; info[pos++]='r';
    info[pos++]='y'; info[pos++]='o'; info[pos++]='s'; info[pos++]='h';
    info[pos++]='k'; info[pos++]='a'; info[pos++]='-'; info[pos++]='l';
    info[pos++]='3'; info[pos++]='-'; info[pos++]='s'; info[pos++]='r';
    info[pos++]='v';
    mat_append_section_bytes(info, &pos, section_rva, section_index);
    hkdf_sha256_pl(ikm, 64, 0, 0, info, pos, out_key, 16);
}

#define WBAES_T_BOXES_OFFSET   ((uint32_t)0u)
#define WBAES_T_BOXES_SIZE     ((uint32_t)(10u * 16u * 256u))
#define WBAES_MB_TABLES_OFFSET (WBAES_T_BOXES_OFFSET + WBAES_T_BOXES_SIZE)
#define WBAES_MB_TABLES_SIZE   ((uint32_t)(9u * 16u * 256u * 4u))
#define WBAES_EXT_IN_OFFSET    (WBAES_MB_TABLES_OFFSET + WBAES_MB_TABLES_SIZE)
#define WBAES_EXT_OUT_OFFSET   (WBAES_EXT_IN_OFFSET + 16u)
#define WBAES_TABLE_ID_OFFSET  (WBAES_EXT_OUT_OFFSET + 16u)
#define WBAES_TABLE_TOTAL_SIZE (WBAES_TABLE_ID_OFFSET + 16u)

static int wbaes_sr_source_index(int target_col, int row) {
    return (((target_col + row) & 3) * 4) + row;
}

static uint8_t wbaes_t_box_lookup(const uint8_t* tbl_blob, int round, int slot, uint8_t b) {
    uint32_t off = WBAES_T_BOXES_OFFSET
                 + (uint32_t)round * 16u * 256u
                 + (uint32_t)slot * 256u
                 + (uint32_t)b;
    return tbl_blob[off];
}

static uint32_t wbaes_mb_table_lookup(const uint8_t* tbl_blob, int round, int slot, uint8_t b) {
    uint32_t off = WBAES_MB_TABLES_OFFSET
                 + (uint32_t)round * 16u * 256u * 4u
                 + (uint32_t)slot * 256u * 4u
                 + (uint32_t)b * 4u;
    uint32_t v = (uint32_t)tbl_blob[off]
               | ((uint32_t)tbl_blob[off + 1u] << 8)
               | ((uint32_t)tbl_blob[off + 2u] << 16)
               | ((uint32_t)tbl_blob[off + 3u] << 24);
    return v;
}

static void wbaes_encrypt_block(const uint8_t* tbl_blob, const uint8_t in[16], uint8_t out[16]) {
    const uint8_t* ext_in_p = tbl_blob + WBAES_EXT_IN_OFFSET;
    const uint8_t* ext_out_p = tbl_blob + WBAES_EXT_OUT_OFFSET;
    uint8_t state[16];
    int i;
    int c;
    int r;
    for (i = 0; i < 16; ++i) {
        state[i] = (uint8_t)(in[i] ^ ext_in_p[i]);
    }
    for (r = 0; r < 9; ++r) {
        uint8_t next_state[16];
        for (c = 0; c < 4; ++c) {
            uint32_t col_word = 0u;
            for (i = 0; i < 4; ++i) {
                int src_idx = wbaes_sr_source_index(c, i);
                uint8_t b = state[src_idx];
                col_word ^= wbaes_mb_table_lookup(tbl_blob, r, c * 4 + i, b);
            }
            next_state[c * 4 + 0] = (uint8_t)((col_word >> 24) & 0xFFu);
            next_state[c * 4 + 1] = (uint8_t)((col_word >> 16) & 0xFFu);
            next_state[c * 4 + 2] = (uint8_t)((col_word >> 8) & 0xFFu);
            next_state[c * 4 + 3] = (uint8_t)(col_word & 0xFFu);
        }
        mem_copy(state, next_state, 16);
        mem_set(next_state, 0, 16);
    }
    {
        uint8_t final_state[16];
        for (c = 0; c < 4; ++c) {
            for (i = 0; i < 4; ++i) {
                int src_idx = wbaes_sr_source_index(c, i);
                uint8_t b = state[src_idx];
                final_state[c * 4 + i] = wbaes_t_box_lookup(tbl_blob, 9, c * 4 + i, b);
            }
        }
        mem_copy(state, final_state, 16);
        mem_set(final_state, 0, 16);
    }
    for (i = 0; i < 16; ++i) {
        out[i] = (uint8_t)(state[i] ^ ext_out_p[i]);
    }
    mem_set(state, 0, 16);
}

static int aes128_wbaes_decrypt_ctr(const uint8_t* tbl_blob, uint32_t tbl_size,
                                     const uint8_t iv[16], const uint8_t* in,
                                     uint8_t* out, uint32_t len) {
    if (tbl_blob == 0 || iv == 0) {
        return 0;
    }
    if (tbl_size < WBAES_TABLE_TOTAL_SIZE) {
        return 0;
    }
    if (len > 0u && (in == 0 || out == 0)) {
        return 0;
    }
    uint8_t counter[16];
    uint8_t ks[16];
    uint32_t off = 0u;
    mem_copy(counter, iv, 16);
    while (off < len) {
        wbaes_encrypt_block(tbl_blob, counter, ks);
        int j;
        for (j = 15; j >= 0; --j) {
            counter[j] = (uint8_t)(counter[j] + 1u);
            if (counter[j] != 0) {
                break;
            }
        }
        uint32_t bl = (len - off < 16u) ? (len - off) : 16u;
        uint32_t k;
        for (k = 0u; k < bl; ++k) {
            out[off + k] = (uint8_t)(in[off + k] ^ ks[k]);
        }
        off += bl;
    }
    mem_set(counter, 0, 16);
    mem_set(ks, 0, 16);
    return 1;
}

static void lz_decompress(const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_len) {
    size_t s = 0;
    size_t d = 0;
    while (d < dst_len && s < src_len) {
        uint8_t flags = src[s++];
        for (int bit = 7; bit >= 0 && d < dst_len && s < src_len; --bit) {
            if (flags & (1u << bit)) {
                if (s + 1 >= src_len) {
                    return;
                }
                uint8_t b0 = src[s++];
                uint8_t b1 = src[s++];
                size_t mlen = ((b0 >> 4) & 0x0Fu) + 3u;
                size_t moff = ((size_t)(b0 & 0x0Fu) << 8) | b1;
                if (moff == 0 || moff > d) {
                    return;
                }
                for (size_t k = 0; k < mlen && d < dst_len; ++k) {
                    dst[d] = dst[d - moff];
                    ++d;
                }
            } else {
                dst[d++] = src[s++];
            }
        }
    }
}

static peb_t* get_peb(void) {
    return (peb_t*)__readgsqword(0x60);
}

static void* find_module(uint64_t target_hash) {
    peb_t* peb = get_peb();
    peb_ldr_data_t* ldr = peb->Ldr;
    list_entry_t* head = &ldr->InLoadOrderModuleList;
    list_entry_t* cur = head->Flink;
    while (cur != head) {
        ldr_entry_t* e = (ldr_entry_t*)cur;
        if (e->BaseDllName.Buffer != 0 && e->BaseDllName.Length > 0) {
            size_t wchars = e->BaseDllName.Length / 2u;
            uint64_t h = fnv1a64_w_upper(e->BaseDllName.Buffer, wchars);
            if (h == target_hash) {
                return e->DllBase;
            }
        }
        cur = cur->Flink;
    }
    return 0;
}

static int rva_in_range(uint32_t rva, uint32_t base, uint32_t size) {
    return rva >= base && rva < base + size;
}

static void* resolve_export(void* module_base, uint64_t target_hash, uint16_t target_ord_arg, int by_ord, int depth);

static void* follow_forwarder(const char* fwd, int depth) {
    if (depth > 3) {
        return 0;
    }
    size_t dot = 0;
    while (fwd[dot] != 0 && fwd[dot] != '.') {
        ++dot;
    }
    if (fwd[dot] != '.') {
        return 0;
    }
    char dllname[64];
    if (dot + 4 >= sizeof(dllname)) {
        return 0;
    }
    for (size_t i = 0; i < dot; ++i) {
        dllname[i] = (char)to_upper_a((uint8_t)fwd[i]);
    }
    dllname[dot + 0] = '.';
    dllname[dot + 1] = 'D';
    dllname[dot + 2] = 'L';
    dllname[dot + 3] = 'L';
    dllname[dot + 4] = 0;
    uint64_t dh = fnv1a64_a_upper(dllname, dot + 4);
    void* m = find_module(dh);
    if (m == 0) {
        return 0;
    }
    const char* fname = fwd + dot + 1;
    if (fname[0] == '#') {
        uint32_t ord = 0;
        size_t i = 1;
        while (fname[i] >= '0' && fname[i] <= '9') {
            ord = ord * 10u + (uint32_t)(fname[i] - '0');
            ++i;
        }
        return resolve_export(m, 0, (uint16_t)ord, 1, depth + 1);
    }
    size_t fl = a_strlen(fname);
    uint64_t fh = fnv1a64_bytes((const uint8_t*)fname, fl);
    return resolve_export(m, fh, 0, 0, depth + 1);
}

static void* resolve_export(void* module_base, uint64_t target_hash, uint16_t target_ord_arg, int by_ord, int depth) {
    if (module_base == 0) {
        return 0;
    }
    uint8_t* base = (uint8_t*)module_base;
    uint32_t e_lfanew = *(uint32_t*)(base + 0x3C);
    uint8_t* nt = base + e_lfanew;
    uint32_t exp_rva = *(uint32_t*)(nt + 0x88);
    uint32_t exp_size = *(uint32_t*)(nt + 0x8C);
    if (exp_rva == 0 || exp_size == 0) {
        return 0;
    }
    uint8_t* ed = base + exp_rva;
    uint32_t ord_base = *(uint32_t*)(ed + 0x10);
    uint32_t n_funcs = *(uint32_t*)(ed + 0x14);
    uint32_t n_names = *(uint32_t*)(ed + 0x18);
    uint32_t funcs_rva = *(uint32_t*)(ed + 0x1C);
    uint32_t names_rva = *(uint32_t*)(ed + 0x20);
    uint32_t ords_rva = *(uint32_t*)(ed + 0x24);
    uint32_t* funcs = (uint32_t*)(base + funcs_rva);
    uint32_t* names = (uint32_t*)(base + names_rva);
    uint16_t* ords = (uint16_t*)(base + ords_rva);
    uint32_t func_rva = 0;
    if (by_ord) {
        uint32_t idx = (uint32_t)target_ord_arg - ord_base;
        if (idx >= n_funcs) {
            return 0;
        }
        func_rva = funcs[idx];
    } else {
        for (uint32_t i = 0; i < n_names; ++i) {
            const char* nm = (const char*)(base + names[i]);
            size_t nl = a_strlen(nm);
            uint64_t h = fnv1a64_bytes((const uint8_t*)nm, nl);
            if (h == target_hash) {
                uint16_t o = ords[i];
                if (o >= n_funcs) {
                    return 0;
                }
                func_rva = funcs[o];
                break;
            }
        }
    }
    if (func_rva == 0) {
        return 0;
    }
    if (rva_in_range(func_rva, exp_rva, exp_size)) {
        return follow_forwarder((const char*)(base + func_rva), depth);
    }
    return base + func_rva;
}

static int resolve_all(resolved_t* r) {
    r->ntdll = find_module(HASH_NTDLL);
    r->kernel32 = find_module(HASH_KERNEL32);
    r->kernelbase = find_module(HASH_KERNELBASE);
    if (r->ntdll == 0 || r->kernel32 == 0) {
        return 0;
    }
    r->NtProtectVirtualMemory = (nt_protect_t)resolve_export(r->ntdll, HASH_NTPROTECT, 0, 0, 0);
    r->NtAllocateVirtualMemory = (nt_alloc_t)resolve_export(r->ntdll, HASH_NTALLOC, 0, 0, 0);
    r->NtFreeVirtualMemory = (nt_free_t)resolve_export(r->ntdll, HASH_NTFREE, 0, 0, 0);
    r->RtlAddFunctionTable = (rtl_add_func_t)resolve_export(r->ntdll, HASH_RTLADDFUNC, 0, 0, 0);
    r->LdrLoadDll = (ldr_load_t)resolve_export(r->ntdll, HASH_LDRLOAD, 0, 0, 0);
    r->VirtualProtect = (vp_t)resolve_export(r->kernel32, HASH_VIRTUALPROTECT, 0, 0, 0);
    r->LoadLibraryA = (ll_t)resolve_export(r->kernel32, HASH_LOADLIBRARYA, 0, 0, 0);
    r->GetProcAddress = (gpa_t)resolve_export(r->kernel32, HASH_GETPROCADDR, 0, 0, 0);
    if (r->VirtualProtect == 0 && r->kernelbase != 0) {
        r->VirtualProtect = (vp_t)resolve_export(r->kernelbase, HASH_VIRTUALPROTECT, 0, 0, 0);
    }
    if (r->LoadLibraryA == 0 && r->kernelbase != 0) {
        r->LoadLibraryA = (ll_t)resolve_export(r->kernelbase, HASH_LOADLIBRARYA, 0, 0, 0);
    }
    if (r->GetProcAddress == 0 && r->kernelbase != 0) {
        r->GetProcAddress = (gpa_t)resolve_export(r->kernelbase, HASH_GETPROCADDR, 0, 0, 0);
    }
    return r->NtProtectVirtualMemory != 0
        && r->NtAllocateVirtualMemory != 0
        && r->NtFreeVirtualMemory != 0
        && r->VirtualProtect != 0
        && r->LoadLibraryA != 0;
}

static uint8_t* find_packed_section(uint8_t* image_base, uint32_t* out_size) {
    uint32_t image_size = image_size_from_headers(image_base);
    if (image_size == 0u) {
        return 0;
    }
    uint32_t e_lfanew = 0;
    mem_copy(&e_lfanew, image_base + 0x3C, 4);
    uint8_t* nt = image_base + e_lfanew;
    uint16_t n_sections = 0;
    uint16_t opt_size = 0;
    mem_copy(&n_sections, nt + 6, 2);
    mem_copy(&opt_size, nt + 0x14, 2);
    if (n_sections == 0u || n_sections > IMG_MAX_SECTIONS || opt_size < 0xF0u) {
        return 0;
    }
    uint8_t* sec = nt + 0x18 + opt_size;
    for (int32_t i = (int32_t)n_sections - 1; i >= 0; --i) {
        uint8_t* s = sec + (uint32_t)i * 40u;
        uint32_t va = 0;
        uint32_t vsize = 0;
        mem_copy(&vsize, s + 8, 4);
        mem_copy(&va, s + 12, 4);
        if (va == 0u || vsize < 8u) { continue; }
        if (!range_u32_ok(va, vsize, image_size)) { continue; }
        uint8_t* base = image_base + va;
        uint32_t step = 8u;
        for (uint32_t off = 0; off + 8u <= vsize; off += step) {
            uint32_t magic = 0;
            mem_copy(&magic, base + off, 4);
            if (magic != IMG_MAGIC) { continue; }
            uint32_t version = 0;
            mem_copy(&version, base + off + 4u, 4);
            if (version != IMG_VERSION_LEGACY && version != IMG_VERSION_MATRYO) { continue; }
            if (out_size != 0) { *out_size = vsize - off; }
            return base + off;
        }
    }
    return 0;
}

static uint32_t chars_to_protect(uint32_t c) {
    int x = (c & IMG_SCN_EXEC) != 0;
    int r = (c & IMG_SCN_READ) != 0;
    int w = (c & IMG_SCN_WRITE) != 0;
    if (x && r && w) return PAGE_EX_RWX;
    if (x && r) return PAGE_EX_R;
    if (x) return PAGE_EX;
    if (r && w) return PAGE_RW;
    if (r) return PAGE_R;
    return PAGE_NA;
}

static void protect_region(const resolved_t* r, void* addr, size_t size, uint32_t prot, uint32_t* old) {
    void* base = addr;
    size_t sz = size;
    uint32_t o = 0;
    r->NtProtectVirtualMemory((void*)(intptr_t)-1, &base, &sz, prot, &o);
    if (old != 0) {
        *old = o;
    }
}

static void* alloc_scratch(const resolved_t* r, size_t size) {
    void* base = 0;
    size_t sz = size;
    long st = r->NtAllocateVirtualMemory((void*)(intptr_t)-1, &base, 0, &sz, MEM_COMMIT_RESERVE, PAGE_RW);
    if (st < 0) {
        return 0;
    }
    return base;
}

static void free_scratch(const resolved_t* r, void* p) {
    void* base = p;
    size_t sz = 0;
    r->NtFreeVirtualMemory((void*)(intptr_t)-1, &base, &sz, MEM_RELEASE);
}

static void unpack_sections(uint8_t* image_base, const uint8_t master[32],
                            uint8_t* packed_base, const packed_header_t* hdr,
                            const resolved_t* r) {
    if (hdr->section_count == 0) {
        return;
    }
    section_descriptor_t* descs = (section_descriptor_t*)(packed_base + hdr->section_table_offset);
    size_t max_enc = 0;
    for (uint32_t i = 0; i < hdr->section_count; ++i) {
        if (descs[i].encrypted_size > max_enc) {
            max_enc = descs[i].encrypted_size;
        }
    }
    if (max_enc == 0) {
        return;
    }
    uint8_t* scratch = (uint8_t*)alloc_scratch(r, max_enc);
    if (scratch == 0) {
        return;
    }
    uint8_t hwid_anchor[32];
    uint8_t tpm_anchor[32];
    uint8_t srv_anchor[32];
    uint8_t build_seed[32];
    compute_hwid_anchor(hwid_anchor);
    compute_tpm_anchor(tpm_anchor);
    compute_server_anchor(srv_anchor);
    derive_build_seed_from_master(master, build_seed);
    for (uint32_t i = 0; i < hdr->section_count; ++i) {
        section_descriptor_t* d = &descs[i];
        if (d->encrypted_size == 0 || d->original_virtual_size == 0) {
            continue;
        }
        mem_copy(scratch, packed_base + d->blob_offset, d->encrypted_size);
        if (d->layers_applied >= MATRYOSHKA_LAYERS_FULL) {
            uint8_t l3_key[16];
            derive_layer3_key(srv_anchor, build_seed, d->original_rva, d->section_index, l3_key);
            xtea_ctr_xor(l3_key, d->layer3_iv, scratch, d->encrypted_size);
            uint8_t l2_key[32];
            derive_layer2_key(tpm_anchor, build_seed, d->original_rva, d->section_index, l2_key);
            chacha20_xor(l2_key, d->layer2_nonce, scratch, d->encrypted_size);
            uint8_t l1_key[16];
            derive_layer1_key(hwid_anchor, build_seed, d->original_rva, d->section_index, l1_key);
            aes128_ctr_xor(l1_key, d->layer1_iv, scratch, d->encrypted_size);
        } else {
            uint8_t skey[32];
            uint8_t siv[16];
            derive_section_key(master, d->original_rva, d->section_index, skey, siv);
            aes256_ctr_xor(skey, siv, scratch, d->encrypted_size);
        }
        uint32_t old = 0;
        protect_region(r, image_base + d->original_rva, d->original_virtual_size, PAGE_RW, &old);
        lz_decompress(scratch, d->compressed_size, image_base + d->original_rva, d->original_virtual_size);
        uint32_t pp = chars_to_protect(d->original_characteristics);
        protect_region(r, image_base + d->original_rva, d->original_virtual_size, pp, &old);
    }
    free_scratch(r, scratch);
}

static void rebuild_iat(uint8_t* image_base, const uint8_t master[32],
                        uint8_t* packed_base, const packed_header_t* hdr,
                        const resolved_t* r) {
    if (hdr->import_count == 0 || hdr->import_table_offset == 0) {
        return;
    }
    uint8_t* tbl = packed_base + hdr->import_table_offset;
    uint32_t count = *(uint32_t*)tbl;
    import_entry_t* entries = (import_entry_t*)(tbl + 4);
    uint32_t pool_size = *(uint32_t*)(tbl + 4 + count * 24u);
    uint8_t* pool_enc = tbl + 4 + count * 24u + 4;
    uint64_t k64 = siphash_2_4(master, 32, 0x494D504F5254434EULL, 0x494D504F5254434EULL);
    uint8_t kb[8];
    mem_copy(kb, &k64, 8);
    uint8_t* pool_local = (uint8_t*)alloc_scratch(r, pool_size > 0 ? pool_size : 16);
    if (pool_local == 0) {
        return;
    }
    for (uint32_t i = 0; i < pool_size; ++i) {
        pool_local[i] = (uint8_t)(pool_enc[i] ^ kb[i & 7u]);
    }
    void* loaded[64];
    uint64_t loaded_h[64];
    uint32_t n_loaded = 0;
    for (uint32_t i = 0; i < count; ++i) {
        import_entry_t* e = &entries[i];
        void* mod = 0;
        for (uint32_t j = 0; j < n_loaded; ++j) {
            if (loaded_h[j] == e->dll_hash) {
                mod = loaded[j];
                break;
            }
        }
        if (mod == 0) {
            mod = find_module(e->dll_hash);
        }
        if (mod == 0) {
            uint32_t off = 0;
            int found = 0;
            while (off + 1 < pool_size) {
                size_t nl = 0;
                while (off + nl < pool_size && pool_local[off + nl] != 0) {
                    ++nl;
                }
                if (nl > 0) {
                    uint64_t dh = fnv1a64_a_upper((const char*)(pool_local + off), nl);
                    if (dh == e->dll_hash) {
                        const char* dll_name = (const char*)(pool_local + off);
                        char host_name[96];
                        size_t host_len = 0;
                        if (resolve_apiset_host(dll_name, nl, host_name, sizeof(host_name), &host_len)) {
                            uint64_t host_hash = fnv1a64_a_upper(host_name, host_len);
                            mod = find_module(host_hash);
                            if (mod == 0) {
                                mod = r->LoadLibraryA(host_name);
                            }
                        } else {
                            mod = r->LoadLibraryA(dll_name);
                        }
                        found = 1;
                        break;
                    }
                }
                off += (uint32_t)(nl + 1u);
            }
            (void)found;
        }
        if (mod == 0) {
            continue;
        }
        if (n_loaded < 64) {
            int already = 0;
            for (uint32_t j = 0; j < n_loaded; ++j) {
                if (loaded_h[j] == e->dll_hash) {
                    already = 1;
                    break;
                }
            }
            if (!already) {
                loaded[n_loaded] = mod;
                loaded_h[n_loaded] = e->dll_hash;
                ++n_loaded;
            }
        }
        void* fp = 0;
        if (e->flags & 0x1u) {
            fp = resolve_export(mod, 0, e->ordinal, 1, 0);
        } else {
            fp = resolve_export(mod, e->func_hash, 0, 0, 0);
        }
        if (fp == 0) {
            continue;
        }
        uint64_t* slot = (uint64_t*)(image_base + e->iat_rva);
        uint32_t old = 0;
        protect_region(r, slot, 8, PAGE_RW, &old);
        *slot = (uint64_t)(uintptr_t)fp;
        uint32_t old2 = 0;
        protect_region(r, slot, 8, old, &old2);
    }
    free_scratch(r, pool_local);
}

static void decrypt_strings(uint8_t* image_base, const uint8_t master[32],
                            uint8_t* packed_base, const packed_header_t* hdr,
                            const resolved_t* r) {
    if (hdr->string_fixup_count == 0 || hdr->string_table_offset == 0) {
        return;
    }
    uint8_t* tbl = packed_base + hdr->string_table_offset;
    uint32_t count = *(uint32_t*)tbl;
    string_fixup_t* entries = (string_fixup_t*)(tbl + 4);
    uint64_t base_key = siphash_2_4(master, 32, 0x5354524B45595A31ULL, 0x5354524B45595A31ULL);
    uint8_t base_xor = (uint8_t)(base_key & 0xFFu);
    for (uint32_t i = 0; i < count; ++i) {
        string_fixup_t* sf = &entries[i];
        uint8_t* p = image_base + sf->rva;
        uint32_t old = 0;
        protect_region(r, p, sf->length, PAGE_RW, &old);
        uint8_t rva_low = (uint8_t)(sf->rva & 0xFFu);
        for (uint32_t j = 0; j < sf->length; ++j) {
            uint8_t kb = (uint8_t)(base_xor ^ (uint8_t)((j * 0x9Eu) & 0xFFu) ^ rva_low);
            p[j] = (uint8_t)(p[j] ^ kb);
        }
        uint32_t old2 = 0;
        protect_region(r, p, sf->length, old, &old2);
    }
}

static void decrypt_resources(uint8_t* image_base,
                              uint8_t* packed_base, const packed_header_t* hdr,
                              const resolved_t* r) {
    if (hdr->resource_fixup_count == 0 || hdr->resource_table_offset == 0) {
        return;
    }
    uint8_t* tbl = packed_base + hdr->resource_table_offset;
    uint32_t count = *(uint32_t*)tbl;
    resource_fixup_t* entries = (resource_fixup_t*)(tbl + 4);
    for (uint32_t i = 0; i < count; ++i) {
        resource_fixup_t* rf = &entries[i];
        uint8_t* p = image_base + rf->rva;
        uint32_t old = 0;
        protect_region(r, p, rf->size, PAGE_RW, &old);
        uint32_t n_chunks = rf->size / 8u;
        for (uint32_t k = 0; k < n_chunks; ++k) {
            uint64_t ki = rf->rolling_key + (uint64_t)k * 0x9E3779B97F4A7C15ULL;
            uint64_t v = 0;
            mem_copy(&v, p + k * 8u, 8);
            v ^= ki;
            mem_copy(p + k * 8u, &v, 8);
        }
        uint32_t tail_start = n_chunks * 8u;
        uint32_t tail = rf->size - tail_start;
        if (tail > 0) {
            uint64_t ki = rf->rolling_key + (uint64_t)n_chunks * 0x9E3779B97F4A7C15ULL;
            uint8_t kb[8];
            mem_copy(kb, &ki, 8);
            for (uint32_t j = 0; j < tail; ++j) {
                p[tail_start + j] = (uint8_t)(p[tail_start + j] ^ kb[j]);
            }
        }
        uint32_t old2 = 0;
        protect_region(r, p, rf->size, old, &old2);
    }
}

static void apply_relocations(uint8_t* image_base, const resolved_t* r) {
    uint32_t e_lfanew = *(uint32_t*)(image_base + 0x3C);
    uint8_t* nt = image_base + e_lfanew;
    uint64_t preferred = *(uint64_t*)(nt + 0x18 + 24);
    uint64_t actual = (uint64_t)(uintptr_t)image_base;
    if (preferred == actual) {
        return;
    }
    int64_t delta = (int64_t)actual - (int64_t)preferred;
    uint32_t reloc_rva = *(uint32_t*)(nt + 0x18 + 112 + 5 * 8);
    uint32_t reloc_size = *(uint32_t*)(nt + 0x18 + 112 + 5 * 8 + 4);
    if (reloc_rva == 0 || reloc_size == 0) {
        return;
    }
    uint8_t* p = image_base + reloc_rva;
    uint8_t* end = p + reloc_size;
    while (p + 8 <= end) {
        uint32_t page_rva = *(uint32_t*)p;
        uint32_t block_size = *(uint32_t*)(p + 4);
        if (block_size < 8 || p + block_size > end) {
            break;
        }
        uint32_t n_entries = (block_size - 8u) / 2u;
        uint16_t* entries = (uint16_t*)(p + 8);
        for (uint32_t i = 0; i < n_entries; ++i) {
            uint16_t e = entries[i];
            uint32_t type = (uint32_t)(e >> 12);
            uint32_t off = (uint32_t)(e & 0x0FFFu);
            uint8_t* tgt = image_base + page_rva + off;
            if (type == 10u) {
                uint32_t old = 0;
                protect_region(r, tgt, 8, PAGE_RW, &old);
                uint64_t v = 0;
                mem_copy(&v, tgt, 8);
                v = (uint64_t)((int64_t)v + delta);
                mem_copy(tgt, &v, 8);
                uint32_t old2 = 0;
                protect_region(r, tgt, 8, old, &old2);
            } else if (type == 3u) {
                uint32_t old = 0;
                protect_region(r, tgt, 4, PAGE_RW, &old);
                uint32_t v = 0;
                mem_copy(&v, tgt, 4);
                v = (uint32_t)((int32_t)v + (int32_t)delta);
                mem_copy(tgt, &v, 4);
                uint32_t old2 = 0;
                protect_region(r, tgt, 4, old, &old2);
            }
        }
        p += block_size;
    }
}

typedef long (__stdcall *nt_query_info_proc_t)(void*, uint32_t, void*, uint32_t, uint32_t*);
typedef long (__stdcall *nt_get_context_thread_t)(void*, void*);
typedef long (__stdcall *nt_query_sys_info_t)(uint32_t, void*, uint32_t, uint32_t*);
typedef int (__stdcall *check_remote_debugger_t)(void*, int*);
typedef void (__stdcall *sleep_t)(uint32_t);

typedef struct env_thread_context_s {
    uint64_t P1Home;
    uint64_t P2Home;
    uint64_t P3Home;
    uint64_t P4Home;
    uint64_t P5Home;
    uint64_t P6Home;
    uint32_t ContextFlags;
    uint32_t MxCsr;
    uint16_t SegCs;
    uint16_t SegDs;
    uint16_t SegEs;
    uint16_t SegFs;
    uint16_t SegGs;
    uint16_t SegSs;
    uint32_t EFlags;
    uint64_t Dr0;
    uint64_t Dr1;
    uint64_t Dr2;
    uint64_t Dr3;
    uint64_t Dr6;
    uint64_t Dr7;
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    uint8_t  pad_fpu[512];
    uint8_t  pad_vec[416];
    uint64_t VectorControl;
    uint64_t DebugControl;
    uint64_t LastBranchToRip;
    uint64_t LastBranchFromRip;
    uint64_t LastExceptionToRip;
    uint64_t LastExceptionFromRip;
} env_thread_context_t;

typedef struct sys_kernel_debugger_info_s {
    uint8_t KernelDebuggerEnabled;
    uint8_t KernelDebuggerNotPresent;
} sys_kernel_debugger_info_t;

typedef struct apiset_namespace_s {
    uint32_t Version;
    uint32_t Size;
    uint32_t Flags;
    uint32_t Count;
    uint32_t EntryOffset;
    uint32_t HashOffset;
    uint32_t HashFactor;
} apiset_namespace_t;

typedef struct apiset_entry_s {
    uint32_t Flags;
    uint32_t NameOffset;
    uint32_t NameLength;
    uint32_t HashedLength;
    uint32_t ValueOffset;
    uint32_t ValueCount;
} apiset_entry_t;

typedef struct apiset_value_s {
    uint32_t Flags;
    uint32_t NameOffset;
    uint32_t NameLength;
    uint32_t ValueOffset;
    uint32_t ValueLength;
} apiset_value_t;

#define ENV_CONTEXT_DEBUG_REGISTERS 0x00100010u
#define ENV_PROCESS_DEBUG_PORT 7u
#define ENV_PROCESS_DEBUG_OBJECT_HANDLE 30u
#define ENV_PROCESS_DEBUG_FLAGS 31u
#define ENV_SYSTEM_KERNEL_DEBUGGER_INFORMATION 23u
#define ENV_KUSER_SHARED_DATA 0x7FFE0000ULL
#define ENV_KUSER_KD_DEBUGGER_ENABLED 0x2D4u

static uint8_t env_lower_byte(uint8_t c) {
    if (c >= 'A' && c <= 'Z') {
        return (uint8_t)(c + 32);
    }
    return c;
}

static int env_is_apiset_name(const char* name, size_t name_len) {
    if (name_len < 8u) {
        return 0;
    }
    uint8_t c0 = env_lower_byte((uint8_t)name[0]);
    uint8_t c1 = env_lower_byte((uint8_t)name[1]);
    uint8_t c2 = env_lower_byte((uint8_t)name[2]);
    uint8_t c3 = (uint8_t)name[3];
    uint8_t c4 = env_lower_byte((uint8_t)name[4]);
    uint8_t c5 = env_lower_byte((uint8_t)name[5]);
    uint8_t c6 = (uint8_t)name[6];
    if (c0 == 'a' && c1 == 'p' && c2 == 'i' && c3 == '-'
        && c4 == 'm' && c5 == 's' && c6 == '-') {
        if (name_len >= 11u) {
            uint8_t c7 = env_lower_byte((uint8_t)name[7]);
            uint8_t c8 = env_lower_byte((uint8_t)name[8]);
            uint8_t c9 = env_lower_byte((uint8_t)name[9]);
            uint8_t c10 = (uint8_t)name[10];
            if (c7 == 'w' && c8 == 'i' && c9 == 'n' && c10 == '-') {
                return 1;
            }
        }
        return 0;
    }
    if (c0 == 'e' && c1 == 'x' && c2 == 't' && c3 == '-'
        && c4 == 'm' && c5 == 's' && c6 == '-') {
        return 1;
    }
    return 0;
}

static int env_wide_eq_ascii_ci(const uint16_t* w, size_t w_chars, const char* a, size_t a_len) {
    if (w_chars != a_len) {
        return 0;
    }
    for (size_t i = 0; i < w_chars; ++i) {
        uint16_t wc = w[i];
        uint8_t ac = (uint8_t)a[i];
        if (wc >= 'A' && wc <= 'Z') wc = (uint16_t)(wc + 32);
        if (ac >= 'A' && ac <= 'Z') ac = (uint8_t)(ac + 32);
        if ((uint8_t)(wc & 0xFFu) != ac) {
            return 0;
        }
    }
    return 1;
}

static size_t env_strip_dll_suffix(const char* name, size_t name_len) {
    if (name_len >= 4) {
        const char* tail = name + (name_len - 4);
        uint8_t a = (uint8_t)tail[0];
        uint8_t b = (uint8_t)tail[1];
        uint8_t c = (uint8_t)tail[2];
        uint8_t d = (uint8_t)tail[3];
        if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32);
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        if (d >= 'A' && d <= 'Z') d = (uint8_t)(d + 32);
        if (a == '.' && b == 'd' && c == 'l' && d == 'l') {
            name_len -= 4;
        }
    }
    return name_len;
}

static int resolve_apiset_host(const char* name, size_t name_len,
                               char* out_host, size_t out_cap, size_t* out_len) {
    if (name == 0 || out_host == 0 || out_cap < 2 || out_len == 0) {
        return 0;
    }
    if (!env_is_apiset_name(name, name_len)) {
        return 0;
    }
    peb_t* peb = get_peb();
    uint8_t* peb_raw = (uint8_t*)peb;
    void* api_set_map_ptr = 0;
    mem_copy(&api_set_map_ptr, peb_raw + 0x68, sizeof(void*));
    if (api_set_map_ptr == 0) {
        return 0;
    }
    uint8_t* base = (uint8_t*)api_set_map_ptr;
    apiset_namespace_t* ns = (apiset_namespace_t*)base;
    if (ns->Version != 6u || ns->Count == 0u || ns->EntryOffset == 0u) {
        return 0;
    }
    size_t basename_len = env_strip_dll_suffix(name, name_len);
    if (basename_len == 0) {
        return 0;
    }
    apiset_entry_t* entries = (apiset_entry_t*)(base + ns->EntryOffset);
    for (uint32_t i = 0; i < ns->Count; ++i) {
        apiset_entry_t* e = &entries[i];
        if (e->NameOffset == 0u || e->NameLength == 0u) {
            continue;
        }
        uint16_t* name_w = (uint16_t*)(base + e->NameOffset);
        uint32_t hashed_chars = e->HashedLength / 2u;
        if (hashed_chars == 0u || hashed_chars > basename_len) {
            continue;
        }
        if (!env_wide_eq_ascii_ci(name_w, hashed_chars, name, hashed_chars)) {
            continue;
        }
        if (basename_len > hashed_chars) {
            int all_digits_or_dash = 1;
            for (size_t k = hashed_chars; k < basename_len; ++k) {
                uint8_t ch = (uint8_t)name[k];
                if (!((ch >= '0' && ch <= '9') || ch == '-')) {
                    all_digits_or_dash = 0;
                    break;
                }
            }
            if (!all_digits_or_dash) {
                continue;
            }
        }
        if (e->ValueCount == 0u || e->ValueOffset == 0u) {
            return 0;
        }
        apiset_value_t* values = (apiset_value_t*)(base + e->ValueOffset);
        apiset_value_t* default_value = &values[0];
        for (uint32_t j = 0; j < e->ValueCount; ++j) {
            if (values[j].NameLength == 0u) {
                default_value = &values[j];
                break;
            }
        }
        if (default_value->ValueLength == 0u || default_value->ValueOffset == 0u) {
            return 0;
        }
        uint16_t* host_w = (uint16_t*)(base + default_value->ValueOffset);
        size_t host_chars = (size_t)(default_value->ValueLength / 2u);
        if (host_chars + 1u > out_cap) {
            return 0;
        }
        for (size_t k = 0; k < host_chars; ++k) {
            out_host[k] = (char)(host_w[k] & 0xFFu);
        }
        out_host[host_chars] = 0;
        *out_len = host_chars;
        return 1;
    }
    return 0;
}

static int env_check_peb_being_debugged(void) {
    peb_t* peb = get_peb();
    uint8_t* p = (uint8_t*)peb;
    return p[0x02] != 0;
}

static int env_check_nt_global_flag(void) {
    peb_t* peb = get_peb();
    uint8_t* p = (uint8_t*)peb;
    uint32_t flags = 0;
    mem_copy(&flags, p + 0xBC, 4);
    return (flags & 0x70u) != 0u;
}

static int env_check_heap_flags(void) {
    peb_t* peb = get_peb();
    uint8_t* p = (uint8_t*)peb;
    void* heap = 0;
    mem_copy(&heap, p + 0x30, sizeof(void*));
    if (heap == 0) {
        return 0;
    }
    uint8_t* h = (uint8_t*)heap;
    uint32_t flags = 0;
    uint32_t force_flags = 0;
    mem_copy(&flags, h + 0x70, 4);
    mem_copy(&force_flags, h + 0x74, 4);
    if (force_flags != 0u) {
        return 1;
    }
    if ((flags & ~0x02u) != 0u) {
        return 1;
    }
    return 0;
}

static int env_check_kuser_kd(void) {
    uint8_t* k = (uint8_t*)(uintptr_t)ENV_KUSER_SHARED_DATA;
    return k[ENV_KUSER_KD_DEBUGGER_ENABLED] != 0;
}

static int env_check_rdtsc_skew(void) {
    int hostile_iterations = 0;
    for (int loop = 0; loop < 5; ++loop) {
        uint32_t aux0 = 0;
        uint32_t aux1 = 0;
        unsigned long long t0 = __rdtscp(&aux0);
        volatile uint32_t spin = 0;
        for (int s = 0; s < 100; ++s) {
            spin += (uint32_t)s;
        }
        unsigned long long t1 = __rdtscp(&aux1);
        (void)spin;
        if (t1 < t0) {
            ++hostile_iterations;
            continue;
        }
        if ((t1 - t0) > 100000000ULL) {
            ++hostile_iterations;
        }
    }
    return (hostile_iterations >= 3) ? 1 : 0;
}

static int env_check_xcr0_consistency(void) {
    int regs[4]; regs[0] = 0; regs[1] = 0; regs[2] = 0; regs[3] = 0;
    __cpuid(regs, 1);
    uint32_t feat_ecx = (uint32_t)regs[2];
    uint32_t feat_edx = (uint32_t)regs[3];
    if ((feat_edx & (1u << 26)) == 0u) {
        return 1;
    }
    if ((feat_ecx & (1u << 27)) != 0u) {
        unsigned long long xcr0 = _xgetbv(0);
        if ((xcr0 & 0x3ull) != 0x3ull) {
            return 1;
        }
    }
    return 0;
}

static void env_decrypt_and_run_poison(const resolved_t* r) {
    if (r == 0 || r->NtAllocateVirtualMemory == 0 || r->NtProtectVirtualMemory == 0
        || r->NtFreeVirtualMemory == 0) {
        return;
    }
    void* page = 0;
    size_t page_sz = 4096;
    long st = r->NtAllocateVirtualMemory((void*)(intptr_t)-1, &page, 0, &page_sz,
                                         MEM_COMMIT_RESERVE, PAGE_RW);
    if (st < 0 || page == 0) {
        return;
    }
    uint8_t* buf = (uint8_t*)page;
    for (uint32_t i = 0; i < 255u; ++i) {
        buf[i] = 0x90u;
    }
    buf[255] = 0xC3u;
    uint8_t poison_key[32];
    uint8_t poison_iv[16];
    uint64_t seed_a = (uint64_t)__rdtsc();
    uint64_t seed_b = seed_a ^ 0xA5A5A5A5A5A5A5A5ULL;
    for (int i = 0; i < 4; ++i) {
        uint64_t kw = siphash_3u64(0xC0DEBABEDEADBEEFULL ^ (uint64_t)i, seed_a, seed_b);
        mem_copy(poison_key + i * 8, &kw, 8);
    }
    for (int i = 0; i < 2; ++i) {
        uint64_t iw = siphash_3u64(0xFEEDFACEDEADC0DEULL ^ (uint64_t)i, seed_b, seed_a);
        mem_copy(poison_iv + i * 8, &iw, 8);
    }
    aes256_ctr_xor(poison_key, poison_iv, buf, 256);
    aes256_ctr_xor(poison_key, poison_iv, buf, 256);
    void* prot_addr = page;
    size_t prot_sz = 256;
    uint32_t old_prot = 0;
    long prot_st = r->NtProtectVirtualMemory((void*)(intptr_t)-1, &prot_addr, &prot_sz, PAGE_EX_R, &old_prot);
    if (prot_st >= 0) {
        void (*fn)(void) = (void (*)(void))buf;
        fn();
    }
    void* free_addr = page;
    size_t free_sz = 0;
    r->NtFreeVirtualMemory((void*)(intptr_t)-1, &free_addr, &free_sz, MEM_RELEASE);
}

static int runtime_environment_check(void) {
    return 0;
    if (env_check_peb_being_debugged()) {
        return 1;
    }
    if (env_check_nt_global_flag()) {
        return 2;
    }
    if (env_check_heap_flags()) {
        return 3;
    }
    void* ntdll_local = find_module(HASH_NTDLL);
    void* kernel32_local = find_module(HASH_KERNEL32);
    if (ntdll_local == 0 || kernel32_local == 0) {
        return 0;
    }
    nt_query_info_proc_t pNtQueryInformationProcess =
        (nt_query_info_proc_t)resolve_export(ntdll_local, HASH_NTQUERYINFOPROC, 0, 0, 0);
    if (pNtQueryInformationProcess != 0) {
        uint64_t debug_port = 0;
        uint32_t ret_len = 0;
        long st1 = pNtQueryInformationProcess((void*)(intptr_t)-1, ENV_PROCESS_DEBUG_PORT,
                                              &debug_port, sizeof(debug_port), &ret_len);
        if (st1 >= 0 && debug_port != 0u) {
            return 4;
        }
        uint64_t debug_object = 0;
        ret_len = 0;
        long st2 = pNtQueryInformationProcess((void*)(intptr_t)-1, ENV_PROCESS_DEBUG_OBJECT_HANDLE,
                                              &debug_object, sizeof(debug_object), &ret_len);
        if (st2 >= 0 && debug_object != 0u) {
            return 5;
        }
        uint32_t debug_flags = 0;
        ret_len = 0;
        long st3 = pNtQueryInformationProcess((void*)(intptr_t)-1, ENV_PROCESS_DEBUG_FLAGS,
                                              &debug_flags, sizeof(debug_flags), &ret_len);
        if (st3 >= 0 && debug_flags == 0u) {
            return 6;
        }
    }
    check_remote_debugger_t pCheckRemoteDebuggerPresent =
        (check_remote_debugger_t)resolve_export(kernel32_local, HASH_CHECKREMOTEDBG, 0, 0, 0);
    if (pCheckRemoteDebuggerPresent != 0) {
        int present = 0;
        if (pCheckRemoteDebuggerPresent((void*)(intptr_t)-1, &present) != 0) {
            if (present != 0) {
                return 7;
            }
        }
    }
    nt_get_context_thread_t pNtGetContextThread =
        (nt_get_context_thread_t)resolve_export(ntdll_local, HASH_NTGETCONTEXTTHREAD, 0, 0, 0);
    if (pNtGetContextThread != 0) {
        __declspec(align(16)) env_thread_context_t ctx_local;
        mem_set(&ctx_local, 0, sizeof(ctx_local));
        ctx_local.ContextFlags = ENV_CONTEXT_DEBUG_REGISTERS;
        long st_ctx = pNtGetContextThread((void*)(intptr_t)-2, &ctx_local);
        if (st_ctx >= 0) {
            uint64_t dr_or = ctx_local.Dr0 | ctx_local.Dr1 | ctx_local.Dr2 | ctx_local.Dr3;
            if (dr_or != 0u) {
                return 8;
            }
        }
    }
    if (env_check_kuser_kd()) {
        return 9;
    }
    if (env_check_rdtsc_skew()) {
        return 10;
    }
    if (env_check_xcr0_consistency()) {
        return 11;
    }
    nt_query_sys_info_t pNtQuerySystemInformation =
        (nt_query_sys_info_t)resolve_export(ntdll_local, HASH_NTQUERYSYSINFO, 0, 0, 0);
    if (pNtQuerySystemInformation != 0) {
        sys_kernel_debugger_info_t kd_info;
        mem_set(&kd_info, 0, sizeof(kd_info));
        uint32_t ret_len = 0;
        long st_kd = pNtQuerySystemInformation(ENV_SYSTEM_KERNEL_DEBUGGER_INFORMATION,
                                               &kd_info, sizeof(kd_info), &ret_len);
        if (st_kd >= 0) {
            if (kd_info.KernelDebuggerEnabled != 0u && kd_info.KernelDebuggerNotPresent == 0u) {
                return 12;
            }
        }
    }
    return 0;
}

static void env_react_to_hostile(int reason, const resolved_t* r) {
    (void)reason;
    env_decrypt_and_run_poison(r);
    if (r != 0 && r->kernel32 != 0) {
        sleep_t pSleep = (sleep_t)resolve_export(r->kernel32, HASH_SLEEP, 0, 0, 0);
        if (pSleep == 0 && r->kernelbase != 0) {
            pSleep = (sleep_t)resolve_export(r->kernelbase, HASH_SLEEP, 0, 0, 0);
        }
        if (pSleep != 0) {
            pSleep(30000u);
        }
    }
    __fastfail(0xDEADC0DEu);
}

void __cdecl aida_unpack(void* image_base_arg) {
    uint8_t* image_base = (uint8_t*)image_base_arg;
    if (image_base == 0) {
        for (;;) { }
    }
    resolved_t r;
    mem_set(&r, 0, sizeof(r));
    if (!resolve_all(&r)) {
        for (;;) { }
    }
    int env_status = runtime_environment_check();
    if (env_status != 0) {
        env_react_to_hostile(env_status, &r);
        for (;;) { }
    }
    uint32_t packed_vsize = 0;
    uint8_t* packed_base = find_packed_section(image_base, &packed_vsize);
    if (packed_base == 0) {
        __fastfail(0xA1DA0001u);
    }
    packed_header_t* hdr = (packed_header_t*)packed_base;
    if (!validate_packed_header(image_base, packed_base, packed_vsize, hdr)) {
        __fastfail(0xA1DA0002u);
    }
    uint8_t* obfuscated = packed_base + hdr->master_key_offset;
    uint8_t* mask = obfuscated + 32;
    uint8_t pe_mask[32];
    derive_pe_mask(hdr->master_key_pe_timestamp, hdr->master_key_pe_size_of_code, pe_mask);
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = (uint8_t)(obfuscated[i] ^ mask[i] ^ pe_mask[i]);
    }
    if ((hdr->bind_flags & 0x1u) != 0u) {
        int regs[4]; regs[0] = 0; regs[1] = 0; regs[2] = 0; regs[3] = 0;
        __cpuid(regs, 1);
        uint32_t fp = (uint32_t)regs[0];
        for (int i = 0; i < 4; ++i) {
            uint64_t k0 = 0, k1 = 0;
            mem_copy(&k0, hdr->bind_salt + 0, 8);
            mem_copy(&k1, hdr->bind_salt + 8, 8);
            k0 ^= (uint64_t)fp;
            k1 ^= (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            uint8_t blk[8] = {0};
            blk[0] = (uint8_t)i;
            uint64_t h = siphash_2_4(blk, 8, k0, k1);
            for (int j = 0; j < 8; ++j) {
                master[i * 8 + j] ^= (uint8_t)(h >> (j * 8));
            }
        }
    }
    unpack_sections(image_base, master, packed_base, hdr, &r);
    rebuild_iat(image_base, master, packed_base, hdr, &r);
    decrypt_strings(image_base, master, packed_base, hdr, &r);
    decrypt_resources(image_base, packed_base, hdr, &r);
    apply_relocations(image_base, &r);
}
