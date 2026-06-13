#define AIDA_TEST_TARGET_FIXTURE_API __declspec(dllexport)
#include "protected_re_fixtures.h"
#include "test_log.h"

#include <cstdio>
#include <cstring>

namespace test_target {
namespace protected_re {

namespace {

constexpr std::uint32_t kMagic = 0x41505246u;
constexpr std::uint16_t kVersion = 1;
constexpr std::uint32_t kEntropySize = 16384;
constexpr std::uint32_t kSmcSize = 4096;
constexpr std::uint8_t kSmcKey = 0x5Au;
constexpr std::uint32_t kSmcRangeSize = 14;
constexpr std::uint32_t kSmcMarkerOffset = 10;
constexpr std::uint32_t kSmcExpectedResult = 0xA1DAA17Du;

std::uint8_t* g_entropy_region = nullptr;
std::uint8_t* g_smc_region = nullptr;
std::uint8_t* g_smc_decryptor_range = nullptr;
bool g_smc_decrypted = false;
std::uint32_t g_last_vm_result = 0;

std::uint32_t xorshift32(std::uint32_t& s)
{
    s ^= s << 13u;
    s ^= s >> 17u;
    s ^= s << 5u;
    return s;
}

void fill_entropy(std::uint8_t* dst, std::uint32_t size, std::uint32_t seed)
{
    if (!dst)
        return;
    std::uint32_t s = seed;
    for (std::uint32_t i = 0; i < size; ++i) {
        if ((i & 3u) == 0u)
            xorshift32(s);
        dst[i] = static_cast<std::uint8_t>(((s >> ((i & 3u) * 8u)) ^ (i * 37u) ^ 0xA5u) & 0xFFu);
    }
}

void initialize_smc_page()
{
    if (!g_smc_region)
        return;

    fill_entropy(g_smc_region, kSmcSize, 0xA1DA5501u);
    const std::uint8_t code[] = {
        0xB8u, 0x7Du, 0xA1u, 0xDAu, 0xA1u, 0xC3u, 0xCCu, 0xCCu
    };
    for (std::uint32_t i = 0; i < sizeof(code); ++i)
        g_smc_region[i] = static_cast<std::uint8_t>(code[i] ^ kSmcKey);
    g_smc_decrypted = false;
    FlushInstructionCache(GetCurrentProcess(), g_smc_region, kSmcSize);
}

void initialize_smc_decryptor_range()
{
    if (!g_smc_region)
        return;
    if (!g_smc_decryptor_range)
        g_smc_decryptor_range = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, kSmcSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!g_smc_decryptor_range)
        return;
    std::uint8_t code[kSmcRangeSize] = {
        0x48u, 0xB8u, 0, 0, 0, 0, 0, 0, 0, 0,
        0x80u, 0x30u, kSmcKey,
        0xC3u
    };
    const std::uint64_t target = reinterpret_cast<std::uint64_t>(g_smc_region);
    std::memcpy(code + 2, &target, sizeof(target));
    std::memcpy(g_smc_decryptor_range, code, sizeof(code));
    for (std::uint32_t i = kSmcRangeSize; i < 64u; ++i)
        g_smc_decryptor_range[i] = 0xCCu;
    FlushInstructionCache(GetCurrentProcess(), g_smc_decryptor_range, 64);
}

std::uint32_t apply_smc_state(bool decrypt)
{
    if (!g_smc_region)
        return 0;
    if (decrypt == g_smc_decrypted)
        return g_smc_decrypted ? 1u : 0u;

    const std::uint32_t code_len = 8;
    for (std::uint32_t i = 0; i < code_len; ++i)
        g_smc_region[i] ^= kSmcKey;
    g_smc_decrypted = decrypt;
    FlushInstructionCache(GetCurrentProcess(), g_smc_region, code_len);
    return g_smc_decrypted ? 1u : 0u;
}

void update_descriptor()
{
    aida_test_protected_re_descriptor.magic = kMagic;
    aida_test_protected_re_descriptor.version = kVersion;
    aida_test_protected_re_descriptor.size = sizeof(aida_test_protected_re_descriptor);
    aida_test_protected_re_descriptor.module_base_va = reinterpret_cast<std::uint64_t>(GetModuleHandleW(nullptr));
    aida_test_protected_re_descriptor.descriptor_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_re_descriptor);
    aida_test_protected_re_descriptor.entropy_region_va = reinterpret_cast<std::uint64_t>(g_entropy_region);
    aida_test_protected_re_descriptor.entropy_region_size = g_entropy_region ? kEntropySize : 0;
    aida_test_protected_re_descriptor.entropy_region_protection = PAGE_EXECUTE_READ;
    aida_test_protected_re_descriptor.smc_region_va = reinterpret_cast<std::uint64_t>(g_smc_region);
    aida_test_protected_re_descriptor.smc_region_size = g_smc_region ? kSmcSize : 0;
    aida_test_protected_re_descriptor.smc_key = kSmcKey;
    aida_test_protected_re_descriptor.entry_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_entry);
    aida_test_protected_re_descriptor.vm_entry_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_vm_entry);
    aida_test_protected_re_descriptor.cff_entry_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_cff_entry);
    aida_test_protected_re_descriptor.mba_entry_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_mba_entry);
    aida_test_protected_re_descriptor.opaque_entry_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_opaque_entry);
    aida_test_protected_re_descriptor.smc_helper_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_smc_decrypt);
    aida_test_protected_re_descriptor.smc_helper_range_va = reinterpret_cast<std::uint64_t>(&aida_test_protected_smc_decrypt);
    aida_test_protected_re_descriptor.smc_helper_range_size = 512;
    aida_test_protected_re_descriptor.smc_expected_result = kSmcExpectedResult;
    aida_test_protected_re_descriptor.smc_decryptor_range_va = reinterpret_cast<std::uint64_t>(g_smc_decryptor_range);
    aida_test_protected_re_descriptor.smc_decryptor_range_size = g_smc_decryptor_range ? kSmcRangeSize : 0;
    aida_test_protected_re_descriptor.smc_decryptor_marker_size = g_smc_decryptor_range ? 3u : 0u;
    aida_test_protected_re_descriptor.smc_decryptor_marker_va = g_smc_decryptor_range ? reinterpret_cast<std::uint64_t>(g_smc_decryptor_range + kSmcMarkerOffset) : 0;
    aida_test_protected_re_descriptor.smc_state_va = reinterpret_cast<std::uint64_t>(&g_smc_decrypted);
}

std::uint32_t default_vm_program(std::uint8_t* out, std::uint32_t size)
{
    const std::uint8_t program[] = {
        0x10u, 0x21u, 0x13u, 0x32u, 0x18u, 0x43u, 0x7Fu
    };
    if (!out || size < sizeof(program))
        return 0;
    std::memcpy(out, program, sizeof(program));
    return static_cast<std::uint32_t>(sizeof(program));
}

}

void init(const config_t& cfg, std::atomic<bool>& running)
{
    (void)running;
    if (!cfg.enabled) {
        update_descriptor();
        return;
    }

    if (!g_entropy_region) {
        g_entropy_region = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, kEntropySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (g_entropy_region) {
            fill_entropy(g_entropy_region, kEntropySize, 0xA1DAE777u);
            DWORD old_protect = 0;
            VirtualProtect(g_entropy_region, kEntropySize, PAGE_EXECUTE_READ, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), g_entropy_region, kEntropySize);
        }
    }

    if (!g_smc_region) {
        g_smc_region = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, kSmcSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        initialize_smc_page();
    }
    initialize_smc_decryptor_range();

    update_descriptor();

    if (cfg.verbose) {
        printf("[protected-re] descriptor=%p entropy=%p/%u smc=%p/%u entry=%p smc_range=%p/%u marker=%p expected=0x%08X\n",
               &aida_test_protected_re_descriptor,
               g_entropy_region,
               g_entropy_region ? kEntropySize : 0,
               g_smc_region,
               g_smc_region ? kSmcSize : 0,
               &aida_test_protected_entry,
               g_smc_decryptor_range,
               aida_test_protected_re_descriptor.smc_decryptor_range_size,
               reinterpret_cast<void*>(aida_test_protected_re_descriptor.smc_decryptor_marker_va),
               aida_test_protected_re_descriptor.smc_expected_result);
        fflush(stdout);
    }
}

void shutdown_all()
{
    if (g_smc_region) {
        VirtualFree(g_smc_region, 0, MEM_RELEASE);
        g_smc_region = nullptr;
        g_smc_decrypted = false;
    }
    if (g_smc_decryptor_range) {
        VirtualFree(g_smc_decryptor_range, 0, MEM_RELEASE);
        g_smc_decryptor_range = nullptr;
    }
    if (g_entropy_region) {
        VirtualFree(g_entropy_region, 0, MEM_RELEASE);
        g_entropy_region = nullptr;
    }
    update_descriptor();
}

std::uint32_t vm_entry_impl(const std::uint8_t* bytecode, std::uint32_t size, std::uint32_t seed) noexcept
{
    std::uint8_t local[32] = {};
    if (!bytecode || size == 0) {
        size = default_vm_program(local, sizeof(local));
        bytecode = local;
    }
    if (size > 256)
        size = 256;

    std::uint32_t acc = seed ^ 0xA1DA5100u;
    std::uint32_t ip = 0;
    __try {
        while (ip < size) {
            const std::uint8_t op = bytecode[ip++];
            switch (op >> 4u) {
            case 0x1u:
                acc += static_cast<std::uint32_t>((op & 0x0Fu) + 1u) * 17u;
                break;
            case 0x2u:
                acc ^= (static_cast<std::uint32_t>(op & 0x0Fu) << ((ip & 3u) * 8u));
                break;
            case 0x3u:
                acc = (acc << ((op & 7u) + 1u)) | (acc >> (31u - (op & 7u)));
                break;
            case 0x4u:
                acc = acc * 33u + static_cast<std::uint32_t>(op);
                break;
            case 0x7u:
                ip = size;
                break;
            default:
                acc += op;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        acc ^= 0xBAD0BAD0u;
    }

    g_last_vm_result = acc;
    return acc;
}

std::uint32_t cff_entry_impl(std::uint32_t seed) noexcept
{
    volatile std::uint32_t state = (seed ^ 0x5A17u) & 7u;
    std::uint32_t acc = seed + 0xA1DAu;
    for (std::uint32_t guard = 0; guard < 32u && state != 9u; ++guard) {
        switch (state) {
        case 0u:
            acc ^= 0x13579BDFu;
            state = 3u;
            break;
        case 1u:
            acc += (acc << 3u) ^ 0x2468ACE0u;
            state = 4u;
            break;
        case 2u:
            acc = (acc >> 1u) | (acc << 31u);
            state = 5u;
            break;
        case 3u:
            acc += seed | 0x101u;
            state = 6u;
            break;
        case 4u:
            acc ^= seed * 33u;
            state = 7u;
            break;
        case 5u:
            acc += 0x51515151u;
            state = 8u;
            break;
        case 6u:
            acc = (acc * 17u) ^ 0xA5A5A5A5u;
            state = 9u;
            break;
        case 7u:
            acc = (acc + 0x11111111u) ^ (acc >> 7u);
            state = 9u;
            break;
        case 8u:
            acc ^= (acc << 11u);
            state = 9u;
            break;
        default:
            state = 9u;
            break;
        }
    }
    return acc;
}

std::uint32_t mba_entry_impl(std::uint32_t x, std::uint32_t y) noexcept
{
    const std::uint32_t add = (x ^ y) + ((x & y) << 1u);
    const std::uint32_t sub = (x + ~y) + 1u;
    const std::uint32_t mix = ((add | sub) + (add & sub)) - ((add ^ sub) >> 1u);
    return (mix ^ ((x & 0x55555555u) + (y & 0xAAAAAAAAu))) + 0xA1DAu;
}

std::uint32_t opaque_entry_impl(std::uint32_t x) noexcept
{
    const std::uint32_t p = x * x + x;
    std::uint32_t acc = x ^ 0xA1DA0F0Fu;
    if ((p & 1u) == 0u)
        acc = (acc << 5u) | (acc >> 27u);
    else
        acc ^= 0xFFFFFFFFu;
    if (((x | 1u) * (x | 1u)) % 8u == 1u)
        acc += 0x13572468u;
    else
        acc ^= 0x86427531u;
    return acc;
}

std::uint32_t entry_impl(std::uint32_t selector, std::uint32_t value) noexcept
{
    switch (selector & 3u) {
    case 0u:
        return vm_entry_impl(nullptr, 0, value);
    case 1u:
        return cff_entry_impl(value);
    case 2u:
        return mba_entry_impl(value, value ^ 0xDEADBEEFu);
    default:
        return opaque_entry_impl(value);
    }
}

std::uint32_t smc_decrypt_impl(std::uint32_t action) noexcept
{
    if (!g_smc_region)
        return 0;
    if (action == 0u)
        return apply_smc_state(true);
    if (action == 1u)
        return apply_smc_state(false);
    if (action == 2u) {
        apply_smc_state(true);
        using fn_t = std::uint32_t(*)();
        fn_t fn = reinterpret_cast<fn_t>(g_smc_region);
        std::uint32_t result = 0;
        __try {
            result = fn();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            result = 0xBAD50000u;
        }
        return result;
    }
    return g_smc_decrypted ? 1u : 0u;
}

}
}

extern "C" __declspec(dllexport) test_target::protected_re::descriptor_t aida_test_protected_re_descriptor = {
    0x41505246u,
    1,
    sizeof(test_target::protected_re::descriptor_t)
};

extern "C" __declspec(dllexport) __declspec(noinline) const test_target::protected_re::descriptor_t* aida_test_protected_re_get_descriptor() noexcept
{
    return &aida_test_protected_re_descriptor;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_protected_entry(std::uint32_t selector, std::uint32_t value) noexcept
{
    return test_target::protected_re::entry_impl(selector, value);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_protected_vm_entry(const std::uint8_t* bytecode, std::uint32_t size, std::uint32_t seed) noexcept
{
    return test_target::protected_re::vm_entry_impl(bytecode, size, seed);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_protected_cff_entry(std::uint32_t seed) noexcept
{
    return test_target::protected_re::cff_entry_impl(seed);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_protected_mba_entry(std::uint32_t x, std::uint32_t y) noexcept
{
    return test_target::protected_re::mba_entry_impl(x, y);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_protected_opaque_entry(std::uint32_t x) noexcept
{
    return test_target::protected_re::opaque_entry_impl(x);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_protected_smc_decrypt(std::uint32_t action) noexcept
{
    return test_target::protected_re::smc_decrypt_impl(action);
}
