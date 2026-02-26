#pragma once

#include <cstdint>
#include <intrin.h>
#include <windows.h>

namespace spoofer {
    
    inline volatile std::uint32_t g_obfuscation_seed = 0xDEADBEEFu;
    inline volatile std::uint64_t g_timing_accumulator = 0;
    inline volatile std::uint64_t g_call_counter = 0;
    inline volatile std::uint64_t g_last_tsc = 0;
    inline volatile std::uint32_t g_entropy_state[4] = {0x6C078965u, 0x9908B0DFu, 0x9D2C5680u, 0xEFC60000u};
    inline volatile std::uint64_t g_stack_cookie = 0;
    
    __forceinline std::uint64_t rotl64(std::uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }
    
    __forceinline std::uint32_t xorshift32() noexcept {
        std::uint32_t x = g_entropy_state[0];
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        g_entropy_state[0] = x;
        return x;
    }
    
    __forceinline std::uint64_t xorshift64() noexcept {
        std::uint64_t x = g_entropy_state[0] | (static_cast<std::uint64_t>(g_entropy_state[1]) << 32);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        g_entropy_state[0] = static_cast<std::uint32_t>(x);
        g_entropy_state[1] = static_cast<std::uint32_t>(x >> 32);
        return x;
    }
    
    __forceinline void init_stack_cookie() noexcept {
        if (g_stack_cookie == 0) {
            std::uint64_t tsc = __rdtsc();
            std::uint64_t perf;
            QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&perf));
            g_stack_cookie = tsc ^ perf ^ (reinterpret_cast<std::uint64_t>(&g_stack_cookie) >> 4);
            g_stack_cookie = rotl64(g_stack_cookie, 17) ^ 0xCAFEBABE12345678ULL;
            g_entropy_state[0] ^= static_cast<std::uint32_t>(tsc);
            g_entropy_state[1] ^= static_cast<std::uint32_t>(perf);
        }
    }
    
    __forceinline void __spoofer_noop() noexcept {
        volatile std::uint32_t v = g_obfuscation_seed;
        v ^= 0xCAFEBABEu;
        v = _rotl(v, 13);
        v ^= __rdtsc() & 0xFFFFFFFFu;
        g_obfuscation_seed = v;
        g_call_counter++;
    }
    
    __forceinline std::uint64_t get_return_address() noexcept {
        return reinterpret_cast<std::uint64_t>(_ReturnAddress());
    }
    
    __forceinline void memory_barrier() noexcept {
        _mm_mfence();
    }
    
    __forceinline void compiler_barrier() noexcept {
        _ReadWriteBarrier();
    }
    
    template<typename T>
    __forceinline T hide_value(T value) noexcept {
        volatile T result = value;
        std::uint64_t key = rotl64(g_obfuscation_seed, 17) ^ __rdtsc();
        result ^= static_cast<T>(key);
        result ^= static_cast<T>(key);
        compiler_barrier();
        return result;
    }
    
    __forceinline void timing_variance() noexcept {
        volatile std::uint32_t spin = (__rdtsc() & 0xF) + 1;
        while (spin--) {
            _mm_pause();
            compiler_barrier();
        }
    }
    
    __forceinline std::uint64_t mix_entropy(std::uint64_t x) noexcept {
        x ^= x >> 33;
        x *= 0xff51afd7ed558ccdULL;
        x ^= x >> 33;
        x *= 0xc4ceb9fe1a85ec53ULL;
        x ^= x >> 33;
        return x;
    }
    
    __forceinline std::uint64_t obfuscate_pointer(std::uint64_t ptr) noexcept {
        std::uint64_t key = mix_entropy(__rdtsc() ^ g_obfuscation_seed);
        return ptr ^ key;
    }
    
    __forceinline std::uint64_t deobfuscate_pointer(std::uint64_t obf, std::uint64_t key) noexcept {
        return obf ^ key;
    }
    
    __forceinline void anti_timing_attack() noexcept {
        std::uint64_t start = __rdtsc();
        volatile int dummy = 0;
        std::uint32_t iterations = static_cast<std::uint32_t>((start ^ g_obfuscation_seed) & 0x1F);
        for (std::uint32_t i = 0; i < iterations; ++i) {
            dummy += static_cast<int>(i);
            _mm_pause();
        }
        g_timing_accumulator += __rdtsc() - start;
        compiler_barrier();
    }
    
    __forceinline bool detect_debugger_timing() noexcept {
        std::uint64_t start = __rdtsc();
        _mm_lfence();
        volatile int x = 1;
        x += 1;
        _mm_lfence();
        std::uint64_t elapsed = __rdtsc() - start;
        return elapsed > 1000000;
    }
    
    __forceinline void scatter_execution() noexcept {
        std::uint32_t pattern = static_cast<std::uint32_t>((xorshift32() ^ __rdtsc()) & 0xF);
        switch (pattern) {
            case 0: _mm_pause(); break;
            case 1: timing_variance(); break;
            case 2: compiler_barrier(); break;
            case 3: __spoofer_noop(); break;
            case 4: _mm_pause(); _mm_pause(); break;
            case 5: anti_timing_attack(); break;
            case 6: memory_barrier(); break;
            case 7: timing_variance(); compiler_barrier(); break;
            case 8: _mm_pause(); __spoofer_noop(); break;
            case 9: { volatile int v = 0; for(int i = 0; i < 3; i++) { v += i; _mm_pause(); } } break;
            case 10: memory_barrier(); _mm_pause(); break;
            case 11: g_entropy_state[1] ^= static_cast<std::uint32_t>(__rdtsc()); break;
            case 12: compiler_barrier(); timing_variance(); break;
            case 13: { std::uint64_t t = __rdtsc(); g_last_tsc = t; } break;
            case 14: anti_timing_attack(); _mm_pause(); break;
            default: break;
        }
    }
    
    __forceinline void heavy_scatter() noexcept {
        std::uint32_t count = (xorshift32() & 0x3) + 2;
        for (std::uint32_t i = 0; i < count; i++) {
            scatter_execution();
        }
    }
}

namespace stack_spoof {
    inline std::uint8_t* g_ntdll_gadget = nullptr;
    inline volatile bool g_gadget_found = false;
    
    __forceinline void find_gadget() {
        if (g_gadget_found) return;
        
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return;
        
        std::uint8_t* base = reinterpret_cast<std::uint8_t*>(ntdll);
        PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        
        PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        
        std::uint8_t* text = base + nt->OptionalHeader.BaseOfCode;
        std::uint32_t text_size = nt->OptionalHeader.SizeOfCode;
        
        for (std::uint32_t i = 0; i < text_size - 2; i++) {
            if (text[i] == 0xFF && text[i + 1] == 0xE3) {
                g_ntdll_gadget = &text[i];
                g_gadget_found = true;
                return;
            }
            if (text[i] == 0xFF && text[i + 1] == 0x23) {
                g_ntdll_gadget = &text[i];
                g_gadget_found = true;
                return;
            }
        }
    }
    
    __forceinline std::uint64_t get_spoof_gadget() {
        if (!g_gadget_found) find_gadget();
        return reinterpret_cast<std::uint64_t>(g_ntdll_gadget);
    }
}

#define SPOOF_FUNC do { \
    ::spoofer::init_stack_cookie(); \
    ::spoofer::__spoofer_noop(); \
    ::spoofer::scatter_execution(); \
    ::stack_spoof::find_gadget(); \
} while(0)

#define SPOOF_PTR(ptr) ::spoofer::hide_value(ptr)

#define SPOOF_HEAVY() ::spoofer::heavy_scatter()
