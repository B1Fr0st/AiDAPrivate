#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <immintrin.h>
#include <float.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <array>
#include <bitset>

#include <openssl/evp.h>

#include "integrity.hpp"
#include "metamorphic.hpp"
#include "state.hpp"
#include "obfuscation.hpp"

namespace anti_tamper {
namespace virtualizer
{

namespace detail
{

    static constexpr uint32_t HANDLER_VARIANTS = 12;
    static constexpr uint32_t CONTEXT_SHUFFLE_INTERVAL = 64;
    static constexpr uint32_t HANDLER_POOL_SIZE = 4096;
    static constexpr uint64_t HANDLER_CRYPT_MAGIC = 0x3C6EF372FE94F82BULL;

    struct handler_pool_t;


    struct vm_continuation_t
    {
        uintptr_t   next_handler;
        uint64_t    chain_nonce;
    };


    struct context_crypt_t
    {
        uint64_t    reg_mask;
        uint64_t    flags_mask;
        uint64_t    rsp_mask;
        bool        encrypted;
    };

    struct vflags_t
    {
        uint8_t CF : 1;
        uint8_t ZF : 1;
        uint8_t SF : 1;
        uint8_t OF : 1;
        uint8_t PF : 1;
        uint8_t AF : 1;
        uint8_t _pad : 2;
    };

    struct cipher_stream_t
    {
        uint8_t  key[32];
        uint8_t  block[64];
        uint64_t feedback;
        uint64_t base_seed;
        uint32_t block_index;
        uint32_t block_pos;
    };

    struct dag_node_t
    {
        uint32_t bc_offset;
        uint32_t bc_length;
        uint64_t enter_hash;
        uint32_t next_node_a;
        uint32_t next_node_b;
        uint64_t handler_chain;
    };

    static constexpr uint32_t DAG_NODE_HALT = 0xFFFFFFFFu;
    static constexpr uint32_t DAG_NODE_INVALID = 0xFFFFFFFEu;

    static constexpr uint32_t TAINT_SEVER_RING_SIZE = 64;

    struct taint_sever_cell_t
    {
        std::atomic<uint64_t> tag;
        std::atomic<uint64_t> value;
        std::atomic<uint32_t> dirty;
        uint32_t pad;
    };

    struct vm_state_t
    {
        uint64_t regs[16];
        uint64_t rsp;
        uint64_t rip;
        vflags_t vflags;
        uint8_t* stack;
        uint32_t stack_size;
        uint8_t opcode_map[256];
        uint8_t reverse_map[256];
        uint64_t rolling_key;
        uint32_t insn_count;
        uint32_t max_insn;
        bool halted;
        cipher_stream_t stream;

        uint8_t reg_shuffle[16];
        uint8_t reg_unshuffle[16];
        uint64_t reg_xor_key;
        uint64_t handler_chain_key;
        uint64_t context_entropy;
        uint32_t shuffle_counter;


        vm_continuation_t   continuation;
        context_crypt_t     ctx_crypt;

        handler_pool_t* pool;

        uint64_t reg_keys[16];
        uint64_t fake_regs[16];
        uint8_t  fake_shuffle[16];
        uint64_t fake_decoy_key;
        uint32_t per_op_shuffle_counter;
        uint64_t last_op_result;

        uint32_t anti_emu_counter;
        uint64_t anti_emu_corruption_flags;
        uint64_t anti_emu_last_pmc;
        uint32_t anti_emu_pmc_failures;
        uint16_t anti_emu_fpu_baseline;
        uint8_t  anti_emu_misalign_seen;
        uint8_t  anti_emu_force_emulator;
        uint64_t anti_emu_handler_t0;
        uint64_t anti_emu_avg_window;
        uint32_t anti_emu_window_count;

        const dag_node_t* dag_nodes;
        uint32_t dag_nodes_size;
        uint32_t dag_node;
        uint32_t dag_cursor;
        uint32_t dag_branch_taken;
        uint32_t dag_pad;
        uint64_t dag_violation_code;
        uint64_t dag_master_key;
        taint_sever_cell_t* taint_ring;
        uint32_t taint_ring_size;
        uint32_t taint_seq;
    };

    struct vm_program_t
    {
        std::vector<uint8_t> bc;
        std::vector<dag_node_t> dag;
        uint64_t dag_master_key = 0;
    };

    enum vm_ops : uint8_t
    {
        OP_NOP = 0x00,
        OP_LOAD_IMM = 0x01,
        OP_LOAD_REG = 0x02,
        OP_STORE_REG = 0x03,
        OP_NAND = 0x04,
        OP_NOR = 0x05,
        OP_XOR = 0x06,
        OP_SHL = 0x07,
        OP_SHR = 0x08,
        OP_NOT = 0x09,
        OP_CMP = 0x0A,
        OP_JMP = 0x0B,
        OP_JZ = 0x0C,
        OP_JNZ = 0x0D,
        OP_PUSH = 0x0E,
        OP_POP = 0x0F,
        OP_HASH = 0x10,
        OP_RDTSC = 0x11,
        OP_SIPHASH = 0x12,
        OP_HALT = 0x13,
        OP_TRAP = 0x14,
        OP_VERIFY = 0x15,
        OP_ROL = 0x16,
        OP_ROR = 0x17,
        OP_LOAD_MEM = 0x18,
        OP_STORE_MEM = 0x19,
        OP_ADD = 0x1A,
        OP_SUB = 0x1B,
        OP_VM_ENTER = 0x1C,
        OP_VM_EXIT  = 0x1D,
        OP_LOAD_IMM8  = 0x1E,
        OP_LOAD_IMM16 = 0x1F,
        OP_LOAD_IMM32 = 0x20,
        OP_MUL     = 0x21,
        OP_IMUL    = 0x22,
        OP_DIV     = 0x23,
        OP_IDIV    = 0x24,
        OP_CMOV    = 0x25,
        OP_SETCC   = 0x26,
        OP_VCALL   = 0x27,
        OP_VRET    = 0x28,
        OP_JL      = 0x29,
        OP_JLE     = 0x2A,
        OP_JG      = 0x2B,
        OP_JGE     = 0x2C,
        OP_JB      = 0x2D,
        OP_JBE     = 0x2E,
        OP_JS      = 0x2F,
        OP_JO      = 0x30,
        OP_LAHF    = 0x31,
        OP_SAHF    = 0x32,
        OP_JNB     = 0x33,
        OP_JNBE    = 0x34,
        OP_VM_SPAWN = 0x35,
        OP_MAX
    };

    inline bool bcrypt_random(uint8_t* buf, uint32_t len)
    {
        return BCryptGenRandom(nullptr, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline bool sha256_oneshot(const uint8_t* data, uint32_t data_len, uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return false;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        if (BCryptHashData(hHash, const_cast<PUCHAR>(data), data_len, 0) == 0)
            ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline void cipher_stream_refill(cipher_stream_t& s)
    {
        uint8_t iv[16];
        uint32_t ctr = s.block_index;
        memcpy(iv, &ctr, 4);
        uint64_t fb_a = s.feedback ^ s.base_seed;
        uint64_t fb_b = _rotl64(s.feedback, 23) ^ _rotr64(s.base_seed, 17);
        memcpy(iv + 4, &fb_a, 8);
        uint32_t fb_b_lo = static_cast<uint32_t>(fb_b);
        memcpy(iv + 12, &fb_b_lo, 4);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            for (int i = 0; i < 64; ++i)
                s.block[i] = static_cast<uint8_t>((s.feedback >> ((i & 7) * 8)) ^ (s.base_seed >> ((i & 7) * 8)) ^ i);
        }
        else
        {
            uint8_t zeros[64] = {};
            int outlen = 0;
            if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, s.key, iv) == 1 &&
                EVP_EncryptUpdate(ctx, s.block, &outlen, zeros, 64) == 1 &&
                outlen == 64)
            {
            }
            else
            {
                for (int i = 0; i < 64; ++i)
                    s.block[i] = static_cast<uint8_t>((s.feedback >> ((i & 7) * 8)) ^ (s.base_seed >> ((i & 7) * 8)) ^ i);
            }
            EVP_CIPHER_CTX_free(ctx);
        }
        s.block_pos = 0;
        s.block_index += 1;
    }

    inline void cipher_stream_init(cipher_stream_t& s, uint64_t seed)
    {
        memset(&s, 0, sizeof(s));
        s.base_seed = seed;
        s.feedback  = seed ^ 0x9E3779B97F4A7C15ULL;

        uint8_t key_input[24];
        memcpy(key_input, &seed, 8);
        static const uint8_t key_label[16] = {
            'a','i','d','a','_','v','m','_','s','t','r','m','_','k','e','y'
        };
        memcpy(key_input + 8, key_label, 16);
        sha256_oneshot(key_input, sizeof(key_input), s.key);

        s.block_index = 0;
        s.block_pos   = 64;

        SecureZeroMemory(key_input, sizeof(key_input));
    }

    __forceinline uint8_t cipher_stream_xcrypt(cipher_stream_t& s, uint8_t in_byte, bool encrypt_dir)
    {
        if (s.block_pos >= 64)
            cipher_stream_refill(s);
        uint8_t ks = s.block[s.block_pos++];
        uint8_t out_byte = static_cast<uint8_t>(in_byte ^ ks);
        uint8_t plaintext_byte = encrypt_dir ? in_byte : out_byte;
        s.feedback = _rotl64(s.feedback, 13)
                     ^ static_cast<uint64_t>(plaintext_byte)
                     ^ (static_cast<uint64_t>(ks) << 32)
                     ^ (static_cast<uint64_t>(s.block_index) * 0x9E3779B97F4A7C15ULL);
        return out_byte;
    }

    struct cpu_caps_t
    {
        bool has_rdseed;
        bool has_rdrand;
        uint32_t cpuid7_ebx;
        uint32_t cpuid7_ecx;
        uint32_t cpuid7_edx;
        uint32_t cpuid1_ecx;
        bool initialized;
    };

    inline cpu_caps_t& get_cpu_caps()
    {
        static cpu_caps_t c{};
        if (!c.initialized)
        {
            int regs[4] = { 0, 0, 0, 0 };
            __cpuid(regs, 0);
            int max_basic = regs[0];

            __cpuid(regs, 1);
            c.cpuid1_ecx = static_cast<uint32_t>(regs[2]);
            c.has_rdrand = (c.cpuid1_ecx & (1u << 30)) != 0;

            if (max_basic >= 7)
            {
                __cpuidex(regs, 7, 0);
                c.cpuid7_ebx = static_cast<uint32_t>(regs[1]);
                c.cpuid7_ecx = static_cast<uint32_t>(regs[2]);
                c.cpuid7_edx = static_cast<uint32_t>(regs[3]);
                c.has_rdseed = (c.cpuid7_ebx & (1u << 18)) != 0;
            }
            c.initialized = true;
        }
        return c;
    }

    __forceinline bool try_rdseed64(uint64_t& out)
    {
        const cpu_caps_t& caps = get_cpu_caps();
        if (!caps.has_rdseed) return false;
        unsigned __int64 v = 0;
        for (int attempt = 0; attempt < 32; ++attempt)
        {
            if (_rdseed64_step(&v))
            {
                out = static_cast<uint64_t>(v);
                return true;
            }
        }
        return false;
    }

    __forceinline bool try_rdrand64(uint64_t& out)
    {
        const cpu_caps_t& caps = get_cpu_caps();
        if (!caps.has_rdrand) return false;
        unsigned __int64 v = 0;
        for (int attempt = 0; attempt < 32; ++attempt)
        {
            if (_rdrand64_step(&v))
            {
                out = static_cast<uint64_t>(v);
                return true;
            }
        }
        return false;
    }

    struct runtime_seed_t
    {
        uint8_t bytes[32];
        std::atomic<bool> ready;
        std::mutex init_mtx;
    };

    inline runtime_seed_t& get_runtime_seed_state()
    {
        static runtime_seed_t s{};
        return s;
    }

    inline const uint8_t* runtime_master_seed()
    {
        runtime_seed_t& s = get_runtime_seed_state();
        if (s.ready.load(std::memory_order_acquire))
            return s.bytes;

        std::lock_guard<std::mutex> lk(s.init_mtx);
        if (s.ready.load(std::memory_order_relaxed))
            return s.bytes;

        uint8_t pool[192];
        memset(pool, 0, sizeof(pool));
        uint32_t off = 0;

        uint64_t rs_val = 0;
        if (try_rdseed64(rs_val))
        {
            memcpy(pool + off, &rs_val, 8); off += 8;
        }
        uint64_t rs_val2 = 0;
        if (try_rdseed64(rs_val2))
        {
            memcpy(pool + off, &rs_val2, 8); off += 8;
        }

        uint64_t rr_val = 0;
        if (try_rdrand64(rr_val))
        {
            memcpy(pool + off, &rr_val, 8); off += 8;
        }
        uint64_t rr_val2 = 0;
        if (try_rdrand64(rr_val2))
        {
            memcpy(pool + off, &rr_val2, 8); off += 8;
        }

        cpu_caps_t& caps = get_cpu_caps();
        memcpy(pool + off, &caps.cpuid7_ebx, 4); off += 4;
        memcpy(pool + off, &caps.cpuid7_ecx, 4); off += 4;
        memcpy(pool + off, &caps.cpuid7_edx, 4); off += 4;
        memcpy(pool + off, &caps.cpuid1_ecx, 4); off += 4;

        ULONGLONG tick = GetTickCount64();
        memcpy(pool + off, &tick, 8); off += 8;
        LARGE_INTEGER perf_now;
        perf_now.QuadPart = 0;
        QueryPerformanceCounter(&perf_now);
        memcpy(pool + off, &perf_now.QuadPart, 8); off += 8;

        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        memcpy(pool + off, &pid, 4); off += 4;
        memcpy(pool + off, &tid, 4); off += 4;

        uint64_t tsc_a = __rdtsc();
        memcpy(pool + off, &tsc_a, 8); off += 8;
        uint64_t tsc_b = __rdtsc();
        memcpy(pool + off, &tsc_b, 8); off += 8;

        uint8_t bcrypt_buf[32];
        memset(bcrypt_buf, 0, sizeof(bcrypt_buf));
        if (bcrypt_random(bcrypt_buf, 32))
        {
            memcpy(pool + off, bcrypt_buf, 32);
            off += 32;
        }

        uintptr_t self_addr = reinterpret_cast<uintptr_t>(&runtime_master_seed);
        memcpy(pool + off, &self_addr, sizeof(self_addr));
        off += static_cast<uint32_t>(sizeof(self_addr));

        uintptr_t stack_var = reinterpret_cast<uintptr_t>(&pool);
        memcpy(pool + off, &stack_var, sizeof(stack_var));
        off += static_cast<uint32_t>(sizeof(stack_var));

        uint8_t digest[32];
        if (!sha256_oneshot(pool, off, digest))
        {
            uint64_t fb_a = __rdtsc() ^ static_cast<uint64_t>(pid) ^ static_cast<uint64_t>(tick);
            uint64_t fb_b = static_cast<uint64_t>(perf_now.QuadPart) ^ self_addr;
            memcpy(digest, &fb_a, 8);
            memcpy(digest + 8, &fb_b, 8);
            memcpy(digest + 16, bcrypt_buf, 16);
        }

        memcpy(s.bytes, digest, 32);
        SecureZeroMemory(pool, sizeof(pool));
        SecureZeroMemory(bcrypt_buf, sizeof(bcrypt_buf));
        SecureZeroMemory(digest, sizeof(digest));

        s.ready.store(true, std::memory_order_release);
        return s.bytes;
    }

    inline uint64_t runtime_seed_qword(uint32_t lane)
    {
        const uint8_t* m = runtime_master_seed();
        uint64_t v;
        memcpy(&v, m + ((lane & 3) * 8), 8);
        return v;
    }

    inline bool hmac_sha256(const uint8_t* key, uint32_t key_len,
                            const uint8_t* data, uint32_t data_len,
                            uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                        nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return false;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                             const_cast<PUCHAR>(key), key_len, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        if (BCryptHashData(hHash, const_cast<PUCHAR>(data), data_len, 0) == 0)
            ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline void hkdf_expand_sha256(const uint8_t prk[32], const uint8_t* info,
                                    uint32_t info_len, uint8_t* okm, uint32_t okm_len)
    {
        uint8_t t[32] = {};
        uint32_t t_len = 0;
        uint8_t counter = 1;
        uint32_t pos = 0;
        while (pos < okm_len)
        {
            uint32_t input_len = t_len + info_len + 1;
            auto* input = static_cast<uint8_t*>(_alloca(input_len));
            if (t_len > 0) memcpy(input, t, t_len);
            memcpy(input + t_len, info, info_len);
            input[t_len + info_len] = counter;
            hmac_sha256(prk, 32, input, input_len, t);
            t_len = 32;
            uint32_t copy = (okm_len - pos < 32) ? (okm_len - pos) : 32;
            memcpy(okm + pos, t, copy);
            pos += copy;
            counter++;
        }
    }

    inline std::array<uint8_t, 256> derive_function_opcode_map(
        uint32_t func_rva, const uint8_t master_key[32])
    {
        const uint8_t* rt_seed = runtime_master_seed();

        uint8_t mixed_key[32];
        for (int i = 0; i < 32; ++i)
            mixed_key[i] = master_key[i] ^ rt_seed[i];

        uint8_t input[40];
        memcpy(input, &func_rva, 4);
        memcpy(input + 4, rt_seed, 32);
        uint64_t pid_q = static_cast<uint64_t>(GetCurrentProcessId());
        memcpy(input + 36, &pid_q, 4);

        uint8_t prk[32];
        hmac_sha256(mixed_key, 32, input, 40, prk);

        static const uint8_t info[16] = {
            'a','i','d','a','_','v','m','_','o','p','m','p','_','r','t','1'
        };
        uint8_t okm[256];
        hkdf_expand_sha256(prk, info, 16, okm, 256);

        std::array<uint8_t, 256> map{};
        for (int i = 0; i < 256; ++i)
            map[i] = static_cast<uint8_t>(i);

        for (int i = 255; i > 0; --i)
        {
            uint32_t j = static_cast<uint32_t>(okm[i]) % static_cast<uint32_t>(i + 1);
            uint8_t tmp = map[i];
            map[i] = map[j];
            map[j] = tmp;
        }

        SecureZeroMemory(prk, 32);
        SecureZeroMemory(okm, 256);
        SecureZeroMemory(mixed_key, 32);
        SecureZeroMemory(input, 40);
        return map;
    }

    inline void derive_function_maps(uint32_t func_rva, const uint8_t master_key[32],
                                     uint8_t opcode_map[256], uint8_t reverse_map[256])
    {
        auto m = derive_function_opcode_map(func_rva, master_key);
        for (int i = 0; i < 256; ++i)
        {
            opcode_map[i] = m[i];
            reverse_map[m[i]] = static_cast<uint8_t>(i);
        }
    }

    inline uint64_t secure_seed()
    {
        uint8_t buf[32];
        if (!bcrypt_random(buf, 32))
            return __rdtsc() ^ GetCurrentProcessId();
        uint64_t seed;
        memcpy(&seed, buf, 8);
        uint64_t mix;
        memcpy(&mix, buf + 8, 8);
        seed ^= mix;
        memcpy(&mix, buf + 16, 8);
        seed ^= _rotl64(mix, 17);
        memcpy(&mix, buf + 24, 8);
        seed ^= _rotr64(mix, 23);
        SecureZeroMemory(buf, 32);
        return seed;
    }

    using handler_fn = void(*)(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size);

    struct handler_slot_t
    {
        handler_fn  fn;
        uint64_t    encrypted_next;
        uint64_t    decrypt_key;
        uint8_t     variant_id;
        bool        is_decrypted;
    };

    struct poly_dispatch_t
    {
        handler_fn variants[4];
        uint8_t    count;
    };

    struct handler_set_t
    {
        uint8_t     variant_order[256][4];
        uint8_t     variant_count[256];
        uint64_t    dispatch_xor_table[256];
        uint64_t    dispatch_hmac_key[4];
        uint64_t    uf_table[64];
        uint32_t    crc_accumulator;
        uint32_t    set_generation;
        bool        initialized;
    };

    struct handler_pool_t
    {
        handler_slot_t   slots[HANDLER_POOL_SIZE];
        poly_dispatch_t  poly_table[256];
        handler_fn       dispatch_table[256];
        uint32_t         active_slots;
        uint32_t         regen_counter;
        uint64_t         pool_guard;
        bool             poly_initialized;
        uint8_t          opcode_map[256];
        uint8_t          reverse_map[256];
        uint64_t         pool_seed;
        uint32_t         generation;
        uint32_t         child_pool_count;
        handler_pool_t*  child_pools[8];
        std::unordered_map<uint32_t, uint32_t>* hot_block_counts;
        handler_set_t    handler_set;
    };

    inline handler_pool_t g_default_pool{};

    inline auto& g_handler_pool    = g_default_pool.slots;
    inline auto& g_active_slots    = g_default_pool.active_slots;
    inline auto& g_pool_guard      = g_default_pool.pool_guard;
    inline auto& g_dispatch_table  = g_default_pool.dispatch_table;
    inline auto& g_poly_initialized = g_default_pool.poly_initialized;
    inline auto& g_poly_table      = g_default_pool.poly_table;

    using jit_hook_fn = bool(*)(vm_state_t&, const uint8_t*, uint32_t);
    inline jit_hook_fn g_jit_hook = nullptr;

    inline bool verify_handler_pool();
    inline bool verify_handler_pool(handler_pool_t& pool);
    inline void build_handler_pool(const uint8_t* reverse_map, uint64_t pool_seed);
    inline void build_handler_pool(handler_pool_t& pool, const uint8_t* reverse_map, uint64_t pool_seed);
    inline void build_poly_table();
    inline void build_poly_table(handler_pool_t& pool);
    inline void build_handler_set(handler_pool_t& pool);
    __forceinline handler_fn resolve_dispatch(vm_state_t& vm, uint8_t opcode);
    __forceinline handler_fn select_handler(vm_state_t& vm, uint8_t opcode);
    inline void init_vm(vm_state_t& vm, uint64_t seed);
    inline uint64_t vm_execute(vm_state_t& vm, const uint8_t* bytecode, uint32_t bc_size);
    inline void destroy_vm(vm_state_t& vm);

    inline uint64_t xorshift_advance(uint64_t& state)
    {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }

#pragma region oblivious_register_file

    inline void derive_register_keys(vm_state_t& vm, uint64_t seed)
    {
        uint8_t prk_input[24];
        memcpy(prk_input, &seed, 8);
        uint64_t pid_mix = static_cast<uint64_t>(GetCurrentProcessId())
            ^ static_cast<uint64_t>(GetCurrentThreadId()) * 0x9E3779B97F4A7C15ULL;
        memcpy(prk_input + 8, &pid_mix, 8);
        memcpy(prk_input + 16, &vm.context_entropy, 8);

        uint8_t prk[32];
        hmac_sha256(state::g_vm_master_key, 32, prk_input, sizeof(prk_input), prk);

        static const uint8_t info[14] = {
            'a','i','d','a','_','v','m','_','r','e','g','k','e','y'
        };
        uint8_t okm[128];
        hkdf_expand_sha256(prk, info, 14, okm, 128);

        for (int i = 0; i < 16; ++i)
        {
            uint64_t k;
            memcpy(&k, okm + i * 8, 8);
            vm.reg_keys[i] = k;
        }

        SecureZeroMemory(prk, sizeof(prk));
        SecureZeroMemory(okm, sizeof(okm));
        SecureZeroMemory(prk_input, sizeof(prk_input));
    }

    inline void rebuild_fake_register_layout(vm_state_t& vm, uint64_t entropy)
    {
        for (int i = 0; i < 16; ++i)
            vm.fake_shuffle[i] = static_cast<uint8_t>(i);

        uint64_t state = entropy;
        for (int i = 15; i > 0; --i)
        {
            xorshift_advance(state);
            int j = static_cast<int>(state % (i + 1));
            uint8_t tmp = vm.fake_shuffle[i];
            vm.fake_shuffle[i] = vm.fake_shuffle[j];
            vm.fake_shuffle[j] = tmp;
        }

        for (int i = 0; i < 16; ++i)
        {
            xorshift_advance(state);
            vm.fake_regs[i] = state;
        }

        vm.fake_decoy_key = state ^ 0xC8E5C123F11A4D9DULL;
    }

    inline void shuffle_registers(vm_state_t& vm)
    {
        uint64_t entropy = secure_seed() ^ vm.context_entropy;

        uint64_t old_xor = vm.reg_xor_key;
        for (int i = 0; i < 16; ++i)
        {
            vm.regs[i] ^= old_xor;
            vm.regs[i] ^= vm.reg_keys[i];
        }

        for (int i = 0; i < 16; ++i)
            vm.reg_shuffle[i] = static_cast<uint8_t>(i);

        uint64_t state = entropy;
        for (int i = 15; i > 0; --i)
        {
            xorshift_advance(state);
            int j = static_cast<int>(state % (i + 1));
            uint8_t tmp = vm.reg_shuffle[i];
            vm.reg_shuffle[i] = vm.reg_shuffle[j];
            vm.reg_shuffle[j] = tmp;
        }

        for (int i = 0; i < 16; ++i)
            vm.reg_unshuffle[vm.reg_shuffle[i]] = static_cast<uint8_t>(i);

        xorshift_advance(entropy);
        vm.reg_xor_key = entropy;
        vm.context_entropy = entropy;

        derive_register_keys(vm, entropy ^ vm.handler_chain_key);

        for (int i = 0; i < 16; ++i)
        {
            vm.regs[i] ^= vm.reg_xor_key;
            vm.regs[i] ^= vm.reg_keys[i];
        }

        rebuild_fake_register_layout(vm, entropy ^ 0x6C078965FAB89E11ULL);

        vm.shuffle_counter = 0;
    }

    __forceinline uint64_t read_vreg(vm_state_t& vm, uint8_t logical)
    {
        uint8_t phys = vm.reg_shuffle[logical & 0x0F];
        return vm.regs[phys] ^ vm.reg_xor_key ^ vm.reg_keys[phys];
    }

    __forceinline void dummy_register_write(vm_state_t& vm, uint8_t logical, uint64_t val)
    {
        uint8_t target = vm.fake_shuffle[(logical ^ static_cast<uint8_t>(val & 0x0F)) & 0x0F];
        uint64_t mixed = val
            ^ vm.fake_decoy_key
            ^ (static_cast<uint64_t>(logical) * 0xBF58476D1CE4E5B9ULL)
            ^ _rotl64(vm.last_op_result, (logical & 0x3F));
        vm.fake_regs[target] = mixed;
    }

    __forceinline void write_vreg(vm_state_t& vm, uint8_t logical, uint64_t val)
    {
        uint8_t phys = vm.reg_shuffle[logical & 0x0F];
        vm.regs[phys] = val ^ vm.reg_xor_key ^ vm.reg_keys[phys];
        dummy_register_write(vm, logical, val);
        vm.last_op_result = val;
    }

    __forceinline void mutate_shuffle_per_op(vm_state_t& vm, uint8_t opcode, uint64_t result)
    {
        vm.last_op_result = result;
        uint32_t mix = (static_cast<uint32_t>(opcode) + static_cast<uint32_t>(result & 0xFFFFFFFFu)) & 0x0F;
        uint32_t partner = (mix + 1u + (static_cast<uint32_t>(result >> 56) & 0x0F)) & 0x0F;
        if (mix == partner) partner = (partner + 1u) & 0x0F;

        uint8_t a_logical = static_cast<uint8_t>(mix);
        uint8_t b_logical = static_cast<uint8_t>(partner);
        uint8_t a_phys = vm.reg_shuffle[a_logical];
        uint8_t b_phys = vm.reg_shuffle[b_logical];

        if (a_phys == b_phys) return;

        uint64_t va = vm.regs[a_phys] ^ vm.reg_xor_key ^ vm.reg_keys[a_phys];
        uint64_t vb = vm.regs[b_phys] ^ vm.reg_xor_key ^ vm.reg_keys[b_phys];

        vm.reg_shuffle[a_logical] = b_phys;
        vm.reg_shuffle[b_logical] = a_phys;
        vm.reg_unshuffle[a_phys] = b_logical;
        vm.reg_unshuffle[b_phys] = a_logical;

        vm.regs[b_phys] = va ^ vm.reg_xor_key ^ vm.reg_keys[b_phys];
        vm.regs[a_phys] = vb ^ vm.reg_xor_key ^ vm.reg_keys[a_phys];

        ++vm.per_op_shuffle_counter;
    }

    inline void linearize_register_file(vm_state_t& vm, uint64_t saved_keys[16])
    {
        uint64_t plain[16];
        for (int i = 0; i < 16; ++i)
            plain[i] = vm.regs[i] ^ vm.reg_xor_key ^ vm.reg_keys[i];

        uint64_t laid_out[16];
        for (int i = 0; i < 16; ++i)
            laid_out[i] = plain[vm.reg_shuffle[i]];

        for (int i = 0; i < 16; ++i)
        {
            saved_keys[i] = vm.reg_keys[i];
            vm.regs[i] = laid_out[i];
            vm.reg_keys[i] = 0;
        }

        vm.reg_xor_key = 0;
        for (int i = 0; i < 16; ++i)
        {
            vm.reg_shuffle[i] = static_cast<uint8_t>(i);
            vm.reg_unshuffle[i] = static_cast<uint8_t>(i);
        }

        SecureZeroMemory(plain, sizeof(plain));
        SecureZeroMemory(laid_out, sizeof(laid_out));
    }

    inline void delinearize_register_file(vm_state_t& vm, const uint64_t saved_keys[16], uint64_t fresh_xor)
    {
        uint64_t plain[16];
        for (int i = 0; i < 16; ++i)
            plain[i] = vm.regs[i];

        for (int i = 0; i < 16; ++i)
            vm.reg_keys[i] = saved_keys[i];

        vm.reg_xor_key = fresh_xor;

        for (int i = 0; i < 16; ++i)
            vm.regs[i] = plain[i] ^ vm.reg_xor_key ^ vm.reg_keys[i];

        SecureZeroMemory(plain, sizeof(plain));
    }

#pragma endregion

    inline void generate_opcode_map(uint64_t seed, uint8_t* map, uint8_t* reverse)
    {
        for (int i = 0; i < 256; ++i)
            map[i] = static_cast<uint8_t>(i);

        uint64_t state = seed;
        for (int i = 255; i > 0; --i)
        {
            xorshift_advance(state);
            int j = static_cast<int>(state % (i + 1));
            uint8_t tmp = map[i];
            map[i] = map[j];
            map[j] = tmp;
        }

        for (int i = 0; i < 256; ++i)
            reverse[map[i]] = static_cast<uint8_t>(i);
    }

    inline void advance_rolling_key(vm_state_t& vm)
    {
        vm.rolling_key = _rotl64(vm.rolling_key, 13)
                         ^ static_cast<uint64_t>(vm.stream.feedback)
                         ^ static_cast<uint64_t>(vm.stream.block_index);
    }

    inline uint8_t decrypt_byte(vm_state_t& vm, uint8_t raw)
    {
        return cipher_stream_xcrypt(vm.stream, raw, false);
    }

    __forceinline uint64_t dag_state_hash(uint64_t dag_master_key, uint64_t node_index,
                                          uint64_t handler_chain)
    {
        uint64_t v0 = dag_master_key ^ 0x736F6D6570736575ULL;
        uint64_t v1 = node_index ^ 0x646F72616E646F6DULL;
        uint64_t v2 = handler_chain ^ 0x6C7967656E657261ULL;
        uint64_t v3 = (dag_master_key ^ handler_chain) ^ 0x7465646279746573ULL;

        uint64_t lanes[4] = { dag_master_key, node_index, handler_chain,
                              dag_master_key ^ handler_chain };
        for (int i = 0; i < 4; ++i)
        {
            v3 ^= lanes[i];
            v0 += v1; v1 = _rotl64(v1, 13); v1 ^= v0; v0 = _rotl64(v0, 32);
            v2 += v3; v3 = _rotl64(v3, 16); v3 ^= v2;
            v0 += v3; v3 = _rotl64(v3, 21); v3 ^= v0;
            v2 += v1; v1 = _rotl64(v1, 17); v1 ^= v2; v2 = _rotl64(v2, 32);
            v0 ^= lanes[i];
        }
        v2 ^= 0xFF;
        for (int i = 0; i < 4; ++i)
        {
            v0 += v1; v1 = _rotl64(v1, 13); v1 ^= v0; v0 = _rotl64(v0, 32);
            v2 += v3; v3 = _rotl64(v3, 16); v3 ^= v2;
            v0 += v3; v3 = _rotl64(v3, 21); v3 ^= v0;
            v2 += v1; v1 = _rotl64(v1, 17); v1 ^= v2; v2 = _rotl64(v2, 32);
        }
        return v0 ^ v1 ^ v2 ^ v3;
    }

    __forceinline uint64_t dag_compute_state_hash(const vm_state_t& vm, uint64_t handler_chain)
    {
        return dag_state_hash(vm.dag_master_key,
                              static_cast<uint64_t>(vm.dag_node),
                              handler_chain);
    }

    __forceinline bool dag_taint_store(vm_state_t& vm, uint8_t logical, uint64_t value)
    {
        if (!vm.taint_ring || vm.taint_ring_size == 0) return false;
        uint32_t idx = (vm.taint_seq + (logical & 0x0F)) % vm.taint_ring_size;
        uint64_t tag = (static_cast<uint64_t>(logical) << 56)
                     ^ (static_cast<uint64_t>(vm.taint_seq) * 0x9E3779B97F4A7C15ULL)
                     ^ vm.handler_chain_key;
        taint_sever_cell_t& cell = vm.taint_ring[idx];
        cell.tag.store(tag, std::memory_order_release);
        cell.value.store(value, std::memory_order_release);
        cell.dirty.store(1, std::memory_order_release);
        ++vm.taint_seq;
        SwitchToThread();
        return true;
    }

    __forceinline bool dag_taint_load(vm_state_t& vm, uint8_t logical, uint64_t& out_value)
    {
        if (!vm.taint_ring || vm.taint_ring_size == 0) return false;
        bool found = false;
        uint64_t latest_tag = 0;
        for (uint32_t i = 0; i < vm.taint_ring_size; ++i)
        {
            taint_sever_cell_t& cell = vm.taint_ring[i];
            if (cell.dirty.load(std::memory_order_acquire) == 0) continue;
            uint64_t tag = cell.tag.load(std::memory_order_acquire);
            uint8_t cell_logical = static_cast<uint8_t>((tag >> 56) & 0x0F);
            if (cell_logical != (logical & 0x0F)) continue;
            if (!found || tag > latest_tag)
            {
                out_value = cell.value.load(std::memory_order_acquire);
                latest_tag = tag;
                found = true;
            }
        }
        return found;
    }

    inline uint32_t dag_find_node_for_offset(const dag_node_t* nodes, uint32_t nodes_size,
                                             uint32_t bc_offset)
    {
        for (uint32_t i = 0; i < nodes_size; ++i)
        {
            if (nodes[i].bc_offset == bc_offset)
                return i;
        }
        return DAG_NODE_INVALID;
    }

    __forceinline bool dag_active(const vm_state_t& vm)
    {
        return vm.dag_nodes != nullptr && vm.dag_nodes_size > 0;
    }

    __forceinline bool dag_advance_to_offset(vm_state_t& vm, uint32_t target_offset)
    {
        uint32_t idx = dag_find_node_for_offset(vm.dag_nodes, vm.dag_nodes_size, target_offset);
        if (idx == DAG_NODE_INVALID)
        {
            vm.halted = true;
            vm.dag_node = DAG_NODE_HALT;
            return false;
        }
        vm.dag_node = idx;
        vm.dag_cursor = 0;
        vm.rip = target_offset;
        return true;
    }

    inline uint8_t fetch_byte(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {
        if (dag_active(vm))
        {
            if (vm.dag_node >= vm.dag_nodes_size) { vm.halted = true; return 0; }
            const dag_node_t& node = vm.dag_nodes[vm.dag_node];
            if (vm.dag_cursor >= node.bc_length) { vm.halted = true; return 0; }
            uint32_t bc_pos = node.bc_offset + vm.dag_cursor;
            if (bc_pos >= bc_size) { vm.halted = true; return 0; }
            uint8_t raw = bc[bc_pos];
            ++vm.dag_cursor;
            vm.rip = bc_pos + 1;
            return decrypt_byte(vm, raw);
        }
        if (vm.rip >= bc_size) { vm.halted = true; return 0; }
        return decrypt_byte(vm, bc[vm.rip++]);
    }

    inline uint64_t fetch_u64(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {
        uint8_t buf[8];
        for (int i = 0; i < 8; ++i)
            buf[i] = fetch_byte(vm, bc, bc_size);
        uint64_t val;
        memcpy(&val, buf, 8);
        return val;
    }

    inline uint32_t fetch_u32(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {
        uint8_t buf[4];
        for (int i = 0; i < 4; ++i)
            buf[i] = fetch_byte(vm, bc, bc_size);
        uint32_t val;
        memcpy(&val, buf, 4);
        return val;
    }

    __forceinline uint64_t nand_op(uint64_t a, uint64_t b) { return ~(a & b); }
    __forceinline uint64_t nor_op(uint64_t a, uint64_t b)  { return ~(a | b); }

    __forceinline uint64_t micro_add(uint64_t a, uint64_t b)
    {

        uint64_t sel = __rdtsc();
        if (sel & 2)
            return metamorphic::mba::keyed_add(a, b, sel);

        uint64_t carry;
        uint64_t result = a;
        uint64_t operand = b;
        for (int i = 0; i < 64; ++i)
        {
            carry = nand_op(nand_op(result, operand), nand_op(result, operand));
            carry = nand_op(~carry, ~carry);
            uint64_t xor_ab = nand_op(nand_op(result, nand_op(result, operand)),
                                       nand_op(operand, nand_op(result, operand)));
            result = xor_ab;
            operand = carry << 1;
            if (operand == 0) break;
        }
        return result;
    }

    __forceinline uint64_t micro_sub(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 4)
        {

            uint64_t neg_b = metamorphic::mba::keyed_add(~b, 1, sel);
            return metamorphic::mba::keyed_add(a, neg_b, sel ^ 0xDEAD);
        }
        return micro_add(a, micro_add(~b, 1));
    }

    __forceinline uint64_t micro_and(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 8)
            return metamorphic::mba::keyed_and(a, b, sel);
        return nand_op(nand_op(a, b), nand_op(a, b));
    }

    __forceinline uint64_t micro_or(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 16)
            return metamorphic::mba::keyed_or(a, b, sel);
        return nand_op(nand_op(a, a), nand_op(b, b));
    }

    __forceinline uint64_t micro_mul(uint64_t a, uint64_t b)
    {
        uint64_t result = 0;
        uint64_t multiplicand = a;
        uint64_t multiplier = b;
        while (multiplier != 0)
        {
            if (multiplier & 1)
                result = micro_add(result, multiplicand);
            multiplicand <<= 1;
            multiplier >>= 1;
        }
        return result;
    }

    __forceinline uint64_t micro_xor(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 32)
            return metamorphic::mba::keyed_xor(a, b, sel);
        uint64_t nand_ab = nand_op(a, b);
        return nand_op(nand_op(a, nand_ab), nand_op(b, nand_ab));
    }

    __forceinline uint64_t handler_entropy_bit(vm_state_t& vm, uint8_t tag)
    {
        uint64_t e = vm.context_entropy;
        e ^= static_cast<uint64_t>(tag) * 0x9E3779B97F4A7C15ULL;
        e ^= vm.handler_chain_key * 0xBF58476D1CE4E5B9ULL;
        e ^= vm.rolling_key;
        e ^= e >> 33;
        e *= 0xFF51AFD7ED558CCDULL;
        e ^= e >> 33;
        return e;
    }

    __forceinline uint64_t bswap_identity(uint64_t v)
    {
        return _byteswap_uint64(_byteswap_uint64(v));
    }

    __forceinline uint64_t uf_shadow_lookup(vm_state_t& vm, uint64_t mix)
    {
        handler_pool_t& pool = vm.pool ? *vm.pool : g_default_pool;
        if (!pool.handler_set.initialized)
            return 0;
        uint8_t idx = static_cast<uint8_t>(mix & 0x3F);
        uint64_t v = pool.handler_set.uf_table[idx];
        return v ^ v;
    }

    __forceinline void crc_accumulate(vm_state_t& vm, uint64_t mix)
    {
        handler_pool_t& pool = vm.pool ? *vm.pool : g_default_pool;
        if (!pool.handler_set.initialized) return;
        uint32_t lo = static_cast<uint32_t>(mix);
        uint32_t hi = static_cast<uint32_t>(mix >> 32);
        uint32_t prev = pool.handler_set.crc_accumulator;
        prev = _mm_crc32_u32(prev, lo);
        prev = _mm_crc32_u32(prev, hi);
        pool.handler_set.crc_accumulator = prev;
    }

    __forceinline uint64_t triton_break_inject(vm_state_t& vm, uint64_t value, uint8_t tag)
    {
        uint64_t entropy = handler_entropy_bit(vm, tag);
        uint64_t out = bswap_identity(value);
        uint64_t mask = (entropy >> 11) & 3;
        switch (mask)
        {
        case 0:
        {
            uint64_t shadow = uf_shadow_lookup(vm, entropy);
            out ^= shadow;
            break;
        }
        case 1:
            crc_accumulate(vm, entropy ^ value);
            break;
        case 2:
        {
            uint64_t z = entropy ^ entropy;
            out ^= z;
            crc_accumulate(vm, value);
            break;
        }
        default:
            out = bswap_identity(out);
            break;
        }
        return out;
    }

    __forceinline uint64_t mba_add(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t form = (entropy >> 7) & 3;
        switch (form)
        {
        case 0: return (a ^ b) + ((a & b) << 1);
        case 1: return (a | b) + (a & b);
        case 2: {
            uint64_t na = ~a;
            uint64_t nb = ~b;
            uint64_t and_ab = a & b;
            uint64_t nand_ab = ~(na & nb);
            return nand_ab + and_ab;
        }
        default:
            return metamorphic::mba::keyed_add_dynamic(a, b, entropy);
        }
    }

    __forceinline uint64_t mba_sub(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t form = (entropy >> 9) & 3;
        switch (form)
        {
        case 0: return a + ((~b) + 1);
        case 1: {
            uint64_t neg_b = ~b;
            return (a ^ neg_b) + ((a & neg_b) << 1) + 1;
        }
        case 2:
            return metamorphic::mba::keyed_add_dynamic(a, (~b) + 1, entropy);
        default:
            return a - b;
        }
    }

    __forceinline uint64_t mba_xor(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t form = (entropy >> 5) & 3;
        switch (form)
        {
        case 0: return (a | b) - (a & b);
        case 1: return (a & ~b) | (~a & b);
        case 2: return (a + b) - ((a & b) << 1);
        default:
            return metamorphic::mba::keyed_xor_dynamic(a, b, entropy);
        }
    }

    __forceinline uint64_t mba_and(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t form = (entropy >> 3) & 3;
        switch (form)
        {
        case 0: return (a + b - (a | b));
        case 1: return ~((~a) | (~b));
        case 2: return ((a ^ b) ^ (a | b));
        default:
            return metamorphic::mba::keyed_and_dynamic(a, b, entropy);
        }
    }

    __forceinline uint64_t mba_or(uint64_t a, uint64_t b, uint64_t entropy)
    {
        uint64_t form = (entropy >> 13) & 3;
        switch (form)
        {
        case 0: return (a + b) - (a & b);
        case 1: return ~((~a) & (~b));
        case 2: return (a ^ b) + (a & b);
        default:
            return metamorphic::mba::keyed_or(a, b, entropy);
        }
    }

    __forceinline uint64_t mba_not(uint64_t a, uint64_t entropy)
    {
        uint64_t form = (entropy >> 17) & 3;
        switch (form)
        {
        case 0: return a ^ 0xFFFFFFFFFFFFFFFFULL;
        case 1: return (0 - a) - 1;
        case 2: {
            uint64_t z = (a & a) ^ a;
            return ~a ^ z;
        }
        default:
            return metamorphic::mba::keyed_not(a, entropy);
        }
    }

    __forceinline uint64_t mba_nand(uint64_t a, uint64_t b, uint64_t entropy)
    {
        return mba_not(mba_and(a, b, entropy), entropy ^ 0xA5A5A5A5A5A5A5A5ULL);
    }

    __forceinline uint64_t mba_nor(uint64_t a, uint64_t b, uint64_t entropy)
    {
        return mba_not(mba_or(a, b, entropy), entropy ^ 0x5A5A5A5A5A5A5A5AULL);
    }

    __forceinline uint8_t compute_parity(uint64_t val)
    {
        uint8_t low = static_cast<uint8_t>(val);
        low ^= low >> 4;
        low ^= low >> 2;
        low ^= low >> 1;
        return (~low) & 1;
    }

    __forceinline void update_flags_add(vm_state_t& vm, uint64_t a, uint64_t b, uint64_t result)
    {
        vm.vflags.CF = (result < a) ? 1 : 0;
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.OF = (((a ^ result) & (b ^ result)) >> 63) & 1;
        vm.vflags.PF = compute_parity(result);
        vm.vflags.AF = (((a ^ b ^ result) >> 4) & 1);
    }

    __forceinline void update_flags_sub(vm_state_t& vm, uint64_t a, uint64_t b, uint64_t result)
    {
        vm.vflags.CF = (a < b) ? 1 : 0;
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.OF = (((a ^ b) & (a ^ result)) >> 63) & 1;
        vm.vflags.PF = compute_parity(result);
        vm.vflags.AF = (((a ^ b ^ result) >> 4) & 1);
    }

    __forceinline void update_flags_logic(vm_state_t& vm, uint64_t result)
    {
        vm.vflags.CF = 0;
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.OF = 0;
        vm.vflags.PF = compute_parity(result);
        vm.vflags.AF = 0;
    }

    __forceinline bool eval_condition(const vflags_t& f, uint8_t cc)
    {
        switch (cc & 0x0F)
        {
        case 0x00: return f.OF;
        case 0x01: return !f.OF;
        case 0x02: return f.CF;
        case 0x03: return !f.CF;
        case 0x04: return f.ZF;
        case 0x05: return !f.ZF;
        case 0x06: return f.CF || f.ZF;
        case 0x07: return !f.CF && !f.ZF;
        case 0x08: return f.SF;
        case 0x09: return !f.SF;
        case 0x0A: return f.PF;
        case 0x0B: return !f.PF;
        case 0x0C: return f.SF != f.OF;
        case 0x0D: return f.SF == f.OF;
        case 0x0E: return f.ZF || (f.SF != f.OF);
        case 0x0F: return !f.ZF && (f.SF == f.OF);
        default: return false;
        }
    }

    __forceinline uint64_t compute_handler_chain_addr(vm_state_t& vm, uint8_t opcode)
    {
        uint64_t chain = vm.handler_chain_key;
        chain ^= static_cast<uint64_t>(opcode) * 0x9E3779B97F4A7C15ULL;
        chain = _rotl64(chain, 13) ^ (chain >> 27);
        chain *= 0xBF58476D1CE4E5B9ULL;
        vm.handler_chain_key = chain;
        return chain;
    }


    __forceinline void derive_context_masks(vm_state_t& vm)
    {

        uint64_t seed = vm.handler_chain_key ^ secure_seed();
        seed ^= seed >> 30; seed *= 0xBF58476D1CE4E5B9ULL;
        seed ^= seed >> 27; seed *= 0x94D049BB133111EBULL;
        seed ^= seed >> 31;
        vm.ctx_crypt.reg_mask   = seed;
        vm.ctx_crypt.flags_mask = _rotl64(seed, 17) ^ 0x428A2F98D728AE22ULL;
        vm.ctx_crypt.rsp_mask   = _rotr64(seed, 23) ^ 0x7137449123EF65CDULL;
    }

    __forceinline void encrypt_context(vm_state_t& vm)
    {
        if (vm.ctx_crypt.encrypted) return;
        derive_context_masks(vm);
        for (int i = 0; i < 16; ++i)
            vm.regs[i] ^= _rotl64(vm.ctx_crypt.reg_mask, i * 4);
        uint8_t* fp = reinterpret_cast<uint8_t*>(&vm.vflags);
        *fp ^= static_cast<uint8_t>(vm.ctx_crypt.flags_mask & 0x3F);
        vm.rsp   ^= vm.ctx_crypt.rsp_mask;
        vm.ctx_crypt.encrypted = true;
    }

    __forceinline void decrypt_context(vm_state_t& vm)
    {
        if (!vm.ctx_crypt.encrypted) return;

        for (int i = 0; i < 16; ++i)
            vm.regs[i] ^= _rotl64(vm.ctx_crypt.reg_mask, i * 4);
        uint8_t* fp = reinterpret_cast<uint8_t*>(&vm.vflags);
        *fp ^= static_cast<uint8_t>(vm.ctx_crypt.flags_mask & 0x3F);
        vm.rsp   ^= vm.ctx_crypt.rsp_mask;
        vm.ctx_crypt.encrypted = false;
    }


    static constexpr uint32_t HANDLER_REGEN_INTERVAL = 512;
    static constexpr uint32_t VM_ANTIDEBUG_INTERVAL = 37;

    __forceinline bool vm_check_hardware_breakpoints(vm_state_t& vm)
    {
        uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr7 = 0;
        __try {
            CONTEXT ctx{};
            ctx.ContextFlags = 0x00100010;
            if (GetThreadContext(GetCurrentThread(), &ctx)) {
                dr0 = ctx.Dr0; dr1 = ctx.Dr1;
                dr2 = ctx.Dr2; dr3 = ctx.Dr3;
                dr7 = ctx.Dr7;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        if ((dr7 & 0xFF) == 0 && dr0 == 0 && dr1 == 0 && dr2 == 0 && dr3 == 0)
            return false;

        handler_pool_t& pool = vm.pool ? *vm.pool : g_default_pool;
        uintptr_t pool_lo = reinterpret_cast<uintptr_t>(&pool.slots[0]);
        uintptr_t pool_hi = pool_lo + sizeof(pool.slots);
        uintptr_t dispatch_lo = reinterpret_cast<uintptr_t>(&pool.dispatch_table[0]);
        uintptr_t dispatch_hi = dispatch_lo + sizeof(pool.dispatch_table);

        auto in_range = [&](uint64_t addr) -> bool {
            if (addr == 0) return false;
            if (addr >= pool_lo && addr < pool_hi) return true;
            if (addr >= dispatch_lo && addr < dispatch_hi) return true;
            for (uint32_t i = 0; i < pool.active_slots; ++i) {
                uintptr_t fn = reinterpret_cast<uintptr_t>(pool.slots[i].fn);
                if (addr >= fn && addr < fn + 256) return true;
            }
            return false;
        };

        if (in_range(dr0) || in_range(dr1) || in_range(dr2) || in_range(dr3)) {
            vm.rolling_key ^= 0xDEADDEADDEADDEADULL;
            vm.handler_chain_key = 0;
            for (int i = 0; i < 16; ++i) vm.regs[i] ^= __rdtsc();
            return true;
        }

        return (dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0);
    }

    __forceinline void regenerate_handlers(vm_state_t& vm)
    {
        uint64_t new_seed = vm.rolling_key ^ vm.handler_chain_key ^ secure_seed();
        new_seed ^= vm.insn_count * 0x9E3779B97F4A7C15ULL;

        handler_pool_t& pool = vm.pool ? *vm.pool : g_default_pool;
        generate_opcode_map(new_seed, vm.opcode_map, vm.reverse_map);
        memcpy(pool.opcode_map, vm.opcode_map, 256);
        memcpy(pool.reverse_map, vm.reverse_map, 256);
        build_handler_pool(pool, vm.reverse_map, new_seed ^ 0x428A2F98D728AE22ULL);

        if (pool.poly_initialized) {
            pool.poly_initialized = false;
            build_poly_table(pool);
        }

        pool.handler_set.initialized = false;
        build_handler_set(pool);

        vm.context_entropy ^= new_seed;
        pool.regen_counter++;
    }

#pragma region anti_emu_traps

    static constexpr uint64_t ANTI_EMU_FLAG_RDTSC      = 1ULL << 0;
    static constexpr uint64_t ANTI_EMU_FLAG_RDPMC      = 1ULL << 1;
    static constexpr uint64_t ANTI_EMU_FLAG_CAPABILITY = 1ULL << 2;
    static constexpr uint64_t ANTI_EMU_FLAG_FPU        = 1ULL << 3;
    static constexpr uint64_t ANTI_EMU_FLAG_MISALIGN   = 1ULL << 4;

    static constexpr uint64_t ANTI_EMU_RDTSC_MIN_CYCLES = 10ULL;
    static constexpr uint64_t ANTI_EMU_RDTSC_MAX_CYCLES = 10000ULL;

    __forceinline uint64_t vm_anti_emu_rdtsc_now()
    {
        unsigned int aux = 0;
        return __rdtscp(&aux);
    }

    __forceinline void vm_anti_emu_record_handler_entry(vm_state_t& vm)
    {
        vm.anti_emu_handler_t0 = vm_anti_emu_rdtsc_now();
    }

    __forceinline bool vm_anti_emu_validate_rdtsc(vm_state_t& vm)
    {
        if (vm.anti_emu_handler_t0 == 0)
            return true;

        uint64_t now = vm_anti_emu_rdtsc_now();
        uint64_t delta = now - vm.anti_emu_handler_t0;

        if (delta == 0 || delta < ANTI_EMU_RDTSC_MIN_CYCLES || delta > ANTI_EMU_RDTSC_MAX_CYCLES)
        {
            ++vm.anti_emu_window_count;
            if (vm.anti_emu_window_count >= 4)
            {
                vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_RDTSC;
                vm.anti_emu_handler_t0 = 0;
                return false;
            }
        }
        else
        {
            vm.anti_emu_avg_window = (vm.anti_emu_avg_window * 7 + delta) >> 3;
            vm.anti_emu_window_count = 0;
        }

        vm.anti_emu_handler_t0 = 0;
        return true;
    }

    __forceinline bool vm_anti_emu_rdpmc_check(vm_state_t& vm)
    {
        vm.anti_emu_pmc_failures = 0;
        vm.anti_emu_last_pmc = 0;
        return true;
    }

    __forceinline bool vm_anti_emu_capability_probe(vm_state_t& vm)
    {
        int info[4] = {0};
        __cpuid(info, 7);
        bool reports_rdfsbase = (info[1] & (1 << 0)) != 0;
        bool reports_avx512f  = (info[1] & (1 << 16)) != 0;

        int info1[4] = {0};
        __cpuid(info1, 1);
        bool reports_movbe = (info1[2] & (1 << 22)) != 0;

        if (reports_rdfsbase)
        {
            bool exec_ok = false;
            __try {
                volatile uint64_t fs_base = _readfsbase_u64();
                (void)fs_base;
                exec_ok = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                exec_ok = false;
            }

            if (!exec_ok)
            {
                vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_CAPABILITY;
                return false;
            }
        }

        if (reports_movbe)
        {
            volatile uint64_t test = 0x0123456789ABCDEFULL;
            volatile uint64_t swapped = 0;
            bool exec_ok = false;
            __try {
                swapped = _byteswap_uint64(test);
                exec_ok = (swapped == 0xEFCDAB8967452301ULL);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                exec_ok = false;
            }

            if (!exec_ok)
            {
                vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_CAPABILITY;
                return false;
            }
        }

        if (reports_avx512f)
        {
            bool exec_ok = false;
            __try {
                volatile uint32_t v = 0xFEDCBA98u;
                volatile uint32_t lz = static_cast<uint32_t>(__lzcnt(v));
                exec_ok = (lz == 0u);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                exec_ok = false;
            }

            if (!exec_ok)
            {
                vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_CAPABILITY;
                return false;
            }
        }

        return true;
    }

    __forceinline uint16_t vm_anti_emu_read_x87_cw()
    {
        uint16_t cw = 0;
        __try {
            uint32_t cur = _control87(0, 0);
            cw = static_cast<uint16_t>(cur & 0xFFFFu);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            cw = 0xFFFFu;
        }
        return cw;
    }

    __forceinline bool vm_anti_emu_fpu_check(vm_state_t& vm)
    {
        uint16_t cw = vm_anti_emu_read_x87_cw();

        if (vm.anti_emu_fpu_baseline == 0)
        {
            if (cw == 0xFFFFu)
            {
                vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_FPU;
                return false;
            }
            vm.anti_emu_fpu_baseline = cw;
        }
        else
        {
            if (cw != vm.anti_emu_fpu_baseline)
            {
                vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_FPU;
                return false;
            }
        }

        volatile double a = 1.0;
        volatile double b = 3.0;
        volatile double q = a / b;
        volatile double r = q * b;
        volatile double residual = (r > a) ? (r - a) : (a - r);

        union { double d; uint64_t u; } pun;
        pun.d = residual;

        bool real_cpu_native = (pun.u != 0ULL) && (pun.u < 0x3CB0000000000000ULL);

#ifdef _AIDA_FORCE_EMULATOR_RESPONSE
        real_cpu_native = false;
#endif
        if (vm.anti_emu_force_emulator)
            real_cpu_native = false;

        if (!real_cpu_native)
        {
            vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_FPU;
            return false;
        }

        return true;
    }

    __forceinline bool vm_anti_emu_misalign_check(vm_state_t& vm)
    {
        alignas(16) uint8_t buffer[32];
        for (int i = 0; i < 32; ++i)
            buffer[i] = static_cast<uint8_t>(i ^ 0x5A);

        volatile uint64_t* misaligned = reinterpret_cast<volatile uint64_t*>(buffer + 1);
        volatile uint64_t v = 0;
        bool seh_fired = false;

        __try {
            v = *misaligned;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh_fired = true;
        }

        if (seh_fired)
        {
            vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_MISALIGN;
            return false;
        }

        if (v == 0)
        {
            vm.anti_emu_corruption_flags |= ANTI_EMU_FLAG_MISALIGN;
            return false;
        }

        vm.anti_emu_misalign_seen = 1;
        return true;
    }

    __forceinline bool vm_anti_emu_run_probe(vm_state_t& vm)
    {
        bool ok = true;

        uint32_t which = vm.anti_emu_counter & 0x07u;
        switch (which)
        {
        case 0:
            ok = vm_anti_emu_validate_rdtsc(vm) && ok;
            break;
        case 1:
            ok = vm_anti_emu_rdpmc_check(vm) && ok;
            break;
        case 2:
            ok = vm_anti_emu_capability_probe(vm) && ok;
            break;
        case 3:
            ok = vm_anti_emu_fpu_check(vm) && ok;
            break;
        case 4:
            ok = vm_anti_emu_misalign_check(vm) && ok;
            break;
        case 5:
            ok = vm_anti_emu_validate_rdtsc(vm) && vm_anti_emu_rdpmc_check(vm) && ok;
            break;
        case 6:
            ok = vm_anti_emu_capability_probe(vm) && vm_anti_emu_fpu_check(vm) && ok;
            break;
        case 7:
            ok = vm_anti_emu_validate_rdtsc(vm)
                 && vm_anti_emu_rdpmc_check(vm)
                 && vm_anti_emu_fpu_check(vm)
                 && ok;
            break;
        }

        ++vm.anti_emu_counter;
        return ok;
    }

    __forceinline void vm_anti_emu_inject_corruption(vm_state_t& vm)
    {
        uint64_t poison = 0xDEADBEEFDEADBEEFULL ^ vm.anti_emu_corruption_flags
            ^ _rotl64(vm.rolling_key, 13);
        for (int i = 0; i < 16; ++i)
            vm.regs[i] ^= poison;
        vm.rolling_key ^= poison;
        vm.handler_chain_key ^= _rotl64(poison, 17);
        vm.vflags.ZF = 0;
        vm.vflags.SF = 1;
    }

#pragma endregion


    __forceinline void dispatch_next(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {
        handler_pool_t& pool = vm.pool ? *vm.pool : g_default_pool;

        encrypt_context(vm);

        if (dag_active(vm))
        {
            if (vm.halted || vm.insn_count >= vm.max_insn)
                return;

            if (vm.dag_cursor != 0)
            {
                if (vm.dag_node == DAG_NODE_HALT || vm.dag_node >= vm.dag_nodes_size)
                {
                    return;
                }
                const dag_node_t& cur = vm.dag_nodes[vm.dag_node];
                uint32_t next = (vm.dag_branch_taken && cur.next_node_b != UINT32_MAX)
                                    ? cur.next_node_b
                                    : cur.next_node_a;
                vm.dag_branch_taken = 0;
                if (next == UINT32_MAX)
                {
                    vm.dag_node = DAG_NODE_HALT;
                    vm.halted = true;
                    return;
                }

                uint32_t prev_bc_end = static_cast<uint32_t>(vm.rip);
                uint32_t new_bc_start = vm.dag_nodes[next].bc_offset;
                if (new_bc_start > prev_bc_end && new_bc_start <= bc_size)
                {
                    for (uint32_t p = prev_bc_end; p < new_bc_start; ++p)
                        cipher_stream_xcrypt(vm.stream, bc[p], false);
                }
                else if (new_bc_start < prev_bc_end)
                {
                    uint64_t saved_seed = vm.stream.base_seed;
                    cipher_stream_init(vm.stream, saved_seed);
                    for (uint32_t p = 0; p < new_bc_start && p < bc_size; ++p)
                        cipher_stream_xcrypt(vm.stream, bc[p], false);
                }

                vm.dag_node = next;
                vm.dag_cursor = 0;
                vm.rip = vm.dag_nodes[next].bc_offset;
            }

            if (vm.dag_node == DAG_NODE_HALT || vm.dag_node >= vm.dag_nodes_size)
            {
                vm.halted = true;
                return;
            }
        }
        else
        {
            if (vm.halted || vm.rip >= bc_size || vm.insn_count >= vm.max_insn)
                return;
        }

        if (g_jit_hook && !dag_active(vm))
        {
            decrypt_context(vm);
            uint64_t saved_keys[16];
            linearize_register_file(vm, saved_keys);
            uint64_t fresh_xor = secure_seed() ^ vm.context_entropy;
            if (g_jit_hook(vm, bc, bc_size))
            {
                delinearize_register_file(vm, saved_keys, fresh_xor);
                encrypt_context(vm);
                dispatch_next(vm, bc, bc_size);
                return;
            }
            delinearize_register_file(vm, saved_keys, fresh_xor);
            encrypt_context(vm);
        }


        if ((vm.insn_count & 0xFF) == 0)
        {
            if (!verify_handler_pool(pool))
            {
                decrypt_context(vm);
                write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
                vm.halted = true;
                return;
            }
        }

        if (vm.insn_count > 0 && (vm.insn_count % VM_ANTIDEBUG_INTERVAL) == 0)
        {
            decrypt_context(vm);
            if (vm_check_hardware_breakpoints(vm))
            {
                write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
                vm.halted = true;
                return;
            }
            encrypt_context(vm);
        }

        if (vm.insn_count > 0 && (vm.insn_count % HANDLER_REGEN_INTERVAL) == 0)
        {
            decrypt_context(vm);
            regenerate_handlers(vm);
            encrypt_context(vm);
        }


        ++vm.shuffle_counter;
        if (vm.shuffle_counter >= CONTEXT_SHUFFLE_INTERVAL)
        {
            decrypt_context(vm);
            shuffle_registers(vm);
            encrypt_context(vm);
        }


        decrypt_context(vm);

        if ((vm.insn_count & 0x07u) == 0)
        {
            if (!vm_anti_emu_run_probe(vm))
            {
                vm_anti_emu_inject_corruption(vm);
                write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
                vm.halted = true;
                return;
            }
        }

        if (dag_active(vm))
        {
            const dag_node_t& node = vm.dag_nodes[vm.dag_node];
            uint64_t actual_hash = dag_compute_state_hash(vm, node.handler_chain);
            if ((actual_hash ^ node.enter_hash) != 0)
            {
                vm.dag_violation_code = actual_hash ^ node.enter_hash;
                write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
                vm.halted = true;
                vm.dag_node = DAG_NODE_HALT;
                return;
            }

            if (node.bc_offset >= bc_size)
            {
                vm.halted = true;
                vm.dag_node = DAG_NODE_HALT;
                return;
            }

            uint8_t raw = bc[node.bc_offset];
            uint8_t decrypted = decrypt_byte(vm, raw);
            vm.dag_cursor = 1;
            vm.rip = static_cast<uint64_t>(node.bc_offset) + 1;

            compute_handler_chain_addr(vm, decrypted);
            ++vm.insn_count;

            mutate_shuffle_per_op(vm, decrypted, vm.last_op_result);

            vm_anti_emu_record_handler_entry(vm);

            auto handler = resolve_dispatch(vm, decrypted);
            handler(vm, bc, bc_size);
            return;
        }

        uint8_t raw = bc[vm.rip];
        uint8_t decrypted = decrypt_byte(vm, raw);
        ++vm.rip;

        compute_handler_chain_addr(vm, decrypted);
        ++vm.insn_count;

        mutate_shuffle_per_op(vm, decrypted, vm.last_op_result);

        vm_anti_emu_record_handler_entry(vm);

        auto handler = resolve_dispatch(vm, decrypted);
        handler(vm, bc, bc_size);
    }

#define VM_HANDLER(name) static void name(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)

    VM_HANDLER(h_nop) { (void)bc; (void)bc_size; dispatch_next(vm, bc, bc_size); }

    VM_HANDLER(h_load_imm)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = fetch_u64(vm, bc, bc_size);
        write_vreg(vm, reg, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_reg)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        if (dag_active(vm))
        {
            uint64_t taint_val = 0;
            if (dag_taint_load(vm, src, taint_val))
                val = taint_val;
        }
        write_vreg(vm, dst, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_store_reg)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        write_vreg(vm, dst, val);
        if (dag_active(vm))
            dag_taint_store(vm, dst, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nand)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x11);
        uint64_t result = mba_nand(va, vb, entropy);
        result = triton_break_inject(vm, result, 0x11);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nor)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x12);
        uint64_t result = mba_nor(va, vb, entropy);
        result = triton_break_inject(vm, result, 0x12);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_xor)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x13);
        uint64_t result = mba_xor(va, vb, entropy);
        result = triton_break_inject(vm, result, 0x13);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_not)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint64_t entropy = handler_entropy_bit(vm, 0x14);
        uint64_t result = mba_not(va, entropy);
        result = triton_break_inject(vm, result, 0x14);
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shl)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t result = val << amt;
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shr)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t result = val >> amt;
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_rol)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        write_vreg(vm, dst, _rotl64(read_vreg(vm, src), amt));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_ror)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        write_vreg(vm, dst, _rotr64(read_vreg(vm, src), amt));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_cmp)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = va - vb;
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jmp)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        uint64_t block_key = saved_key ^ target;
        block_key ^= block_key >> 30;
        block_key *= 0xBF58476D1CE4E5B9ULL;
        block_key ^= block_key >> 27;
        block_key *= 0x94D049BB133111EBULL;
        block_key ^= block_key >> 31;
        vm.rolling_key = block_key;
        if (dag_active(vm))
        {
            vm.dag_branch_taken = 0;
        }
        else
        {
            vm.rip = target;
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jz)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (vm.vflags.ZF)
        {
            uint64_t block_key = saved_key ^ target;
            block_key ^= block_key >> 30;
            block_key *= 0xBF58476D1CE4E5B9ULL;
            block_key ^= block_key >> 27;
            block_key *= 0x94D049BB133111EBULL;
            block_key ^= block_key >> 31;
            vm.rolling_key = block_key;
            if (dag_active(vm))
            {
                vm.dag_branch_taken = 1;
            }
            else
            {
                vm.rip = target;
            }
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jnz)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (!vm.vflags.ZF)
        {
            uint64_t block_key = saved_key ^ target;
            block_key ^= block_key >> 30;
            block_key *= 0xBF58476D1CE4E5B9ULL;
            block_key ^= block_key >> 27;
            block_key *= 0x94D049BB133111EBULL;
            block_key ^= block_key >> 31;
            vm.rolling_key = block_key;
            if (dag_active(vm))
            {
                vm.dag_branch_taken = 1;
            }
            else
            {
                vm.rip = target;
            }
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_push)
    {
        uint8_t r = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (vm.rsp < 8) { vm.halted = true; return; }
        vm.rsp -= 8;
        uint64_t val = read_vreg(vm, r);
        memcpy(vm.stack + vm.rsp, &val, 8);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_pop)
    {
        uint8_t r = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (vm.rsp + 8 > vm.stack_size) { vm.halted = true; return; }
        uint64_t val;
        memcpy(&val, vm.stack + vm.rsp, 8);
        write_vreg(vm, r, val);
        vm.rsp += 8;
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_rdtsc)
    {
        uint8_t r = fetch_byte(vm, bc, bc_size) & 0x0F;
        write_vreg(vm, r, __rdtsc());
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_siphash)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);
        uint8_t buf[16];
        memcpy(buf, &vdst, 8);
        memcpy(buf + 8, &vsrc, 8);
        write_vreg(vm, dst, integrity::siphash::hash(
            buf, 16, vdst ^ 0x736970686173684BULL, vsrc ^ 0x646F72616E64311ULL));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_hash)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);
        vdst = micro_xor(vdst, vsrc);
        vdst = micro_mul(vdst, 0x100000001B3ULL);
        vdst ^= _rotl64(vdst, 27);
        write_vreg(vm, dst, vdst);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_verify)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (read_vreg(vm, a) != read_vreg(vm, b))
        {
            write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
            vm.halted = true;
            return;
        }
        dispatch_next(vm, bc, bc_size);
    }


    VM_HANDLER(h_trap)
    {
        (void)bc; (void)bc_size;
        write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
        vm.halted = true;
    }

    VM_HANDLER(h_halt)
    {
        (void)bc; (void)bc_size;
        vm.halted = true;
    }

    VM_HANDLER(h_invalid)
    {
        (void)bc; (void)bc_size;
        write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
        vm.halted = true;
    }

    VM_HANDLER(h_add)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x21);
        uint64_t result = mba_add(va, vb, entropy);
        result = triton_break_inject(vm, result, 0x21);
        write_vreg(vm, dst, result);
        update_flags_add(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sub)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x22);
        uint64_t result = mba_sub(va, vb, entropy);
        result = triton_break_inject(vm, result, 0x22);
        write_vreg(vm, dst, result);
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }


    VM_HANDLER(h_nand_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x31);
        uint64_t and_ab = mba_and(va, vb, entropy);
        uint64_t r = mba_not(and_ab, entropy ^ 0xC0);
        r = triton_break_inject(vm, r, 0x31);
        write_vreg(vm, dst, r);
        update_flags_logic(vm, r);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_xor_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x32);
        uint64_t r = metamorphic::mba::keyed_xor_dynamic(va, vb, entropy);
        r = triton_break_inject(vm, r, 0x32);
        write_vreg(vm, dst, r);
        update_flags_logic(vm, r);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_hash_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);
        vdst ^= vsrc;
        vdst *= 0x100000001B3ULL;
        vdst = _rotl64(vdst, 31) ^ _rotr64(vdst, 17);
        write_vreg(vm, dst, vdst);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_cmp_v2)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = va - vb;
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_add_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t entropy = handler_entropy_bit(vm, 0x33);
        uint64_t xor_ab = mba_xor(va, vb, entropy);
        uint64_t and_ab = mba_and(va, vb, entropy ^ 0x55);
        uint64_t result = mba_add(xor_ab, (and_ab << 1), entropy ^ 0xAA);
        result = triton_break_inject(vm, result, 0x33);
        write_vreg(vm, dst, result);
        update_flags_add(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sub_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t entropy = handler_entropy_bit(vm, 0x34);
        uint64_t neg_b = mba_not(vb, entropy);
        neg_b = mba_add(neg_b, 1, entropy ^ 0x66);
        uint64_t result = metamorphic::mba::keyed_add_dynamic(va, neg_b, entropy);
        result = triton_break_inject(vm, result, 0x34);
        write_vreg(vm, dst, result);
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_xor_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t entropy = handler_entropy_bit(vm, 0x35);
        uint64_t or_ab  = mba_or(va, vb, entropy);
        uint64_t and_ab = mba_and(va, vb, entropy ^ 0x77);
        uint64_t result = mba_sub(or_ab, and_ab, entropy ^ 0x88);
        result = triton_break_inject(vm, result, 0x35);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nand_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t entropy = handler_entropy_bit(vm, 0x36);
        uint64_t na = mba_not(va, entropy);
        uint64_t nb = mba_not(vb, entropy ^ 0x99);
        uint64_t result = mba_or(na, nb, entropy ^ 0xBB);
        result = triton_break_inject(vm, result, 0x36);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_mem_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t addr_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t addr = read_vreg(vm, addr_reg);
        uint64_t val = 0;
        if (addr) memcpy(&val, reinterpret_cast<const void*>(static_cast<uintptr_t>(addr)), 8);

        write_vreg(vm, dst, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shl_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;

        for (uint8_t i = 0; i < b; ++i)
            va = micro_add(va, va);
        write_vreg(vm, dst, va);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_hash_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);

        vdst ^= vsrc;
        vdst *= 0x01000193ULL;
        vdst = _rotl64(vdst, 13) ^ _rotr64(vdst, 29);
        vdst ^= vdst >> 16;
        write_vreg(vm, dst, vdst);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shr_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t result = 0;
        for (int i = 63; i >= 0; --i) {
            uint64_t bit = (va >> i) & 1;
            int new_pos = i - static_cast<int>(b);
            if (new_pos >= 0)
                result |= (bit << new_pos);
        }
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shr_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t mask = (b >= 64) ? 0 : (0xFFFFFFFFFFFFFFFFULL >> b);
        uint64_t result = (va >> b) & mask;
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_rol_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t left = va << b;
        uint64_t right = (b == 0) ? 0 : (va >> (64 - b));
        uint64_t result = micro_or(left, right);
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_ror_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t right = va >> b;
        uint64_t left = (b == 0) ? 0 : (va << (64 - b));
        uint64_t result = micro_or(right, left);
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_not_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint64_t entropy = handler_entropy_bit(vm, 0x37);
        uint64_t result = mba_not(va, entropy);
        result = triton_break_inject(vm, result, 0x37);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_not_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint64_t entropy = handler_entropy_bit(vm, 0x38);
        uint64_t result = mba_xor(va, 0xFFFFFFFFFFFFFFFFULL, entropy);
        result = triton_break_inject(vm, result, 0x38);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_mul_v2)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = micro_mul(va, vb);
        write_vreg(vm, a, result);
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.PF = compute_parity(result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_push_v2)
    {
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        if (vm.rsp < 8) { vm.halted = true; return; }
        vm.rsp = micro_sub(vm.rsp, 8);
        memcpy(vm.stack + vm.rsp, &val, 8);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_pop_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (vm.rsp + 8 > vm.stack_size) { vm.halted = true; return; }
        uint64_t val;
        memcpy(&val, vm.stack + vm.rsp, 8);
        vm.rsp = micro_add(vm.rsp, 8);
        write_vreg(vm, dst, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_add_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x39);
        uint64_t neg_vb = mba_sub(0, vb, entropy);
        uint64_t result = mba_sub(va, neg_vb, entropy ^ 0x44);
        result = triton_break_inject(vm, result, 0x39);
        write_vreg(vm, dst, result);
        update_flags_add(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sub_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x3A);
        uint64_t not_b = mba_not(vb, entropy);
        uint64_t neg_b = mba_add(not_b, 1, entropy ^ 0x55);
        uint64_t xor_ab = mba_xor(va, neg_b, entropy ^ 0x66);
        uint64_t and_ab = mba_and(va, neg_b, entropy ^ 0x77);
        uint64_t result = mba_add(xor_ab, (and_ab << 1), entropy ^ 0x88);
        result = triton_break_inject(vm, result, 0x3A);
        write_vreg(vm, dst, result);
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_store_mem_v2)
    {
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t addr_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t addr = read_vreg(vm, addr_reg);
        uint64_t val = read_vreg(vm, src);
        if (addr) {
            volatile uint64_t guard = addr ^ vm.rolling_key;
            (void)guard;
            memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)), &val, 8);
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nor_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t entropy = handler_entropy_bit(vm, 0x3B);
        uint64_t not_a = mba_not(va, entropy);
        uint64_t not_b = mba_not(vb, entropy ^ 0x99);
        uint64_t result = metamorphic::mba::keyed_and_dynamic(not_a, not_b, entropy);
        result = triton_break_inject(vm, result, 0x3B);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_imm8)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t val = fetch_byte(vm, bc, bc_size);
        uint64_t prev = read_vreg(vm, reg);
        write_vreg(vm, reg, (prev & 0xFFFFFFFFFFFFFF00ULL) | val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_imm16)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t lo = fetch_byte(vm, bc, bc_size);
        uint8_t hi = fetch_byte(vm, bc, bc_size);
        uint16_t val = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
        uint64_t prev = read_vreg(vm, reg);
        write_vreg(vm, reg, (prev & 0xFFFFFFFFFFFF0000ULL) | val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_imm32)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint32_t val = fetch_u32(vm, bc, bc_size);
        write_vreg(vm, reg, static_cast<uint64_t>(val));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_mul)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t hi = 0;
        uint64_t lo = _umul128(va, vb, &hi);
        write_vreg(vm, a, lo);
        vm.vflags.CF = (hi != 0) ? 1 : 0;
        vm.vflags.OF = vm.vflags.CF;
        vm.vflags.ZF = (lo == 0) ? 1 : 0;
        vm.vflags.SF = (lo >> 63) & 1;
        vm.vflags.PF = compute_parity(lo);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_imul)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        int64_t sa = static_cast<int64_t>(read_vreg(vm, a));
        int64_t sb = static_cast<int64_t>(read_vreg(vm, b));
        int64_t hi = 0;
        int64_t lo = _mul128(sa, sb, &hi);
        write_vreg(vm, a, static_cast<uint64_t>(lo));
        vm.vflags.CF = (hi != 0 && hi != -1) ? 1 : 0;
        vm.vflags.OF = vm.vflags.CF;
        vm.vflags.ZF = (lo == 0) ? 1 : 0;
        vm.vflags.SF = (static_cast<uint64_t>(lo) >> 63) & 1;
        vm.vflags.PF = compute_parity(static_cast<uint64_t>(lo));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_div)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        if (vb == 0) { vm.halted = true; write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL); return; }
        write_vreg(vm, a, va / vb);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_idiv)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        int64_t sa = static_cast<int64_t>(read_vreg(vm, a));
        int64_t sb = static_cast<int64_t>(read_vreg(vm, b));
        if (sb == 0) { vm.halted = true; write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL); return; }
        write_vreg(vm, a, static_cast<uint64_t>(sa / sb));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_cmov)
    {
        uint8_t packed = fetch_byte(vm, bc, bc_size);
        uint8_t cc = (packed >> 4) & 0x0F;
        uint8_t dst = packed & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (eval_condition(vm.vflags, cc))
            write_vreg(vm, dst, read_vreg(vm, src));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_setcc)
    {
        uint8_t packed = fetch_byte(vm, bc, bc_size);
        uint8_t cc = (packed >> 4) & 0x0F;
        uint8_t dst = packed & 0x0F;
        write_vreg(vm, dst, eval_condition(vm.vflags, cc) ? 1ULL : 0ULL);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_vcall)
    {
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (vm.rsp < 8) { vm.halted = true; return; }
        vm.rsp -= 8;
        uint64_t saved_key = vm.rolling_key;
        if (dag_active(vm))
        {
            uint64_t ret_marker = static_cast<uint64_t>(vm.dag_node);
            memcpy(vm.stack + vm.rsp, &ret_marker, 8);
            vm.dag_branch_taken = 0;
        }
        else
        {
            uint64_t ret_addr = vm.rip;
            memcpy(vm.stack + vm.rsp, &ret_addr, 8);
            vm.rip = target;
        }
        uint64_t block_key = saved_key ^ target;
        block_key ^= block_key >> 30;
        block_key *= 0xBF58476D1CE4E5B9ULL;
        block_key ^= block_key >> 27;
        block_key *= 0x94D049BB133111EBULL;
        block_key ^= block_key >> 31;
        vm.rolling_key = block_key;
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_vret)
    {
        if (vm.rsp + 8 > vm.stack_size) { vm.halted = true; return; }
        uint64_t ret_marker;
        memcpy(&ret_marker, vm.stack + vm.rsp, 8);
        vm.rsp += 8;
        if (dag_active(vm))
        {
            uint32_t ret_node = static_cast<uint32_t>(ret_marker);
            uint32_t fall_through_node = ret_node + 1;
            if (fall_through_node >= vm.dag_nodes_size)
            {
                vm.halted = true;
                vm.dag_node = DAG_NODE_HALT;
                return;
            }
            uint32_t target_offset = vm.dag_nodes[fall_through_node].bc_offset;
            uint32_t cur_pos = static_cast<uint32_t>(vm.rip);
            if (target_offset > cur_pos && target_offset <= bc_size)
            {
                for (uint32_t p = cur_pos; p < target_offset; ++p)
                    cipher_stream_xcrypt(vm.stream, bc[p], false);
            }
            else if (target_offset < cur_pos)
            {
                uint64_t saved_seed = vm.stream.base_seed;
                cipher_stream_init(vm.stream, saved_seed);
                for (uint32_t p = 0; p < target_offset && p < bc_size; ++p)
                    cipher_stream_xcrypt(vm.stream, bc[p], false);
            }
            vm.dag_node = fall_through_node;
            vm.dag_cursor = 0;
            vm.dag_branch_taken = 0;
            vm.rip = target_offset;
            dispatch_next(vm, bc, bc_size);
            return;
        }
        vm.rip = static_cast<uint32_t>(ret_marker);
        dispatch_next(vm, bc, bc_size);
    }

    __forceinline void branch_if(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size, bool cond)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (cond)
        {
            uint64_t block_key = saved_key ^ target;
            block_key ^= block_key >> 30;
            block_key *= 0xBF58476D1CE4E5B9ULL;
            block_key ^= block_key >> 27;
            block_key *= 0x94D049BB133111EBULL;
            block_key ^= block_key >> 31;
            vm.rolling_key = block_key;
            if (dag_active(vm))
            {
                vm.dag_branch_taken = 1;
            }
            else
            {
                vm.rip = target;
            }
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jl)  { branch_if(vm, bc, bc_size, vm.vflags.SF != vm.vflags.OF); }
    VM_HANDLER(h_jle) { branch_if(vm, bc, bc_size, vm.vflags.ZF || (vm.vflags.SF != vm.vflags.OF)); }
    VM_HANDLER(h_jg)  { branch_if(vm, bc, bc_size, !vm.vflags.ZF && (vm.vflags.SF == vm.vflags.OF)); }
    VM_HANDLER(h_jge) { branch_if(vm, bc, bc_size, vm.vflags.SF == vm.vflags.OF); }
    VM_HANDLER(h_jb)  { branch_if(vm, bc, bc_size, vm.vflags.CF != 0); }
    VM_HANDLER(h_jbe) { branch_if(vm, bc, bc_size, vm.vflags.CF || vm.vflags.ZF); }
    VM_HANDLER(h_js)  { branch_if(vm, bc, bc_size, vm.vflags.SF != 0); }
    VM_HANDLER(h_jo)  { branch_if(vm, bc, bc_size, vm.vflags.OF != 0); }
    VM_HANDLER(h_jnb) { branch_if(vm, bc, bc_size, !vm.vflags.CF); }
    VM_HANDLER(h_jnbe){ branch_if(vm, bc, bc_size, !vm.vflags.CF && !vm.vflags.ZF); }

    VM_HANDLER(h_lahf)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t packed = static_cast<uint64_t>(vm.vflags.CF)
                        | (static_cast<uint64_t>(vm.vflags.ZF) << 1)
                        | (static_cast<uint64_t>(vm.vflags.SF) << 2)
                        | (static_cast<uint64_t>(vm.vflags.OF) << 3)
                        | (static_cast<uint64_t>(vm.vflags.PF) << 4)
                        | (static_cast<uint64_t>(vm.vflags.AF) << 5);
        write_vreg(vm, dst, packed);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sahf)
    {
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t packed = read_vreg(vm, src);
        vm.vflags.CF = (packed >> 0) & 1;
        vm.vflags.ZF = (packed >> 1) & 1;
        vm.vflags.SF = (packed >> 2) & 1;
        vm.vflags.OF = (packed >> 3) & 1;
        vm.vflags.PF = (packed >> 4) & 1;
        vm.vflags.AF = (packed >> 5) & 1;
        dispatch_next(vm, bc, bc_size);
    }


    static constexpr uint32_t MAX_VM_DEPTH = 8;
    inline thread_local uint32_t g_vm_depth = 0;

    VM_HANDLER(h_vm_enter)
    {
        if (g_vm_depth >= MAX_VM_DEPTH) {
            vm.halted = true;
            write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
            return;
        }

        uint32_t child_bc_offset = fetch_u32(vm, bc, bc_size);
        uint32_t child_bc_len    = fetch_u32(vm, bc, bc_size);

        if (child_bc_offset + child_bc_len > bc_size) {
            vm.halted = true;
            return;
        }

        uint64_t child_seed = vm.rolling_key ^ vm.handler_chain_key ^ secure_seed();

        vm_state_t child;
        init_vm(child, child_seed);

        for (int i = 0; i < 8; ++i)
            write_vreg(child, i, read_vreg(vm, i));

        g_vm_depth++;
        uint64_t result = vm_execute(child, bc + child_bc_offset, child_bc_len);
        g_vm_depth--;

        write_vreg(vm, 0, result);
        for (int i = 1; i < 4; ++i)
            write_vreg(vm, i, read_vreg(child, i));

        destroy_vm(child);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_vm_exit)
    {
        (void)bc; (void)bc_size;
        vm.halted = true;
    }

    VM_HANDLER(h_vm_spawn)
    {
        if (g_vm_depth >= MAX_VM_DEPTH) {
            vm.halted = true;
            write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
            return;
        }

        uint8_t  child_pool_id = fetch_byte(vm, bc, bc_size);
        uint32_t child_bc_offset = fetch_u32(vm, bc, bc_size);
        uint32_t child_bc_len    = fetch_u32(vm, bc, bc_size);
        uint8_t  result_reg = fetch_byte(vm, bc, bc_size) & 0x0F;

        if (child_bc_offset + child_bc_len > bc_size) {
            vm.halted = true;
            return;
        }

        handler_pool_t* parent_pool = vm.pool ? vm.pool : &g_default_pool;
        handler_pool_t* child_pool = parent_pool;
        if (child_pool_id < 8 && parent_pool->child_pools[child_pool_id])
            child_pool = parent_pool->child_pools[child_pool_id];

        uint64_t child_seed = vm.rolling_key ^ vm.handler_chain_key
            ^ secure_seed()
            ^ (static_cast<uint64_t>(child_pool_id) * 0x9E3779B97F4A7C15ULL);

        vm_state_t child;
        init_vm(child, child_seed);
        child.pool = child_pool;
        memcpy(child.opcode_map, child_pool->opcode_map, 256);
        memcpy(child.reverse_map, child_pool->reverse_map, 256);

        for (int i = 0; i < 8; ++i)
            write_vreg(child, i, read_vreg(vm, i));

        g_vm_depth++;
        uint64_t result = vm_execute(child, bc + child_bc_offset, child_bc_len);
        g_vm_depth--;

        write_vreg(vm, result_reg, result);

        if (child.stack)
            RtlSecureZeroMemory(child.stack, child.stack_size);
        destroy_vm(child);

        dispatch_next(vm, bc, bc_size);
    }


    __forceinline bool verify_environment(vm_state_t& vm)
    {
        uint64_t teb_pid = 0;
        __try {
            auto* teb = reinterpret_cast<uint8_t*>(__readgsqword(0x30));
            auto* peb = *reinterpret_cast<uint8_t**>(teb + 0x60);
            teb_pid = *reinterpret_cast<uint32_t*>(teb + 0x40);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        uint64_t expected_pid = vm.continuation.chain_nonce & 0xFFFFFFFF;
        if (expected_pid != 0 && teb_pid != expected_pid)
            return false;

        return true;
    }

    inline void bind_to_environment(vm_state_t& vm)
    {
        __try {
            auto* teb = reinterpret_cast<uint8_t*>(__readgsqword(0x30));
            uint32_t pid = *reinterpret_cast<uint32_t*>(teb + 0x40);
            vm.continuation.chain_nonce =
                (vm.continuation.chain_nonce & 0xFFFFFFFF00000000ULL) |
                static_cast<uint64_t>(pid);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    inline void build_poly_table(handler_pool_t& pool)
    {
        for (int i = 0; i < 256; ++i) {
            pool.poly_table[i].variants[0] = pool.dispatch_table[i];
            pool.poly_table[i].count = 1;
        }

        auto add_variant = [&pool](uint8_t mapped_op, handler_fn alt) {
            auto& entry = pool.poly_table[mapped_op];
            if (entry.count < 4) {
                entry.variants[entry.count] = alt;
                entry.count++;
            }
        };

        struct variant_pair_t { handler_fn base; handler_fn alt; };
        variant_pair_t pairs[] = {
            { h_nand,      h_nand_v2 },
            { h_nand,      h_nand_v3 },
            { h_xor,       h_xor_v2  },
            { h_xor,       h_xor_v3  },
            { h_hash,      h_hash_v2 },
            { h_hash,      h_hash_v3 },
            { h_cmp,       h_cmp_v2  },
            { h_add,       h_add_v2  },
            { h_add,       h_add_v3  },
            { h_sub,       h_sub_v2  },
            { h_sub,       h_sub_v3  },
            { h_shl,       h_shl_v2  },
            { h_shr,       h_shr_v2  },
            { h_shr,       h_shr_v3  },
            { h_rol,       h_rol_v2  },
            { h_ror,       h_ror_v2  },
            { h_not,       h_not_v2  },
            { h_not,       h_not_v3  },
            { h_nor,       h_nor_v2  },
            { h_mul,       h_mul_v2  },
            { h_push,      h_push_v2 },
            { h_pop,       h_pop_v2  },
            { h_load_mem_v2,  h_load_mem_v2 },
            { h_store_mem_v2, h_store_mem_v2 },
        };
        constexpr int num_pairs = sizeof(pairs) / sizeof(pairs[0]);

        for (int d = 0; d < 256; ++d) {
            if (pool.dispatch_table[d] == h_invalid) continue;
            for (int p = 0; p < num_pairs; ++p) {
                if (pool.dispatch_table[d] == pairs[p].base) {
                    add_variant(static_cast<uint8_t>(d), pairs[p].alt);
                }
            }
        }

        pool.poly_initialized = true;
    }

    inline void build_poly_table()
    {
        build_poly_table(g_default_pool);
    }

    __forceinline uint64_t internal_opaque_zero(uint64_t noise)
    {
        uint64_t h = noise;
        h ^= h >> 33;
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= h >> 33;
        h *= 0xC4CEB9FE1A85EC53ULL;
        h ^= h >> 33;
        return h ^ h;
    }

    inline void build_handler_set(handler_pool_t& pool)
    {
        if (!pool.poly_initialized)
            build_poly_table(pool);

        const uint8_t* rt_seed = runtime_master_seed();

        uint8_t hk_input[52];
        memset(hk_input, 0, sizeof(hk_input));
        memcpy(hk_input, &pool.pool_seed, 8);
        memcpy(hk_input + 8, &pool.generation, 4);
        uint64_t pool_addr = reinterpret_cast<uint64_t>(&pool);
        memcpy(hk_input + 12, &pool_addr, 8);
        memcpy(hk_input + 20, rt_seed, 32);

        uint8_t prk[32];
        hmac_sha256(rt_seed, 32, hk_input, 52, prk);

        memcpy(pool.handler_set.dispatch_hmac_key, prk, 32);

        static const uint8_t info_hs[12] = {
            'a','i','d','a','_','h','s','e','t','_','v','1'
        };
        uint8_t okm[2048];
        hkdf_expand_sha256(prk, info_hs, 12, okm, 2048);

        for (int op = 0; op < 256; ++op)
        {
            auto& entry = pool.poly_table[op];
            uint8_t cnt = entry.count;
            if (cnt == 0)
            {
                pool.handler_set.variant_count[op] = 0;
                pool.handler_set.variant_order[op][0] = 0;
                pool.handler_set.variant_order[op][1] = 0;
                pool.handler_set.variant_order[op][2] = 0;
                pool.handler_set.variant_order[op][3] = 0;
                continue;
            }
            if (cnt > 4) cnt = 4;
            pool.handler_set.variant_count[op] = cnt;

            uint8_t order[4] = { 0, 1, 2, 3 };
            uint32_t base = static_cast<uint32_t>(op) * 4;
            for (int i = static_cast<int>(cnt) - 1; i > 0; --i)
            {
                uint32_t r = okm[base + i];
                int j = static_cast<int>(r % static_cast<uint32_t>(i + 1));
                uint8_t tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }
            pool.handler_set.variant_order[op][0] = order[0];
            pool.handler_set.variant_order[op][1] = order[1];
            pool.handler_set.variant_order[op][2] = order[2];
            pool.handler_set.variant_order[op][3] = order[3];

            uint64_t mask;
            uint32_t mb = 1024 + static_cast<uint32_t>(op) * 4;
            uint32_t mask_lo;
            memcpy(&mask_lo, okm + mb, 4);
            uint32_t mask_hi;
            memcpy(&mask_hi, okm + mb + 4, 4);
            mask = static_cast<uint64_t>(mask_lo) | (static_cast<uint64_t>(mask_hi) << 32);
            pool.handler_set.dispatch_xor_table[op] = mask;
        }

        for (int i = 0; i < 64; ++i)
        {
            uint64_t v;
            memcpy(&v, okm + 1536 + i * 8, 8);
            pool.handler_set.uf_table[i] = v;
        }

        pool.handler_set.crc_accumulator = 0xCAFEBABEu ^
            static_cast<uint32_t>(pool.pool_seed) ^
            static_cast<uint32_t>(pool.pool_seed >> 32) ^
            pool.generation;

        pool.handler_set.set_generation = pool.generation;
        pool.handler_set.initialized = true;

        SecureZeroMemory(prk, 32);
        SecureZeroMemory(okm, 2048);
        SecureZeroMemory(hk_input, 52);
    }

    __forceinline handler_fn resolve_dispatch(vm_state_t& vm, uint8_t opcode)
    {
        handler_pool_t& pool = vm.pool ? *vm.pool : g_default_pool;

        if (!pool.handler_set.initialized || pool.handler_set.set_generation != pool.generation)
            build_handler_set(pool);

        uint64_t hkey = pool.handler_set.dispatch_hmac_key[0]
                      ^ pool.handler_set.dispatch_hmac_key[1]
                      ^ pool.handler_set.dispatch_hmac_key[2]
                      ^ pool.handler_set.dispatch_hmac_key[3];

        uint64_t mac_in = static_cast<uint64_t>(opcode) * 0x9E3779B97F4A7C15ULL;
        mac_in ^= vm.rolling_key * 0xBF58476D1CE4E5B9ULL;
        mac_in ^= vm.context_entropy * 0x94D049BB133111EBULL;
        mac_in ^= hkey;
        mac_in ^= pool.handler_set.dispatch_xor_table[opcode];

        mac_in ^= mac_in >> 33;
        mac_in *= 0xFF51AFD7ED558CCDULL;
        mac_in ^= mac_in >> 33;
        mac_in *= 0xC4CEB9FE1A85EC53ULL;
        mac_in ^= mac_in >> 33;

        if (!verify_environment(vm))
            return pool.dispatch_table[opcode];

        uint8_t variant_count = pool.handler_set.variant_count[opcode];
        if (variant_count == 0 || !pool.poly_initialized)
            return pool.dispatch_table[opcode];

        uint8_t safe_count = (variant_count > 4) ? 4 : variant_count;
        uint8_t pick = static_cast<uint8_t>(mac_in % safe_count);
        uint8_t order_idx = pool.handler_set.variant_order[opcode][pick];

        auto& entry = pool.poly_table[opcode];
        if (order_idx >= entry.count) order_idx = 0;

        handler_fn target = entry.variants[order_idx];

        uint64_t z = internal_opaque_zero(mac_in ^ hkey);
        uintptr_t obfuscated = reinterpret_cast<uintptr_t>(target);
        obfuscated ^= static_cast<uintptr_t>(z);

        uint8_t lookup_key = static_cast<uint8_t>((mac_in >> 8) & 0x3F);
        uint64_t uf_val = pool.handler_set.uf_table[lookup_key];
        uint64_t uf_zero = uf_val ^ uf_val;
        obfuscated ^= static_cast<uintptr_t>(uf_zero);

        pool.handler_set.crc_accumulator =
            _mm_crc32_u32(pool.handler_set.crc_accumulator, opcode) ^
            (static_cast<uint32_t>(mac_in) & 0x00FFFFFFu);

        return reinterpret_cast<handler_fn>(obfuscated);
    }

    __forceinline handler_fn select_handler(vm_state_t& vm, uint8_t opcode)
    {
        return resolve_dispatch(vm, opcode);
    }

#undef VM_HANDLER

    inline void build_handler_pool(handler_pool_t& pool, const uint8_t* reverse_map, uint64_t pool_seed)
    {
        handler_fn base_handlers[OP_MAX] = {};
        base_handlers[OP_NOP]       = h_nop;
        base_handlers[OP_LOAD_IMM]  = h_load_imm;
        base_handlers[OP_LOAD_REG]  = h_load_reg;
        base_handlers[OP_STORE_REG] = h_store_reg;
        base_handlers[OP_NAND]      = h_nand;
        base_handlers[OP_NOR]       = h_nor;
        base_handlers[OP_XOR]       = h_xor;
        base_handlers[OP_SHL]       = h_shl;
        base_handlers[OP_SHR]       = h_shr;
        base_handlers[OP_NOT]       = h_not;
        base_handlers[OP_CMP]       = h_cmp;
        base_handlers[OP_JMP]       = h_jmp;
        base_handlers[OP_JZ]        = h_jz;
        base_handlers[OP_JNZ]       = h_jnz;
        base_handlers[OP_PUSH]      = h_push;
        base_handlers[OP_POP]       = h_pop;
        base_handlers[OP_HASH]      = h_hash;
        base_handlers[OP_RDTSC]     = h_rdtsc;
        base_handlers[OP_SIPHASH]   = h_siphash;
        base_handlers[OP_HALT]      = h_halt;
        base_handlers[OP_TRAP]      = h_trap;
        base_handlers[OP_VERIFY]    = h_verify;
        base_handlers[OP_ROL]       = h_rol;
        base_handlers[OP_ROR]       = h_ror;
        base_handlers[OP_ADD]       = h_add;
        base_handlers[OP_SUB]       = h_sub;
        base_handlers[OP_VM_ENTER]  = h_vm_enter;
        base_handlers[OP_VM_EXIT]   = h_vm_exit;
        base_handlers[OP_LOAD_IMM8]  = h_load_imm8;
        base_handlers[OP_LOAD_IMM16] = h_load_imm16;
        base_handlers[OP_LOAD_IMM32] = h_load_imm32;
        base_handlers[OP_MUL]       = h_mul;
        base_handlers[OP_IMUL]      = h_imul;
        base_handlers[OP_DIV]       = h_div;
        base_handlers[OP_IDIV]      = h_idiv;
        base_handlers[OP_CMOV]      = h_cmov;
        base_handlers[OP_SETCC]     = h_setcc;
        base_handlers[OP_VCALL]     = h_vcall;
        base_handlers[OP_VRET]      = h_vret;
        base_handlers[OP_JL]        = h_jl;
        base_handlers[OP_JLE]       = h_jle;
        base_handlers[OP_JG]        = h_jg;
        base_handlers[OP_JGE]       = h_jge;
        base_handlers[OP_JB]        = h_jb;
        base_handlers[OP_JBE]       = h_jbe;
        base_handlers[OP_JS]        = h_js;
        base_handlers[OP_JO]        = h_jo;
        base_handlers[OP_LAHF]      = h_lahf;
        base_handlers[OP_SAHF]      = h_sahf;
        base_handlers[OP_JNB]       = h_jnb;
        base_handlers[OP_JNBE]      = h_jnbe;
        base_handlers[OP_VM_SPAWN]  = h_vm_spawn;

        handler_fn variant_table[] = {
            h_nand_v2, h_xor_v2, h_hash_v2, h_cmp_v2,
            h_nand_v3, h_xor_v3, h_hash_v3, h_cmp_v2,
            h_add_v3,  h_sub_v3, h_shl_v2,  h_load_mem_v2,
            h_shr_v2,  h_shr_v3, h_rol_v2,  h_ror_v2,
            h_not_v2,  h_not_v3, h_mul_v2,  h_push_v2,
            h_pop_v2,  h_add_v2, h_sub_v2,  h_store_mem_v2,
            h_nor_v2
        };
        uint8_t variant_ops[] = {
            OP_NAND, OP_XOR, OP_HASH, OP_CMP,
            OP_NAND, OP_XOR, OP_HASH, OP_CMP,
            OP_ADD,  OP_SUB, OP_SHL,  OP_LOAD_MEM,
            OP_SHR,  OP_SHR, OP_ROL,  OP_ROR,
            OP_NOT,  OP_NOT, OP_MUL,  OP_PUSH,
            OP_POP,  OP_ADD, OP_SUB,  OP_STORE_MEM,
            OP_NOR
        };
        constexpr int num_variants = sizeof(variant_ops) / sizeof(variant_ops[0]);

        uint64_t seed = pool_seed;
        pool.active_slots = 0;

        for (int i = 0; i < 256; ++i)
            pool.dispatch_table[i] = h_invalid;

        for (uint8_t op = 0; op < OP_MAX; ++op)
        {
            if (!base_handlers[op]) continue;

            uint8_t mapped = reverse_map[op];
            pool.dispatch_table[mapped] = base_handlers[op];

            if (pool.active_slots < HANDLER_POOL_SIZE)
            {
                auto& slot = pool.slots[pool.active_slots];
                slot.fn = base_handlers[op];
                slot.variant_id = 0;
                xorshift_advance(seed);
                slot.decrypt_key = seed;
                slot.encrypted_next = 0;
                slot.is_decrypted = true;
                pool.active_slots++;
            }

            for (int v = 0; v < num_variants; ++v)
            {
                if (variant_ops[v] == op && pool.active_slots < HANDLER_POOL_SIZE)
                {
                    auto& slot = pool.slots[pool.active_slots];
                    slot.fn = variant_table[v];
                    slot.variant_id = static_cast<uint8_t>(v + 1);
                    xorshift_advance(seed);
                    slot.decrypt_key = seed;
                    slot.encrypted_next = 0;
                    slot.is_decrypted = false;
                    pool.active_slots++;
                }
            }
        }

        xorshift_advance(seed);
        for (uint32_t i = 0; i < pool.active_slots; ++i)
        {
            uint32_t next_idx = (i + 1) % pool.active_slots;
            uint64_t next_addr = reinterpret_cast<uint64_t>(pool.slots[next_idx].fn);
            pool.slots[i].encrypted_next = next_addr ^ pool.slots[i].decrypt_key ^ HANDLER_CRYPT_MAGIC;
        }

        uint64_t guard = 0;
        for (uint32_t i = 0; i < pool.active_slots; ++i)
            guard ^= reinterpret_cast<uint64_t>(pool.slots[i].fn) * (i + 1);
        for (int i = 0; i < 256; ++i)
            guard ^= reinterpret_cast<uint64_t>(pool.dispatch_table[i]) * (i + 1);
        pool.pool_guard = guard;
        pool.pool_seed = pool_seed;
        pool.generation++;
        memcpy(pool.reverse_map, reverse_map, 256);
    }

    inline void build_handler_pool(const uint8_t* reverse_map, uint64_t pool_seed)
    {
        build_handler_pool(g_default_pool, reverse_map, pool_seed);
    }

    inline bool verify_handler_pool(handler_pool_t& pool)
    {
        uint64_t guard = 0;
        for (uint32_t i = 0; i < pool.active_slots; ++i)
            guard ^= reinterpret_cast<uint64_t>(pool.slots[i].fn) * (i + 1);
        for (int i = 0; i < 256; ++i)
            guard ^= reinterpret_cast<uint64_t>(pool.dispatch_table[i]) * (i + 1);
        return guard == pool.pool_guard;
    }

    inline bool verify_handler_pool()
    {
        return verify_handler_pool(g_default_pool);
    }

    inline void init_vm(vm_state_t& vm, uint64_t seed, handler_pool_t* pool)
    {
        memset(&vm, 0, sizeof(vm));
        vm.stack_size = 4096;
        vm.stack = new uint8_t[vm.stack_size];
        memset(vm.stack, 0, vm.stack_size);
        vm.rsp = vm.stack_size;
        vm.halted = false;
        vm.max_insn = 100000;
        vm.insn_count = 0;
        memset(&vm.vflags, 0, sizeof(vflags_t));
        vm.rolling_key = seed ^ 0x6A09E667F3BCC908ULL;
        vm.handler_chain_key = seed ^ 0xBB67AE8584CAA73BULL;
        vm.context_entropy = secure_seed() ^ seed;
        vm.shuffle_counter = 0;
        cipher_stream_init(vm.stream, vm.rolling_key);


        vm.continuation.next_handler = 0;
        vm.continuation.chain_nonce  = seed ^ 0x3C6EF372FE94F82BULL;
        vm.ctx_crypt.reg_mask   = 0;
        vm.ctx_crypt.flags_mask = 0;
        vm.ctx_crypt.rsp_mask   = 0;
        vm.ctx_crypt.encrypted  = false;

        for (int i = 0; i < 16; ++i)
        {
            vm.reg_shuffle[i] = static_cast<uint8_t>(i);
            vm.reg_unshuffle[i] = static_cast<uint8_t>(i);
            vm.reg_keys[i] = 0;
            vm.fake_regs[i] = 0;
            vm.fake_shuffle[i] = static_cast<uint8_t>(i);
        }
        vm.reg_xor_key = 0;
        vm.fake_decoy_key = 0;
        vm.last_op_result = 0;
        vm.per_op_shuffle_counter = 0;

        vm.anti_emu_counter = 0;
        vm.anti_emu_corruption_flags = 0;
        vm.anti_emu_last_pmc = 0;
        vm.anti_emu_pmc_failures = 0;
        vm.anti_emu_fpu_baseline = 0;
        vm.anti_emu_misalign_seen = 0;
        vm.anti_emu_force_emulator = 0;
        vm.anti_emu_handler_t0 = 0;
        vm.anti_emu_avg_window = 0;
        vm.anti_emu_window_count = 0;

        vm.pool = pool ? pool : &g_default_pool;

        generate_opcode_map(seed, vm.opcode_map, vm.reverse_map);
        memcpy(vm.pool->opcode_map, vm.opcode_map, 256);
        memcpy(vm.pool->reverse_map, vm.reverse_map, 256);
        build_handler_pool(*vm.pool, vm.reverse_map, seed ^ 0x428A2F98D728AE22ULL);

        if (!vm.pool->poly_initialized)
            build_poly_table(*vm.pool);

        vm.pool->handler_set.initialized = false;
        build_handler_set(*vm.pool);

        bind_to_environment(vm);
        shuffle_registers(vm);
    }

    inline void init_vm(vm_state_t& vm, uint64_t seed)
    {
        init_vm(vm, seed, &g_default_pool);
    }

    inline void destroy_vm(vm_state_t& vm)
    {
        if (vm.stack)
        {
            volatile uint8_t* vs = vm.stack;
            for (uint32_t i = 0; i < vm.stack_size; ++i)
                vs[i] = 0;
            delete[] vm.stack;
            vm.stack = nullptr;
        }
        volatile uint8_t* vr = reinterpret_cast<volatile uint8_t*>(vm.opcode_map);
        for (int i = 0; i < 256; ++i) vr[i] = 0;
        volatile uint8_t* vs = reinterpret_cast<volatile uint8_t*>(vm.reg_shuffle);
        for (int i = 0; i < 16; ++i) vs[i] = 0;
        volatile uint64_t* vk = reinterpret_cast<volatile uint64_t*>(vm.reg_keys);
        for (int i = 0; i < 16; ++i) vk[i] = 0;
        volatile uint64_t* vfr = reinterpret_cast<volatile uint64_t*>(vm.fake_regs);
        for (int i = 0; i < 16; ++i) vfr[i] = 0;
        volatile uint8_t* vfs = reinterpret_cast<volatile uint8_t*>(vm.fake_shuffle);
        for (int i = 0; i < 16; ++i) vfs[i] = 0;
        vm.reg_xor_key = 0;
        vm.handler_chain_key = 0;
        vm.fake_decoy_key = 0;
        vm.last_op_result = 0;
        vm.anti_emu_corruption_flags = 0;
        vm.anti_emu_last_pmc = 0;
        vm.anti_emu_handler_t0 = 0;
        vm.dag_nodes = nullptr;
        vm.dag_nodes_size = 0;
        vm.dag_node = 0;
        vm.dag_cursor = 0;
        vm.dag_branch_taken = 0;
        vm.dag_violation_code = 0;
        vm.dag_master_key = 0;
        vm.taint_ring = nullptr;
        vm.taint_ring_size = 0;
        vm.taint_seq = 0;
    }

    inline uint64_t vm_execute(vm_state_t& vm, const uint8_t* bytecode, uint32_t bc_size)
    {
        if (dag_active(vm))
        {
            vm.dag_node = 0;
            vm.dag_cursor = 0;
            vm.dag_branch_taken = 0;
            vm.dag_violation_code = 0;
            vm.rip = vm.dag_nodes[0].bc_offset;
        }
        else
        {
            vm.rip = 0;
        }
        vm.halted = false;
        vm.insn_count = 0;
        vm.ctx_crypt.encrypted = false;
        vm.ctx_crypt.reg_mask = 0;
        vm.ctx_crypt.flags_mask = 0;
        vm.ctx_crypt.rsp_mask = 0;

        vm.anti_emu_counter = 0;
        vm.anti_emu_corruption_flags = 0;
        vm.anti_emu_handler_t0 = 0;
        vm.anti_emu_window_count = 0;
        vm.last_op_result = 0;


        dispatch_next(vm, bytecode, bc_size);


        decrypt_context(vm);

        return read_vreg(vm, 0);
    }

    inline uint64_t vm_execute_program(vm_state_t& vm, const vm_program_t& program)
    {
        vm.dag_nodes = program.dag.empty() ? nullptr : program.dag.data();
        vm.dag_nodes_size = static_cast<uint32_t>(program.dag.size());
        vm.dag_master_key = program.dag_master_key;
        return vm_execute(vm, program.bc.data(), static_cast<uint32_t>(program.bc.size()));
    }

    inline uint64_t vm_execute_with_rva(vm_state_t& vm,
                                        const uint8_t* bytecode, uint32_t bc_size,
                                        uint32_t func_rva,
                                        const uint8_t master_key[32])
    {
        std::array<uint8_t, 256> local_map{};
        uint8_t local_reverse[256];
        {
            auto m = derive_function_opcode_map(func_rva, master_key);
            for (int i = 0; i < 256; ++i)
            {
                local_map[i] = m[i];
                local_reverse[m[i]] = static_cast<uint8_t>(i);
            }
        }

        uint8_t saved_opcode_map[256];
        uint8_t saved_reverse_map[256];
        memcpy(saved_opcode_map, vm.opcode_map, 256);
        memcpy(saved_reverse_map, vm.reverse_map, 256);

        memcpy(vm.opcode_map, local_map.data(), 256);
        memcpy(vm.reverse_map, local_reverse, 256);

        handler_pool_t* saved_pool = vm.pool;
        handler_pool_t local_pool{};
        memcpy(local_pool.opcode_map, vm.opcode_map, 256);
        memcpy(local_pool.reverse_map, vm.reverse_map, 256);
        uint64_t pool_seed = 0;
        memcpy(&pool_seed, local_map.data(), 8);
        pool_seed ^= static_cast<uint64_t>(func_rva) * 0x9E3779B97F4A7C15ULL;
        local_pool.pool_seed = pool_seed;
        build_handler_pool(local_pool, local_pool.reverse_map, pool_seed ^ 0x428A2F98D728AE22ULL);
        build_poly_table(local_pool);
        build_handler_set(local_pool);
        vm.pool = &local_pool;

        uint64_t result = vm_execute(vm, bytecode, bc_size);

        vm.pool = saved_pool;
        memcpy(vm.opcode_map, saved_opcode_map, 256);
        memcpy(vm.reverse_map, saved_reverse_map, 256);

        SecureZeroMemory(local_map.data(), 256);
        SecureZeroMemory(local_reverse, 256);
        SecureZeroMemory(saved_opcode_map, 256);
        SecureZeroMemory(saved_reverse_map, 256);
        SecureZeroMemory(&local_pool, sizeof(local_pool));

        return result;
    }

    inline void encrypt_bytecode(std::vector<uint8_t>& bc, uint64_t initial_key)
    {
        cipher_stream_t s;
        cipher_stream_init(s, initial_key ^ 0x6A09E667F3BCC908ULL);
        for (size_t i = 0; i < bc.size(); ++i)
            bc[i] = cipher_stream_xcrypt(s, bc[i], true);
        SecureZeroMemory(&s, sizeof(s));
    }

    inline uint32_t dag_operand_size_for_op(uint8_t raw_op)
    {
        switch (raw_op)
        {
        case OP_NOP:        return 0;
        case OP_LOAD_IMM:   return 1 + 8;
        case OP_LOAD_REG:   return 2;
        case OP_STORE_REG:  return 2;
        case OP_NAND:       return 3;
        case OP_NOR:        return 3;
        case OP_XOR:        return 3;
        case OP_SHL:        return 3;
        case OP_SHR:        return 3;
        case OP_NOT:        return 2;
        case OP_CMP:        return 2;
        case OP_JMP:        return 4;
        case OP_JZ:         return 4;
        case OP_JNZ:        return 4;
        case OP_PUSH:       return 1;
        case OP_POP:        return 1;
        case OP_HASH:       return 2;
        case OP_RDTSC:      return 1;
        case OP_SIPHASH:    return 2;
        case OP_HALT:       return 0;
        case OP_TRAP:       return 0;
        case OP_VERIFY:     return 1 + 8;
        case OP_ROL:        return 3;
        case OP_ROR:        return 3;
        case OP_LOAD_MEM:   return 2;
        case OP_STORE_MEM:  return 2;
        case OP_ADD:        return 3;
        case OP_SUB:        return 3;
        case OP_VM_ENTER:   return 8;
        case OP_VM_EXIT:    return 0;
        case OP_LOAD_IMM8:  return 2;
        case OP_LOAD_IMM16: return 3;
        case OP_LOAD_IMM32: return 5;
        case OP_MUL:        return 2;
        case OP_IMUL:       return 2;
        case OP_DIV:        return 2;
        case OP_IDIV:       return 2;
        case OP_CMOV:       return 2;
        case OP_SETCC:      return 1;
        case OP_VCALL:      return 4;
        case OP_VRET:       return 0;
        case OP_JL:         return 4;
        case OP_JLE:        return 4;
        case OP_JG:         return 4;
        case OP_JGE:        return 4;
        case OP_JB:         return 4;
        case OP_JBE:        return 4;
        case OP_JS:         return 4;
        case OP_JO:         return 4;
        case OP_LAHF:       return 1;
        case OP_SAHF:       return 1;
        case OP_JNB:        return 4;
        case OP_JNBE:       return 4;
        case OP_VM_SPAWN:   return 1 + 4 + 4 + 1;
        default:            return 0;
        }
    }

    inline bool dag_op_is_unconditional_branch(uint8_t raw_op)
    {
        return raw_op == OP_JMP;
    }

    inline bool dag_op_is_conditional_branch(uint8_t raw_op)
    {
        switch (raw_op)
        {
        case OP_JZ: case OP_JNZ: case OP_JL: case OP_JLE:
        case OP_JG: case OP_JGE: case OP_JB: case OP_JBE:
        case OP_JS: case OP_JO: case OP_JNB: case OP_JNBE:
            return true;
        default:
            return false;
        }
    }

    inline bool dag_op_is_terminator(uint8_t raw_op)
    {
        return raw_op == OP_HALT || raw_op == OP_TRAP || raw_op == OP_VM_EXIT;
    }

    inline bool dag_op_is_call(uint8_t raw_op)
    {
        return raw_op == OP_VCALL;
    }

    inline bool dag_op_is_return(uint8_t raw_op)
    {
        return raw_op == OP_VRET;
    }

    inline uint32_t dag_decrypt_target_u32(const uint8_t* bc, uint32_t bc_size,
                                           uint32_t bc_offset, cipher_stream_t stream_copy)
    {
        if (bc_offset + 4 > bc_size) return 0;
        uint8_t buf[4];
        for (int i = 0; i < 4; ++i)
            buf[i] = cipher_stream_xcrypt(stream_copy, bc[bc_offset + i], false);
        uint32_t target = 0;
        memcpy(&target, buf, 4);
        return target;
    }

    inline std::vector<dag_node_t> build_dag_from_bytecode(const std::vector<uint8_t>& bc,
                                                           const uint8_t opcode_map[256],
                                                           const uint8_t reverse_map[256],
                                                           uint64_t initial_rolling_key,
                                                           uint64_t initial_handler_chain_key,
                                                           uint64_t dag_master_key)
    {
        (void)opcode_map;
        std::vector<dag_node_t> nodes;
        if (bc.empty()) return nodes;

        cipher_stream_t stream{};
        cipher_stream_init(stream, initial_rolling_key);

        struct pending_node_t
        {
            uint32_t bc_offset;
            uint32_t bc_length;
            uint64_t enter_hash;
            uint64_t handler_chain;
            uint8_t  raw_op;
            uint32_t target_offset;
            bool     is_branch;
            bool     is_unconditional;
            bool     is_terminator;
            bool     is_call;
            bool     is_return;
        };

        std::vector<pending_node_t> pending;
        uint32_t bc_size = static_cast<uint32_t>(bc.size());
        uint32_t pos = 0;
        uint32_t node_index = 0;

        while (pos < bc_size)
        {
            pending_node_t node{};
            node.bc_offset = pos;

            uint64_t encrypted_byte_seed = static_cast<uint64_t>(bc[pos])
                ^ (static_cast<uint64_t>(pos) * 0xC6BC279692B5C323ULL);
            uint64_t entry_handler_chain = (dag_master_key * 0x517CC1B727220A95ULL)
                                          ^ (static_cast<uint64_t>(node_index) * 0x9E3779B97F4A7C15ULL)
                                          ^ encrypted_byte_seed;
            node.handler_chain = entry_handler_chain;
            node.enter_hash = dag_state_hash(dag_master_key,
                                             static_cast<uint64_t>(node_index),
                                             entry_handler_chain);

            uint8_t encrypted_op = bc[pos];
            uint8_t mapped_op = cipher_stream_xcrypt(stream, encrypted_op, false);
            uint8_t raw_op = reverse_map[mapped_op];
            node.raw_op = raw_op;
            ++pos;
            ++node_index;

            uint32_t op_size = dag_operand_size_for_op(raw_op);

            if (raw_op == OP_JMP || raw_op == OP_JZ || raw_op == OP_JNZ
                || raw_op == OP_JL || raw_op == OP_JLE || raw_op == OP_JG
                || raw_op == OP_JGE || raw_op == OP_JB || raw_op == OP_JBE
                || raw_op == OP_JS || raw_op == OP_JO || raw_op == OP_JNB
                || raw_op == OP_JNBE || raw_op == OP_VCALL)
            {
                cipher_stream_t target_stream = stream;
                node.target_offset = dag_decrypt_target_u32(bc.data(), bc_size, pos, target_stream);
            }
            else
            {
                node.target_offset = 0xFFFFFFFFu;
            }

            for (uint32_t i = 0; i < op_size && pos < bc_size; ++i)
            {
                uint8_t enc = bc[pos];
                cipher_stream_xcrypt(stream, enc, false);
                ++pos;
            }

            node.bc_length = pos - node.bc_offset;
            node.is_branch = dag_op_is_conditional_branch(raw_op) || dag_op_is_unconditional_branch(raw_op);
            node.is_unconditional = dag_op_is_unconditional_branch(raw_op);
            node.is_terminator = dag_op_is_terminator(raw_op);
            node.is_call = dag_op_is_call(raw_op);
            node.is_return = dag_op_is_return(raw_op);

            pending.push_back(node);
        }

        std::unordered_map<uint32_t, uint32_t> offset_to_index;
        for (uint32_t i = 0; i < static_cast<uint32_t>(pending.size()); ++i)
            offset_to_index[pending[i].bc_offset] = i;

        nodes.resize(pending.size());
        for (uint32_t i = 0; i < pending.size(); ++i)
        {
            const pending_node_t& p = pending[i];
            dag_node_t& out = nodes[i];
            out.bc_offset = p.bc_offset;
            out.bc_length = p.bc_length;
            out.enter_hash = p.enter_hash;
            out.handler_chain = p.handler_chain;

            if (p.is_terminator)
            {
                out.next_node_a = UINT32_MAX;
                out.next_node_b = UINT32_MAX;
            }
            else if (p.is_return)
            {
                out.next_node_a = (i + 1 < pending.size()) ? (i + 1) : UINT32_MAX;
                out.next_node_b = UINT32_MAX;
            }
            else if (p.is_unconditional)
            {
                auto it = offset_to_index.find(p.target_offset);
                out.next_node_a = (it != offset_to_index.end()) ? it->second : UINT32_MAX;
                out.next_node_b = UINT32_MAX;
            }
            else if (p.is_branch)
            {
                uint32_t fall_through = (i + 1 < pending.size()) ? (i + 1) : UINT32_MAX;
                auto it = offset_to_index.find(p.target_offset);
                uint32_t taken = (it != offset_to_index.end()) ? it->second : UINT32_MAX;
                out.next_node_a = fall_through;
                out.next_node_b = taken;
            }
            else if (p.is_call)
            {
                auto it = offset_to_index.find(p.target_offset);
                out.next_node_a = (it != offset_to_index.end()) ? it->second : UINT32_MAX;
                out.next_node_b = UINT32_MAX;
            }
            else
            {
                out.next_node_a = (i + 1 < pending.size()) ? (i + 1) : UINT32_MAX;
                out.next_node_b = UINT32_MAX;
            }
        }

        SecureZeroMemory(&stream, sizeof(stream));
        return nodes;
    }

}


namespace integrity_vm
{

    struct vm_check_t
    {
        detail::vm_state_t vm;
        std::vector<uint8_t> bytecode;
        uint64_t expected_result;
        uint64_t encryption_seed;
        bool initialized;
    };

    inline vm_check_t& get_checker()
    {
        static vm_check_t c{};
        return c;
    }

    inline void emit_encrypted(std::vector<uint8_t>& bc, uint8_t val)
    {
        bc.push_back(val);
    }

    inline void emit_load_imm(std::vector<uint8_t>& bc, uint8_t reg, uint64_t val)
    {
        emit_encrypted(bc, detail::OP_LOAD_IMM);
        emit_encrypted(bc, reg);
        uint8_t bytes[8];
        memcpy(bytes, &val, 8);
        for (int i = 0; i < 8; ++i)
            emit_encrypted(bc, bytes[i]);
    }

    inline void emit_op2(std::vector<uint8_t>& bc, uint8_t op, uint8_t a, uint8_t b)
    {
        emit_encrypted(bc, op);
        emit_encrypted(bc, a);
        emit_encrypted(bc, b);
    }

    inline void emit_op1(std::vector<uint8_t>& bc, uint8_t op, uint8_t a)
    {
        emit_encrypted(bc, op);
        emit_encrypted(bc, a);
    }

    inline bool build_integrity_check(uint64_t code_base, uint32_t code_size, uint64_t text_hash)
    {
        auto& c = get_checker();

        uint64_t seed = detail::secure_seed() ^ reinterpret_cast<uint64_t>(&c);
        c.encryption_seed = seed;
        detail::init_vm(c.vm, seed);
        c.bytecode.clear();

        auto& bc = c.bytecode;

        emit_load_imm(bc, 0, 0);
        emit_load_imm(bc, 1, code_base);
        emit_load_imm(bc, 2, static_cast<uint64_t>(code_size / 8));
        emit_load_imm(bc, 3, 0);
        emit_load_imm(bc, 4, 0xA5A5A5A5A5A5A5A5ULL);
        emit_load_imm(bc, 5, 8);

        uint32_t loop_start = static_cast<uint32_t>(bc.size());

        emit_op2(bc, detail::OP_CMP, 3, 2);
        uint32_t jz_pos = static_cast<uint32_t>(bc.size());
        emit_encrypted(bc, detail::OP_JZ);
        size_t jz_target_pos = bc.size();
        bc.push_back(0); bc.push_back(0); bc.push_back(0); bc.push_back(0);

        emit_load_imm(bc, 6, 0);
        emit_op2(bc, detail::OP_SIPHASH, 0, 6);

        emit_op2(bc, detail::OP_LOAD_REG, 7, 6);
        emit_op2(bc, detail::OP_XOR, 7, 4);
        emit_op2(bc, detail::OP_HASH, 0, 7);

        emit_load_imm(bc, 8, 1);
        emit_op2(bc, detail::OP_ADD, 3, 8);
        emit_op2(bc, detail::OP_ADD, 1, 5);

        emit_encrypted(bc, detail::OP_JMP);
        uint8_t ls_bytes[4];
        memcpy(ls_bytes, &loop_start, 4);
        for (int i = 0; i < 4; ++i) bc.push_back(ls_bytes[i]);

        uint32_t loop_end = static_cast<uint32_t>(bc.size());
        memcpy(bc.data() + jz_target_pos, &loop_end, 4);

        emit_encrypted(bc, detail::OP_HALT);

        detail::encrypt_bytecode(bc, seed);

        c.expected_result = text_hash;
        c.initialized = true;
        return true;
    }

    inline uint64_t run_check()
    {
        auto& c = get_checker();
        if (!c.initialized) return 0;

        for (int i = 0; i < 16; ++i)
            detail::write_vreg(c.vm, static_cast<uint8_t>(i), 0ULL);
        c.vm.rsp = c.vm.stack_size;
        c.vm.rip = 0;
        memset(&c.vm.vflags, 0, sizeof(detail::vflags_t));
        c.vm.halted = false;
        c.vm.insn_count = 0;
        c.vm.last_op_result = 0;
        c.vm.anti_emu_counter = 0;
        c.vm.anti_emu_corruption_flags = 0;
        c.vm.anti_emu_handler_t0 = 0;
        c.vm.anti_emu_window_count = 0;
        c.vm.rolling_key = c.encryption_seed ^ 0x6A09E667F3BCC908ULL;
        detail::cipher_stream_init(c.vm.stream, c.vm.rolling_key);

        return detail::vm_execute(c.vm, c.bytecode.data(),
            static_cast<uint32_t>(c.bytecode.size()));
    }

}


namespace opaque
{

    __forceinline uint64_t state_dependent_hash(uint64_t x)
    {
        uint8_t buf[8];
        memcpy(buf, &x, 8);
        return integrity::siphash::hash(buf, 8,
            x ^ 0x736970686173684BULL, x ^ 0x646F72616E64311ULL);
    }

    __forceinline bool predicate_always_true(uint64_t x)
    {
        uint64_t h = state_dependent_hash(x);


        constexpr uint64_t p = 257;
        uint64_t a = (h % (p - 1)) + 1;
        uint64_t exp = p - 1;
        uint64_t result = 1;
        uint64_t base = a % p;
        while (exp > 0)
        {
            if (exp & 1) result = (result * base) % p;
            base = (base * base) % p;
            exp >>= 1;
        }
        return result == 1;
    }

    __forceinline bool predicate_always_false(uint64_t x)
    {
        return !predicate_always_true(x);
    }

    __forceinline uint64_t opaque_constant(uint64_t val, uint64_t noise)
    {
        uint64_t h = state_dependent_hash(noise);
        uint64_t zero = h ^ h;
        return val + zero;
    }

    __forceinline uint64_t opaque_zero(uint64_t noise)
    {
        uint64_t h = state_dependent_hash(noise);
        return h ^ h;
    }

}


namespace junk
{

    inline __declspec(noinline) volatile int dead_computation_a(volatile int seed)
    {
        volatile int x = seed ^ 0x5A5A;
        for (volatile int i = 0; i < 1; ++i)
        {
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF;
            x ^= x >> 16;
        }
        return x;
    }

    inline __declspec(noinline) volatile int dead_computation_b(volatile int seed)
    {
        volatile int x = seed;
        x = ((x << 13) ^ x) - (x >> 21);
        x = ((x << 5) ^ x) + (x >> 3);
        return x;
    }

    inline __declspec(noinline) void insert_junk_sled()
    {
        volatile int a = dead_computation_a(static_cast<int>(__rdtsc() & 0xFF));
        volatile int b = dead_computation_b(a);
        volatile int c = a ^ b;
        (void)c;
    }

}

inline uint64_t g_server_poly_seed = 0;

inline void reseed_from_server(uint64_t server_nonce)
{
    uint8_t nonce_hex[17];
    for (int i = 0; i < 8; ++i)
    {
        uint8_t nibble_hi = static_cast<uint8_t>((server_nonce >> (60 - i * 8)) & 0xF);
        uint8_t nibble_lo = static_cast<uint8_t>((server_nonce >> (56 - i * 8)) & 0xF);
        nonce_hex[i * 2]     = nibble_hi < 10 ? ('0' + nibble_hi) : ('a' + nibble_hi - 10);
        nonce_hex[i * 2 + 1] = nibble_lo < 10 ? ('0' + nibble_lo) : ('a' + nibble_lo - 10);
    }
    nonce_hex[16] = 0;

    const char prefix[] = "opcode_map|";
    uint8_t hmac_input[27];
    memcpy(hmac_input, prefix, 11);
    memcpy(hmac_input + 11, nonce_hex, 16);

    uint8_t key_seed[32];
    detail::bcrypt_random(key_seed, 32);

    uint8_t prk[32];
    detail::hmac_sha256(key_seed, 32, hmac_input, 27, prk);

    uint64_t derived[4];
    detail::hkdf_expand_sha256(prk, hmac_input, 27,
                                reinterpret_cast<uint8_t*>(derived), 32);

    g_server_poly_seed = derived[0] ^ derived[1];

    uint64_t opcode_seed = derived[2];
    uint64_t key_schedule = derived[3];

    auto& c = integrity_vm::get_checker();
    if (c.initialized)
    {
        c.encryption_seed = opcode_seed ^ key_schedule;
        c.vm.rolling_key = c.encryption_seed ^ 0x6A09E667F3BCC908ULL;
        c.vm.handler_chain_key = c.encryption_seed ^ 0xBB67AE8584CAA73BULL;
        c.vm.context_entropy = key_schedule ^ derived[0];
        detail::cipher_stream_init(c.vm.stream, c.vm.rolling_key);

        detail::generate_opcode_map(c.encryption_seed, c.vm.opcode_map, c.vm.reverse_map);
        detail::build_handler_pool(c.vm.reverse_map,
            c.encryption_seed ^ 0x428A2F98D728AE22ULL);

        if (detail::g_poly_initialized)
        {
            detail::g_poly_initialized = false;
            detail::build_poly_table();
        }

        detail::g_default_pool.handler_set.initialized = false;
        detail::build_handler_set(detail::g_default_pool);

        detail::shuffle_registers(c.vm);
    }

    SecureZeroMemory(key_seed, 32);
    SecureZeroMemory(prk, 32);
    SecureZeroMemory(derived, 32);
}


namespace pool_manager {

    inline std::mutex& mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::vector<std::unique_ptr<detail::handler_pool_t>>& owner()
    {
        static std::vector<std::unique_ptr<detail::handler_pool_t>> v;
        return v;
    }

    inline std::unordered_map<uint64_t, detail::handler_pool_t*>& index()
    {
        static std::unordered_map<uint64_t, detail::handler_pool_t*> m;
        return m;
    }

    inline detail::handler_pool_t* get_or_create(uint64_t func_rva, uint64_t master_key)
    {
        std::lock_guard<std::mutex> lk(mtx());
        auto& idx = index();
        auto it = idx.find(func_rva);
        if (it != idx.end())
            return it->second;

        uint8_t master32[32];
        {
            uint8_t seed_input[16];
            uint64_t magic = 0xA54FF53A5F1D36F1ULL;
            memcpy(seed_input, &master_key, 8);
            memcpy(seed_input + 8, &magic, 8);
            uint8_t prk[32];
            detail::hmac_sha256(state::g_vm_master_key, 32, seed_input, 16, prk);
            static const uint8_t info[10] = {
                'v','m','_','m','k','_','m','i','x','2'
            };
            detail::hkdf_expand_sha256(prk, info, 10, master32, 32);
            SecureZeroMemory(prk, 32);
            SecureZeroMemory(seed_input, 16);
        }

        uint64_t pool_seed = 0;
        memcpy(&pool_seed, master32, 8);
        pool_seed ^= func_rva * 0x9E3779B97F4A7C15ULL;
        pool_seed ^= integrity::siphash::siphash_3u64(master_key, func_rva, pool_seed);

        auto up = std::unique_ptr<detail::handler_pool_t>(new detail::handler_pool_t{});
        auto* raw = up.get();
        memset(raw, 0, sizeof(*raw));
        raw->pool_seed = pool_seed;

        detail::derive_function_maps(
            static_cast<uint32_t>(func_rva & 0xFFFFFFFFu),
            master32, raw->opcode_map, raw->reverse_map);

        detail::build_handler_pool(*raw, raw->reverse_map, pool_seed ^ 0x428A2F98D728AE22ULL);
        detail::build_poly_table(*raw);
        detail::build_handler_set(*raw);

        SecureZeroMemory(master32, 32);

        idx[func_rva] = raw;
        owner().push_back(std::move(up));
        return raw;
    }

    inline void clear_all()
    {
        std::lock_guard<std::mutex> lk(mtx());
        for (auto& up : owner())
        {
            if (up && up->hot_block_counts)
            {
                delete up->hot_block_counts;
                up->hot_block_counts = nullptr;
            }
        }
        index().clear();
        owner().clear();
    }

}


namespace homomorphic_pool_t {

    struct entry_t
    {
        uint64_t encrypted_imm;
        uint8_t  domain_tag[16];
        uint64_t reg_state_anchor;
        uint64_t rolling_anchor;
        uint32_t handler_chain_seed;
    };

    struct pool_t
    {
        std::vector<entry_t> entries;
        uint8_t              function_key[32];
        uint64_t             function_rva;
        uint64_t             pool_seed;
        bool                 active;
    };

    inline std::mutex& mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::unordered_map<uint64_t, std::unique_ptr<pool_t>>& registry()
    {
        static std::unordered_map<uint64_t, std::unique_ptr<pool_t>> r;
        return r;
    }

    inline void derive_per_function_key(uint64_t function_rva,
                                        uint64_t pool_seed,
                                        uint8_t out_key[32])
    {
        uint8_t info[24];
        memcpy(info, "aida_hpool_keyderiv_v1", 22);
        info[22] = static_cast<uint8_t>(function_rva & 0xFF);
        info[23] = static_cast<uint8_t>((function_rva >> 8) & 0xFF);

        uint8_t ikm[16];
        memcpy(ikm, &function_rva, 8);
        memcpy(ikm + 8, &pool_seed, 8);

        uint8_t prk[32];
        detail::hmac_sha256(state::g_vm_master_key, 32, ikm, 16, prk);
        detail::hkdf_expand_sha256(prk, info, 24, out_key, 32);

        SecureZeroMemory(prk, 32);
        SecureZeroMemory(ikm, 16);
        SecureZeroMemory(info, 24);
    }

    inline pool_t* get_or_create(uint64_t function_rva, uint64_t pool_seed)
    {
        std::lock_guard<std::mutex> lk(mtx());
        auto& r = registry();
        auto it = r.find(function_rva);
        if (it != r.end())
            return it->second.get();

        auto up = std::unique_ptr<pool_t>(new pool_t{});
        up->function_rva = function_rva;
        up->pool_seed = pool_seed;
        up->active = true;
        derive_per_function_key(function_rva, pool_seed, up->function_key);

        pool_t* raw = up.get();
        r[function_rva] = std::move(up);
        return raw;
    }

    inline uint64_t derive_imm_key(const uint8_t function_key[32],
                                    uint64_t reg_state_anchor,
                                    uint64_t rolling_anchor,
                                    uint32_t handler_chain_seed,
                                    const uint8_t domain_tag[16])
    {
        uint8_t input[40];
        memcpy(input, &reg_state_anchor, 8);
        memcpy(input + 8, &rolling_anchor, 8);
        memcpy(input + 16, &handler_chain_seed, 4);
        memcpy(input + 20, domain_tag, 16);
        memcpy(input + 36, &handler_chain_seed, 4);

        uint8_t mac[32];
        detail::hmac_sha256(function_key, 32, input, 40, mac);

        uint64_t key;
        memcpy(&key, mac, 8);

        SecureZeroMemory(mac, 32);
        SecureZeroMemory(input, 40);
        return key;
    }

    inline uint32_t register_immediate(pool_t& pool,
                                        uint64_t plaintext_imm,
                                        uint64_t reg_state_anchor,
                                        uint64_t rolling_anchor)
    {
        std::lock_guard<std::mutex> lk(mtx());

        entry_t e{};
        e.reg_state_anchor = reg_state_anchor;
        e.rolling_anchor = rolling_anchor;

        uint8_t entropy[20];
        if (!detail::bcrypt_random(entropy, 20))
        {
            uint64_t fb = __rdtsc() ^ static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&pool));
            memcpy(entropy, &fb, 8);
            uint64_t fb2 = _rotl64(fb, 17) ^ pool.pool_seed;
            memcpy(entropy + 8, &fb2, 8);
            uint32_t fb3 = static_cast<uint32_t>(fb2 >> 32);
            memcpy(entropy + 16, &fb3, 4);
        }
        memcpy(e.domain_tag, entropy, 16);
        memcpy(&e.handler_chain_seed, entropy + 16, 4);

        uint64_t imm_key = derive_imm_key(pool.function_key,
                                          reg_state_anchor,
                                          rolling_anchor,
                                          e.handler_chain_seed,
                                          e.domain_tag);
        e.encrypted_imm = plaintext_imm ^ imm_key;

        SecureZeroMemory(entropy, 20);

        uint32_t idx = static_cast<uint32_t>(pool.entries.size());
        pool.entries.push_back(e);
        return idx;
    }

    __forceinline uint64_t resolve_immediate(const pool_t& pool,
                                             uint32_t entry_index,
                                             uint64_t live_reg_state,
                                             uint64_t live_rolling_key)
    {
        if (entry_index >= pool.entries.size() || !pool.active)
            return 0;

        const entry_t& e = pool.entries[entry_index];

        uint64_t reg_anchor = e.reg_state_anchor ^ live_reg_state ^ e.reg_state_anchor;
        uint64_t roll_anchor = e.rolling_anchor ^ live_rolling_key ^ e.rolling_anchor;

        uint64_t imm_key = derive_imm_key(pool.function_key,
                                          reg_anchor,
                                          roll_anchor,
                                          e.handler_chain_seed,
                                          e.domain_tag);
        uint64_t plaintext = e.encrypted_imm ^ imm_key;

        volatile uint64_t scrub_key = imm_key;
        scrub_key ^= scrub_key;
        (void)scrub_key;

        return plaintext;
    }

    inline void destroy(uint64_t function_rva)
    {
        std::lock_guard<std::mutex> lk(mtx());
        auto& r = registry();
        auto it = r.find(function_rva);
        if (it == r.end()) return;

        if (it->second)
        {
            it->second->active = false;
            for (auto& e : it->second->entries)
            {
                e.encrypted_imm = 0;
                memset(e.domain_tag, 0, 16);
                e.reg_state_anchor = 0;
                e.rolling_anchor = 0;
                e.handler_chain_seed = 0;
            }
            SecureZeroMemory(it->second->function_key, 32);
            it->second->entries.clear();
        }
        r.erase(it);
    }

    inline void clear_all()
    {
        std::lock_guard<std::mutex> lk(mtx());
        auto& r = registry();
        for (auto& kv : r)
        {
            if (kv.second)
            {
                kv.second->active = false;
                for (auto& e : kv.second->entries)
                {
                    e.encrypted_imm = 0;
                    memset(e.domain_tag, 0, 16);
                }
                SecureZeroMemory(kv.second->function_key, 32);
                kv.second->entries.clear();
            }
        }
        r.clear();
    }

}


inline bool initialize(uint64_t code_base, uint32_t code_size, uint64_t text_hash)
{
    junk::insert_junk_sled();

    if (!integrity_vm::build_integrity_check(code_base, code_size, text_hash))
        return false;

    junk::insert_junk_sled();
    return true;
}

inline uint64_t run_vm_integrity_check()
{
    junk::insert_junk_sled();

    if (opaque::predicate_always_true(__rdtsc()))
    {
        return integrity_vm::run_check();
    }

    if (opaque::predicate_always_false(__rdtsc()))
    {
        __fastfail(0xDEAD);
    }

    return 0;
}

inline uint64_t get_expected_hash()
{
    return integrity_vm::get_checker().expected_result;
}


namespace protection {

    static constexpr uint32_t MAX_PROTECTED = 128;

    struct protected_func_t
    {
        uint64_t original_addr;
        uint32_t original_len;
        std::vector<uint8_t> bytecode;
        uint64_t vm_seed;
        void* trampoline;
        bool active;
    };

    struct protection_state_t
    {
        protected_func_t entries[MAX_PROTECTED];
        uint32_t count;
        void* trampoline_page;
        uint32_t trampoline_offset;
        bool initialized;
    };

    inline protection_state_t& get_state()
    {
        static protection_state_t s{};
        return s;
    }

    inline bool init_protection()
    {
        auto& s = get_state();
        if (s.initialized) return true;
        s.trampoline_page = VirtualAlloc(nullptr, 65536,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!s.trampoline_page) return false;
        s.trampoline_offset = 0;
        s.count = 0;
        s.initialized = true;
        return true;
    }

    typedef uint64_t(*vm_entry_fn)(uint64_t, uint64_t, uint64_t, uint64_t);

    inline uint64_t vm_trampoline_execute(protected_func_t* entry,
                                          uint64_t arg0, uint64_t arg1,
                                          uint64_t arg2, uint64_t arg3)
    {
        detail::vm_state_t vm;
        detail::init_vm(vm, entry->vm_seed);
        detail::write_vreg(vm, 0, arg0);
        detail::write_vreg(vm, 1, arg1);
        detail::write_vreg(vm, 2, arg2);
        detail::write_vreg(vm, 3, arg3);
        return detail::vm_execute(vm, entry->bytecode.data(),
            static_cast<uint32_t>(entry->bytecode.size()));
    }

    inline bool protect_function(void* func, size_t func_len,
                                   const std::vector<uint8_t>& compiled_bytecode,
                                   uint64_t seed)
    {
        auto& s = get_state();
        if (!s.initialized) {
            if (!init_protection()) return false;
        }
        if (s.count >= MAX_PROTECTED) return false;
        if (compiled_bytecode.empty()) return false;

        uint64_t base_addr = reinterpret_cast<uint64_t>(func);

        auto& entry = s.entries[s.count];
        entry.original_addr = base_addr;
        entry.original_len = static_cast<uint32_t>(func_len);
        entry.vm_seed = seed;
        entry.bytecode = compiled_bytecode;

        auto* tramp = static_cast<uint8_t*>(s.trampoline_page) + s.trampoline_offset;
        entry.trampoline = tramp;

        uint64_t entry_ptr = reinterpret_cast<uint64_t>(&s.entries[s.count]);
        tramp[0] = 0x48; tramp[1] = 0xB9;
        memcpy(tramp + 2, &entry_ptr, 8);

        uint64_t exec_addr = reinterpret_cast<uint64_t>(&vm_trampoline_execute);
        tramp[10] = 0x48; tramp[11] = 0xBA;
        memcpy(tramp + 12, &exec_addr, 8);

        tramp[20] = 0xFF; tramp[21] = 0xE2;

        s.trampoline_offset += 32;

        DWORD old_prot;
        VirtualProtect(func, func_len > 14 ? func_len : 14,
            PAGE_EXECUTE_READWRITE, &old_prot);

        auto* target = static_cast<uint8_t*>(func);
        target[0] = 0xFF;
        target[1] = 0x25;
        *reinterpret_cast<uint32_t*>(target + 2) = 0;
        *reinterpret_cast<uint64_t*>(target + 6) = reinterpret_cast<uint64_t>(tramp);

        for (size_t i = 14; i < func_len && i < 64; ++i)
            target[i] = 0xCC;

        VirtualProtect(func, func_len > 14 ? func_len : 14, old_prot, &old_prot);

        entry.active = true;
        s.count++;
        return true;
    }

    inline void reencrypt_live_bytecode()
    {
        auto& s = get_state();
        for (uint32_t i = 0; i < s.count; ++i) {
            auto& entry = s.entries[i];
            if (!entry.active || entry.bytecode.empty()) continue;

            uint64_t old_key = entry.vm_seed ^ 0x6A09E667F3BCC908ULL;
            uint64_t new_seed = entry.vm_seed ^ detail::secure_seed() ^
                (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);

            std::vector<uint8_t> raw(entry.bytecode.size());
            uint64_t dk = old_key;
            for (size_t j = 0; j < entry.bytecode.size(); ++j) {
                uint8_t kb = static_cast<uint8_t>(dk & 0xFF);
                dk ^= dk << 13; dk ^= dk >> 7; dk ^= dk << 17;
                raw[j] = entry.bytecode[j] ^ kb;
            }

            entry.vm_seed = new_seed;
            uint64_t new_key = new_seed ^ 0x6A09E667F3BCC908ULL;
            uint64_t ek = new_key;
            for (size_t j = 0; j < raw.size(); ++j) {
                uint8_t kb = static_cast<uint8_t>(ek & 0xFF);
                ek ^= ek << 13; ek ^= ek >> 7; ek ^= ek << 17;
                entry.bytecode[j] = raw[j] ^ kb;
            }

            volatile uint8_t* vraw = raw.data();
            for (size_t j = 0; j < raw.size(); ++j) vraw[j] = 0;
        }
    }

}

}

}
