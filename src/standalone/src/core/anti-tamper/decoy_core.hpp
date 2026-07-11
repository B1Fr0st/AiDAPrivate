#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include "key_pipeline.hpp"

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace anti_tamper {
namespace ai_deception {
namespace decoy_core {

    static constexpr size_t k_payload_size = 65536;
    static constexpr uint32_t CANARY_TOTAL_SIZE = 52;
    static constexpr uint32_t CANARY_DATA_SIZE  = 48;
    static constexpr uint32_t CANARY_CRC_SIZE   = 4;

    inline uint32_t canary_crc32_ieee(const uint8_t* data, size_t len) noexcept
    {
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < len; ++i)
        {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j)
            {
                uint32_t mask = -(crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
        return ~crc;
    }

    enum class canary_verify_result_t : uint8_t {
        INTACT     = 0,
        CORRUPTION = 1,
        PATCHED    = 2,
    };

    inline canary_verify_result_t verify_canary_integrity(
        const uint8_t* canary, const uint8_t* baseline, size_t len) noexcept
    {
        if (len < CANARY_TOTAL_SIZE) return canary_verify_result_t::CORRUPTION;

        uint32_t stored_crc;
        std::memcpy(&stored_crc, canary + CANARY_DATA_SIZE, CANARY_CRC_SIZE);
        uint32_t computed_crc = canary_crc32_ieee(canary, CANARY_DATA_SIZE);

        if (computed_crc != stored_crc)
            return canary_verify_result_t::CORRUPTION;

        if (std::memcmp(canary, baseline, CANARY_DATA_SIZE) != 0)
            return canary_verify_result_t::PATCHED;

        return canary_verify_result_t::INTACT;
    }

    inline void compute_canary_crc_field(uint8_t* canary) noexcept
    {
        uint32_t crc = canary_crc32_ieee(canary, CANARY_DATA_SIZE);
        canary[48] = static_cast<uint8_t>(crc & 0xFFu);
        canary[49] = static_cast<uint8_t>((crc >> 8) & 0xFFu);
        canary[50] = static_cast<uint8_t>((crc >> 16) & 0xFFu);
        canary[51] = static_cast<uint8_t>((crc >> 24) & 0xFFu);
    }

    alignas(16) static constexpr uint8_t kDecoyCoreKey[16] = {
        0x5A, 0x3C, 0x91, 0x17, 0xBE, 0x04, 0x4F, 0x22,
        0xD1, 0x68, 0xAA, 0x73, 0x3E, 0x52, 0x9B, 0xC6
    };
    alignas(16) static constexpr uint8_t kDecoyCoreIv[16] = {
        0x8F, 0x21, 0x0C, 0x44, 0x77, 0xE9, 0x13, 0xB2,
        0x05, 0x6A, 0xC3, 0x18, 0x90, 0x4D, 0xFB, 0x29
    };

    inline uint8_t* payload_buffer() noexcept
    {
        static uint8_t buffer[k_payload_size];
        return buffer;
    }

    inline std::once_flag& init_flag() noexcept
    {
        static std::once_flag f;
        return f;
    }

    inline std::atomic<bool>& decoy_mode_flag() noexcept
    {
        static std::atomic<bool> flag{ false };
        return flag;
    }

    inline uint64_t xorshift64(uint64_t& s) noexcept
    {
        if (s == 0) s = 0x9E3779B97F4A7C15ULL;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }

    inline void write_le32(uint8_t* p, uint32_t v) noexcept
    {
        p[0] = static_cast<uint8_t>(v & 0xFFu);
        p[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
        p[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
        p[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
    }

    inline void write_le16(uint8_t* p, uint16_t v) noexcept
    {
        p[0] = static_cast<uint8_t>(v & 0xFFu);
        p[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    }

    inline void build_fake_pe(uint8_t* buf) noexcept
    {
        std::memset(buf, 0, k_payload_size);

        buf[0] = 'M';
        buf[1] = 'Z';
        static const char dos_stub[] = "This program cannot be run in DOS mode.\r\n$";
        std::memcpy(buf + 0x40, dos_stub, sizeof(dos_stub) - 1);
        write_le32(buf + 0x3C, 0x80u);

        uint8_t* pe = buf + 0x80;
        pe[0] = 'P'; pe[1] = 'E'; pe[2] = 0; pe[3] = 0;
        write_le16(pe + 4, static_cast<uint16_t>(0x8664));
        write_le16(pe + 6, static_cast<uint16_t>(3));
        write_le32(pe + 8, 0x63FF1A2Cu);
        write_le32(pe + 12, 0u);
        write_le32(pe + 16, 0u);
        write_le16(pe + 20, static_cast<uint16_t>(240));
        write_le16(pe + 22, static_cast<uint16_t>(0x2022));

        uint8_t* opt = pe + 24;
        write_le16(opt + 0, static_cast<uint16_t>(0x20B));
        opt[2] = 14;
        opt[3] = 30;
        write_le32(opt + 4, 0x8000u);
        write_le32(opt + 8, 0x4000u);
        write_le32(opt + 12, 0x3000u);
        write_le32(opt + 16, 0x1000u);
        write_le32(opt + 20, 0x1000u);
        write_le32(opt + 24, 0u);
        uint8_t* opt_plus = opt + 24;
        (void)opt_plus;
        write_le32(opt + 28, 0u);
        write_le32(opt + 32, 0u);
        write_le32(opt + 36, 0u);
        write_le16(opt + 40, static_cast<uint16_t>(6));
        write_le16(opt + 42, static_cast<uint16_t>(0));
        write_le16(opt + 44, static_cast<uint16_t>(10));
        write_le16(opt + 46, static_cast<uint16_t>(0));
        write_le16(opt + 48, static_cast<uint16_t>(6));
        write_le16(opt + 50, static_cast<uint16_t>(0));
        write_le32(opt + 52, 0u);
        write_le32(opt + 56, static_cast<uint32_t>(k_payload_size));
        write_le32(opt + 60, 0x400u);
        write_le32(opt + 64, 0u);
        write_le16(opt + 68, static_cast<uint16_t>(0));
        write_le16(opt + 70, static_cast<uint16_t>(0x8160));
        write_le32(opt + 72, 0u);
        write_le32(opt + 76, 0u);
        write_le32(opt + 80, 0u);
        write_le32(opt + 84, 0u);
        write_le32(opt + 88, 0u);
        write_le32(opt + 92, 0u);
        write_le32(opt + 96, 16u);

        uint8_t* sec = buf + 0x100;
        static const char n_text[8]  = { '.', 't', 'e', 'x', 't',  0,   0,  0 };
        static const char n_rdata[8] = { '.', 'r', 'd', 'a', 't', 'a', 0,  0 };
        static const char n_data[8]  = { '.', 'd', 'a', 't', 'a',  0,   0,  0 };

        std::memcpy(sec + 0, n_text, 8);
        write_le32(sec + 8, 0x8000u);
        write_le32(sec + 12, 0x1000u);
        write_le32(sec + 16, 0x8000u);
        write_le32(sec + 20, 0x1000u);
        write_le32(sec + 24, 0u);
        write_le32(sec + 28, 0u);
        write_le16(sec + 32, 0);
        write_le16(sec + 34, 0);
        write_le32(sec + 36, 0x60000020u);

        std::memcpy(sec + 40 + 0, n_rdata, 8);
        write_le32(sec + 40 + 8, 0x4000u);
        write_le32(sec + 40 + 12, 0x9000u);
        write_le32(sec + 40 + 16, 0x4000u);
        write_le32(sec + 40 + 20, 0x9000u);
        write_le32(sec + 40 + 24, 0u);
        write_le32(sec + 40 + 28, 0u);
        write_le16(sec + 40 + 32, 0);
        write_le16(sec + 40 + 34, 0);
        write_le32(sec + 40 + 36, 0x40000040u);

        std::memcpy(sec + 80 + 0, n_data, 8);
        write_le32(sec + 80 + 8, 0x3000u);
        write_le32(sec + 80 + 12, 0xD000u);
        write_le32(sec + 80 + 16, 0x3000u);
        write_le32(sec + 80 + 20, 0xD000u);
        write_le32(sec + 80 + 24, 0u);
        write_le32(sec + 80 + 28, 0u);
        write_le16(sec + 80 + 32, 0);
        write_le16(sec + 80 + 34, 0);
        write_le32(sec + 80 + 36, 0xC0000040u);

        uint64_t rng = 0;
        {
            uint8_t derived[8] = {};
            if (!anti_tamper::key_pipeline::derive(
                    "aida.decoy.text_rng",
                    nullptr, 0,
                    derived, sizeof(derived)))
            {
                __fastfail(0xA1DAA0E3u);
            }
            std::memcpy(&rng, derived, sizeof(rng));
            SecureZeroMemory(derived, sizeof(derived));
        }
        uint8_t* text = buf + 0x1000;
        const size_t text_size = 0x8000;
        size_t off = 0;
        static const uint8_t patterns[8][4] = {
            { 0x48, 0x89, 0xC8, 0x90 },
            { 0x48, 0x01, 0xC8, 0x90 },
            { 0x48, 0x29, 0xC8, 0x90 },
            { 0x48, 0x31, 0xC8, 0x90 },
            { 0x48, 0x8D, 0x05, 0x00 },
            { 0xE8, 0x10, 0x00, 0x00 },
            { 0x48, 0x83, 0xC0, 0x10 },
            { 0x48, 0x83, 0xE8, 0x08 }
        };
        while (off + 140 < text_size)
        {
            text[off++] = 0x55;
            text[off++] = 0x48;
            text[off++] = 0x89;
            text[off++] = 0xE5;
            text[off++] = 0x48;
            text[off++] = 0x83;
            text[off++] = 0xEC;
            text[off++] = static_cast<uint8_t>(xorshift64(rng) & 0x7Fu);
            const size_t body = 60 + static_cast<size_t>(xorshift64(rng) % 61ULL);
            for (size_t i = 0; i < body && off + 4 < text_size; ++i)
            {
                const uint64_t r = xorshift64(rng);
                const uint8_t* pat = patterns[r & 7ULL];
                for (int k = 0; k < 4 && off < text_size; ++k)
                    text[off++] = pat[k];
            }
            if (off < text_size)
                text[off++] = 0xC3;
        }
        while (off < text_size)
            text[off++] = 0x90;

        uint8_t* rdata = buf + 0x9000;
        write_le32(rdata + 0, 0u);
        write_le32(rdata + 4, 0u);
        write_le32(rdata + 8, 0u);
        write_le32(rdata + 12, 0x2041494Cu);
        write_le32(rdata + 16, 1u);
        write_le32(rdata + 20, 2u);
        write_le32(rdata + 24, 2u);
        write_le32(rdata + 28, 0x9100u);
        write_le32(rdata + 32, 0x9108u);
        write_le32(rdata + 36, 0x9110u);
        write_le32(rdata + 40, 0x9000u + 200u);
        write_le32(rdata + 44, 0x9000u + 224u);

        static const char name_a[] = "DecompileFunction";
        static const char name_b[] = "AnalyzeControlFlow";
        std::memcpy(rdata + 200, name_a, sizeof(name_a));
        std::memcpy(rdata + 224, name_b, sizeof(name_b));

        static const char rdata_msg_1[] = "Hex-Rays decompiler runtime v7.7";
        static const char rdata_msg_2[] = "aida_core::AnalyzeControlFlow";
        static const char rdata_msg_3[] = "aida_core::DecompileFunction";
        std::memcpy(rdata + 512, rdata_msg_1, sizeof(rdata_msg_1));
        std::memcpy(rdata + 576, rdata_msg_2, sizeof(rdata_msg_2));
        std::memcpy(rdata + 640, rdata_msg_3, sizeof(rdata_msg_3));

        uint8_t* data = buf + 0xD000;
        static const char s_license[] = "license_ok";
        static const char s_session[] = "session_valid";
        size_t data_off = 0x100;
        for (int i = 0; i < 8 && data_off + sizeof(s_session) + 0x200 < 0x3000; ++i)
        {
            const char* s = (i & 1) ? s_license : s_session;
            const size_t n = std::strlen(s) + 1;
            std::memcpy(data + data_off, s, n);
            data_off += n + 0x200;
        }
    }

    inline bool aes_ctr_inplace(uint8_t* buf, size_t len) noexcept
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (st < 0) return false;

        st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
            sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
        if (st < 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        BCRYPT_KEY_HANDLE hKey = nullptr;
        st = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<uint8_t*>(kDecoyCoreKey)),
            static_cast<ULONG>(sizeof(kDecoyCoreKey)), 0);
        if (st < 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        uint8_t counter[16];
        std::memcpy(counter, kDecoyCoreIv, 16);
        uint8_t keystream[16];
        size_t processed = 0;
        while (processed < len)
        {
            uint8_t block_in[16];
            std::memcpy(block_in, counter, 16);
            ULONG out_bytes = 0;
            st = BCryptEncrypt(hKey, block_in, 16, nullptr, nullptr, 0,
                keystream, 16, &out_bytes, 0);
            if (st < 0 || out_bytes != 16)
            {
                BCryptDestroyKey(hKey);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return false;
            }
            const size_t block_len = (len - processed < 16) ? (len - processed) : 16;
            for (size_t i = 0; i < block_len; ++i)
                buf[processed + i] ^= keystream[i];
            processed += block_len;
            for (int i = 15; i >= 0; --i)
            {
                if (++counter[i] != 0) break;
            }
        }

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return true;
    }

    inline void init_payload() noexcept
    {
        uint8_t* buf = payload_buffer();
        build_fake_pe(buf);
        aes_ctr_inplace(buf, k_payload_size);
    }

    inline const uint8_t* get_payload() noexcept
    {
        std::call_once(init_flag(), init_payload);
        return payload_buffer();
    }

    inline size_t get_payload_size_fn() noexcept { return k_payload_size; }

    inline void compute_sha256(uint8_t out[32]) noexcept
    {
        const uint8_t* p = get_payload();
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        {
            std::memset(out, 0, 32);
            return;
        }
        BCRYPT_HASH_HANDLE hHash = nullptr;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) < 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            std::memset(out, 0, 32);
            return;
        }
        BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<uint8_t*>(p)),
            static_cast<ULONG>(k_payload_size), 0);
        BCryptFinishHash(hHash, out, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    static const char* const k_mnemonics[12] = {
        "mov", "add", "sub", "xor", "lea", "push", "pop",
        "call", "ret", "jmp", "cmp", "test"
    };
    static const char* const k_regs[16] = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
    };

    inline std::string build_decomp(uint64_t addr) noexcept
    {
        uint64_t s = addr ? addr : 0x00C0FFEEULL;
        s ^= 0x9E3779B97F4A7C15ULL;
        const size_t lines = 5 + static_cast<size_t>(xorshift64(s) % 16ULL);
        std::string out;
        out.reserve(lines * 48 + 64);
        char buf[192];
        int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "sub_%llX:\n", static_cast<unsigned long long>(addr));
        if (n > 0) out.append(buf, static_cast<size_t>(n));
        for (size_t i = 0; i < lines; ++i)
        {
            const uint64_t r = xorshift64(s);
            const char* m = k_mnemonics[r % 12ULL];
            const char* r1 = k_regs[(r >> 4) & 0xFULL];
            const char* r2 = k_regs[(r >> 8) & 0xFULL];
            const uint32_t imm = static_cast<uint32_t>(xorshift64(s) & 0xFFFFFFFFULL);
            const int mode = static_cast<int>((r >> 12) & 3ULL);
            if (std::strcmp(m, "push") == 0 || std::strcmp(m, "pop") == 0 ||
                std::strcmp(m, "call") == 0)
            {
                n = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "  %s %s\n", m, r1);
            }
            else if (std::strcmp(m, "ret") == 0)
            {
                n = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "  ret\n");
            }
            else if (std::strcmp(m, "jmp") == 0)
            {
                n = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "  jmp 0x%08X\n", imm);
            }
            else if (mode == 0)
            {
                n = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "  %s %s, %s\n", m, r1, r2);
            }
            else
            {
                n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "  %s %s, 0x%08X\n", m, r1, imm);
            }
            if (n > 0) out.append(buf, static_cast<size_t>(n));
        }
        return out;
    }

    inline std::string build_cfg(uint64_t addr) noexcept
    {
        uint64_t s = addr ? addr : 0xDEADBEEFULL;
        s ^= 0xBF58476D1CE4E5B9ULL;
        const int blocks = 2 + static_cast<int>(xorshift64(s) % 7ULL);
        const int complexity = 1 + static_cast<int>(xorshift64(s) % 5ULL);
        const int loops = static_cast<int>(xorshift64(s) % 3ULL);
        const char* loops_msg =
            (loops == 0) ? "no loops detected."
          : (loops == 1) ? "1 natural loop detected."
                         : "2 nested loops detected.";
        char buf[256];
        int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "Function at 0x%llX: %d basic blocks, cyclomatic complexity %d, %s",
            static_cast<unsigned long long>(addr), blocks, complexity, loops_msg);
        if (n <= 0) return std::string();
        return std::string(buf, static_cast<size_t>(n));
    }

    inline const char* decompile_function(uint64_t addr) noexcept
    {
        thread_local std::string tls;
        tls = build_decomp(addr);
        return tls.c_str();
    }

    inline const char* analyze_control_flow(uint64_t addr) noexcept
    {
        thread_local std::string tls;
        tls = build_cfg(addr);
        return tls.c_str();
    }

    inline void enable_decoy_mode() noexcept
    {
        decoy_mode_flag().store(true, std::memory_order_release);
        std::call_once(init_flag(), init_payload);
    }

    inline bool is_decoy_mode_active() noexcept
    {
        return decoy_mode_flag().load(std::memory_order_acquire);
    }

}

inline const uint8_t* get_decoy_core_payload() noexcept
{
    return decoy_core::get_payload();
}

inline size_t get_decoy_core_payload_size() noexcept
{
    return decoy_core::get_payload_size_fn();
}

inline void compute_decoy_core_sha256(uint8_t out[32]) noexcept
{
    decoy_core::compute_sha256(out);
}

inline const char* decoy_decompile_function(uint64_t addr) noexcept
{
    return decoy_core::decompile_function(addr);
}

inline const char* decoy_analyze_control_flow(uint64_t addr) noexcept
{
    return decoy_core::analyze_control_flow(addr);
}

inline void enable_decoy_mode() noexcept
{
    decoy_core::enable_decoy_mode();
}

inline bool is_decoy_mode_active() noexcept
{
    return decoy_core::is_decoy_mode_active();
}

inline uint32_t canary_crc32(const uint8_t* data, size_t len) noexcept
{
    return decoy_core::canary_crc32_ieee(data, len);
}

inline decoy_core::canary_verify_result_t verify_canary(
    const uint8_t* canary, const uint8_t* baseline, size_t len) noexcept
{
    return decoy_core::verify_canary_integrity(canary, baseline, len);
}

inline void compute_canary_crc(uint8_t* canary) noexcept
{
    decoy_core::compute_canary_crc_field(canary);
}

}
}
