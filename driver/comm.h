#pragma once
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <memory>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <type_traits>
#include <string>
#include <vector>
#include <intrin.h>

namespace dynamic_key {
    inline std::uint32_t g_cached_key = 0;
    inline std::uint32_t g_server_seed = 0;

    __forceinline std::uint32_t derive_server_seed(std::uint64_t server_nonce, std::uint32_t token_hash, std::uint32_t session_key) {
        std::uint64_t mix = server_nonce;
        mix ^= (static_cast<std::uint64_t>(token_hash) << 32) | session_key;

        std::uint32_t seed = static_cast<std::uint32_t>(mix) ^ static_cast<std::uint32_t>(mix >> 32);
        seed ^= _rotl(seed, 7) ^ 0x9E3779B9u;
        seed *= 0x85ebca6bu;
        seed ^= seed >> 13;
        if (seed == 0) seed = 1;
        return seed;
    }

    __forceinline std::uint32_t compute() {
        int cpu[4] = {0};
        __cpuid(cpu, 0);
        std::uint32_t h = 0x811C9DC5u;
        h = (h ^ static_cast<std::uint32_t>(cpu[1])) * 0x01000193u;
        h = (h ^ static_cast<std::uint32_t>(cpu[2])) * 0x01000193u;
        h = (h ^ static_cast<std::uint32_t>(cpu[3])) * 0x01000193u;
        __cpuid(cpu, 1);
        h = (h ^ static_cast<std::uint32_t>(cpu[0])) * 0x01000193u;
        h = (h ^ static_cast<std::uint32_t>(cpu[3])) * 0x01000193u;
        volatile std::uint32_t build = *reinterpret_cast<volatile std::uint32_t*>(static_cast<std::uintptr_t>(0x7FFE0260)) & 0xFFFFu;
        h = (h ^ build) * 0x01000193u;
        if (g_server_seed != 0) {
            h = (h ^ g_server_seed) * 0x01000193u;
            h ^= _rotl(g_server_seed, 11);
        }
        h ^= h >> 16;
        h *= 0x85ebca6bu;
        h ^= h >> 13;
        if (h == 0) h = 1;
        return h;
    }

    __forceinline std::uint32_t get() {
        if (g_cached_key != 0) return g_cached_key;
        g_cached_key = compute();
        return g_cached_key;
    }

    __forceinline void set_server_seed(std::uint64_t server_nonce, std::uint32_t token_hash, std::uint32_t session_key) {
        g_server_seed = derive_server_seed(server_nonce, token_hash, session_key);
        g_cached_key = 0;
    }

    __forceinline void reset_server_seed() {
        g_server_seed = 0;
        g_cached_key = 0;
    }
}

__forceinline std::uint32_t hash_build_key(std::uint32_t key) {
    key ^= key >> 16;
    key *= 0x85ebca6bu;
    key ^= key >> 13;
    key *= 0xc2b2ae35u;
    key ^= key >> 16;
    return key;
}

__forceinline std::uint32_t secondary_hash(std::uint32_t key) {
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = (key >> 16) ^ key;
    return key;
}

namespace ioctl_codes {
    inline std::uint32_t g_server_ioctl_seed = 0;

    __forceinline std::uint32_t get_base() {
        std::uint32_t key = dynamic_key::get();
        std::uint32_t base = ((hash_build_key(key) ^ secondary_hash(key >> 3)) & 0x7FF) | 0x800;
        if (g_server_ioctl_seed != 0) {
            base ^= hash_build_key(g_server_ioctl_seed) & 0x7FF;
            base = (base & 0x7FF) | 0x800;
        }
        return base;
    }

    __forceinline std::uint32_t derive_server_ioctl_seed(std::uint64_t server_nonce, std::uint32_t token_hash, std::uint32_t session_key) {
        std::uint32_t nonce_lo = static_cast<std::uint32_t>(server_nonce);
        std::uint32_t nonce_hi = static_cast<std::uint32_t>(server_nonce >> 32);
        std::uint32_t seed = hash_build_key(nonce_lo ^ _rotl(nonce_hi, 7) ^ token_hash ^ _rotl(session_key, 13));
        seed ^= secondary_hash(token_hash ^ session_key ^ 0xA17A5EEDu);
        if (seed == 0) seed = 1;
        return seed;
    }

    __forceinline void set_server_ioctl_seed(std::uint64_t server_nonce, std::uint32_t token_hash, std::uint32_t session_key) {
        g_server_ioctl_seed = derive_server_ioctl_seed(server_nonce, token_hash, session_key);
    }

    __forceinline void reset_server_ioctl_seed() {
        g_server_ioctl_seed = 0;
    }

    __forceinline DWORD make(std::uint32_t offset) {
        return static_cast<DWORD>(0x00220000u | ((get_base() + offset) << 2));
    }

    __forceinline DWORD DTB()  { return make(0); }
    __forceinline DWORD PHYS() { return make(1); }
    __forceinline DWORD BASE() { return make(2); }
    __forceinline DWORD RC()   { return make(4); }
    __forceinline DWORD CR()   { return make(5); }
    __forceinline DWORD AM()   { return make(6); }
    __forceinline DWORD FM()   { return make(7); }
    __forceinline DWORD HB()   { return make(8); }


    __forceinline DWORD TCTX()  { return make(9); }
    __forceinline DWORD TENUM() { return make(10); }
    __forceinline DWORD TSR()   { return make(11); }
    __forceinline DWORD QM()    { return make(12); }
    __forceinline DWORD PM()    { return make(13); }
    __forceinline DWORD ER()    { return make(14); }
    __forceinline DWORD RPEB()  { return make(15); }
    __forceinline DWORD SDF()   { return make(16); }
    __forceinline DWORD MEX()   { return make(17); }
    __forceinline DWORD V2P()   { return make(18); }


    __forceinline DWORD NCON() { return make(19); }
    __forceinline DWORD NCAP() { return make(20); }
    __forceinline DWORD NCPG() { return make(21); }
    __forceinline DWORD NDNS() { return make(22); }
    __forceinline DWORD NFLT() { return make(23); }
    __forceinline DWORD NSTS() { return make(24); }


    __forceinline DWORD EWFP() { return make(25); }
    __forceinline DWORD GSKT() { return make(26); }
    __forceinline DWORD SNBF() { return make(27); }
    __forceinline DWORD DTCP() { return make(28); }


    __forceinline DWORD PINJ() { return make(29); }
    __forceinline DWORD PMOD() { return make(30); }
    __forceinline DWORD PRED() { return make(31); }
    __forceinline DWORD STRM() { return make(32); }
    __forceinline DWORD DPIN() { return make(33); }
    __forceinline DWORD IHLD() { return make(34); }
    __forceinline DWORD CKIL() { return make(35); }
    __forceinline DWORD DNSS() { return make(36); }
    __forceinline DWORD BWMN() { return make(37); }
    __forceinline DWORD NIFS() { return make(38); }
    __forceinline DWORD PCEX() { return make(39); }
    __forceinline DWORD NFPR() { return make(40); }
    __forceinline DWORD DPRT() { return make(41); }
    __forceinline DWORD ABRT() { return make(42); }
    __forceinline DWORD ADBG() { return make(43); }
    __forceinline DWORD SRVT() { return make(44); }
    __forceinline DWORD ADMP() { return make(45); }
    __forceinline DWORD SRV2() { return make(46); }
    __forceinline DWORD RECU() { return make(47); }
    __forceinline DWORD TIRA() { return make(48); }
    __forceinline DWORD CANR() { return make(49); }
    __forceinline DWORD CANQ() { return make(50); }
    __forceinline DWORD DBGA() { return make(51); }
    __forceinline DWORD HVDT() { return make(52); }
    __forceinline DWORD RELA() { return make(53); }
    __forceinline DWORD EVTS() { return make(54); }

    __forceinline DWORD PSBX() { return make(55); }
    __forceinline DWORD USBX() { return make(56); }
    __forceinline DWORD NLOG() { return make(57); }
    __forceinline DWORD NPKT() { return make(58); }
    __forceinline DWORD SSDT() { return make(59); }
    __forceinline DWORD TQIF() { return make(60); }
    __forceinline DWORD TTERM(){ return make(61); }
    __forceinline DWORD HCLS() { return make(62); }
    __forceinline DWORD DMAR() { return make(63); }
    __forceinline DWORD PCIE() { return make(64); }
    __forceinline DWORD PCWL() { return make(65); }
    __forceinline DWORD DMCP() { return make(66); }
    __forceinline DWORD PMPT() { return make(67); }
    __forceinline DWORD EPTH() { return make(68); }
    __forceinline DWORD DMST() { return make(69); }
    __forceinline DWORD DMCT() { return make(70); }
    __forceinline DWORD TXTS() { return make(71); }

    __forceinline DWORD KRDM() { return make(72); }
    __forceinline DWORD RTHS() { return make(72); }
    __forceinline DWORD XREV() { return make(73); }
    __forceinline DWORD RUHS() { return make(74); }
    __forceinline DWORD KPHS() { return make(75); }
    __forceinline DWORD SDGR() { return make(76); }
    __forceinline DWORD SCBS() { return make(77); }

    __forceinline DWORD HSHK() { return make(78); }
    __forceinline DWORD HRES() { return make(79); }
    __forceinline DWORD WMRK() { return make(80); }
    __forceinline DWORD CEDH() { return make(81); }

    __forceinline DWORD HWID() {
        return static_cast<DWORD>(CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA1D0, METHOD_BUFFERED, FILE_READ_DATA));
    }
}

namespace hwid_kernel_proto {
    constexpr std::uint32_t kReplyMagic       = 0x48574944u;
    constexpr std::uint32_t kReplyVersion     = 2u;
    constexpr std::uint32_t kFactorCount      = 9u;

#pragma pack(push, 8)
    struct reply_t {
        std::uint32_t  magic;
        std::uint32_t  version;
        std::uint8_t   hwid_hash[32];
        std::uint8_t   factor_hashes[kFactorCount][32];
        std::uint8_t   hmac_signature[32];
        std::uint32_t  factor_present_mask;
        std::uint32_t  reserved0;
        std::int64_t   timestamp_qpc;
        std::int64_t   nonce_tsc;
    };
#pragma pack(pop)
    static_assert(sizeof(reply_t) == 8 + 32 + (32 * kFactorCount) + 32 + 4 + 4 + 8 + 8,
        "hwid_kernel_proto::reply_t size mismatch with kernel AIDA_HWID_REPLY");
}

namespace voyager {
    namespace detail {

        struct raw_ioctl_telemetry {
            std::uint32_t requested_code = 0;
            std::uint32_t effective_code = 0;
            std::uint32_t decoded_offset = 0;
            std::uint32_t decoded_offset_valid = 0;
            std::uint32_t buffer_size = 0;
            std::uint32_t bytes_returned = 0;
            std::uint32_t gle = 0;
            std::uint32_t initial_bytes_returned = 0;
            std::uint32_t initial_gle = 0;
            std::uint32_t retry_bytes_returned = 0;
            std::uint32_t retry_gle = 0;
            std::uint32_t pre_base = 0;
            std::uint32_t pre_global_base = 0;
            std::uint32_t pre_key_hash = 0;
            std::uint32_t pre_global_key_hash = 0;
            std::uint32_t pre_ioctl_seed_hash = 0;
            std::uint32_t pre_global_ioctl_seed_hash = 0;
            std::uint32_t post_base = 0;
            std::uint32_t post_global_base = 0;
            std::uint32_t post_key_hash = 0;
            std::uint32_t post_global_key_hash = 0;
            std::uint32_t post_ioctl_seed_hash = 0;
            std::uint32_t post_global_ioctl_seed_hash = 0;
            std::uint32_t retry_base = 0;
            std::uint32_t retry_global_base = 0;
            std::uint32_t retry_key_hash = 0;
            std::uint32_t retry_global_key_hash = 0;
            std::uint32_t retry_ioctl_seed_hash = 0;
            std::uint32_t retry_global_ioctl_seed_hash = 0;
            std::uint32_t retry_effective_code = 0;
            std::uint32_t retry_attempted = 0;
            std::uint32_t retry_recomputed_changed = 0;
            std::uint32_t retry_reason = 0;
            std::uint32_t retry_ok = 0;
            std::uint32_t heartbeat_attempted = 0;
            std::uint32_t heartbeat_ok = 0;
            std::uint32_t heartbeat_ioctl = 0;
            std::uint32_t heartbeat_bytes = 0;
            std::uint32_t heartbeat_gle = 0;
            std::uint64_t heartbeat_response = 0;
            std::uint64_t elapsed_ms = 0;
            std::uint64_t initial_elapsed_ms = 0;
            std::uint64_t retry_elapsed_ms = 0;
            std::uint64_t heartbeat_tsc = 0;
            std::uint64_t whoswho_tsc = 0;
            std::uint64_t sentinel_tsc = 0;
            std::uint32_t local_pid = 0;
            std::uint32_t local_tid = 0;
            std::uint32_t attached_pid = 0;
            std::uint32_t req_pid = 0;
            std::uint32_t req_tid = 0;
            std::uint32_t connected = 0;
            std::uint32_t server_seed_present = 0;
            std::uint32_t ioctl_seed_present = 0;
            std::uint32_t global_server_seed_present_pre = 0;
            std::uint32_t global_ioctl_seed_present_pre = 0;
            std::uint32_t global_server_seed_present_post = 0;
            std::uint32_t global_ioctl_seed_present_post = 0;
            std::uint64_t handle_value = 0;
        };

        __forceinline bool decode_ioctl_offset_from_base(DWORD control_code,
                                                         std::uint32_t base,
                                                         std::uint32_t& offset) noexcept {
            if ((control_code & 0xFFFF0000u) != 0x00220000u)
                return false;
            const std::uint32_t encoded = (control_code & 0x0000FFFFu) >> 2;
            if (encoded < base)
                return false;
            const std::uint32_t candidate = encoded - base;
            if (candidate > 80u)
                return false;
            offset = candidate;
            return true;
        }

        __forceinline void append_ioctl_raw_debug_log(const char* msg) noexcept {
            if (msg == nullptr || msg[0] == '\0')
                return;
            char module[MAX_PATH] = {};
            const DWORD module_len = GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
            if (module_len == 0 || module_len >= sizeof(module))
                return;
            char* slash = std::strrchr(module, '\\');
            if (slash == nullptr)
                return;
            *(slash + 1) = '\0';
            char path[MAX_PATH] = {};
            _snprintf_s(path, sizeof(path), _TRUNCATE, "%saida_debug.log", module);
            HANDLE file = CreateFileA(path,
                FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return;
            SYSTEMTIME st{};
            GetLocalTime(&st);
            char line[4352];
            const int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
                "[%02u:%02u:%02u.%03u] [comm-raw] %s\r\n",
                static_cast<unsigned>(st.wHour),
                static_cast<unsigned>(st.wMinute),
                static_cast<unsigned>(st.wSecond),
                static_cast<unsigned>(st.wMilliseconds),
                msg);
            if (len > 0) {
                DWORD written = 0;
                WriteFile(file, line, static_cast<DWORD>(len), &written, nullptr);
            }
            CloseHandle(file);
        }

        __forceinline std::uint32_t get_heartbeat_magic() {
            return 0xDEADBEEFu ^ dynamic_key::get();
        }
        __forceinline void debug_ioctl_raw_log(const char* phase,
                                               const raw_ioctl_telemetry& t) noexcept {
            char buf[4096];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "[AIDA-IOCTL-RAW] %s requested=0x%08X effective=0x%08X offset=%u offset_valid=%u size=%u bytes=%u gle=%u initial_bytes=%u initial_gle=%u retry_attempted=%u retry_changed=%u retry_reason=%u retry_ok=%u retry_effective=0x%08X retry_bytes=%u retry_gle=%u pre_base=0x%04X pre_global_base=0x%04X post_base=0x%04X post_global_base=0x%04X retry_base=0x%04X retry_global_base=0x%04X pre_key_hash=0x%08X pre_global_key_hash=0x%08X post_key_hash=0x%08X post_global_key_hash=0x%08X retry_key_hash=0x%08X retry_global_key_hash=0x%08X pre_ioctl_seed_hash=0x%08X pre_global_ioctl_seed_hash=0x%08X post_ioctl_seed_hash=0x%08X post_global_ioctl_seed_hash=0x%08X retry_ioctl_seed_hash=0x%08X retry_global_ioctl_seed_hash=0x%08X connected=%u handle=0x%llX attached_pid=%u req_pid=%u req_tid=%u local_pid=%u local_tid=%u server_seed=%u ioctl_seed=%u glob_seed_pre=%u/%u glob_seed_post=%u/%u hb_attempted=%u hb_ok=%u hb_ioctl=0x%08X hb_bytes=%u hb_gle=%u hb_response=0x%llX hb_tsc=%llu whoswho_tsc=%llu sentinel_tsc=%llu elapsed_ms=%llu initial_elapsed_ms=%llu retry_elapsed_ms=%llu",
                phase ? phase : "?",
                t.requested_code,
                t.effective_code,
                t.decoded_offset,
                t.decoded_offset_valid,
                t.buffer_size,
                t.bytes_returned,
                t.gle,
                t.initial_bytes_returned,
                t.initial_gle,
                t.retry_attempted,
                t.retry_recomputed_changed,
                t.retry_reason,
                t.retry_ok,
                t.retry_effective_code,
                t.retry_bytes_returned,
                t.retry_gle,
                t.pre_base,
                t.pre_global_base,
                t.post_base,
                t.post_global_base,
                t.retry_base,
                t.retry_global_base,
                t.pre_key_hash,
                t.pre_global_key_hash,
                t.post_key_hash,
                t.post_global_key_hash,
                t.retry_key_hash,
                t.retry_global_key_hash,
                t.pre_ioctl_seed_hash,
                t.pre_global_ioctl_seed_hash,
                t.post_ioctl_seed_hash,
                t.post_global_ioctl_seed_hash,
                t.retry_ioctl_seed_hash,
                t.retry_global_ioctl_seed_hash,
                t.connected,
                static_cast<unsigned long long>(t.handle_value),
                t.attached_pid,
                t.req_pid,
                t.req_tid,
                t.local_pid,
                t.local_tid,
                t.server_seed_present,
                t.ioctl_seed_present,
                t.global_server_seed_present_pre,
                t.global_ioctl_seed_present_pre,
                t.global_server_seed_present_post,
                t.global_ioctl_seed_present_post,
                t.heartbeat_attempted,
                t.heartbeat_ok,
                t.heartbeat_ioctl,
                t.heartbeat_bytes,
                t.heartbeat_gle,
                static_cast<unsigned long long>(t.heartbeat_response),
                static_cast<unsigned long long>(t.heartbeat_tsc),
                static_cast<unsigned long long>(t.whoswho_tsc),
                static_cast<unsigned long long>(t.sentinel_tsc),
                static_cast<unsigned long long>(t.elapsed_ms),
                static_cast<unsigned long long>(t.initial_elapsed_ms),
                static_cast<unsigned long long>(t.retry_elapsed_ms));
            OutputDebugStringA(buf);
            OutputDebugStringA("\n");
            append_ioctl_raw_debug_log(buf);
        }
        constexpr std::uint64_t HEARTBEAT_REFRESH_INTERVAL = 200000000ULL;

        struct heartbeat_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint64_t timestamp;
            std::uint64_t response;
            std::uint64_t whoswho_tsc;
            std::uint64_t sentinel_tsc;
        };
        static_assert(sizeof(heartbeat_request) == 40, "heartbeat_request size mismatch with kernel driver");

        struct dtb_solve {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t dtb;
        };
        static_assert(sizeof(dtb_solve) == 16, "dtb_solve size mismatch with kernel driver");

        struct physical_request {
            std::uint32_t pid;
            std::uint32_t padding_1;
            std::uint64_t dtb;
            void* address;
            void* buffer;
            std::size_t size;
            std::size_t ret_size;
            std::uint8_t should_write;
            std::uint8_t padding_2[7];
        };
        static_assert(sizeof(physical_request) == 56, "physical_request size mismatch with kernel driver");

        struct base_address_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t* out_address;
        };
        static_assert(sizeof(base_address_request) == 16, "base_address_request size mismatch with kernel driver");

        struct remote_call_request {
            std::uint64_t dtb;
            std::uint64_t target_function;
            std::uint64_t shellcode_address;
            std::uint64_t spoof_return;
            std::uint64_t arg1;
            std::uint64_t arg2;
            std::uint64_t arg3;
            std::uint64_t arg4;
            std::uint64_t result;
            std::uint64_t completed;
            std::uint64_t original_rip;
            std::uint64_t trampoline_addr;
        };
        static_assert(sizeof(remote_call_request) == 96, "remote_call_request size mismatch with kernel driver");

        struct call_result_request {
            std::uint64_t dtb;
            std::uint64_t result_address;
            std::uint64_t result;
            std::uint64_t completed;
        };
        static_assert(sizeof(call_result_request) == 32, "call_result_request size mismatch with kernel driver");

        struct alloc_mem_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t size;
            std::uint64_t allocated_address;
            std::uint64_t actual_size;
        };
        static_assert(sizeof(alloc_mem_request) == 32, "alloc_mem_request size mismatch with kernel driver");

        struct free_mem_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t address;
        };
        static_assert(sizeof(free_mem_request) == 16, "free_mem_request size mismatch with kernel driver");

        constexpr std::size_t SHELLCODE_ALLOC_SIZE = 0x2000;
        constexpr std::size_t CONTEXT_OFFSET = 0x0;
        constexpr std::size_t CODE_OFFSET = 0x200;
        constexpr std::size_t EPILOGUE_OFFSET = 0x600;

        constexpr std::size_t CTX_TARGET_FUNC = 0x00;
        constexpr std::size_t CTX_SPOOF_GADGET = 0x08;
        constexpr std::size_t CTX_PARAM1 = 0x10;
        constexpr std::size_t CTX_PARAM2 = 0x18;
        constexpr std::size_t CTX_PARAM3 = 0x20;
        constexpr std::size_t CTX_PARAM4 = 0x28;
        constexpr std::size_t CTX_RET_VALUE = 0x30;
        constexpr std::size_t CTX_SAVED_RSP = 0x38;
        constexpr std::size_t CTX_ORIGINAL_RIP = 0x40;
        constexpr std::size_t CTX_RBX_BACKUP = 0x48;
        constexpr std::size_t CTX_EXEC_DONE = 0x50;
        constexpr std::size_t CTX_TRAMPOLINE = 0x58;


        struct thread_ctx_request {
            std::uint32_t pid;
            std::uint32_t tid;
            std::uint32_t should_set;
            std::uint32_t padding;
            std::uint64_t register_mask;
            std::uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
            std::uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
            std::uint64_t rip, rflags;
            std::uint64_t cs, ss;
            std::uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
        };
        static_assert(sizeof(thread_ctx_request) == 232, "thread_ctx_request size mismatch with kernel driver");

        static constexpr std::size_t MAX_ENUM_THREADS = 256;

        struct thread_entry {
            std::uint32_t tid;
            std::uint32_t state;
            std::uint64_t rip;
        };
        static_assert(sizeof(thread_entry) == 16, "thread_entry size mismatch");

        struct thread_enum_request {
            std::uint32_t pid;
            std::uint32_t thread_count;
            thread_entry entries[MAX_ENUM_THREADS];
        };
        static_assert(sizeof(thread_enum_request) == 8 + sizeof(thread_entry) * MAX_ENUM_THREADS, "thread_enum_request size mismatch");

        struct suspend_resume_request {
            std::uint32_t tid;
            std::uint32_t should_resume;
            std::uint32_t previous_count;
            std::uint32_t pid;
        };
        static_assert(sizeof(suspend_resume_request) == 16, "suspend_resume_request size mismatch");

        struct thread_query_information_request {
            std::uint32_t pid;
            std::uint32_t tid;
            std::uint32_t info_class;
            std::uint32_t return_length;
            std::uint32_t status;
            std::uint32_t padding;
            std::int64_t exit_status;
            std::uint64_t teb_base;
            std::uint64_t client_process;
            std::uint64_t client_thread;
            std::uint64_t affinity_mask;
            std::int32_t priority;
            std::int32_t base_priority;
        };
        static_assert(sizeof(thread_query_information_request) == 72, "thread_query_information_request size mismatch");

        struct terminate_thread_request {
            std::uint32_t pid;
            std::uint32_t tid;
            std::uint32_t exit_status;
            std::uint32_t status;
        };
        static_assert(sizeof(terminate_thread_request) == 16, "terminate_thread_request size mismatch");

        struct close_handle_request {
            std::uint32_t pid;
            std::uint32_t status;
            std::uint64_t handle_value;
        };
        static_assert(sizeof(close_handle_request) == 16, "close_handle_request size mismatch");

        struct query_memory_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t address;
            std::uint64_t region_base;
            std::uint64_t region_size;
            std::uint32_t state;
            std::uint32_t protect;
            std::uint32_t type;
            std::uint32_t allocation_protect;
            std::uint64_t allocation_base;
        };
        static_assert(sizeof(query_memory_request) == 56, "query_memory_request size mismatch");

        struct protect_memory_request {
            std::uint32_t pid;
            std::uint32_t new_protect;
            std::uint64_t address;
            std::uint64_t size;
            std::uint32_t old_protect;
            std::uint32_t padding;
        };
        static_assert(sizeof(protect_memory_request) == 32, "protect_memory_request size mismatch");

        static constexpr std::size_t MAX_ENUM_REGIONS = 4096;

        struct region_entry {
            std::uint64_t base;
            std::uint64_t size;
            std::uint32_t state;
            std::uint32_t protect;
            std::uint32_t type;
            std::uint32_t padding;
        };
        static_assert(sizeof(region_entry) == 32, "region_entry size mismatch");

        struct enum_regions_request {
            std::uint32_t pid;
            std::uint32_t include_all;
            std::uint64_t start_address;
            std::uint64_t max_address;
            std::uint32_t region_count;
            std::uint32_t padding;
            region_entry entries[MAX_ENUM_REGIONS];
        };
        static_assert(sizeof(enum_regions_request) == 32 + sizeof(region_entry) * MAX_ENUM_REGIONS, "enum_regions_request size mismatch");

        struct read_peb_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t peb_address;
            std::uint64_t image_base;
            std::uint8_t  being_debugged;
            std::uint8_t  pad1[3];
            std::uint32_t nt_global_flag;
            std::uint64_t ldr_address;
            std::uint64_t process_heap;
            std::uint32_t number_of_heaps;
            std::uint32_t max_heaps;
            std::uint64_t process_heaps;
        };
        static_assert(sizeof(read_peb_request) == 64, "read_peb_request size mismatch");

        struct spoof_debug_request {
            std::uint32_t pid;
            std::uint32_t result_flags;
        };
        static_assert(sizeof(spoof_debug_request) == 8, "spoof_debug_request size mismatch");

        struct module_export_request {
            std::uint64_t dtb;
            std::uint64_t module_base;
            char export_name[128];
            std::uint64_t resolved_address;
            std::uint32_t ordinal;
            std::uint32_t padding;
        };
        static_assert(sizeof(module_export_request) == 160, "module_export_request size mismatch");

        struct virt_to_phys_request {
            std::uint64_t dtb;
            std::uint64_t virtual_address;
            std::uint64_t physical_address;
        };
        static_assert(sizeof(virt_to_phys_request) == 24, "virt_to_phys_request size mismatch");

        struct ssdt_query_request {
            std::uint64_t lstar;
            std::uint64_t descriptor_address;
            std::uint64_t service_table;
            std::uint64_t counter_table;
            std::uint64_t argument_table;
            std::uint32_t service_limit;
            std::uint32_t flags;
        };
        static_assert(sizeof(ssdt_query_request) == 48, "ssdt_query_request size mismatch");


#pragma pack(push, 8)

        static constexpr std::size_t MAX_NET_CONNECTIONS = 1024;
        static constexpr std::size_t NET_PKT_MAX_PAYLOAD = 1500;
        static constexpr std::size_t NET_CAP_GET_MAX = 32;
        static constexpr std::size_t NET_DNS_GET_MAX = 64;

        struct net_conn_entry {
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t state;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
            char          process_path[260];
            std::uint32_t padding_pp;
        };
        static_assert(sizeof(net_conn_entry) == 320, "net_conn_entry size mismatch");

        struct net_enum_conn_request {
            std::uint32_t filter_pid;
            std::uint32_t filter_protocol;
            std::uint32_t connection_count;
            std::uint32_t padding;
            net_conn_entry entries[MAX_NET_CONNECTIONS];
        };

        struct net_cap_ctrl_request {
            std::uint32_t operation;
            std::uint32_t filter_pid;
            std::uint32_t filter_port;
            std::uint32_t filter_protocol;
            std::uint8_t  filter_ip[16];
            std::uint32_t max_packet_bytes;
            std::uint32_t capture_active;
            std::uint32_t packets_captured;
            std::uint32_t packets_dropped;
        };
        static_assert(sizeof(net_cap_ctrl_request) == 48, "net_cap_ctrl_request size mismatch");

        struct net_packet_entry {
            std::uint64_t timestamp;
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t direction;
            std::uint32_t payload_size;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint32_t reserved;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
            std::uint8_t  payload[NET_PKT_MAX_PAYLOAD];
        };
        static_assert(sizeof(net_packet_entry) == 1576, "net_packet_entry size mismatch");

        struct net_cap_get_request {
            std::uint32_t max_packets;
            std::uint32_t packet_count;
            net_packet_entry packets[NET_CAP_GET_MAX];
        };

        struct net_dns_entry {
            std::uint64_t timestamp;
            std::uint32_t pid;
            std::uint32_t query_type;
            char domain[260];
            std::uint8_t  resolved_addr[16];
            std::uint32_t ttl;
            std::uint32_t response_code;
        };
        static_assert(sizeof(net_dns_entry) == 304, "net_dns_entry size mismatch");

        struct net_dns_get_request {
            std::uint32_t filter_pid;
            std::uint32_t entry_count;
            net_dns_entry entries[NET_DNS_GET_MAX];
        };

        struct net_filter_rule_request {
            std::uint32_t rule_id;
            std::uint32_t action;
            std::uint32_t direction;
            std::uint32_t protocol;
            std::uint32_t pid;
            std::uint32_t port;
            std::uint8_t  ip_addr[16];
            std::uint8_t  ip_mask[16];
            std::uint32_t operation;
            std::uint32_t rule_count;
        };
        static_assert(sizeof(net_filter_rule_request) == 64, "net_filter_rule_request size mismatch");

        struct net_stats_request {
            std::uint32_t filter_pid;
            std::uint32_t padding;
            std::uint64_t bytes_sent;
            std::uint64_t bytes_received;
            std::uint64_t packets_sent;
            std::uint64_t packets_received;
            std::uint32_t active_connections;
            std::uint32_t capture_active;
            std::uint32_t total_captured;
            std::uint32_t total_dropped;
            std::uint32_t total_dns_logged;
            std::uint32_t active_filter_rules;
        };
        static_assert(sizeof(net_stats_request) == 64, "net_stats_request size mismatch");


        static constexpr std::size_t MAX_WFP_CALLOUTS = 256;
        static constexpr std::uint32_t WFP_ENTRY_TYPE_CALLOUT = 0;
        static constexpr std::uint32_t WFP_ENTRY_TYPE_FILTER = 1;
        static constexpr std::uint32_t WFP_AIDA_MATCH_SUBLAYER = 0x00000001u;
        static constexpr std::uint32_t WFP_AIDA_MATCH_ACTION_CALLOUT = 0x00000002u;
        static constexpr std::uint32_t WFP_AIDA_MATCH_DISPLAY_DATA = 0x00000004u;
        static constexpr std::uint32_t WFP_AIDA_MATCH_RUNTIME_FALLBACK = 0x80000000u;
        static constexpr std::size_t MAX_SOCKET_HANDLES = 512;
        static constexpr std::size_t SNIFF_MAX_CAPTURES = 16;
        static constexpr std::size_t SNIFF_MAX_BUF_SIZE = 2048;
        static constexpr std::size_t MAX_TCPIP_CONNECTIONS = 1024;

        struct GUID_COMPAT {
            std::uint32_t Data1;
            std::uint16_t Data2;
            std::uint16_t Data3;
            std::uint8_t  Data4[8];
        };

        struct wfp_callout_entry {
            std::uint64_t classify_fn;
            std::uint64_t notify_fn;
            std::uint64_t flow_delete_fn;
            std::uint64_t owning_module_base;
            std::uint64_t filter_id;
            std::uint32_t callout_id;
            std::uint32_t layer_id;
            std::uint32_t flags;
            std::uint32_t entry_type;
            GUID_COMPAT   callout_key;
            GUID_COMPAT   applicable_layer;
            GUID_COMPAT   sublayer_key;
            std::uint32_t action_type;
            std::uint32_t provider_present;
            std::uint32_t aida_match_reason;
            std::uint32_t padding0;
            char          owning_module[64];
        };
        static_assert(sizeof(wfp_callout_entry) == 184, "wfp_callout_entry size mismatch");

        struct wfp_callout_enum_request {
            char          filter_module[64];
            std::uint32_t callout_count;
            std::uint32_t padding;
            wfp_callout_entry entries[MAX_WFP_CALLOUTS];
        };

        struct socket_handle_entry {
            std::uint64_t handle_value;
            std::uint64_t afd_endpoint_addr;
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t state;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
        };
        static_assert(sizeof(socket_handle_entry) == 72, "socket_handle_entry size mismatch");

        struct socket_handle_enum_request {
            std::uint32_t target_pid;
            std::uint32_t socket_count;
            socket_handle_entry entries[MAX_SOCKET_HANDLES];
        };

        struct sniff_capture {
            std::uint64_t timestamp;
            std::uint64_t thread_id;
            std::uint32_t buffer_size;
            std::uint32_t padding;
            std::uint8_t  buffer[SNIFF_MAX_BUF_SIZE];
        };
        static_assert(sizeof(sniff_capture) == 2072, "sniff_capture size mismatch");

        struct sniff_net_buffers_request {
            std::uint64_t target_address;
            std::uint32_t buffer_reg_index;
            std::uint32_t size_reg_index;
            std::uint32_t max_captures;
            std::uint32_t operation;
            std::uint32_t capture_count;
            std::uint32_t active;
            std::uint32_t target_tid;
            std::uint32_t bp_index;
            sniff_capture captures[SNIFF_MAX_CAPTURES];
        };

        struct tcpip_conn_entry {
            std::uint64_t tcb_address;
            std::uint64_t owning_module_base;
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t state;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
            std::uint64_t create_time;
            std::uint64_t bytes_in;
            std::uint64_t bytes_out;
        };
        static_assert(sizeof(tcpip_conn_entry) == 96, "tcpip_conn_entry size mismatch");

        struct tcpip_conn_dump_request {
            std::uint32_t target_pid;
            std::uint32_t filter_protocol;
            std::uint32_t connection_count;
            std::uint32_t padding;
            tcpip_conn_entry entries[MAX_TCPIP_CONNECTIONS];
        };


        static constexpr std::uint32_t INJECT_MAX_PAYLOAD = 1500;

        struct packet_inject_request {
            std::uint32_t direction;
            std::uint32_t protocol;
            std::uint32_t address_family;
            std::uint32_t src_port;
            std::uint32_t dst_port;
            std::uint32_t payload_size;
            std::uint8_t  src_addr[16];
            std::uint8_t  dst_addr[16];
            std::uint32_t tcp_flags;
            std::uint32_t tcp_seq;
            std::uint32_t tcp_ack;
            std::uint32_t status;
            std::uint8_t  payload[INJECT_MAX_PAYLOAD];
        };


        static constexpr std::uint32_t MOD_MAX_PATTERN = 256;
        static constexpr std::uint32_t MOD_MAX_REPLACE = 256;
        static constexpr std::uint32_t MOD_MAX_RULES   = 32;

        struct packet_mod_rule {
            std::uint32_t rule_id;
            std::uint32_t operation;
            std::uint32_t direction;
            std::uint32_t protocol;
            std::uint32_t port;
            std::uint32_t pid;
            std::uint32_t pattern_size;
            std::uint32_t replace_size;
            std::uint8_t  pattern[MOD_MAX_PATTERN];
            std::uint8_t  replacement[MOD_MAX_REPLACE];
            std::uint32_t match_count;
            std::uint32_t active;
        };

        struct packet_mod_rule_list {
            std::uint32_t operation;
            std::uint32_t rule_count;
            packet_mod_rule rules[MOD_MAX_RULES];
        };


        static constexpr std::uint32_t REDIR_MAX_RULES = 16;

        struct traffic_redirect_rule {
            std::uint32_t rule_id;
            std::uint32_t operation;
            std::uint32_t protocol;
            std::uint32_t match_port;
            std::uint8_t  match_addr[16];
            std::uint32_t redirect_port;
            std::uint8_t  redirect_addr[16];
            std::uint32_t address_family;
            std::uint32_t match_count;
            std::uint32_t active;
            std::uint32_t exclude_pid;
        };

        struct traffic_redirect_list {
            std::uint32_t operation;
            std::uint32_t rule_count;
            traffic_redirect_rule rules[REDIR_MAX_RULES];
        };


        static constexpr std::uint32_t STREAM_MAX_SIZE = 64 * 1024;

        struct stream_reassemble_request {
            std::uint32_t operation;
            std::uint32_t src_port;
            std::uint32_t dst_port;
            std::uint32_t pid;
            std::uint8_t  src_addr[16];
            std::uint8_t  dst_addr[16];
            std::uint32_t stream_size;
            std::uint32_t total_packets;
            std::uint32_t stream_count;
            std::uint32_t truncated;
            std::uint8_t  stream_data[STREAM_MAX_SIZE];
        };


        static constexpr std::uint32_t DPI_MAX_RESULTS = 64;

        struct dpi_header_info {
            std::uint64_t timestamp;
            std::uint32_t direction;
            std::uint32_t protocol;
            std::uint32_t src_port;
            std::uint32_t dst_port;
            std::uint8_t  src_addr[16];
            std::uint8_t  dst_addr[16];
            std::uint32_t address_family;
            std::uint32_t pid;
            std::uint32_t tcp_flags;
            std::uint32_t tcp_seq;
            std::uint32_t tcp_ack;
            std::uint32_t tcp_window;
            std::uint32_t payload_size;
            std::uint32_t is_http;
            std::uint32_t is_tls;
            std::uint32_t is_dns;
            std::uint32_t http_method;
            std::uint32_t tls_version;
            std::uint32_t tls_content_type;
            char          http_host[128];
            char          http_path[256];
            char          tls_sni[128];
        };
        static_assert(sizeof(dpi_header_info) == 624, "dpi_header_info size mismatch");

        struct dpi_request {
            std::uint32_t filter_pid;
            std::uint32_t filter_protocol;
            std::uint32_t filter_port;
            std::uint32_t flags;
            std::uint32_t result_count;
            std::uint32_t padding;
            dpi_header_info results[DPI_MAX_RESULTS];
        };


        static constexpr std::uint32_t INTERCEPT_MAX_HELD    = 32;
        static constexpr std::uint32_t INTERCEPT_MAX_PAYLOAD = 1500;

        struct held_packet {
            std::uint64_t hold_id;
            std::uint64_t timestamp;
            std::uint32_t direction;
            std::uint32_t protocol;
            std::uint32_t src_port;
            std::uint32_t dst_port;
            std::uint8_t  src_addr[16];
            std::uint8_t  dst_addr[16];
            std::uint32_t pid;
            std::uint32_t payload_size;
            std::uint8_t  payload[INTERCEPT_MAX_PAYLOAD];
            std::uint32_t address_family;
            std::uint32_t padding;
        };

        struct intercept_request {
            std::uint32_t operation;
            std::uint32_t filter_pid;
            std::uint32_t filter_port;
            std::uint32_t filter_protocol;
            std::uint64_t hold_id;
            std::uint32_t held_count;
            std::uint32_t intercepting;
            std::uint32_t modify_payload_size;
            std::uint32_t padding;
            std::uint8_t  modify_payload[INTERCEPT_MAX_PAYLOAD];
            std::uint32_t padding2;
            held_packet   held_packets[INTERCEPT_MAX_HELD];
        };


        struct conn_kill_request {
            std::uint32_t protocol;
            std::uint32_t address_family;
            std::uint32_t src_port;
            std::uint32_t dst_port;
            std::uint8_t  src_addr[16];
            std::uint8_t  dst_addr[16];
            std::uint32_t pid;
            std::uint32_t status;
        };


        static constexpr std::uint32_t DNS_SPOOF_MAX_RULES  = 32;
        static constexpr std::uint32_t DNS_SPOOF_MAX_DOMAIN = 128;

        struct dns_spoof_rule {
            std::uint32_t rule_id;
            std::uint32_t operation;
            char          domain[DNS_SPOOF_MAX_DOMAIN];
            std::uint8_t  spoof_addr[16];
            std::uint32_t address_family;
            std::uint32_t match_count;
            std::uint32_t active;
            std::uint32_t ttl;
        };

        struct dns_spoof_list {
            std::uint32_t operation;
            std::uint32_t rule_count;
            dns_spoof_rule rules[DNS_SPOOF_MAX_RULES];
        };


        static constexpr std::uint32_t BW_MAX_PROCESSES = 128;

        struct bw_process_entry {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t bytes_sent;
            std::uint64_t bytes_recv;
            std::uint64_t packets_sent;
            std::uint64_t packets_recv;
            std::uint64_t last_activity_time;
        };
        static_assert(sizeof(bw_process_entry) == 48, "bw_process_entry size mismatch");

        struct bw_monitor_request {
            std::uint32_t operation;
            std::uint32_t filter_pid;
            std::uint64_t total_bytes_sent;
            std::uint64_t total_bytes_recv;
            std::uint64_t total_packets_sent;
            std::uint64_t total_packets_recv;
            std::uint64_t bytes_per_second_in;
            std::uint64_t bytes_per_second_out;
            std::uint32_t monitoring_active;
            std::uint32_t process_count;
            bw_process_entry processes[BW_MAX_PROCESSES];
        };


        static constexpr std::uint32_t NET_IF_MAX      = 32;
        static constexpr std::uint32_t NET_IF_NAME_LEN = 64;

        struct net_interface_entry {
            std::uint32_t if_index;
            std::uint32_t if_type;
            std::uint32_t mtu;
            std::uint32_t oper_status;
            std::uint64_t speed;
            std::uint8_t  mac_addr[6];
            std::uint8_t  pad[2];
            std::uint8_t  ipv4_addr[4];
            std::uint8_t  ipv4_mask[4];
            std::uint8_t  ipv6_addr[16];
            char          name[NET_IF_NAME_LEN];
            char          description[NET_IF_NAME_LEN];
            std::uint64_t in_octets;
            std::uint64_t out_octets;
        };

        struct net_interface_enum {
            std::uint32_t interface_count;
            std::uint32_t padding;
            net_interface_entry interfaces[NET_IF_MAX];
        };


        struct pcap_global_header {
            std::uint32_t magic_number;
            std::uint16_t version_major;
            std::uint16_t version_minor;
            std::int32_t  thiszone;
            std::uint32_t sigfigs;
            std::uint32_t snaplen;
            std::uint32_t network;
        };

        static constexpr std::uint32_t PCAP_MAX_EXPORT_PACKETS = 256;
        static constexpr std::uint32_t PCAP_RECORD_MAX_SIZE    = 1548;

        struct pcap_record {
            std::uint32_t ts_sec;
            std::uint32_t ts_usec;
            std::uint32_t incl_len;
            std::uint32_t orig_len;
            std::uint8_t  data[PCAP_RECORD_MAX_SIZE];
        };

        struct pcap_export_request {
            std::uint32_t operation;
            std::uint32_t filter_pid;
            std::uint32_t filter_protocol;
            std::uint32_t max_packets;
            std::uint32_t packet_count;
            std::uint32_t data_size;
            pcap_global_header header;
            pcap_record records[PCAP_MAX_EXPORT_PACKETS];
        };


        static constexpr std::uint32_t FINGERPRINT_MAX = 64;

        struct net_fingerprint_entry {
            std::uint8_t  remote_addr[16];
            std::uint32_t address_family;
            std::uint32_t ttl;
            std::uint32_t window_size;
            std::uint32_t mss;
            std::uint32_t window_scale;
            std::uint32_t df_flag;
            std::uint32_t sack_permitted;
            std::uint32_t nop_count;
            std::uint32_t tcp_options_order;
            char          os_guess[64];
        };

        struct net_fingerprint_request {
            std::uint32_t operation;
            std::uint32_t result_count;
            net_fingerprint_entry entries[FINGERPRINT_MAX];
        };


        static constexpr std::uint32_t DPRT_OP_REGISTER   = 0;
        static constexpr std::uint32_t DPRT_OP_QUERY      = 1;
        static constexpr std::uint32_t DPRT_OP_UNREGISTER = 2;

        static constexpr std::uint32_t DPRT_STATUS_INACTIVE = 0;
        static constexpr std::uint32_t DPRT_STATUS_ACTIVE   = 1;
        static constexpr std::uint32_t DPRT_STATUS_TAMPERED = 2;
        static constexpr std::uint32_t DPRT_STATUS_DEBUGGER = 3;

        struct dll_protect_request {
            std::uint32_t operation;
            std::uint32_t pid;
            std::uint64_t module_base;
            std::uint64_t text_section_va;
            std::uint32_t text_section_size;
            std::uint32_t padding;
            std::uint64_t expected_hash;
            std::uint64_t current_hash;
            std::uint32_t status;
            std::uint32_t check_interval;
            std::uint64_t last_check_tsc;
        };
        static_assert(sizeof(dll_protect_request) == 64, "dll_protect_request must match kernel struct");

        struct abort_request {
            std::uint32_t magic;
            std::uint32_t reason_code;
            std::uint64_t evidence_hash;
            std::uint64_t timestamp;
        };
        static_assert(sizeof(abort_request) == 24, "abort_request must match kernel struct");

        struct latch_targeting_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint32_t reason;
            std::uint32_t reserved;
        };
        static_assert(sizeof(latch_targeting_request) == 16, "latch_targeting_request must match kernel struct");

        struct anti_debug_request {
            std::uint32_t operation;
            std::uint32_t pid;
            std::uint32_t tid;
            std::uint32_t result_flags;
            std::uint64_t detected_debugger_pid;
            std::uint64_t dr_clear_count;
        };
        static_assert(sizeof(anti_debug_request) == 32, "anti_debug_request must match kernel struct");

        struct text_scan_request {
            std::uint64_t module_base;
            std::uint64_t exception_dir_va;
            std::uint32_t exception_dir_size;
            std::uint32_t padding;
            std::uint64_t hit_rva;
        };
        static_assert(sizeof(text_scan_request) == 32, "text_scan_request must match kernel struct");

        struct server_token_relay {
            std::uint32_t token_hash;
            std::uint32_t session_key;
            std::uint64_t timestamp;
            std::uint64_t server_nonce;
            std::uint32_t result;
            std::uint32_t padding;
        };
        static_assert(sizeof(server_token_relay) == 32, "server_token_relay must match kernel struct");

        struct anti_dump_request {
            std::uint32_t operation;
            std::uint32_t pid;
            std::uint64_t blocks_count;
            std::uint32_t result;
            std::uint32_t padding;
        };
        static_assert(sizeof(anti_dump_request) == 24, "anti_dump_request must match kernel struct");

        struct server_token_relay_v2 {
            std::uint32_t token_hash;
            std::uint32_t session_key;
            std::uint64_t timestamp;
            std::uint64_t server_nonce;
            std::uint64_t driver_proof;
            std::uint32_t result;
            std::uint32_t padding;
        };
        static_assert(sizeof(server_token_relay_v2) == 40, "server_token_relay_v2 must match kernel struct");

        struct re_evidence_blob_t {
            std::uint64_t magic;
            std::uint32_t version;
            std::uint32_t signal_family;
            std::uint32_t signal_id;
            std::uint32_t score;
            std::uint32_t pid;
            std::uint32_t reserved0;
            std::uint64_t caller_image_hash;
            std::uint64_t signals_bitmap_hash;
            std::uint64_t timestamp;
        };
        static_assert(sizeof(re_evidence_blob_t) == 56, "re_evidence_blob_t must match kernel struct");

        constexpr std::uint32_t HANDSHAKE_MAGIC = 0x4853484Bu;

        struct handshake_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint8_t  challenge[32];
            std::uint8_t  response[32];
            std::uint8_t  driver_challenge[32];
            std::uint32_t verified;
            std::uint32_t padding;
        };
        static_assert(sizeof(handshake_request) == 112, "handshake_request must match kernel struct");

        struct re_confirmed_usermode_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            re_evidence_blob_t evidence;
        };
        static_assert(sizeof(re_confirmed_usermode_request) == 64, "re_confirmed_usermode_request must match kernel struct");

        struct kernel_read_usermem_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t address;
            std::uint64_t size;
            std::uint32_t status;
            std::uint32_t bytes_copied;
            std::uint8_t  data[4096];
        };
        static_assert(sizeof(kernel_read_usermem_request) == 4128, "kernel_read_usermem_request size mismatch");

        struct tier_a_query_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint32_t present_flag;
            std::uint32_t tier_mask;
            std::uint64_t first_driver_base;
        };
        static_assert(sizeof(tier_a_query_request) == 24, "tier_a_query_request must match kernel struct");

        struct canary_register_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint64_t va;
            std::uint64_t size;
            std::uint32_t pid;
            std::uint32_t result;
        };
        static_assert(sizeof(canary_register_request) == 32, "canary_register_request must match kernel struct");

        struct hv_detect_request {
            std::uint64_t flags;
        };
        static_assert(sizeof(hv_detect_request) == 8, "hv_detect_request must match kernel struct");
        static constexpr std::uint64_t HV_DETECT_FLAG_TESTLAB_SAFE = 0x0000000000000001ull;

        static constexpr std::uint32_t DEBUG_EVENT_TYPE_INVALID         = 0;
        static constexpr std::uint32_t DEBUG_EVENT_TYPE_IMAGE_LOADED    = 1;
        static constexpr std::uint32_t DEBUG_EVENT_TYPE_PROCESS_CREATED = 2;
        static constexpr std::uint32_t DEBUG_EVENT_TYPE_PROCESS_EXITED  = 3;

        static constexpr std::uint32_t DEBUG_EVENT_FLAG_KERNEL_IMAGE = 0x00000001u;
        static constexpr std::uint32_t DEBUG_EVENT_FLAG_SYSTEM_MODE  = 0x00000002u;

        static constexpr std::uint32_t DEBUG_EVENT_PATH_CHARS = 260;

        struct debug_event_t {
            std::uint32_t event_type;
            std::uint32_t process_id;
            std::uint32_t thread_id;
            std::uint32_t flags;
            std::uint64_t timestamp;
            std::uint64_t image_base;
            std::uint64_t image_size;
            wchar_t       image_path[DEBUG_EVENT_PATH_CHARS];
        };
        static_assert(sizeof(debug_event_t) == 560, "debug_event_t size must match kernel struct");

        static constexpr std::uint32_t DRAIN_DEBUG_EVENTS_CAP = 64;

        struct drain_debug_events_request {
            std::uint32_t session_key;
            std::uint32_t max_events;
            std::uint32_t returned_count;
            std::uint32_t dropped_since_last_drain;
            std::uint64_t total_dropped;
            std::uint64_t total_published;
            debug_event_t events[DRAIN_DEBUG_EVENTS_CAP];
        };
        static_assert(sizeof(drain_debug_events_request) ==
            (4u + 4u + 4u + 4u + 8u + 8u + DRAIN_DEBUG_EVENTS_CAP * sizeof(debug_event_t)),
            "drain_debug_events_request size must match kernel struct");

        static constexpr std::uint32_t SANDBOX_FLAG_BLOCK_PERSISTENCE   = 0x00000001u;
        static constexpr std::uint32_t SANDBOX_FLAG_BLOCK_DRIVER_INSTALL = 0x00000002u;
        static constexpr std::uint32_t SANDBOX_FLAG_BLOCK_RAW_DISK      = 0x00000004u;
        static constexpr std::uint32_t SANDBOX_FLAG_BLOCK_KERNEL_HANDLE = 0x00000008u;
        static constexpr std::uint32_t SANDBOX_FLAG_LOG_NETWORK         = 0x00000010u;
        static constexpr std::uint32_t SANDBOX_FLAG_BLOCK_CHILD_SPAWN   = 0x00000020u;
        static constexpr std::uint32_t SANDBOX_FLAG_DEFAULT =
            SANDBOX_FLAG_BLOCK_PERSISTENCE
          | SANDBOX_FLAG_BLOCK_DRIVER_INSTALL
          | SANDBOX_FLAG_BLOCK_RAW_DISK
          | SANDBOX_FLAG_BLOCK_KERNEL_HANDLE
          | SANDBOX_FLAG_LOG_NETWORK;

        struct protect_sandbox_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint32_t pid;
            std::uint32_t flags;
            std::uint32_t result;
            std::uint32_t reserved;
            std::uint64_t denials_so_far;
        };
        static_assert(sizeof(protect_sandbox_request) == 32, "protect_sandbox_request must match kernel struct");

        struct net_log_register_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint32_t pid;
            std::uint32_t operation;
            std::uint32_t result;
            std::uint32_t reserved;
        };
        static_assert(sizeof(net_log_register_request) == 24, "net_log_register_request must match kernel struct");

        static constexpr std::uint32_t NET_PKT_PULL_RING_CAPACITY    = 2048u;
        static constexpr std::uint32_t NET_PKT_PULL_PAYLOAD_RETAIN   = 256u;
        static constexpr std::uint32_t NET_PKT_PULL_RECORD_SIZE      = 384u;
        static constexpr std::uint32_t NET_PKT_PULL_REQ_MAGIC        = 0x4E50414Bu;
        static constexpr std::uint32_t NET_PKT_PULL_RESP_MAGIC       = 0x4E50414Du;
        static constexpr std::uint32_t NET_PKT_FLAG_TRUNCATED        = 0x00000001u;

        struct net_packet_pull_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint32_t pid;
            std::uint32_t max_records;
            std::uint32_t reserved;
            std::uint32_t padding;
        };
        static_assert(sizeof(net_packet_pull_request) == 24, "net_packet_pull_request must be 24 bytes");

        struct net_packet_pull_response_header {
            std::uint32_t magic;
            std::uint32_t record_count;
            std::uint64_t dropped_since_last_pull;
        };
        static_assert(sizeof(net_packet_pull_response_header) == 16, "net_packet_pull_response_header must be 16 bytes");

        struct net_packet_record {
            std::uint64_t timestamp;
            std::uint64_t tcp_seq;
            std::uint32_t pid;
            std::uint32_t payload_len;
            std::uint32_t flags;
            std::uint16_t local_port;
            std::uint16_t remote_port;
            std::uint16_t address_family;
            std::uint8_t  protocol;
            std::uint8_t  direction;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
            std::uint8_t  payload[256];
            std::uint8_t  pad[60];
        };
        static_assert(sizeof(net_packet_record) == 384, "net_packet_record must be exactly 384 bytes (kernel ABI)");

#pragma pack(push, 1)
        struct hv_detect_result {
            std::uint8_t sidt_lock_prefix;
            std::uint8_t sidt_invalid_pf;
            std::uint8_t sidt_tlb_only;
            std::uint8_t sidt_timing;
            std::uint8_t sidt_compat_mode;
            std::uint8_t sidt_noncanonical_gp;
            std::uint8_t sidt_noncanonical_ss;
            std::uint8_t sidt_cpl3_umip_off;
            std::uint8_t sidt_cpl3_umip_on;

            std::uint8_t lidt_lock_prefix;
            std::uint8_t lidt_invalid_pf;
            std::uint8_t lidt_tlb_only;
            std::uint8_t lidt_timing;
            std::uint8_t lidt_noncanonical_gp;
            std::uint8_t lidt_noncanonical_ss;
            std::uint8_t lidt_cpl3_gp;

            std::uint8_t ve_trigger;
            std::uint8_t ve_lbr_stack;
            std::uint8_t ve_xsetbv_gp;
            std::uint8_t ve_cr4_vmxe;

            std::uint8_t vmf_cpuid_vendor;
            std::uint8_t vmf_hyperv_guest;
            std::uint8_t vmf_smbios_vm;
            std::uint8_t vmf_acpi_vm;
            std::uint8_t vmf_pci_vm;
            std::uint8_t vmf_disk_vm;
            std::uint8_t vmf_mac_vm;
            std::uint8_t vmf_registry_vm;

            std::uint8_t total_run;
            std::uint8_t total_failed;
            std::uint8_t ms_hv_root;
            std::uint8_t is_virtual_machine;

            char         vm_vendor_name[16];
            std::uint8_t measurements_hmac[16];
            std::uint8_t reserved_pad[16];
        };
        static_assert(sizeof(hv_detect_result) == 80, "hv_detect_result must match kernel struct");
#pragma pack(pop)

        struct iommu_status {
            std::uint8_t  dmar_present;
            std::uint8_t  ivrs_present;
            std::uint8_t  vtd_enabled;
            std::uint8_t  amd_vi_enabled;
            std::uint8_t  iommu_present;
            std::uint8_t  remapping_bypassed;
            std::uint8_t  pad[2];
            std::uint64_t dmar_table_pa;
            std::uint64_t ivrs_table_pa;
            std::uint32_t remapping_units;
            std::uint32_t risk_level;
            std::uint64_t detection_timestamp;
        };
        static_assert(sizeof(iommu_status) == 40, "iommu_status must match kernel struct");

        struct pcie_device_entry {
            std::uint16_t vendor_id;
            std::uint16_t device_id;
            std::uint32_t class_code;
            std::uint8_t  bus;
            std::uint8_t  device;
            std::uint8_t  function;
            std::uint8_t  header_type;
            std::uint64_t bar_pa[6];
            std::uint64_t bar_size;
            std::uint32_t flags;
            std::uint32_t whitelist_status;
        };
        static_assert(sizeof(pcie_device_entry) == 80, "pcie_device_entry must match kernel struct");

        static constexpr std::size_t MAX_PCIE_DEVICES = 256;

        struct pcie_enum_result {
            std::uint32_t device_count;
            std::uint32_t unknown_count;
            pcie_device_entry entries[MAX_PCIE_DEVICES];
        };
        static_assert(sizeof(pcie_enum_result) == 8 + sizeof(pcie_device_entry) * MAX_PCIE_DEVICES,
            "pcie_enum_result must match kernel struct");

        struct pcie_whitelist_request {
            std::uint32_t operation;
            std::uint32_t entry_count;
            std::uint16_t vendor_id;
            std::uint16_t device_id;
            std::uint32_t result;
            std::uint64_t timestamp;
        };
        static_assert(sizeof(pcie_whitelist_request) == 24, "pcie_whitelist_request must match kernel struct");

        struct canary_poison_request {
            std::uint64_t va;
            std::uint64_t pa;
            std::uint64_t poison_signature;
            std::uint64_t original_value;
            std::uint32_t active;
            std::uint32_t result;
        };
        static_assert(sizeof(canary_poison_request) == 40, "canary_poison_request must match kernel struct");

        struct pte_protection_entry {
            std::uint64_t va;
            std::uint64_t pa;
            std::uint64_t original_pte;
            std::uint64_t current_pte;
            std::uint32_t page_size;
            std::uint32_t active;
        };
        static_assert(sizeof(pte_protection_entry) == 40, "pte_protection_entry must match kernel struct");

        static constexpr std::size_t MAX_PTE_PROTECTION_ENTRIES = 64;

        struct pte_protection_table {
            std::uint32_t entry_count;
            std::uint32_t active_count;
            pte_protection_entry entries[MAX_PTE_PROTECTION_ENTRIES];
        };
        static_assert(sizeof(pte_protection_table) == 8 + sizeof(pte_protection_entry) * MAX_PTE_PROTECTION_ENTRIES,
            "pte_protection_table must match kernel struct");

        struct ept_check_result {
            std::uint8_t  ept_present;
            std::uint8_t  npte_present;
            std::uint8_t  ept_hook_detected;
            std::uint8_t  vmm_present;
            std::uint8_t  pad[4];
            std::uint64_t ept_pointer_msr;
            std::uint32_t npte_anomaly_count;
            std::uint32_t risk_level;
            std::uint64_t detection_timestamp;
        };
        static_assert(sizeof(ept_check_result) == 32, "ept_check_result must match kernel struct");

        struct dma_protection_state {
            iommu_status  iommu;
            std::uint32_t canary_count;
            std::uint32_t canary_hits;
            std::uint32_t pcie_unknown_count;
            std::uint32_t ept_anomaly_count;
            std::uint32_t tier1_refused;
            std::uint32_t tier2_bsod_armed;
            std::uint64_t timestamp;
        };
        static_assert(sizeof(dma_protection_state) == 72, "dma_protection_state must match kernel struct");

        struct dma_countermeasure_request {
            std::uint32_t action;
            std::uint32_t reason;
            std::uint32_t target_pid;
            std::uint32_t result;
            std::uint64_t evidence_hash;
            std::uint64_t timestamp;
        };
        static_assert(sizeof(dma_countermeasure_request) == 32, "dma_countermeasure_request must match kernel struct");

#pragma pack(push, 8)
        struct re_tool_hash_update_request {
            std::uint32_t magic;
            std::uint32_t hash_count;
            std::uint32_t session_key;
            std::uint32_t padding;
            std::uint8_t  hashes[16 * 32];
            std::uint32_t werfault_hash_count;
            std::uint32_t werfault_padding;
            std::uint8_t  werfault_hashes[16 * 32];
            std::uint64_t timestamp;
        };
        static_assert(sizeof(re_tool_hash_update_request) == 1056, "re_tool_hash_update_request must match kernel struct");
#pragma pack(pop)

#pragma pack(push, 8)
        struct ce_driver_hash_update_request {
            std::uint32_t magic;
            std::uint32_t hash_count;
            std::uint32_t session_key;
            std::uint32_t padding;
            std::uint8_t  hashes[32 * 32];
            std::uint64_t timestamp;
        };
        static_assert(sizeof(ce_driver_hash_update_request) == 1048, "ce_driver_hash_update_request must match kernel struct");
#pragma pack(pop)

#pragma pack(push, 1)
        struct reloc_mask_entry_abi_t {
            std::uint32_t offset;
            std::uint32_t size;
            std::uint32_t reloc_type;
            std::uint32_t _pad;
            std::uint8_t  original_value[8];
        };
#pragma pack(pop)
        static_assert(sizeof(reloc_mask_entry_abi_t) == 24, "reloc_mask_entry_abi_t must be 24 bytes");

        constexpr std::uint32_t MAX_RELOC_MASK_ENTRIES_ABI = 512;

        struct usermode_hash_register_t {
            std::uint64_t text_base;
            std::uint32_t text_size;
            std::uint32_t mask_count;
            std::uint64_t reloc_delta;
            std::uint8_t  expected_sha256[32];
            std::uint32_t result;
            std::uint32_t _pad;
            reloc_mask_entry_abi_t mask_entries[MAX_RELOC_MASK_ENTRIES_ABI];
        };
        static_assert(sizeof(usermode_hash_register_t) == 64 + 24 * MAX_RELOC_MASK_ENTRIES_ABI,
            "usermode_hash_register_t size mismatch");

        struct cross_ring_evidence_abi_t {
            std::uint32_t detecting_checker_id;
            std::uint32_t target_checker_id;
            std::uint64_t region_base;
            std::uint64_t region_size;
            std::uint8_t  expected_hash[32];
            std::uint8_t  actual_hash[32];
            std::uint8_t  modified_bytes[256];
            std::uint32_t modified_bytes_len;
            std::uint32_t _pad;
        };
        static_assert(sizeof(cross_ring_evidence_abi_t) == 352,
            "cross_ring_evidence_abi_t must be 352 bytes");

        struct prologue_hash_request {
            std::uint64_t va;
            std::uint32_t size;
            std::uint32_t pad;
            std::uint64_t hash_result;
        };
        static_assert(sizeof(prologue_hash_request) == 24, "prologue_hash_request must match kernel struct");

        struct dispatch_guard_query {
            std::uint8_t  hook_detected;
            std::uint8_t  pad[7];
            std::uint64_t hook_target;
        };
        static_assert(sizeof(dispatch_guard_query) == 16, "dispatch_guard_query must match kernel struct");

        struct callback_scan_query {
            std::uint8_t  hostile_drivers;
            std::uint8_t  modified_callbacks;
            std::uint8_t  pad[6];
        };
        static_assert(sizeof(callback_scan_query) == 8, "callback_scan_query must match kernel struct");

#pragma pack(push, 1)
        struct watermark_verify_request {
            std::uint8_t  expected_watermark[16];
            std::uint32_t watermark_rva;
            std::uint32_t pad;
            std::uint8_t  actual_watermark[16];
            std::uint8_t  verified;
        };
#pragma pack(pop)
        static_assert(sizeof(watermark_verify_request) == 41, "watermark_verify_request must be 41 bytes");

#pragma pack(pop)
    }

    namespace detail {
        class writer_priority_shared_mutex {
        public:
            writer_priority_shared_mutex() = default;
            writer_priority_shared_mutex(const writer_priority_shared_mutex&) = delete;
            writer_priority_shared_mutex& operator=(const writer_priority_shared_mutex&) = delete;
            writer_priority_shared_mutex(writer_priority_shared_mutex&&) = delete;
            writer_priority_shared_mutex& operator=(writer_priority_shared_mutex&&) = delete;

            void lock_shared() noexcept {
                std::unique_lock<std::mutex> lk(mtx_);
                cv_.wait(lk, [&] { return waiting_writers_ == 0 && !writer_owned_; });
                ++active_readers_;
            }

            bool try_lock_shared() noexcept {
                std::unique_lock<std::mutex> lk(mtx_, std::try_to_lock);
                if (!lk.owns_lock())
                    return false;
                if (waiting_writers_ != 0 || writer_owned_)
                    return false;
                ++active_readers_;
                return true;
            }

            template <typename Rep, typename Period>
            bool try_lock_shared_for(const std::chrono::duration<Rep, Period>& dur) noexcept {
                return try_lock_shared_until(std::chrono::steady_clock::now() + dur);
            }

            template <typename Clock, typename Duration>
            bool try_lock_shared_until(const std::chrono::time_point<Clock, Duration>& deadline) noexcept {
                std::unique_lock<std::mutex> lk(mtx_);
                if (!cv_.wait_until(lk, deadline, [&] { return waiting_writers_ == 0 && !writer_owned_; }))
                    return false;
                ++active_readers_;
                return true;
            }

            void unlock_shared() noexcept {
                std::unique_lock<std::mutex> lk(mtx_);
                if (active_readers_ > 0)
                    --active_readers_;
                const bool notify = active_readers_ == 0 && waiting_writers_ > 0;
                lk.unlock();
                if (notify)
                    cv_.notify_all();
            }

            void lock() noexcept {
                std::unique_lock<std::mutex> lk(mtx_);
                ++waiting_writers_;
                cv_.wait(lk, [&] { return active_readers_ == 0 && !writer_owned_; });
                writer_owned_ = true;
                --waiting_writers_;
            }

            bool try_lock() noexcept {
                std::unique_lock<std::mutex> lk(mtx_, std::try_to_lock);
                if (!lk.owns_lock())
                    return false;
                if (active_readers_ != 0 || writer_owned_)
                    return false;
                writer_owned_ = true;
                return true;
            }

            template <typename Rep, typename Period>
            bool try_lock_for(const std::chrono::duration<Rep, Period>& dur) noexcept {
                return try_lock_until(std::chrono::steady_clock::now() + dur);
            }

            template <typename Clock, typename Duration>
            bool try_lock_until(const std::chrono::time_point<Clock, Duration>& deadline) noexcept {
                std::unique_lock<std::mutex> lk(mtx_);
                ++waiting_writers_;
                const bool acquired = cv_.wait_until(lk, deadline, [&] { return active_readers_ == 0 && !writer_owned_; });
                if (!acquired) {
                    --waiting_writers_;
                    const bool notify_readers = active_readers_ == 0 && waiting_writers_ == 0 && !writer_owned_;
                    lk.unlock();
                    if (notify_readers)
                        cv_.notify_all();
                    return false;
                }
                writer_owned_ = true;
                --waiting_writers_;
                return true;
            }

            void unlock() noexcept {
                std::unique_lock<std::mutex> lk(mtx_);
                writer_owned_ = false;
                lk.unlock();
                cv_.notify_all();
            }

            std::uint32_t get_waiting_writers() const noexcept {
                std::lock_guard<std::mutex> lk(mtx_);
                return waiting_writers_;
            }

            std::uint32_t get_active_readers() const noexcept {
                std::lock_guard<std::mutex> lk(mtx_);
                return active_readers_;
            }

            bool is_writer_owned() const noexcept {
                std::lock_guard<std::mutex> lk(mtx_);
                return writer_owned_;
            }

        private:
            mutable std::mutex mtx_;
            std::condition_variable_any cv_;
            std::uint32_t active_readers_ = 0;
            std::uint32_t waiting_writers_ = 0;
            bool writer_owned_ = false;
        };

        using session_relay_cache_provider_t = bool (*)(std::uint32_t* out_token_hash, std::uint64_t* out_server_nonce);
    }

    namespace device_names_um {
        static const wchar_t* const g_device_bases[] = {
            L"RdpRefMp",
            L"KsecDD",
            L"MountPointManager",
            L"VolumesSafeForWriteAccess",
            L"VolMgrControl",
            L"DeviceApi",
            L"Ucx01000",
            L"USBPDO",
            L"ACPI_HAL",
            L"PnpManager",
            L"WdfLdr",
            L"KernelCng",
            L"WUDFLpcDevice",
            L"DxgKrnl",
            L"NdisCap",
            L"WfpLwfs",
        };
        constexpr std::size_t NUM_DEVICE_BASES = 16;

        inline std::uint32_t get_device_seed() {
            std::uint32_t hash = dynamic_key::get();
            hash = (hash * 0x45D9F3Bu) ^ (hash >> 16);
            hash = (hash * 0x1B873593u) ^ (hash >> 13);
            return hash;
        }

        inline std::wstring get_device_path() {
            std::uint32_t seed = get_device_seed();
            std::size_t idx = seed % NUM_DEVICE_BASES;
            std::wstring path = L"\\\\.\\";
            path += g_device_bases[idx];

            std::uint32_t suffix_seed = seed >> 4;
            std::uint32_t suffix_val = (suffix_seed >> 8) % 100;
            if (suffix_val >= 10) {
                path += static_cast<wchar_t>(L'0' + (suffix_val / 10) % 10);
                path += static_cast<wchar_t>(L'0' + suffix_val % 10);
            } else {
                path += static_cast<wchar_t>(L'0' + suffix_val);
            }

            return path;
        }
    }

    class device_t final {
    public:
        device_t() noexcept = default;
        ~device_t() noexcept { disconnect(); }

        device_t(const device_t&) = delete;
        device_t& operator=(const device_t&) = delete;
        device_t(device_t&&) = delete;
        device_t& operator=(device_t&&) = delete;

        bool connect() noexcept;
        void disconnect() noexcept;
        void clear_process_context() noexcept;
        [[nodiscard]] bool is_connected() const noexcept { return driver_handle_ != INVALID_HANDLE_VALUE; }

        bool send_heartbeat() noexcept;
        bool refresh_heartbeat() noexcept;
        [[nodiscard]] bool sentinel_bridge_ready() const noexcept { return last_bridge_sentinel_tsc_ != 0; }
        [[nodiscard]] std::uint64_t sentinel_ready_since_tsc() const noexcept { return first_sentinel_ready_tsc_; }

        std::uint32_t find_process(const char* process_name) noexcept;
        std::uint64_t find_image() noexcept;

        void solve_dtb() noexcept;
        std::uint64_t solve_dtb_for_pid(std::uint32_t pid) noexcept;
        void solve_kernel_dtb() noexcept;

        template<typename T>
        [[nodiscard]] T read(std::uint64_t address) const noexcept;

        template<typename T>
        void write(std::uint64_t address, const T& value) const noexcept;

        std::size_t read_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept;
        std::size_t write_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept;

        std::size_t read_kernel_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept;
        std::size_t write_kernel_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept;

        bool kernel_read_usermem(std::uint32_t pid, std::uint64_t address, void* out, std::size_t len) noexcept;

        std::uint64_t allocate_memory(std::size_t size) noexcept;
        bool free_memory(std::uint64_t address) noexcept;

        std::uint64_t call_function(std::uint64_t function_address, std::uint64_t arg1 = 0, std::uint64_t arg2 = 0, std::uint64_t arg3 = 0, std::uint64_t arg4 = 0) noexcept;

        template<typename RetType = std::uint64_t>
        RetType call(std::uint64_t function_address) noexcept {
            return static_cast<RetType>(call_function(function_address, 0, 0, 0, 0));
        }

        template<typename RetType = std::uint64_t, typename A1>
        RetType call(std::uint64_t function_address, A1 a1) noexcept {
            return static_cast<RetType>(call_function(function_address,
                static_cast<std::uint64_t>(a1), 0, 0, 0));
        }

        template<typename RetType = std::uint64_t, typename A1, typename A2>
        RetType call(std::uint64_t function_address, A1 a1, A2 a2) noexcept {
            return static_cast<RetType>(call_function(function_address,
                static_cast<std::uint64_t>(a1),
                static_cast<std::uint64_t>(a2), 0, 0));
        }

        template<typename RetType = std::uint64_t, typename A1, typename A2, typename A3>
        RetType call(std::uint64_t function_address, A1 a1, A2 a2, A3 a3) noexcept {
            return static_cast<RetType>(call_function(function_address,
                static_cast<std::uint64_t>(a1),
                static_cast<std::uint64_t>(a2),
                static_cast<std::uint64_t>(a3), 0));
        }

        template<typename RetType = std::uint64_t, typename A1, typename A2, typename A3, typename A4>
        RetType call(std::uint64_t function_address, A1 a1, A2 a2, A3 a3, A4 a4) noexcept {
            return static_cast<RetType>(call_function(function_address,
                static_cast<std::uint64_t>(a1),
                static_cast<std::uint64_t>(a2),
                static_cast<std::uint64_t>(a3),
                static_cast<std::uint64_t>(a4)));
        }

        std::uint64_t find_gadget(const char* pattern, std::size_t pattern_size) noexcept;


        struct thread_context {
            std::uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
            std::uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
            std::uint64_t rip, rflags;
            std::uint64_t cs, ss;
            std::uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
            std::uint64_t kernel_gs_base;
        };

        struct thread_info {
            std::uint32_t tid;
            std::uint32_t state;
            std::uint64_t rip;
        };

        struct memory_region_info {
            std::uint64_t base;
            std::uint64_t size;
            std::uint32_t state;
            std::uint32_t protect;
            std::uint32_t type;
            std::uint32_t allocation_protect;
            std::uint64_t allocation_base;
        };

        struct peb_info {
            std::uint64_t peb_address;
            std::uint64_t image_base;
            std::uint8_t  being_debugged;
            std::uint32_t nt_global_flag;
            std::uint64_t ldr_address;
            std::uint64_t process_heap;
            std::uint32_t number_of_heaps;
            std::uint32_t max_heaps;
            std::uint64_t process_heaps;
        };

        struct ssdt_info {
            std::uint64_t lstar;
            std::uint64_t descriptor_address;
            std::uint64_t service_table;
            std::uint64_t counter_table;
            std::uint64_t argument_table;
            std::uint32_t service_limit;
            std::uint32_t flags;
        };

        bool get_thread_context(std::uint32_t tid, thread_context& ctx) noexcept;
        bool set_thread_context(std::uint32_t tid, const thread_context& ctx, std::uint64_t register_mask) noexcept;
        std::vector<thread_info> enumerate_threads() noexcept;
        bool suspend_thread(std::uint32_t tid, std::uint32_t* prev_count = nullptr) noexcept;
        bool resume_thread(std::uint32_t tid, std::uint32_t* prev_count = nullptr) noexcept;
        bool query_thread_basic_information(std::uint32_t tid, detail::thread_query_information_request& info) noexcept;
        bool terminate_thread(std::uint32_t tid, std::uint32_t exit_status = 0xDEADu) noexcept;
        bool close_process_handle(std::uint32_t pid, std::uint64_t handle_value) noexcept;
        bool query_memory(std::uint64_t address, memory_region_info& info) noexcept;
        bool protect_memory(std::uint64_t address, std::uint64_t size, std::uint32_t new_protect, std::uint32_t* old_protect = nullptr) noexcept;
        bool protect_memory_bounded(std::uint64_t address, std::uint64_t size, std::uint32_t new_protect, std::uint32_t* old_protect, std::uint32_t deadline_ms) noexcept;
        std::vector<detail::region_entry> enumerate_memory_regions(std::uint64_t start = 0, std::uint64_t end_addr = 0, bool include_all = false) noexcept;
        bool read_peb(peb_info& info) noexcept;
        bool spoof_debug_flags(std::uint32_t* result_flags = nullptr) noexcept;
        std::uint64_t resolve_export(std::uint64_t module_base, const char* export_name) noexcept;
        std::uint64_t virtual_to_physical(std::uint64_t virtual_address) noexcept;
        bool query_ssdt(ssdt_info& info) noexcept;
        bool set_hardware_breakpoint(std::uint32_t tid, int index, std::uint64_t address, int type = 0, int size = 0) noexcept;
        bool clear_hardware_breakpoint(std::uint32_t tid, int index) noexcept;


        struct net_connection_info {
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t state;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
            char          process_path[260];
        };

        struct captured_packet {
            std::uint64_t timestamp;
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t direction;
            std::uint32_t payload_size;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
            std::vector<std::uint8_t> payload;
        };

        struct dns_entry {
            std::uint64_t timestamp;
            std::uint32_t pid;
            std::uint32_t query_type;
            std::string   domain;
            std::uint8_t  resolved_addr[16];
            std::uint32_t response_code;
            std::uint32_t ttl;
        };

        struct network_stats {
            std::uint64_t bytes_sent;
            std::uint64_t bytes_received;
            std::uint64_t packets_sent;
            std::uint64_t packets_received;
            std::uint32_t active_connections;
            std::uint32_t capture_active;
            std::uint32_t total_captured;
            std::uint32_t total_dropped;
            std::uint32_t total_dns_logged;
            std::uint32_t active_filter_rules;
        };

        std::vector<net_connection_info> enumerate_connections(std::uint32_t filter_pid = 0, std::uint32_t filter_protocol = 0) noexcept;
        bool start_capture(std::uint32_t filter_pid = 0, std::uint32_t filter_port = 0, std::uint32_t filter_protocol = 0, const std::uint8_t* filter_ip = nullptr, std::uint32_t max_payload = 1500) noexcept;
        bool stop_capture() noexcept;
        bool get_capture_status(bool& active, std::uint32_t& captured, std::uint32_t& dropped) noexcept;
        std::vector<captured_packet> get_captured_packets(std::uint32_t max_packets = 32) noexcept;
        std::vector<captured_packet> get_captured_packets_bounded(std::uint32_t max_packets, std::uint32_t deadline_ms) noexcept;
        void cancel_inflight_capture() noexcept;
        std::vector<dns_entry> get_dns_queries(std::uint32_t filter_pid = 0) noexcept;
        bool add_filter_rule(std::uint32_t action, std::uint32_t direction, std::uint32_t protocol = 0, std::uint32_t pid = 0, std::uint32_t port = 0, const std::uint8_t* ip_addr = nullptr, const std::uint8_t* ip_mask = nullptr, std::uint32_t* out_rule_id = nullptr) noexcept;
        bool remove_filter_rule(std::uint32_t rule_id) noexcept;
        bool clear_filter_rules() noexcept;
        bool get_network_stats(network_stats& stats) noexcept;


        struct wfp_callout_info {
            std::uint64_t classify_fn;
            std::uint64_t notify_fn;
            std::uint64_t flow_delete_fn;
            std::uint64_t owning_module_base;
            std::uint64_t filter_id;
            std::uint32_t callout_id;
            std::uint32_t layer_id;
            std::uint32_t flags;
            std::uint32_t entry_type;
            std::uint32_t action_type;
            std::uint32_t provider_present;
            std::uint32_t aida_match_reason;
            std::string   callout_key_str;
            std::string   applicable_layer_str;
            std::string   sublayer_key_str;
            std::string   owning_module;
        };
        std::vector<wfp_callout_info> enumerate_wfp_callouts(const std::string& filter_module = {}) noexcept;

        struct socket_info {
            std::uint64_t handle_value;
            std::uint64_t afd_endpoint_addr;
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t state;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
        };
        std::vector<socket_info> get_socket_handles(std::uint32_t target_pid = 0) noexcept;

        bool sniff_net_buffers_start(std::uint64_t address, std::uint32_t buf_reg, std::uint32_t size_reg,
                                     std::uint32_t max_captures = 1, std::uint32_t tid = 0, std::uint32_t bp_index = 0) noexcept;
        bool sniff_net_buffers_stop() noexcept;

        struct sniff_result {
            std::uint64_t timestamp;
            std::uint64_t thread_id;
            std::vector<std::uint8_t> buffer;
        };
        std::vector<sniff_result> sniff_net_buffers_get(bool& active) noexcept;

        bool sniff_net_buffers_store(std::uint64_t timestamp, std::uint64_t thread_id,
                                     const std::uint8_t* data, std::uint32_t size) noexcept;

        struct tcpip_connection {
            std::uint64_t tcb_address;
            std::uint64_t owning_module_base;
            std::uint32_t pid;
            std::uint32_t protocol;
            std::uint32_t state;
            std::uint32_t local_port;
            std::uint32_t remote_port;
            std::uint32_t address_family;
            std::uint8_t  local_addr[16];
            std::uint8_t  remote_addr[16];
            std::uint64_t create_time;
            std::uint64_t bytes_in;
            std::uint64_t bytes_out;
        };
        std::vector<tcpip_connection> dump_tcpip_connections(std::uint32_t target_pid = 0, std::uint32_t filter_protocol = 0) noexcept;


        bool inject_packet(std::uint32_t direction, std::uint32_t protocol, std::uint32_t af,
                           std::uint32_t src_port, std::uint32_t dst_port,
                           const std::uint8_t* src_addr, const std::uint8_t* dst_addr,
                           const std::uint8_t* payload, std::uint32_t payload_size,
                           std::uint32_t tcp_flags = 0, std::uint32_t tcp_seq = 0, std::uint32_t tcp_ack = 0) noexcept;

        bool packet_mod_rule_op(std::uint32_t operation, std::uint32_t rule_id = 0,
                    std::uint32_t direction = 2, std::uint32_t protocol = 0,
                                std::uint32_t port = 0, std::uint32_t pid = 0,
                                const std::uint8_t* pattern = nullptr, std::uint32_t pattern_size = 0,
                                const std::uint8_t* replacement = nullptr, std::uint32_t replace_size = 0,
                                std::uint32_t* out_rule_id = nullptr) noexcept;

        struct mod_rule_info { std::uint32_t rule_id; std::uint32_t direction; std::uint32_t protocol;
                               std::uint32_t port; std::uint32_t pid; std::uint32_t match_count; std::uint32_t active; };
        std::vector<mod_rule_info> list_packet_mod_rules() noexcept;

        bool traffic_redirect_op(std::uint32_t operation, std::uint32_t rule_id = 0,
                     std::uint32_t protocol = 0,
                                 std::uint32_t match_port = 0, const std::uint8_t* match_addr = nullptr,
                                 std::uint32_t redirect_port = 0, const std::uint8_t* redirect_addr = nullptr,
                                 std::uint32_t af = 2, std::uint32_t* out_rule_id = nullptr,
                                 std::uint32_t exclude_pid = 0) noexcept;

        struct redirect_rule_info { std::uint32_t rule_id; std::uint32_t protocol; std::uint32_t match_port;
                                    std::uint32_t redirect_port; std::uint32_t af; std::uint32_t match_count; std::uint32_t active; };
        std::vector<redirect_rule_info> list_redirect_rules() noexcept;

        bool stream_reassemble_op(std::uint32_t operation, std::uint32_t src_port = 0, std::uint32_t dst_port = 0,
                                  std::uint32_t pid = 0, const std::uint8_t* src_addr = nullptr,
                                  const std::uint8_t* dst_addr = nullptr,
                                  std::vector<std::uint8_t>* out_data = nullptr,
                                  std::uint32_t* out_packets = nullptr, std::uint32_t* out_truncated = nullptr) noexcept;

        struct dpi_result {
            std::uint64_t timestamp; std::uint32_t direction; std::uint32_t protocol;
            std::uint32_t src_port; std::uint32_t dst_port; std::uint32_t pid;
            std::uint32_t payload_size; std::uint32_t af;
            std::uint8_t  src_addr[16]; std::uint8_t dst_addr[16];
            std::uint32_t tcp_flags; std::uint32_t tcp_window;
            bool is_http; bool is_tls; bool is_dns;
            std::uint32_t http_method; std::uint32_t tls_version; std::uint32_t tls_content_type;
            std::string http_host; std::string http_path; std::string tls_sni;
        };
        std::vector<dpi_result> get_dpi_results(std::uint32_t filter_pid = 0, std::uint32_t filter_protocol = 0,
                                                std::uint32_t filter_port = 0, std::uint32_t flags = 0) noexcept;

        struct held_packet_info {
            std::uint64_t hold_id; std::uint64_t timestamp; std::uint32_t direction;
            std::uint32_t protocol; std::uint32_t src_port; std::uint32_t dst_port;
            std::uint32_t pid; std::uint32_t payload_size; std::uint32_t af;
            std::uint8_t src_addr[16]; std::uint8_t dst_addr[16];
            std::vector<std::uint8_t> payload;
        };
        bool intercept_op(std::uint32_t operation, std::uint32_t filter_pid = 0, std::uint32_t filter_port = 0,
                          std::uint32_t filter_protocol = 0, std::uint64_t hold_id = 0,
                          const std::uint8_t* modify_payload = nullptr, std::uint32_t modify_size = 0,
                          std::uint32_t* out_held_count = nullptr, bool* out_active = nullptr) noexcept;
        std::vector<held_packet_info> get_held_packets() noexcept;

        bool kill_connection(std::uint32_t protocol, std::uint32_t af,
                             std::uint32_t src_port, std::uint32_t dst_port,
                             const std::uint8_t* src_addr, const std::uint8_t* dst_addr,
                             std::uint32_t pid = 0) noexcept;

        bool dns_spoof_op(std::uint32_t operation, std::uint32_t rule_id = 0,
                  const char* domain = nullptr,
                          const std::uint8_t* spoof_addr = nullptr, std::uint32_t af = 2,
                          std::uint32_t ttl = 300, std::uint32_t* out_rule_id = nullptr) noexcept;

        struct dns_spoof_info { std::uint32_t rule_id; std::string domain;
                                std::uint32_t af; std::uint32_t match_count; std::uint32_t active; std::uint32_t ttl; };
        std::vector<dns_spoof_info> list_dns_spoof_rules() noexcept;

        struct bw_stats {
            std::uint64_t total_bytes_sent; std::uint64_t total_bytes_recv;
            std::uint64_t total_packets_sent; std::uint64_t total_packets_recv;
            std::uint64_t bps_in; std::uint64_t bps_out;
            bool active;
        };
        struct bw_process_info {
            std::uint32_t pid; std::uint64_t bytes_sent; std::uint64_t bytes_recv;
            std::uint64_t packets_sent; std::uint64_t packets_recv; std::uint64_t last_activity;
        };
        bool bw_monitor_op(std::uint32_t operation, std::uint32_t filter_pid = 0,
                           bw_stats* out_stats = nullptr) noexcept;
        std::vector<bw_process_info> get_bw_per_process(std::uint32_t filter_pid = 0) noexcept;

        struct net_iface_info {
            std::uint32_t if_index; std::uint32_t if_type; std::uint32_t mtu;
            std::uint32_t oper_status; std::uint64_t speed;
            std::uint8_t mac_addr[6]; std::uint8_t ipv4_addr[4]; std::uint8_t ipv4_mask[4];
            std::uint8_t ipv6_addr[16];
            std::string name; std::string description;
            std::uint64_t in_octets; std::uint64_t out_octets;
        };
        std::vector<net_iface_info> enumerate_interfaces() noexcept;

        struct pcap_packet {
            std::uint32_t ts_sec; std::uint32_t ts_usec;
            std::vector<std::uint8_t> data;
        };
        struct pcap_export_result {
            detail::pcap_global_header header;
            std::vector<pcap_packet> packets;
        };
        bool export_pcap(std::uint32_t filter_pid = 0, std::uint32_t filter_protocol = 0,
                         std::uint32_t max_packets = 64, pcap_export_result* out = nullptr) noexcept;

        struct fingerprint_info {
            std::uint8_t remote_addr[16]; std::uint32_t af;
            std::uint32_t ttl; std::uint32_t window_size; std::uint32_t mss;
            std::uint32_t window_scale; std::uint32_t df_flag;
            std::uint32_t sack_permitted; std::uint32_t nop_count;
            std::string os_guess;
        };
        bool fingerprint_op(std::uint32_t operation) noexcept;
        std::vector<fingerprint_info> get_fingerprints() noexcept;


        struct dll_protect_status {
            std::uint32_t status;
            std::uint64_t current_hash;
            std::uint64_t expected_hash;
            std::uint64_t last_check_tsc;
        };
        bool register_dll_protection(std::uint64_t module_base,
                                     std::uint64_t text_va, std::uint32_t text_size,
                                     std::uint64_t expected_hash,
                                     std::uint32_t check_interval_ms = 2000) noexcept;
        bool register_dll_protection_for_pid(std::uint32_t pid,
                                             std::uint64_t module_base,
                                             std::uint64_t text_va, std::uint32_t text_size,
                                             std::uint64_t expected_hash,
                                             std::uint32_t check_interval_ms = 2000) noexcept;
        bool query_dll_protection(dll_protect_status& out) noexcept;
        bool unregister_dll_protection() noexcept;
        bool unregister_dll_protection_for_pid(std::uint32_t pid, std::uint64_t module_base = 0) noexcept;

        bool register_usermode_hash(std::uint64_t text_base, std::uint32_t text_size,
                                    std::uint64_t reloc_delta,
                                    const std::uint8_t sha256[32],
                                    const detail::reloc_mask_entry_abi_t* mask_entries,
                                    std::uint32_t mask_count) noexcept;
        bool verify_cross_ring_evidence(const detail::cross_ring_evidence_abi_t& evidence) noexcept;


        bool trigger_kernel_bsod(std::uint32_t reason_code, std::uint64_t evidence_hash) noexcept;
        bool latch_targeting_from_usermode(std::uint32_t reason) noexcept;

        bool tier_a_driver_present_query(bool& out_present, std::uint32_t* out_mask = nullptr,
                                         std::uint64_t* out_first_base = nullptr) noexcept;
        bool canary_register(std::uint64_t va, std::uint64_t size) noexcept;
        bool canary_register_for_pid(std::uint64_t va, std::uint64_t size, std::uint32_t pid) noexcept;
        bool canary_query_count(std::uint32_t& out_count) noexcept;
        bool re_confirmed_usermode_bsod(const detail::re_evidence_blob_t& evidence) noexcept;

        bool query_dma_protection_state(detail::dma_protection_state& out) noexcept;
        bool query_iommu_status(detail::iommu_status& out) noexcept;
        bool enumerate_pcie_devices(detail::pcie_enum_result& out) noexcept;
        bool add_pcie_whitelist(std::uint16_t vendor_id, std::uint16_t device_id) noexcept;
        bool register_canary_poison(std::uint64_t va, std::uint64_t poison_signature) noexcept;
        bool protect_page_pte(std::uint64_t va) noexcept;
        bool unprotect_page_pte(std::uint64_t va) noexcept;
        bool check_ept_state(detail::ept_check_result& out) noexcept;
        bool trigger_dma_countermeasure(std::uint32_t action, std::uint32_t reason) noexcept;

        bool update_re_tool_hashes(const std::uint8_t* hashes, std::uint32_t count) noexcept;
        bool update_werfault_hashes(const std::uint8_t* hashes, std::uint32_t count) noexcept;
        bool update_ce_driver_hashes(const std::uint8_t* hashes, std::uint32_t count) noexcept;

        struct anti_debug_result {
            std::uint32_t result_flags;
            std::uint64_t detected_debugger_pid;
            std::uint64_t dr_clear_count;
        };
        bool kernel_anti_debug_query(anti_debug_result& out) noexcept;
        bool kernel_anti_debug_clear_dr(std::uint64_t* out_clear_count = nullptr) noexcept;
        bool kernel_anti_debug_clear_process_dr(std::uint32_t pid, std::uint64_t* out_clear_count = nullptr) noexcept;
        bool kernel_anti_debug_scan_debuggers(std::uint64_t* out_debugger_pid = nullptr) noexcept;
        bool kernel_anti_debug_scan_text(std::uint64_t module_base, std::uint64_t exception_dir_va, std::uint32_t exception_dir_size, std::uint64_t* out_hit_rva) noexcept;
        bool kernel_anti_debug_hide_thread(std::uint32_t pid, std::uint32_t tid) noexcept;
        bool kernel_anti_debug_hide_all_threads(std::uint32_t pid) noexcept;
        bool kernel_anti_debug_install_instrumentation(std::uint32_t pid, void* callback) noexcept;
        bool kernel_anti_debug_remove_instrumentation(std::uint32_t pid) noexcept;

        struct anti_dump_result {
            std::uint64_t blocks_count;
        };
        bool kernel_anti_dump_full(std::uint32_t pid) noexcept;
        bool kernel_anti_dump_register_filter(std::uint32_t pid) noexcept;
        bool kernel_anti_dump_hide_threads(std::uint32_t pid) noexcept;
        bool kernel_anti_dump_erase_headers(std::uint32_t pid) noexcept;
        bool kernel_anti_dump_query(anti_dump_result& out) noexcept;
        bool kernel_anti_dump_permit_pid(std::uint32_t pid) noexcept;
        bool kernel_anti_dump_unpermit_pid(std::uint32_t pid) noexcept;
        bool kernel_anti_dump_stop_continuous() noexcept;
        bool kernel_anti_dump_start_continuous(std::uint32_t pid) noexcept;

        bool protect_sandbox_pid(std::uint32_t pid, std::uint32_t flags = 0, std::uint64_t* out_denials = nullptr) noexcept;
        bool unprotect_sandbox_pid(std::uint32_t pid, std::uint64_t* out_denials = nullptr) noexcept;
        bool net_log_register_pid(std::uint32_t pid, bool enable) noexcept;
        bool malware_safe_pull_packets(std::uint32_t pid,
                                       std::uint32_t max_records,
                                       std::vector<detail::net_packet_record>& out,
                                       std::uint64_t* out_dropped_since_last_pull = nullptr) noexcept;

        bool relay_server_token(std::uint32_t token_hash, std::uint64_t server_nonce) noexcept;
        bool relay_server_token_v2(std::uint32_t token_hash, std::uint64_t server_nonce, std::uint64_t* out_driver_proof = nullptr) noexcept;

        bool initiate_driver_handshake(std::uint8_t out_driver_challenge[32]) noexcept;
        bool complete_driver_challenge(const std::uint8_t driver_challenge[32]) noexcept;

        bool run_hv_detect(detail::hv_detect_result& out) noexcept;

        bool kernel_read_prologue_hash(std::uint64_t va, std::uint32_t size, std::uint64_t& out_hash) noexcept;
        bool query_sentinel_dispatch_guard(std::uint8_t& out_hook_detected, std::uint64_t& out_hook_target) noexcept;
        bool query_sentinel_callback_scan(std::uint8_t& out_hostile_drivers, std::uint8_t& out_modified_callbacks) noexcept;

        bool verify_watermark(const std::uint8_t expected[16], std::uint32_t watermark_rva,
                              std::uint8_t actual_out[16], std::uint8_t& verified_out) noexcept;

        enum class debug_event_type_e : std::uint32_t {
            invalid         = 0,
            image_loaded    = 1,
            process_created = 2,
            process_exited  = 3,
        };

        struct debug_event_record {
            debug_event_type_e type = debug_event_type_e::invalid;
            std::uint32_t      process_id = 0;
            std::uint32_t      thread_id = 0;
            std::uint32_t      flags = 0;
            std::uint64_t      timestamp = 0;
            std::uint64_t      image_base = 0;
            std::uint64_t      image_size = 0;
            std::wstring       image_path;
        };

        struct debug_event_drain_stats {
            std::uint32_t returned_count = 0;
            std::uint32_t dropped_since_last_drain = 0;
            std::uint64_t total_dropped = 0;
            std::uint64_t total_published = 0;
        };

        bool drain_debug_events(std::vector<debug_event_record>& out,
                                std::size_t max_events = detail::DRAIN_DEBUG_EVENTS_CAP,
                                debug_event_drain_stats* out_stats = nullptr) noexcept;

        bool send_ioctl_raw(std::uint32_t ioctl_code,
                            void* in_out_buffer,
                            std::uint32_t buffer_size,
                            std::uint32_t& bytes_returned) const noexcept {
            bytes_returned = 0;
            detail::raw_ioctl_telemetry trace{};
            trace.requested_code = ioctl_code;
            trace.buffer_size = buffer_size;
            trace.local_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
            trace.local_tid = static_cast<std::uint32_t>(GetCurrentThreadId());
            trace.attached_pid = process_id_;
            trace.connected = is_connected() ? 1u : 0u;
            trace.handle_value = reinterpret_cast<std::uint64_t>(driver_handle_);
            trace.server_seed_present = server_seed_ != 0 ? 1u : 0u;
            trace.ioctl_seed_present = server_ioctl_seed_ != 0 ? 1u : 0u;
            trace.global_server_seed_present_pre = dynamic_key::g_server_seed != 0 ? 1u : 0u;
            trace.global_ioctl_seed_present_pre = ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u;
            trace.pre_base = compute_ioctl_base_snapshot();
            trace.pre_global_base = ioctl_codes::get_base();
            trace.pre_key_hash = hash_build_key(compute_dynamic_key_snapshot());
            trace.pre_global_key_hash = hash_build_key(dynamic_key::get());
            trace.pre_ioctl_seed_hash = server_ioctl_seed_ != 0 ? hash_build_key(server_ioctl_seed_) : 0u;
            trace.pre_global_ioctl_seed_hash = ioctl_codes::g_server_ioctl_seed != 0 ? hash_build_key(ioctl_codes::g_server_ioctl_seed) : 0u;
            trace.heartbeat_tsc = last_heartbeat_tsc_.load(std::memory_order_acquire);
            trace.whoswho_tsc = last_bridge_whoswho_tsc_;
            trace.sentinel_tsc = last_bridge_sentinel_tsc_;
            if (in_out_buffer != nullptr && buffer_size >= sizeof(std::uint32_t)) {
                std::memcpy(&trace.req_pid, in_out_buffer, sizeof(trace.req_pid));
            }
            if (in_out_buffer != nullptr && buffer_size >= sizeof(std::uint32_t) * 2u) {
                std::memcpy(&trace.req_tid, static_cast<const std::uint8_t*>(in_out_buffer) + sizeof(std::uint32_t), sizeof(trace.req_tid));
            }
            std::uint32_t decoded_offset = 0;
            bool decoded_offset_valid = detail::decode_ioctl_offset_from_base(static_cast<DWORD>(ioctl_code), trace.pre_global_base, decoded_offset);
            if (!decoded_offset_valid)
                decoded_offset_valid = detail::decode_ioctl_offset_from_base(static_cast<DWORD>(ioctl_code), trace.pre_base, decoded_offset);
            trace.decoded_offset = decoded_offset;
            trace.decoded_offset_valid = decoded_offset_valid ? 1u : 0u;
            detail::debug_ioctl_raw_log("ENTRY", trace);

            sync_dynamic_security_state();
            trace.post_base = compute_ioctl_base_snapshot();
            trace.post_global_base = ioctl_codes::get_base();
            trace.post_key_hash = hash_build_key(compute_dynamic_key_snapshot());
            trace.post_global_key_hash = hash_build_key(dynamic_key::get());
            trace.post_ioctl_seed_hash = server_ioctl_seed_ != 0 ? hash_build_key(server_ioctl_seed_) : 0u;
            trace.post_global_ioctl_seed_hash = ioctl_codes::g_server_ioctl_seed != 0 ? hash_build_key(ioctl_codes::g_server_ioctl_seed) : 0u;
            trace.global_server_seed_present_post = dynamic_key::g_server_seed != 0 ? 1u : 0u;
            trace.global_ioctl_seed_present_post = ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u;
            DWORD effective_ioctl_code = decoded_offset_valid
                ? make_ioctl_snapshot(decoded_offset)
                : static_cast<DWORD>(ioctl_code);
            trace.effective_code = effective_ioctl_code;
            detail::debug_ioctl_raw_log("POST_SYNC", trace);

            if (!is_connected() || in_out_buffer == nullptr || buffer_size == 0) {
                const DWORD reject_error = !is_connected() ? ERROR_INVALID_HANDLE : ERROR_INVALID_PARAMETER;
                trace.gle = reject_error;
                trace.connected = is_connected() ? 1u : 0u;
                last_raw_ioctl_ = trace;
                SetLastError(reject_error);
                detail::debug_ioctl_raw_log("REJECT", trace);
                return false;
            }

            auto send_raw_once = [&](DWORD code, DWORD& out_bytes, DWORD& out_error, std::uint64_t& out_elapsed) noexcept -> BOOL {
                out_bytes = 0;
                out_error = ERROR_SUCCESS;
                const ULONGLONG start_tick = GetTickCount64();
                SetLastError(ERROR_SUCCESS);
                BOOL result = DeviceIoControl(
                    driver_handle_,
                    code,
                    in_out_buffer,
                    static_cast<DWORD>(buffer_size),
                    in_out_buffer,
                    static_cast<DWORD>(buffer_size),
                    &out_bytes,
                    nullptr
                );
                out_error = result ? ERROR_SUCCESS : GetLastError();
                out_elapsed = static_cast<std::uint64_t>(GetTickCount64() - start_tick);
                return result;
            };

            auto refresh_current_seed_heartbeat = [&]() noexcept -> bool {
                trace.heartbeat_attempted = 1u;
                sync_dynamic_security_state();
                detail::heartbeat_request hb{};
                hb.magic = heartbeat_magic_snapshot();
                hb.session_key = session_key_;
                hb.timestamp = __rdtsc();
                hb.response = 0;
                const DWORD hb_ioctl = make_ioctl_snapshot(8);
                trace.heartbeat_ioctl = hb_ioctl;
                capture_heartbeat_security_snapshot(8, hb_ioctl, hb.magic);
                DWORD hb_bytes = 0;
                SetLastError(ERROR_SUCCESS);
                BOOL hb_result = DeviceIoControl(
                    driver_handle_,
                    hb_ioctl,
                    &hb,
                    sizeof(hb),
                    &hb,
                    sizeof(hb),
                    &hb_bytes,
                    nullptr
                );
                DWORD hb_error = hb_result ? ERROR_SUCCESS : GetLastError();
                const bool hb_ok = hb_result && hb_bytes >= sizeof(hb) && hb.response != 0;
                if (!hb_ok && hb_error == ERROR_SUCCESS) {
                    if (hb_result && hb_bytes < sizeof(hb))
                        hb_error = ERROR_MORE_DATA;
                    else if (hb_result && hb.response == 0)
                        hb_error = ERROR_ACCESS_DENIED;
                    else
                        hb_error = ERROR_GEN_FAILURE;
                }
                last_heartbeat_dioctl_result_ = hb_result;
                last_heartbeat_bytes_ = hb_bytes;
                last_heartbeat_response_ = hb.response;
                last_heartbeat_error_.store(hb_ok ? 0 : hb_error, std::memory_order_release);
                capture_heartbeat_security_snapshot(8, hb_ioctl, hb.magic);
                if (hb_ok) {
                    last_heartbeat_tsc_.store(__rdtsc(), std::memory_order_release);
                    last_bridge_whoswho_tsc_ = hb.whoswho_tsc;
                    last_bridge_sentinel_tsc_ = hb.sentinel_tsc;
                    if (hb.sentinel_tsc != 0 && first_sentinel_ready_tsc_ == 0)
                        first_sentinel_ready_tsc_ = hb.sentinel_tsc;
                }
                trace.heartbeat_ok = hb_ok ? 1u : 0u;
                trace.heartbeat_bytes = static_cast<std::uint32_t>(hb_bytes);
                trace.heartbeat_gle = hb_error;
                trace.heartbeat_response = hb.response;
                trace.heartbeat_tsc = last_heartbeat_tsc_.load(std::memory_order_acquire);
                trace.whoswho_tsc = last_bridge_whoswho_tsc_;
                trace.sentinel_tsc = last_bridge_sentinel_tsc_;
                return hb_ok;
            };

            DWORD br = 0;
            DWORD gle = ERROR_SUCCESS;
            std::uint64_t elapsed = 0;
            BOOL ok = send_raw_once(effective_ioctl_code, br, gle, elapsed);
            trace.initial_bytes_returned = static_cast<std::uint32_t>(br);
            trace.initial_gle = gle;
            trace.initial_elapsed_ms = elapsed;
            trace.bytes_returned = static_cast<std::uint32_t>(br);
            trace.gle = gle;
            trace.elapsed_ms = elapsed;
            bytes_returned = static_cast<std::uint32_t>(br);

            const bool invalid_function = !ok && gle == ERROR_INVALID_FUNCTION;
            const bool zero_byte_dynamic = ok && br == 0 && decoded_offset_valid;
            if (decoded_offset_valid && (invalid_function || zero_byte_dynamic)) {
                trace.retry_reason = invalid_function ? ERROR_INVALID_FUNCTION : ERROR_MORE_DATA;
                refresh_current_seed_heartbeat();
                sync_dynamic_security_state();
                trace.retry_base = compute_ioctl_base_snapshot();
                trace.retry_global_base = ioctl_codes::get_base();
                trace.retry_key_hash = hash_build_key(compute_dynamic_key_snapshot());
                trace.retry_global_key_hash = hash_build_key(dynamic_key::get());
                trace.retry_ioctl_seed_hash = server_ioctl_seed_ != 0 ? hash_build_key(server_ioctl_seed_) : 0u;
                trace.retry_global_ioctl_seed_hash = ioctl_codes::g_server_ioctl_seed != 0 ? hash_build_key(ioctl_codes::g_server_ioctl_seed) : 0u;
                const DWORD retry_ioctl_code = make_ioctl_snapshot(decoded_offset);
                trace.retry_effective_code = retry_ioctl_code;
                trace.retry_recomputed_changed = retry_ioctl_code != effective_ioctl_code ? 1u : 0u;
                if (retry_ioctl_code != effective_ioctl_code) {
                    trace.retry_attempted = 1u;
                    DWORD retry_br = 0;
                    DWORD retry_gle = ERROR_SUCCESS;
                    std::uint64_t retry_elapsed = 0;
                    BOOL retry_ok = send_raw_once(retry_ioctl_code, retry_br, retry_gle, retry_elapsed);
                    trace.retry_ok = retry_ok ? 1u : 0u;
                    trace.retry_bytes_returned = static_cast<std::uint32_t>(retry_br);
                    trace.retry_gle = retry_gle;
                    trace.retry_elapsed_ms = retry_elapsed;
                    ok = retry_ok;
                    br = retry_br;
                    gle = retry_gle;
                    elapsed += retry_elapsed;
                    effective_ioctl_code = retry_ioctl_code;
                    trace.effective_code = effective_ioctl_code;
                    trace.bytes_returned = static_cast<std::uint32_t>(br);
                    trace.gle = gle;
                    trace.elapsed_ms = elapsed;
                    bytes_returned = static_cast<std::uint32_t>(br);
                }
                detail::debug_ioctl_raw_log(trace.retry_attempted ? "RETRY" : "RETRY_SKIPPED", trace);
            }
            last_raw_ioctl_ = trace;
            detail::debug_ioctl_raw_log((ok && br != 0 && elapsed <= 250) ? "OK" : (ok ? "OK_SUSPICIOUS" : "FAILED"), trace);
            if (!ok)
                SetLastError(gle);
            return ok != FALSE;
        }

        [[nodiscard]] std::uint32_t get_process_id() const noexcept { return process_id_; }
        [[nodiscard]] std::uint64_t get_base_address() const noexcept { return base_address_; }
        [[nodiscard]] std::uint64_t get_dtb() const noexcept { return dtb_; }
        [[nodiscard]] std::uint64_t get_kernel_dtb() const noexcept { return kernel_dtb_; }
        [[nodiscard]] DWORD get_last_connect_error() const noexcept { return last_connect_error_; }
        [[nodiscard]] DWORD get_last_heartbeat_error() const noexcept { return last_heartbeat_error_.load(std::memory_order_acquire); }
        [[nodiscard]] DWORD get_last_heartbeat_bytes_returned() const noexcept { return last_heartbeat_bytes_; }
        [[nodiscard]] std::uint64_t get_last_heartbeat_response() const noexcept { return last_heartbeat_response_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_ioctl_code() const noexcept { return last_heartbeat_ioctl_code_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_magic() const noexcept { return last_heartbeat_magic_; }
        [[nodiscard]] BOOL get_last_heartbeat_dioctl_result() const noexcept { return last_heartbeat_dioctl_result_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_base() const noexcept { return last_heartbeat_base_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_key_hash() const noexcept { return last_heartbeat_key_hash_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_ioctl_seed_hash() const noexcept { return last_heartbeat_ioctl_seed_hash_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_server_seed_present() const noexcept { return last_heartbeat_server_seed_present_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_ioctl_seed_present() const noexcept { return last_heartbeat_ioctl_seed_present_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_global_server_seed_present() const noexcept { return last_heartbeat_global_server_seed_present_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_global_ioctl_seed_present() const noexcept { return last_heartbeat_global_ioctl_seed_present_; }
        [[nodiscard]] std::uint32_t get_last_heartbeat_offset() const noexcept { return last_heartbeat_offset_; }
        [[nodiscard]] detail::raw_ioctl_telemetry get_last_raw_ioctl_telemetry() const noexcept { return last_raw_ioctl_; }
        [[nodiscard]] bool has_server_seed() const noexcept { return server_seed_ != 0; }
        [[nodiscard]] bool has_server_ioctl_seed() const noexcept { return server_ioctl_seed_ != 0; }
        [[nodiscard]] std::uint32_t get_server_ioctl_seed_hash() const noexcept { return server_ioctl_seed_ != 0 ? hash_build_key(server_ioctl_seed_) : 0; }
        [[nodiscard]] bool session_invalidated() const noexcept;
        [[nodiscard]] bool is_dynamic_session_seeded() const noexcept {
            return server_seed_ != 0 && server_ioctl_seed_ != 0 &&
                   dynamic_key::g_server_seed != 0 && ioctl_codes::g_server_ioctl_seed != 0;
        }
        void set_session_relay_cache_provider(detail::session_relay_cache_provider_t cb) noexcept {
            session_relay_cache_provider_.store(cb, std::memory_order_release);
        }
        [[nodiscard]] detail::session_relay_cache_provider_t get_session_relay_cache_provider() const noexcept {
            return session_relay_cache_provider_.load(std::memory_order_acquire);
        }
        [[nodiscard]] std::uint32_t get_seed_rotation_waiting_writers() const noexcept {
            return seed_rotation_mtx_.get_waiting_writers();
        }
        [[nodiscard]] std::uint32_t get_seed_rotation_active_readers() const noexcept {
            return seed_rotation_mtx_.get_active_readers();
        }
        [[nodiscard]] std::uint32_t get_shared_send_request_inflight_count() const noexcept {
            return shared_send_request_inflight_count_.load(std::memory_order_acquire);
        }
        [[nodiscard]] std::uint32_t get_seed_rotation_writer_acquiring() const noexcept {
            return seed_rotation_writer_acquiring_.load(std::memory_order_acquire);
        }
        [[nodiscard]] bool is_session_pending_recovery() const noexcept {
            return session_pending_recovery_.load(std::memory_order_acquire) != 0;
        }
        [[nodiscard]] std::uint32_t get_shared_lock_oldest_holder_tid() const noexcept {
            return shared_lock_oldest_holder_tid_.load(std::memory_order_acquire);
        }
        bool force_post_desync_relay_v2(DWORD* out_error = nullptr) noexcept;

        void set_process_id(std::uint32_t pid) noexcept;
        void set_base_address(std::uint64_t base) noexcept { base_address_ = base; }
        void set_dtb(std::uint64_t dtb) noexcept { dtb_ = dtb; }
        void set_kernel_dtb(std::uint64_t dtb) noexcept { kernel_dtb_ = dtb; }
        [[nodiscard]] std::uint64_t get_shellcode_address_diag() const noexcept { return shellcode_address_; }
        [[nodiscard]] std::uint32_t get_shellcode_pid_diag() const noexcept { return shellcode_pid_; }
        [[nodiscard]] std::uint64_t get_shellcode_dtb_at_alloc_diag() const noexcept { return shellcode_dtb_at_alloc_; }
        void sync_dynamic_security_state() const noexcept {
            if (dynamic_key::g_server_seed != server_seed_) {
                dynamic_key::g_server_seed = server_seed_;
                dynamic_key::g_cached_key = 0;
            }
            ioctl_codes::g_server_ioctl_seed = server_ioctl_seed_;
        }
        [[nodiscard]] std::uint32_t compute_dynamic_key_snapshot() const noexcept;
        [[nodiscard]] std::uint32_t compute_ioctl_base_snapshot() const noexcept;
        [[nodiscard]] DWORD make_ioctl_snapshot(std::uint32_t offset) const noexcept;
        [[nodiscard]] std::uint32_t heartbeat_magic_snapshot() const noexcept;
        [[nodiscard]] bool decode_ioctl_offset_snapshot(DWORD control_code, std::uint32_t& offset) const noexcept;
        void capture_heartbeat_security_snapshot(std::uint32_t offset, DWORD ioctl_code, std::uint32_t magic) const noexcept;
        void log_security_snapshot(const char* where, DWORD requested, DWORD effective, DWORD err) const noexcept;

    private:
        HANDLE driver_handle_ = INVALID_HANDLE_VALUE;
        std::uint32_t process_id_ = 0;
        std::uint64_t base_address_ = 0;
        std::uint64_t dtb_ = 0;
        std::uint64_t kernel_dtb_ = 0;
        std::uint64_t shellcode_address_ = 0;
        std::uint64_t spoof_gadget_ = 0;
        std::uint32_t session_key_ = 0;
        std::uint32_t server_seed_ = 0;
        std::uint32_t server_ioctl_seed_ = 0;
        mutable std::atomic<std::uint64_t> last_heartbeat_tsc_{0};
        mutable std::uint64_t last_bridge_whoswho_tsc_ = 0;
        mutable std::uint64_t last_bridge_sentinel_tsc_ = 0;
        mutable std::uint64_t first_sentinel_ready_tsc_ = 0;
        DWORD last_failed_tid_ = 0;
        DWORD last_hijacked_tid_ = 0;
        DWORD last_connect_error_ = 0;
        mutable std::atomic<DWORD> last_heartbeat_error_{0};
        mutable DWORD last_heartbeat_bytes_ = 0;
        mutable std::uint64_t last_heartbeat_response_ = 0;
        mutable std::uint32_t last_heartbeat_ioctl_code_ = 0;
        mutable std::uint32_t last_heartbeat_magic_ = 0;
        mutable BOOL  last_heartbeat_dioctl_result_ = FALSE;
        mutable std::uint32_t last_heartbeat_base_ = 0;
        mutable std::uint32_t last_heartbeat_key_hash_ = 0;
        mutable std::uint32_t last_heartbeat_ioctl_seed_hash_ = 0;
        mutable std::uint32_t last_heartbeat_server_seed_present_ = 0;
        mutable std::uint32_t last_heartbeat_ioctl_seed_present_ = 0;
        mutable std::uint32_t last_heartbeat_global_server_seed_present_ = 0;
        mutable std::uint32_t last_heartbeat_global_ioctl_seed_present_ = 0;
        mutable std::uint32_t last_heartbeat_offset_ = 0;
        mutable detail::raw_ioctl_telemetry last_raw_ioctl_{};
        mutable detail::writer_priority_shared_mutex seed_rotation_mtx_;
        mutable std::atomic<void*> inflight_capture_thread_{nullptr};
        mutable std::atomic<bool> inflight_capture_cancel_pending_{false};


        std::uint64_t ntdll_base_ = 0;
        std::uint64_t ntdll_size_ = 0;
        mutable std::atomic<std::uint32_t> server_token_relay_priority_request_{0};
        mutable std::atomic<std::uint32_t> server_token_relay_priority_yields_observed_{0};
        mutable std::atomic<std::uint32_t> last_acquiring_reader_tid_{0};
        mutable std::atomic<std::uint32_t> last_acquiring_reader_ioctl_{0};
        mutable std::atomic<std::uint64_t> last_acquiring_reader_tsc_{0};
        mutable std::atomic<std::uint64_t> relay_v2_attempts_{0};
        mutable std::atomic<std::uint64_t> relay_v2_commits_{0};
        mutable std::atomic<std::uint64_t> relay_v2_writer_timeouts_{0};
        mutable std::atomic<std::uint64_t> relay_v2_last_attempt_tick_{0};
        mutable std::atomic<std::uint64_t> relay_v2_last_commit_tick_{0};
        mutable std::atomic<std::uint64_t> relay_v2_last_writer_timeout_tick_{0};
        mutable std::atomic<std::uint32_t> seed_rotation_writer_acquiring_{0};
        mutable std::atomic<std::uint32_t> shared_send_request_inflight_count_{0};
        mutable std::atomic<std::uint32_t> shared_lock_oldest_holder_tid_{0};
        mutable std::atomic<std::uint64_t> shared_lock_oldest_holder_acquired_tsc_{0};
        mutable std::atomic<std::uint32_t> session_pending_recovery_{0};
        mutable std::atomic<std::uint64_t> session_pending_recovery_since_tick_{0};
        mutable std::atomic<detail::session_relay_cache_provider_t> session_relay_cache_provider_{nullptr};
        std::uint32_t shellcode_pid_ = 0;
        std::uint64_t shellcode_dtb_at_alloc_ = 0;

        bool send_request(DWORD control_code, void* input, DWORD input_size) const noexcept;
        bool send_request_in_lock(DWORD control_code, void* input, DWORD input_size,
                                  bool predecoded_dynamic_offset_valid = false,
                                  std::uint32_t predecoded_dynamic_offset = 0) const noexcept;
        bool force_post_desync_relay_v2_locked(DWORD* out_error) noexcept;
        void maybe_emit_relay_v2_cadence_summary() const noexcept;
        void record_reader_acquired_for_diag(DWORD control_code) const noexcept;
        bool send_poll_request(void* input, DWORD input_size, std::uint64_t call_id, int iteration) const noexcept;
        bool force_heartbeat() const noexcept;
        std::size_t transfer_physical_read(std::uint32_t pid, std::uint64_t dtb, std::uint64_t address,
                                           void* buffer, std::size_t size) const noexcept;
        std::size_t transfer_physical_write(std::uint32_t pid, std::uint64_t dtb, std::uint64_t address,
                                            const void* buffer, std::size_t size) const noexcept;
        bool ensure_shellcode_allocated() noexcept;
        bool find_spoof_gadget() noexcept;
        std::uint64_t call_function_attempt(std::uint64_t call_id, int attempt_index, std::uint64_t function_address, std::uint64_t arg1, std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4, const DWORD* blacklist, int blacklist_count, std::uint32_t bound_pid, std::uint64_t bound_dtb, std::uint64_t bound_base, std::uint64_t bound_shellcode, std::uint64_t bound_spoof, bool& out_completed) noexcept;

        friend struct device_t_layout_pin;
    };

    struct device_t_layout_pin {
#pragma warning(push)
#pragma warning(disable: 4485 4647 4623 4624 4625 4626)
        static_assert(offsetof(device_t, inflight_capture_thread_)
                      < offsetof(device_t, server_token_relay_priority_request_),
                      "inflight_capture_thread_ must precede server_token_relay_priority_request_ to prevent handle/counter aliasing across stale TUs");
        static_assert(offsetof(device_t, inflight_capture_cancel_pending_)
                      < offsetof(device_t, server_token_relay_priority_request_),
                      "inflight_capture_cancel_pending_ must precede server_token_relay_priority_request_ to prevent layout aliasing across stale TUs");
        static_assert(offsetof(device_t, server_token_relay_priority_request_)
                      < offsetof(device_t, server_token_relay_priority_yields_observed_),
                      "server_token_relay_priority_request_ must precede server_token_relay_priority_yields_observed_ to keep the relay observability slots at end-of-class");
        static_assert(offsetof(device_t, server_token_relay_priority_yields_observed_)
                      < offsetof(device_t, seed_rotation_writer_acquiring_),
                      "writer-priority lock telemetry must precede the new writer-priority intent atomic");
        static_assert(offsetof(device_t, seed_rotation_writer_acquiring_)
                      < offsetof(device_t, shared_send_request_inflight_count_),
                      "seed_rotation_writer_acquiring_ must precede shared_send_request_inflight_count_ for diagnostic ordering");
        static_assert(offsetof(device_t, shared_send_request_inflight_count_)
                      < offsetof(device_t, shared_lock_oldest_holder_tid_),
                      "shared_send_request_inflight_count_ must precede shared_lock_oldest_holder_tid_ for diagnostic ordering");
        static_assert(offsetof(device_t, shared_lock_oldest_holder_tid_)
                      < offsetof(device_t, session_pending_recovery_),
                      "shared_lock_oldest_holder_tid_ must precede session_pending_recovery_ for diagnostic ordering");
        static_assert(offsetof(device_t, session_pending_recovery_)
                      < offsetof(device_t, session_relay_cache_provider_),
                      "session_pending_recovery_ must precede the session relay cache provider hook so the pending-recovery gate is below the late-bound provider pointer");
        static_assert(offsetof(device_t, shellcode_address_) < offsetof(device_t, shellcode_pid_),
                      "shellcode_address_ must precede shellcode_pid_ so the PID-bind companion field is added strictly after the legacy slot");
        static_assert(offsetof(device_t, shellcode_pid_) < offsetof(device_t, shellcode_dtb_at_alloc_),
                      "shellcode_pid_ must precede shellcode_dtb_at_alloc_ to keep the per-PID shellcode binding ABI ordered: address, pid, dtb-at-alloc");
        static_assert(offsetof(device_t, session_relay_cache_provider_) < offsetof(device_t, shellcode_pid_),
                      "shellcode_pid_/shellcode_dtb_at_alloc_ must live at end-of-class to preserve the existing instance layout across stale TUs");
#pragma warning(pop)
    };

    template<typename T>
    [[nodiscard]] T device_t::read(std::uint64_t address) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable for memory operations");

        alignas(T) T result{};
        if (read_raw(address, &result, sizeof(T)) == sizeof(T)) {
            return result;
        }
        return T{};
    }

    template<typename T>
    void device_t::write(std::uint64_t address, const T& value) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable for memory operations");
        write_raw(address, &value, sizeof(T));
    }

    using kernel_demote_detected_callback_t = void(*)(const char*);
    void install_kernel_demote_detected_callback(kernel_demote_detected_callback_t callback) noexcept;

    using send_request_success_callback_t = void(*)();
    void install_send_request_success_callback(send_request_success_callback_t callback) noexcept;
}

inline std::unique_ptr<voyager::device_t> device = std::make_unique<voyager::device_t>();
