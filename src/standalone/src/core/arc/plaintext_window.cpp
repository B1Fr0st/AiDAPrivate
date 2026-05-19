#include "plaintext_window.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <cstring>
#include <mutex>

#pragma comment(lib, "bcrypt.lib")

namespace aida::arc::plaintext_window
{
    namespace detail
    {
        static std::mutex   g_last_error_mtx;
        static std::string  g_last_error_global;

        static void set_error(std::string& out, const char* code)
        {
            if (!code) code = "";
            out.assign(code);
            std::lock_guard<std::mutex> lk(g_last_error_mtx);
            g_last_error_global.assign(code);
        }

        static bool bcrypt_random(uint8_t* buf, size_t len)
        {
            if (!buf || len == 0) return false;
            NTSTATUS st = BCryptGenRandom(nullptr,
                                          buf,
                                          static_cast<ULONG>(len),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            return BCRYPT_SUCCESS(st);
        }

        static bool hmac_sha256(const uint8_t* key,
                                size_t key_len,
                                const uint8_t* data,
                                size_t data_len,
                                uint8_t out[32])
        {
            if (!key || !data || !out || key_len == 0) return false;
            BCRYPT_ALG_HANDLE  alg  = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            NTSTATUS st = BCryptOpenAlgorithmProvider(
                &alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (!BCRYPT_SUCCESS(st) || !alg) return false;
            bool ok = false;
            st = BCryptCreateHash(alg,
                                  &hash,
                                  nullptr,
                                  0,
                                  const_cast<PUCHAR>(key),
                                  static_cast<ULONG>(key_len),
                                  0);
            if (BCRYPT_SUCCESS(st) && hash)
            {
                st = BCryptHashData(hash,
                                    const_cast<PUCHAR>(data),
                                    static_cast<ULONG>(data_len),
                                    0);
                if (BCRYPT_SUCCESS(st))
                {
                    st = BCryptFinishHash(hash, out, 32, 0);
                    ok = BCRYPT_SUCCESS(st);
                }
            }
            if (hash) BCryptDestroyHash(hash);
            if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
            return ok;
        }

        static bool hkdf_sha256_extract(const uint8_t* salt,
                                        size_t salt_len,
                                        const uint8_t* ikm,
                                        size_t ikm_len,
                                        uint8_t out_prk[32])
        {
            if (salt_len == 0)
            {
                uint8_t zero[32] = {};
                return hmac_sha256(zero, 32, ikm, ikm_len, out_prk);
            }
            return hmac_sha256(salt, salt_len, ikm, ikm_len, out_prk);
        }

        static bool hkdf_sha256_expand(const uint8_t prk[32],
                                       const uint8_t* info,
                                       size_t info_len,
                                       uint8_t* out,
                                       size_t out_len)
        {
            if (!out || out_len == 0 || out_len > 32 * 255) return false;
            uint8_t t[32] = {};
            size_t t_len = 0;
            size_t produced = 0;
            uint8_t counter = 1;
            uint8_t scratch[32 + 256] = {};
            while (produced < out_len)
            {
                size_t off = 0;
                if (t_len > 0)
                {
                    memcpy(scratch + off, t, t_len);
                    off += t_len;
                }
                if (info && info_len > 0)
                {
                    if (info_len > sizeof(scratch) - off - 1)
                    {
                        SecureZeroMemory(t, sizeof(t));
                        SecureZeroMemory(scratch, sizeof(scratch));
                        return false;
                    }
                    memcpy(scratch + off, info, info_len);
                    off += info_len;
                }
                scratch[off++] = counter;
                if (!hmac_sha256(prk, 32, scratch, off, t))
                {
                    SecureZeroMemory(t, sizeof(t));
                    SecureZeroMemory(scratch, sizeof(scratch));
                    return false;
                }
                size_t take = (out_len - produced) < 32 ? (out_len - produced) : 32;
                memcpy(out + produced, t, take);
                produced += take;
                t_len = 32;
                ++counter;
            }
            SecureZeroMemory(t, sizeof(t));
            SecureZeroMemory(scratch, sizeof(scratch));
            return true;
        }

        static bool derive_page_key(const uint8_t sealing_key[kSealingKeySize],
                                    uint64_t allocation_id,
                                    uint64_t page_index,
                                    uint8_t out_key[32])
        {
            uint8_t prk[32] = {};
            const uint8_t empty_salt[1] = { 0 };
            if (!hkdf_sha256_extract(empty_salt, 0, sealing_key, kSealingKeySize, prk))
            {
                SecureZeroMemory(prk, sizeof(prk));
                return false;
            }
            uint8_t info[32] = {};
            const char tag[] = "page|";
            memcpy(info, tag, sizeof(tag) - 1);
            size_t off = sizeof(tag) - 1;
            memcpy(info + off, &allocation_id, sizeof(allocation_id));
            off += sizeof(allocation_id);
            memcpy(info + off, &page_index, sizeof(page_index));
            off += sizeof(page_index);
            bool ok = hkdf_sha256_expand(prk, info, off, out_key, 32);
            SecureZeroMemory(prk, sizeof(prk));
            SecureZeroMemory(info, sizeof(info));
            return ok;
        }

        static void build_iv(uint64_t allocation_id,
                             uint64_t page_index,
                             uint8_t out_iv[kAesGcmIvSize])
        {
            uint8_t scratch[16] = {};
            memcpy(scratch, &allocation_id, 8);
            memcpy(scratch + 8, &page_index, 8);
            memcpy(out_iv, scratch, kAesGcmIvSize);
            SecureZeroMemory(scratch, sizeof(scratch));
        }

        static bool aes_gcm_encrypt(const uint8_t key32[32],
                                    const uint8_t iv12[12],
                                    const uint8_t* plain,
                                    size_t plain_len,
                                    uint8_t* out_cipher,
                                    uint8_t out_tag[16])
        {
            if (!key32 || !iv12 || !plain || !out_cipher || !out_tag) return false;
            if (plain_len > kArcPageSize) return false;
            BCRYPT_ALG_HANDLE alg = nullptr;
            BCRYPT_KEY_HANDLE key = nullptr;
            NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
            if (!BCRYPT_SUCCESS(st) || !alg) return false;
            bool ok = false;
            st = BCryptSetProperty(
                alg,
                BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
                0);
            if (BCRYPT_SUCCESS(st))
            {
                st = BCryptGenerateSymmetricKey(alg,
                                                &key,
                                                nullptr,
                                                0,
                                                const_cast<PUCHAR>(key32),
                                                32,
                                                0);
            }
            if (BCRYPT_SUCCESS(st) && key)
            {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(iv12);
                info.cbNonce = 12;
                info.pbTag   = out_tag;
                info.cbTag   = 16;
                ULONG written = 0;
                st = BCryptEncrypt(key,
                                   const_cast<PUCHAR>(plain),
                                   static_cast<ULONG>(plain_len),
                                   &info,
                                   nullptr,
                                   0,
                                   out_cipher,
                                   static_cast<ULONG>(plain_len),
                                   &written,
                                   0);
                ok = BCRYPT_SUCCESS(st) && written == static_cast<ULONG>(plain_len);
            }
            if (key) BCryptDestroyKey(key);
            if (alg) BCryptCloseAlgorithmProvider(alg, 0);
            return ok;
        }

        static bool aes_gcm_decrypt(const uint8_t key32[32],
                                    const uint8_t iv12[12],
                                    const uint8_t* cipher,
                                    size_t cipher_len,
                                    const uint8_t tag16[16],
                                    uint8_t* out_plain)
        {
            if (!key32 || !iv12 || !cipher || !tag16 || !out_plain) return false;
            if (cipher_len > kArcPageSize) return false;
            BCRYPT_ALG_HANDLE alg = nullptr;
            BCRYPT_KEY_HANDLE key = nullptr;
            NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
            if (!BCRYPT_SUCCESS(st) || !alg) return false;
            bool ok = false;
            st = BCryptSetProperty(
                alg,
                BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
                0);
            if (BCRYPT_SUCCESS(st))
            {
                st = BCryptGenerateSymmetricKey(alg,
                                                &key,
                                                nullptr,
                                                0,
                                                const_cast<PUCHAR>(key32),
                                                32,
                                                0);
            }
            if (BCRYPT_SUCCESS(st) && key)
            {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(iv12);
                info.cbNonce = 12;
                info.pbTag   = const_cast<PUCHAR>(tag16);
                info.cbTag   = 16;
                ULONG written = 0;
                st = BCryptDecrypt(key,
                                   const_cast<PUCHAR>(cipher),
                                   static_cast<ULONG>(cipher_len),
                                   &info,
                                   nullptr,
                                   0,
                                   out_plain,
                                   static_cast<ULONG>(cipher_len),
                                   &written,
                                   0);
                ok = BCRYPT_SUCCESS(st) && written == static_cast<ULONG>(cipher_len);
            }
            if (key) BCryptDestroyKey(key);
            if (alg) BCryptCloseAlgorithmProvider(alg, 0);
            return ok;
        }

        static uint64_t qpc_freq_us()
        {
            static std::atomic<uint64_t> s_cached{0};
            uint64_t cached = s_cached.load(std::memory_order_acquire);
            if (cached != 0) return cached;
            LARGE_INTEGER f{};
            if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) return 0;
            uint64_t v = static_cast<uint64_t>(f.QuadPart);
            s_cached.store(v, std::memory_order_release);
            return v;
        }

        static uint64_t qpc_now_us(uint64_t freq)
        {
            if (freq == 0) return 0;
            LARGE_INTEGER c{};
            if (!QueryPerformanceCounter(&c)) return 0;
            return (static_cast<uint64_t>(c.QuadPart) * 1000000ULL) / freq;
        }

        static bool page_in_range(const handle_t& h, size_t page_index)
        {
            if (h.signature != kHandleSignature) return false;
            if (!h.base) return false;
            return page_index < h.reserved_pages;
        }

        static uint8_t* page_slot_ptr(const handle_t& h, size_t page_index)
        {
            auto* base = reinterpret_cast<uint8_t*>(h.base);
            return base + (page_index * kPageSlotSize);
        }

        static bool protect_slot_rw(const handle_t& h, size_t page_index)
        {
            DWORD old = 0;
            return VirtualProtect(page_slot_ptr(h, page_index),
                                  kPageSlotSize,
                                  PAGE_READWRITE,
                                  &old) != FALSE;
        }

        static bool protect_slot_noaccess(const handle_t& h, size_t page_index)
        {
            DWORD old = 0;
            return VirtualProtect(page_slot_ptr(h, page_index),
                                  kPageSlotSize,
                                  PAGE_NOACCESS,
                                  &old) != FALSE;
        }
    }

    bool create(size_t logical_pages, handle_t& out, std::string& last_error)
    {
        using namespace detail;
        memset(&out, 0, sizeof(out));
        if (logical_pages == 0)
        {
            set_error(last_error, "plaintext_window_create_zero_pages");
            return false;
        }
        if (logical_pages > (16ULL * 1024ULL))
        {
            set_error(last_error, "plaintext_window_create_too_many_pages");
            return false;
        }

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        if (si.dwPageSize == 0)
        {
            set_error(last_error, "plaintext_window_create_systeminfo_failed");
            return false;
        }
        if (static_cast<size_t>(si.dwPageSize) != kOsPageSize)
        {
            set_error(last_error, "plaintext_window_create_unsupported_os_page_size");
            return false;
        }

        size_t total_bytes = logical_pages * kPageSlotSize;

        void* base = VirtualAlloc(nullptr,
                                  total_bytes,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_NOACCESS);
        if (!base)
        {
            set_error(last_error, "plaintext_window_create_virtualalloc_failed");
            return false;
        }

        page_metadata_t* meta = static_cast<page_metadata_t*>(
            HeapAlloc(GetProcessHeap(),
                      HEAP_ZERO_MEMORY,
                      logical_pages * sizeof(page_metadata_t)));
        if (!meta)
        {
            VirtualFree(base, 0, MEM_RELEASE);
            set_error(last_error, "plaintext_window_create_meta_heap_failed");
            return false;
        }

        uint8_t sealing[kSealingKeySize] = {};
        if (!bcrypt_random(sealing, sizeof(sealing)))
        {
            SecureZeroMemory(sealing, sizeof(sealing));
            HeapFree(GetProcessHeap(), 0, meta);
            VirtualFree(base, 0, MEM_RELEASE);
            set_error(last_error, "plaintext_window_create_rng_sealing_failed");
            return false;
        }

        uint64_t alloc_id = 0;
        if (!bcrypt_random(reinterpret_cast<uint8_t*>(&alloc_id), sizeof(alloc_id)))
        {
            SecureZeroMemory(sealing, sizeof(sealing));
            HeapFree(GetProcessHeap(), 0, meta);
            VirtualFree(base, 0, MEM_RELEASE);
            set_error(last_error, "plaintext_window_create_rng_id_failed");
            return false;
        }
        if (alloc_id == 0)
        {
            alloc_id = 0x9E3779B97F4A7C15ULL;
        }

        out.signature                 = kHandleSignature;
        out.base                      = base;
        out.total_bytes               = total_bytes;
        out.reserved_pages            = logical_pages;
        out.logical_pages             = logical_pages;
        out.allocation_id             = alloc_id;
        memcpy(out.sealing_key, sealing, sizeof(out.sealing_key));
        out.live_page_index           = 0;
        out.live_page_active          = false;
        out.live_page_revealed_qpc_us = 0;
        out.freq_us                   = qpc_freq_us();
        out.metadata                  = meta;
        SecureZeroMemory(sealing, sizeof(sealing));
        return true;
    }

    bool consume_page(handle_t& h,
                      size_t page_index,
                      const uint8_t* src_plain,
                      uint32_t src_size,
                      std::string& last_error)
    {
        using namespace detail;
        if (h.signature != kHandleSignature || !h.base)
        {
            set_error(last_error, "plaintext_window_consume_bad_handle");
            return false;
        }
        if (!page_in_range(h, page_index))
        {
            set_error(last_error, "plaintext_window_consume_index_out_of_range");
            return false;
        }
        if (!src_plain || src_size == 0 || src_size > kArcPageSize)
        {
            set_error(last_error, "plaintext_window_consume_bad_input");
            return false;
        }
        if (!h.metadata)
        {
            set_error(last_error, "plaintext_window_consume_metadata_null");
            return false;
        }
        if (h.live_page_active)
        {
            set_error(last_error, "plaintext_window_consume_reveal_in_flight");
            return false;
        }

        uint8_t page_key[32] = {};
        if (!derive_page_key(h.sealing_key, h.allocation_id, page_index, page_key))
        {
            SecureZeroMemory(page_key, sizeof(page_key));
            set_error(last_error, "plaintext_window_consume_derive_failed");
            return false;
        }

        uint8_t iv[kAesGcmIvSize] = {};
        build_iv(h.allocation_id, page_index, iv);

        uint8_t cipher_buf[kArcPageSize] = {};
        uint8_t tag_buf[kAesGcmTagSize]  = {};
        if (!aes_gcm_encrypt(page_key, iv, src_plain, src_size, cipher_buf, tag_buf))
        {
            SecureZeroMemory(page_key, sizeof(page_key));
            SecureZeroMemory(iv, sizeof(iv));
            SecureZeroMemory(cipher_buf, sizeof(cipher_buf));
            SecureZeroMemory(tag_buf, sizeof(tag_buf));
            set_error(last_error, "plaintext_window_consume_gcm_failed");
            return false;
        }

        if (!protect_slot_rw(h, page_index))
        {
            SecureZeroMemory(page_key, sizeof(page_key));
            SecureZeroMemory(iv, sizeof(iv));
            SecureZeroMemory(cipher_buf, sizeof(cipher_buf));
            SecureZeroMemory(tag_buf, sizeof(tag_buf));
            set_error(last_error, "plaintext_window_consume_vprotect_rw_failed");
            return false;
        }

        uint8_t* slot = page_slot_ptr(h, page_index);
        memcpy(slot, cipher_buf, src_size);
        if (src_size < kArcPageSize)
        {
            SecureZeroMemory(slot + src_size, kArcPageSize - src_size);
        }

        h.metadata[page_index].cipher_len = src_size;
        memcpy(h.metadata[page_index].iv, iv, kAesGcmIvSize);
        memcpy(h.metadata[page_index].tag, tag_buf, kAesGcmTagSize);
        h.metadata[page_index].populated = true;

        bool seal_ok = protect_slot_noaccess(h, page_index);

        SecureZeroMemory(page_key, sizeof(page_key));
        SecureZeroMemory(iv, sizeof(iv));
        SecureZeroMemory(cipher_buf, sizeof(cipher_buf));
        SecureZeroMemory(tag_buf, sizeof(tag_buf));

        if (!seal_ok)
        {
            set_error(last_error, "plaintext_window_consume_vprotect_seal_failed");
            return false;
        }
        return true;
    }

    bool reveal_page(handle_t& h,
                     size_t page_index,
                     uint8_t* out_plain,
                     uint32_t out_capacity,
                     uint32_t& out_size,
                     std::string& last_error)
    {
        using namespace detail;
        out_size = 0;
        if (h.signature != kHandleSignature || !h.base)
        {
            set_error(last_error, "plaintext_window_reveal_bad_handle");
            return false;
        }
        if (!page_in_range(h, page_index))
        {
            set_error(last_error, "plaintext_window_reveal_index_out_of_range");
            return false;
        }
        if (!out_plain || out_capacity == 0 || out_capacity > kArcPageSize)
        {
            set_error(last_error, "plaintext_window_reveal_bad_output");
            return false;
        }
        if (h.live_page_active)
        {
            uint64_t now_us = qpc_now_us(h.freq_us);
            uint64_t elapsed_ms = (now_us > h.live_page_revealed_qpc_us)
                ? (now_us - h.live_page_revealed_qpc_us) / 1000ULL
                : 0ULL;
            if (h.live_page_index != static_cast<uint64_t>(page_index) && elapsed_ms < kHoldMs)
            {
                set_error(last_error, "plaintext_window_reveal_concurrent_window");
                return false;
            }
            if (h.live_page_index != static_cast<uint64_t>(page_index))
            {
                std::string ignored;
                finish_reveal(h, static_cast<size_t>(h.live_page_index), ignored);
            }
        }

        if (!h.metadata || !h.metadata[page_index].populated)
        {
            set_error(last_error, "plaintext_window_reveal_page_not_populated");
            return false;
        }

        const uint32_t stored_len = h.metadata[page_index].cipher_len;
        if (stored_len == 0 || stored_len > kArcPageSize || stored_len > out_capacity)
        {
            set_error(last_error, "plaintext_window_reveal_bad_stored_len");
            return false;
        }

        if (!protect_slot_rw(h, page_index))
        {
            set_error(last_error, "plaintext_window_reveal_vprotect_rw_failed");
            return false;
        }

        uint8_t page_key[32] = {};
        if (!derive_page_key(h.sealing_key, h.allocation_id, page_index, page_key))
        {
            SecureZeroMemory(page_key, sizeof(page_key));
            protect_slot_noaccess(h, page_index);
            set_error(last_error, "plaintext_window_reveal_derive_failed");
            return false;
        }

        uint8_t* slot = page_slot_ptr(h, page_index);
        if (!aes_gcm_decrypt(page_key,
                             h.metadata[page_index].iv,
                             slot,
                             stored_len,
                             h.metadata[page_index].tag,
                             out_plain))
        {
            SecureZeroMemory(page_key, sizeof(page_key));
            SecureZeroMemory(out_plain, out_capacity);
            protect_slot_noaccess(h, page_index);
            set_error(last_error, "plaintext_window_reveal_gcm_failed");
            return false;
        }
        SecureZeroMemory(page_key, sizeof(page_key));

        h.live_page_index           = static_cast<uint64_t>(page_index);
        h.live_page_active          = true;
        h.live_page_revealed_qpc_us = qpc_now_us(h.freq_us);
        out_size = stored_len;
        return true;
    }

    bool finish_reveal(handle_t& h,
                       size_t page_index,
                       std::string& last_error)
    {
        using namespace detail;
        if (h.signature != kHandleSignature || !h.base)
        {
            set_error(last_error, "plaintext_window_finish_bad_handle");
            return false;
        }
        if (!page_in_range(h, page_index))
        {
            set_error(last_error, "plaintext_window_finish_index_out_of_range");
            return false;
        }

        bool seal_ok = protect_slot_noaccess(h, page_index);

        if (h.live_page_active && h.live_page_index == static_cast<uint64_t>(page_index))
        {
            h.live_page_active          = false;
            h.live_page_index           = 0;
            h.live_page_revealed_qpc_us = 0;
        }

        if (!seal_ok)
        {
            set_error(last_error, "plaintext_window_finish_vprotect_seal_failed");
            return false;
        }
        return true;
    }

    namespace detail
    {
        struct stream_sink_ctx_t
        {
            const std::function<bool(const uint8_t*,
                                     uint32_t,
                                     size_t,
                                     size_t)>* sink;
            const uint8_t* plain;
            uint32_t       size;
            size_t         index;
            size_t         total;
            bool           result;
        };

        __declspec(noinline) static void invoke_sink_seh(stream_sink_ctx_t* ctx)
        {
            __try {
                ctx->result = (*ctx->sink)(ctx->plain, ctx->size, ctx->index, ctx->total);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ctx->result = false;
            }
        }
    }

    bool stream_to_loader(handle_t& h,
                          const std::function<bool(const uint8_t* page_bytes,
                                                   uint32_t page_size,
                                                   size_t page_index,
                                                   size_t total_pages)>& sink,
                          std::string& last_error)
    {
        using namespace detail;
        if (h.signature != kHandleSignature || !h.base)
        {
            set_error(last_error, "plaintext_window_stream_bad_handle");
            return false;
        }
        if (!sink)
        {
            set_error(last_error, "plaintext_window_stream_no_sink");
            return false;
        }

        uint8_t plain_buf[kArcPageSize] = {};
        const size_t total = h.logical_pages;
        for (size_t i = 0; i < total; ++i)
        {
            uint32_t sz = 0;
            uint64_t window_open_us = qpc_now_us(h.freq_us);
            if (!reveal_page(h, i, plain_buf, static_cast<uint32_t>(sizeof(plain_buf)), sz, last_error))
            {
                SecureZeroMemory(plain_buf, sizeof(plain_buf));
                return false;
            }

            stream_sink_ctx_t ctx{};
            ctx.sink   = &sink;
            ctx.plain  = plain_buf;
            ctx.size   = sz;
            ctx.index  = i;
            ctx.total  = total;
            ctx.result = false;
            invoke_sink_seh(&ctx);
            bool sink_ok = ctx.result;

            SecureZeroMemory(plain_buf, sizeof(plain_buf));
            std::string seal_err;
            if (!finish_reveal(h, i, seal_err))
            {
                last_error = seal_err;
                return false;
            }

            uint64_t now_us = qpc_now_us(h.freq_us);
            uint64_t elapsed_ms = (now_us > window_open_us)
                ? (now_us - window_open_us) / 1000ULL
                : 0ULL;
            (void)elapsed_ms;

            if (!sink_ok)
            {
                set_error(last_error, "plaintext_window_stream_sink_rejected");
                return false;
            }
        }
        return true;
    }

    void destroy(handle_t& h)
    {
        using namespace detail;
        if (h.signature != kHandleSignature)
        {
            memset(&h, 0, sizeof(h));
            return;
        }
        if (h.base)
        {
            for (size_t i = 0; i < h.reserved_pages; ++i)
            {
                DWORD old = 0;
                if (VirtualProtect(page_slot_ptr(h, i),
                                   kPageSlotSize,
                                   PAGE_READWRITE,
                                   &old) == FALSE)
                {
                    continue;
                }
                for (size_t pass = 0; pass < kOverwritePasses; ++pass)
                {
                    uint8_t entropy[256];
                    if (!bcrypt_random(entropy, sizeof(entropy)))
                    {
                        memset(entropy, static_cast<int>(0x55u ^ static_cast<uint8_t>(pass)), sizeof(entropy));
                    }
                    auto* dst = page_slot_ptr(h, i);
                    size_t remaining = kPageSlotSize;
                    size_t off = 0;
                    while (remaining > 0)
                    {
                        size_t chunk = remaining < sizeof(entropy) ? remaining : sizeof(entropy);
                        memcpy(dst + off, entropy, chunk);
                        off += chunk;
                        remaining -= chunk;
                    }
                    SecureZeroMemory(entropy, sizeof(entropy));
                }
                SecureZeroMemory(page_slot_ptr(h, i), kPageSlotSize);
            }
            VirtualFree(h.base, 0, MEM_RELEASE);
        }
        if (h.metadata)
        {
            SecureZeroMemory(h.metadata, h.reserved_pages * sizeof(page_metadata_t));
            HeapFree(GetProcessHeap(), 0, h.metadata);
        }
        SecureZeroMemory(h.sealing_key, sizeof(h.sealing_key));
        memset(&h, 0, sizeof(h));
    }

    const char* last_error_global()
    {
        using namespace detail;
        std::lock_guard<std::mutex> lk(g_last_error_mtx);
        return g_last_error_global.c_str();
    }
}
