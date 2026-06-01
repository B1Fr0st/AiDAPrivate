#include "license_state.hpp"

#include "arc_build_seed.hpp"

#include <Windows.h>
#include <bcrypt.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <atomic>
#include <cstring>
#include <mutex>
#include <type_traits>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    using aida::license_state::license_state_t;
    using aida::license_state::status_pending;

    constexpr uint8_t  k_state_version_v1     = 1;
    constexpr uint64_t k_magic_const_xor      = 0xA1DA0FF1CEDDA1DAULL;
    constexpr size_t   k_mac_offset_bytes     = offsetof(license_state_t, mac);
    constexpr size_t   k_mac_truncated_bytes  = 16;

    std::mutex s_state_mtx;

    alignas(license_state_t) uint8_t s_state_storage[sizeof(license_state_t)] = {};

    std::atomic<bool> s_initialized{false};

    struct secret_holder_t
    {
        uint8_t* buf = nullptr;
        size_t   size = 0;
    };

    secret_holder_t s_secret_holder{};
    std::mutex s_secret_mtx;

    bool bcrypt_random(uint8_t* out, size_t n)
    {
        if (out == nullptr || n == 0) return false;
        return BCryptGenRandom(nullptr, out, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    bool allocate_secret_buffer()
    {
        std::lock_guard<std::mutex> lk(s_secret_mtx);
        if (s_secret_holder.buf != nullptr) return true;
        size_t alloc_size = 32;
        void* mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, alloc_size);
        if (mem == nullptr) return false;
        s_secret_holder.buf = static_cast<uint8_t*>(mem);
        s_secret_holder.size = alloc_size;
        return true;
    }

    void release_secret_buffer()
    {
        std::lock_guard<std::mutex> lk(s_secret_mtx);
        if (s_secret_holder.buf != nullptr)
        {
            SecureZeroMemory(s_secret_holder.buf, s_secret_holder.size);
            HeapFree(GetProcessHeap(), 0, s_secret_holder.buf);
            s_secret_holder.buf = nullptr;
            s_secret_holder.size = 0;
        }
    }

    bool derive_state_secret_into_holder()
    {
        if (!allocate_secret_buffer()) return false;
        auto okm = arc_internal::arc_build_subkey_bytes("aida.license.state.v1");
        uint8_t acc = 0;
        for (size_t i = 0; i < okm.size(); ++i) acc |= okm[i];
        if (acc == 0)
        {
            SecureZeroMemory(okm.data(), okm.size());
            return false;
        }
        uint8_t process_entropy[32];
        if (!bcrypt_random(process_entropy, sizeof(process_entropy)))
        {
            SecureZeroMemory(okm.data(), okm.size());
            return false;
        }
        std::lock_guard<std::mutex> lk(s_secret_mtx);
        if (s_secret_holder.buf == nullptr || s_secret_holder.size < 32)
        {
            SecureZeroMemory(okm.data(), okm.size());
            SecureZeroMemory(process_entropy, sizeof(process_entropy));
            return false;
        }
        for (size_t i = 0; i < 32; ++i)
        {
            s_secret_holder.buf[i] = static_cast<uint8_t>(okm[i] ^ process_entropy[i]);
        }
        SecureZeroMemory(okm.data(), okm.size());
        SecureZeroMemory(process_entropy, sizeof(process_entropy));
        return true;
    }

    bool copy_secret_locked_unsafe(uint8_t out[32])
    {
        std::lock_guard<std::mutex> lk(s_secret_mtx);
        if (s_secret_holder.buf == nullptr || s_secret_holder.size < 32) return false;
        for (size_t i = 0; i < 32; ++i) out[i] = s_secret_holder.buf[i];
        return true;
    }

    constexpr char k_binding_domain_prefix[] = "AIDA_LSB_V1";
    constexpr size_t k_binding_domain_prefix_len = sizeof(k_binding_domain_prefix);
    constexpr size_t k_binding_secret_bytes = 32;
    constexpr size_t k_image_hash_bytes = 32;

    alignas(32) uint8_t s_binding_secret[k_binding_secret_bytes] = {};
    alignas(32) uint8_t s_image_hash[k_image_hash_bytes] = {};
    std::atomic<bool> s_binding_ready{false};
    std::atomic<bool> s_image_hash_ready{false};
    std::mutex s_binding_mtx;

    bool copy_binding_secret(uint8_t out[32])
    {
        if (!s_binding_ready.load(std::memory_order_acquire)) return false;
        std::lock_guard<std::mutex> lk(s_binding_mtx);
        for (size_t i = 0; i < k_binding_secret_bytes; ++i) out[i] = s_binding_secret[i];
        return true;
    }

    bool derive_bound_mac_key(uint8_t out_key[32])
    {
        alignas(32) uint8_t secret[32] = {};
        if (!copy_secret_locked_unsafe(secret)) return false;
        alignas(32) uint8_t binding[k_binding_secret_bytes] = {};
        if (!copy_binding_secret(binding))
        {
            SecureZeroMemory(secret, sizeof(secret));
            return false;
        }
        uint8_t hmac_out[32] = {};
        unsigned int hmac_len = 0;
        if (!HMAC(EVP_sha256(), secret, 32,
                  binding, k_binding_secret_bytes,
                  hmac_out, &hmac_len) || hmac_len != 32)
        {
            SecureZeroMemory(secret, sizeof(secret));
            SecureZeroMemory(binding, sizeof(binding));
            SecureZeroMemory(hmac_out, sizeof(hmac_out));
            return false;
        }
        for (size_t i = 0; i < 32; ++i) out_key[i] = hmac_out[i];
        SecureZeroMemory(secret, sizeof(secret));
        SecureZeroMemory(binding, sizeof(binding));
        SecureZeroMemory(hmac_out, sizeof(hmac_out));
        return true;
    }

    bool compute_mac(const license_state_t& st, uint8_t out_mac[16])
    {
        alignas(32) uint8_t mac_key[32] = {};
        if (!derive_bound_mac_key(mac_key)) return false;
        uint8_t hmac_out[32] = {};
        unsigned int hmac_len = 0;
        if (!HMAC(EVP_sha256(), mac_key, 32,
                  reinterpret_cast<const uint8_t*>(&st),
                  k_mac_offset_bytes,
                  hmac_out, &hmac_len) || hmac_len != 32)
        {
            SecureZeroMemory(mac_key, sizeof(mac_key));
            SecureZeroMemory(hmac_out, sizeof(hmac_out));
            return false;
        }
        for (size_t i = 0; i < k_mac_truncated_bytes; ++i) out_mac[i] = hmac_out[i];
        SecureZeroMemory(mac_key, sizeof(mac_key));
        SecureZeroMemory(hmac_out, sizeof(hmac_out));
        return true;
    }

    bool magic_self_check(const license_state_t& st)
    {
        uint64_t expected = st.magic_a ^ st.magic_b ^ k_magic_const_xor;
        return st.magic_c == expected;
    }

    void copy_state_in(const license_state_t& src)
    {
        std::memcpy(s_state_storage, &src, sizeof(license_state_t));
    }

    void copy_state_out(license_state_t& dst)
    {
        std::memcpy(&dst, s_state_storage, sizeof(license_state_t));
    }

    void state_failfast_mac_mismatch()
    {
        __fastfail(0xA1DA0001u);
    }

    bool generate_session_magics(uint64_t& a, uint64_t& b, uint64_t& c)
    {
        uint8_t entropy[16];
        if (!bcrypt_random(entropy, sizeof(entropy))) return false;
        std::memcpy(&a, entropy, sizeof(a));
        std::memcpy(&b, entropy + 8, sizeof(b));
        c = a ^ b ^ k_magic_const_xor;
        SecureZeroMemory(entropy, sizeof(entropy));
        return true;
    }

    bool is_protector_volatile_section(const char* name8)
    {
        if (name8 == nullptr) return true;
        char buf[9] = {};
        for (size_t i = 0; i < 8; ++i) buf[i] = name8[i];
        static const char* k_skips[] = {
            ".epheme", ".dthunk", ".licbind", ".feat", ".gehi", ".dseal",
            ".rsrc", ".reloc", ".pdata", ".xdata", ".idata", ".tls"
        };
        for (const char* s : k_skips)
        {
            size_t len = 0;
            while (s[len] != 0 && len < 8) ++len;
            bool eq = true;
            for (size_t i = 0; i < len; ++i)
            {
                if (buf[i] != s[i]) { eq = false; break; }
            }
            if (eq && (len == 8 || buf[len] == 0)) return true;
        }
        return false;
    }

    bool snapshot_image_text_hash(uint8_t out_hash[k_image_hash_bytes])
    {
        HMODULE hmod = GetModuleHandleW(nullptr);
        if (hmod == nullptr) return false;
        auto base = reinterpret_cast<const uint8_t*>(hmod);
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        WORD count = nt->FileHeader.NumberOfSections;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) return false;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return false;
        }

        for (WORD i = 0; i < count; ++i)
        {
            const IMAGE_SECTION_HEADER& sh = sec[i];
            if (is_protector_volatile_section(reinterpret_cast<const char*>(sh.Name))) continue;
            DWORD characteristics = sh.Characteristics;
            if ((characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 &&
                (characteristics & IMAGE_SCN_MEM_READ) == 0) continue;
            if ((characteristics & IMAGE_SCN_MEM_WRITE) != 0) continue;
            DWORD vsize = sh.Misc.VirtualSize;
            if (vsize == 0) continue;
            const uint8_t* sec_base = base + sh.VirtualAddress;
            uint8_t header_buf[16] = {};
            std::memcpy(header_buf, sh.Name, 8);
            header_buf[8]  = static_cast<uint8_t>(sh.VirtualAddress & 0xff);
            header_buf[9]  = static_cast<uint8_t>((sh.VirtualAddress >> 8) & 0xff);
            header_buf[10] = static_cast<uint8_t>((sh.VirtualAddress >> 16) & 0xff);
            header_buf[11] = static_cast<uint8_t>((sh.VirtualAddress >> 24) & 0xff);
            header_buf[12] = static_cast<uint8_t>(vsize & 0xff);
            header_buf[13] = static_cast<uint8_t>((vsize >> 8) & 0xff);
            header_buf[14] = static_cast<uint8_t>((vsize >> 16) & 0xff);
            header_buf[15] = static_cast<uint8_t>((vsize >> 24) & 0xff);
            if (EVP_DigestUpdate(ctx, header_buf, sizeof(header_buf)) != 1)
            {
                EVP_MD_CTX_free(ctx);
                return false;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            size_t consumed = 0;
            while (consumed < vsize)
            {
                const uint8_t* probe = sec_base + consumed;
                if (VirtualQuery(probe, &mbi, sizeof(mbi)) == 0) break;
                size_t region_remaining = 0;
                {
                    auto region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                    auto probe_addr = reinterpret_cast<uintptr_t>(probe);
                    if (region_end <= probe_addr) break;
                    region_remaining = static_cast<size_t>(region_end - probe_addr);
                }
                size_t to_hash = region_remaining;
                if (to_hash > (vsize - consumed)) to_hash = vsize - consumed;
                bool committed = (mbi.State == MEM_COMMIT);
                bool no_access = (mbi.Protect == PAGE_NOACCESS) || (mbi.Protect == 0);
                if (committed && !no_access)
                {
                    if (EVP_DigestUpdate(ctx, probe, to_hash) != 1)
                    {
                        EVP_MD_CTX_free(ctx);
                        return false;
                    }
                }
                else
                {
                    uint8_t zero_marker[1] = { 0 };
                    if (EVP_DigestUpdate(ctx, zero_marker, sizeof(zero_marker)) != 1)
                    {
                        EVP_MD_CTX_free(ctx);
                        return false;
                    }
                }
                consumed += to_hash;
                if (to_hash == 0) break;
            }
        }

        unsigned char digest[EVP_MAX_MD_SIZE] = {};
        unsigned int digest_len = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len < k_image_hash_bytes)
        {
            EVP_MD_CTX_free(ctx);
            SecureZeroMemory(digest, sizeof(digest));
            return false;
        }
        EVP_MD_CTX_free(ctx);
        for (size_t i = 0; i < k_image_hash_bytes; ++i) out_hash[i] = digest[i];
        SecureZeroMemory(digest, sizeof(digest));
        return true;
    }

    bool derive_binding_secret_locked()
    {
        HMODULE hmod = GetModuleHandleW(nullptr);
        if (hmod == nullptr) return false;
        auto base = reinterpret_cast<const uint8_t*>(hmod);
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        uint64_t pe_image_base = reinterpret_cast<uint64_t>(hmod);
        uint64_t pe_size_of_image = static_cast<uint64_t>(nt->OptionalHeader.SizeOfImage);
        uint64_t pe_timestamp = static_cast<uint64_t>(nt->FileHeader.TimeDateStamp);
        uint64_t pe_entry_rva = static_cast<uint64_t>(nt->OptionalHeader.AddressOfEntryPoint);

        uint8_t boot_salt[32] = {};
        if (!bcrypt_random(boot_salt, sizeof(boot_salt))) return false;

        LARGE_INTEGER qpc{};
        if (!QueryPerformanceCounter(&qpc)) qpc.QuadPart = 0;
        uint64_t boot_qpc_anchor = static_cast<uint64_t>(qpc.QuadPart);

        DWORD pid = GetCurrentProcessId();
        uint64_t process_id = static_cast<uint64_t>(pid);

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
        {
            SecureZeroMemory(boot_salt, sizeof(boot_salt));
            return false;
        }
        auto fail_cleanup = [&]() {
            EVP_MD_CTX_free(ctx);
            SecureZeroMemory(boot_salt, sizeof(boot_salt));
        };
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) { fail_cleanup(); return false; }
        if (EVP_DigestUpdate(ctx, k_binding_domain_prefix, k_binding_domain_prefix_len) != 1)
        {
            fail_cleanup();
            return false;
        }
        auto absorb_u64 = [&](uint64_t v) -> bool {
            uint8_t buf[8];
            for (size_t i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
            return EVP_DigestUpdate(ctx, buf, sizeof(buf)) == 1;
        };
        if (!absorb_u64(pe_image_base) ||
            !absorb_u64(pe_size_of_image) ||
            !absorb_u64(pe_timestamp) ||
            !absorb_u64(pe_entry_rva) ||
            !absorb_u64(boot_qpc_anchor) ||
            !absorb_u64(process_id))
        {
            fail_cleanup();
            return false;
        }
        if (EVP_DigestUpdate(ctx, boot_salt, sizeof(boot_salt)) != 1)
        {
            fail_cleanup();
            return false;
        }

        unsigned char digest[EVP_MAX_MD_SIZE] = {};
        unsigned int digest_len = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len < k_binding_secret_bytes)
        {
            fail_cleanup();
            SecureZeroMemory(digest, sizeof(digest));
            return false;
        }
        EVP_MD_CTX_free(ctx);
        SecureZeroMemory(boot_salt, sizeof(boot_salt));

        uint8_t acc = 0;
        for (size_t i = 0; i < k_binding_secret_bytes; ++i) acc |= digest[i];
        if (acc == 0)
        {
            SecureZeroMemory(digest, sizeof(digest));
            return false;
        }
        for (size_t i = 0; i < k_binding_secret_bytes; ++i) s_binding_secret[i] = digest[i];
        SecureZeroMemory(digest, sizeof(digest));
        return true;
    }
}

namespace aida::license_state
{
    bool materialize_state_secret(uint8_t out_secret[32])
    {
        if (out_secret == nullptr) return false;
        alignas(32) uint8_t base_secret[32] = {};
        if (!copy_secret_locked_unsafe(base_secret)) return false;
        alignas(32) uint8_t binding[k_binding_secret_bytes] = {};
        if (!copy_binding_secret(binding))
        {
            SecureZeroMemory(base_secret, sizeof(base_secret));
            return false;
        }
        uint8_t hmac_out[32] = {};
        unsigned int hmac_len = 0;
        if (!HMAC(EVP_sha256(), base_secret, 32,
                  binding, k_binding_secret_bytes,
                  hmac_out, &hmac_len) || hmac_len != 32)
        {
            SecureZeroMemory(base_secret, sizeof(base_secret));
            SecureZeroMemory(binding, sizeof(binding));
            SecureZeroMemory(hmac_out, sizeof(hmac_out));
            return false;
        }
        for (size_t i = 0; i < 32; ++i) out_secret[i] = hmac_out[i];
        SecureZeroMemory(base_secret, sizeof(base_secret));
        SecureZeroMemory(binding, sizeof(binding));
        SecureZeroMemory(hmac_out, sizeof(hmac_out));
        return true;
    }

    bool initialize()
    {
        if (s_initialized.load(std::memory_order_acquire)) return true;
        std::lock_guard<std::mutex> lk(s_state_mtx);
        if (s_initialized.load(std::memory_order_acquire)) return true;
        if (!derive_state_secret_into_holder()) return false;

        {
            std::lock_guard<std::mutex> bk(s_binding_mtx);
            if (!derive_binding_secret_locked()) return false;
        }
        s_binding_ready.store(true, std::memory_order_release);

        uint8_t initial_hash[k_image_hash_bytes] = {};
        if (!snapshot_image_text_hash(initial_hash))
        {
            SecureZeroMemory(initial_hash, sizeof(initial_hash));
            return false;
        }
        {
            std::lock_guard<std::mutex> bk(s_binding_mtx);
            for (size_t i = 0; i < k_image_hash_bytes; ++i) s_image_hash[i] = initial_hash[i];
        }
        SecureZeroMemory(initial_hash, sizeof(initial_hash));
        s_image_hash_ready.store(true, std::memory_order_release);

        license_state_t st{};
        st.version = k_state_version_v1;
        st.status  = static_cast<uint8_t>(status_pending);
        st.tier    = 0;
        st.flags   = 0;
        for (auto& r : st.reserved) r = 0;
        st.session_epoch = 0;
        if (!generate_session_magics(st.magic_a, st.magic_b, st.magic_c)) return false;
        for (auto& m : st.mac) m = 0;

        uint8_t mac[16] = {};
        if (!compute_mac(st, mac)) return false;
        std::memcpy(st.mac, mac, sizeof(mac));
        SecureZeroMemory(mac, sizeof(mac));

        copy_state_in(st);
        s_initialized.store(true, std::memory_order_release);
        return true;
    }

    bool recheck_image_hash()
    {
        if (!s_image_hash_ready.load(std::memory_order_acquire)) return false;
        uint8_t current[k_image_hash_bytes] = {};
        if (!snapshot_image_text_hash(current))
        {
            SecureZeroMemory(current, sizeof(current));
            return false;
        }
        uint8_t diff = 0;
        {
            std::lock_guard<std::mutex> bk(s_binding_mtx);
            for (size_t i = 0; i < k_image_hash_bytes; ++i)
            {
                diff |= static_cast<uint8_t>(current[i] ^ s_image_hash[i]);
            }
        }
        SecureZeroMemory(current, sizeof(current));
        return diff == 0;
    }

    bool image_binding_active()
    {
        return s_binding_ready.load(std::memory_order_acquire)
            && s_image_hash_ready.load(std::memory_order_acquire);
    }

    bool is_initialized()
    {
        return s_initialized.load(std::memory_order_acquire);
    }

    bool set_state(const license_state_t& new_state, std::string& last_error)
    {
        if (!s_initialized.load(std::memory_order_acquire))
        {
            last_error = "license_state_not_initialized";
            return false;
        }
        if (new_state.version != k_state_version_v1)
        {
            last_error = "license_state_bad_version";
            return false;
        }
        if (!magic_self_check(new_state))
        {
            last_error = "license_state_magic_invariant_violated";
            return false;
        }
        std::lock_guard<std::mutex> lk(s_state_mtx);
        license_state_t copy = new_state;
        for (auto& m : copy.mac) m = 0;
        uint8_t mac[16] = {};
        if (!compute_mac(copy, mac))
        {
            last_error = "license_state_mac_compute_failed";
            return false;
        }
        std::memcpy(copy.mac, mac, sizeof(mac));
        SecureZeroMemory(mac, sizeof(mac));
        copy_state_in(copy);
        return true;
    }

    bool read_state(license_state_t& out, std::string& last_error)
    {
        if (!s_initialized.load(std::memory_order_acquire))
        {
            last_error = "license_state_not_initialized";
            return false;
        }
        std::lock_guard<std::mutex> lk(s_state_mtx);
        license_state_t snapshot{};
        copy_state_out(snapshot);
        if (snapshot.version != k_state_version_v1)
        {
            last_error = "license_state_bad_version_runtime";
            state_failfast_mac_mismatch();
        }
        if (!magic_self_check(snapshot))
        {
            last_error = "license_state_magic_runtime_invariant_violated";
            state_failfast_mac_mismatch();
        }
        license_state_t mac_input = snapshot;
        for (auto& m : mac_input.mac) m = 0;
        uint8_t expected[16] = {};
        if (!compute_mac(mac_input, expected))
        {
            last_error = "license_state_mac_recompute_failed";
            state_failfast_mac_mismatch();
        }
        uint8_t diff = 0;
        for (size_t i = 0; i < k_mac_truncated_bytes; ++i)
        {
            diff |= static_cast<uint8_t>(expected[i] ^ snapshot.mac[i]);
        }
        SecureZeroMemory(expected, sizeof(expected));
        if (diff != 0)
        {
            last_error = "license_state_mac_mismatch";
            state_failfast_mac_mismatch();
        }
        out = snapshot;
        return true;
    }

    bool is_valid_or_degraded()
    {
        std::string err;
        license_state_t st{};
        if (!read_state(st, err)) return false;
        return st.status == static_cast<uint8_t>(status_valid)
            && ((st.flags & static_cast<uint8_t>(flag_arc_loaded)) != 0);
    }

    bool is_arc_loaded()
    {
        std::string err;
        license_state_t st{};
        if (!read_state(st, err)) return false;
        return (st.flags & static_cast<uint8_t>(flag_arc_loaded)) != 0;
    }

    bool is_driver_attached()
    {
        std::string err;
        license_state_t st{};
        if (!read_state(st, err)) return false;
        return (st.flags & static_cast<uint8_t>(flag_driver_attached)) != 0;
    }

    bool is_heartbeat_ok()
    {
        std::string err;
        license_state_t st{};
        if (!read_state(st, err)) return false;
        return (st.flags & static_cast<uint8_t>(flag_heartbeat_ok)) != 0;
    }

    bool is_license_pending_activation()
    {
        std::string err;
        license_state_t st{};
        if (!read_state(st, err)) return true;
        return st.status == static_cast<uint8_t>(status_pending)
            || st.status == static_cast<uint8_t>(status_unset);
    }

    uint8_t current_tier()
    {
        std::string err;
        license_state_t st{};
        if (!read_state(st, err)) return 0;
        return st.tier;
    }

    uint64_t current_session_epoch()
    {
        std::string err;
        license_state_t st{};
        if (!read_state(st, err)) return 0;
        return st.session_epoch;
    }

    bool transition_to(status_e new_status, std::string& last_error)
    {
        license_state_t st{};
        if (!read_state(st, last_error)) return false;
        st.status = static_cast<uint8_t>(new_status);
        return set_state(st, last_error);
    }

    bool set_flags(uint8_t set_mask, uint8_t clear_mask, std::string& last_error)
    {
        license_state_t st{};
        if (!read_state(st, last_error)) return false;
        uint8_t flags = st.flags;
        flags = static_cast<uint8_t>(flags & ~clear_mask);
        flags = static_cast<uint8_t>(flags | set_mask);
        st.flags = flags;
        return set_state(st, last_error);
    }

    bool set_tier(uint8_t tier, std::string& last_error)
    {
        license_state_t st{};
        if (!read_state(st, last_error)) return false;
        st.tier = tier;
        return set_state(st, last_error);
    }

    bool bump_session_epoch(uint64_t& out_new_epoch, std::string& last_error)
    {
        license_state_t st{};
        if (!read_state(st, last_error)) return false;
        st.session_epoch += 1;
        out_new_epoch = st.session_epoch;
        return set_state(st, last_error);
    }

    void shutdown()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        SecureZeroMemory(s_state_storage, sizeof(s_state_storage));
        s_initialized.store(false, std::memory_order_release);
        release_secret_buffer();
        {
            std::lock_guard<std::mutex> bk(s_binding_mtx);
            SecureZeroMemory(s_binding_secret, sizeof(s_binding_secret));
            SecureZeroMemory(s_image_hash, sizeof(s_image_hash));
        }
        s_binding_ready.store(false, std::memory_order_release);
        s_image_hash_ready.store(false, std::memory_order_release);
    }
}
