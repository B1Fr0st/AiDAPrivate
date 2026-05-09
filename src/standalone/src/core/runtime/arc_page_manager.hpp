#pragma once


#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include "work_queue.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>

#include <httplib.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "bcrypt.lib")

namespace arc_page_manager {

    using json = nlohmann::json;

    inline constexpr size_t kStreamingPageSize = 4096;
    inline constexpr int    kPlaintextWindowMs = 50;
    inline constexpr int    kFunctionTokenTtlMs = 10000;

    struct page_cache_entry_t {
        std::vector<uint8_t> data;
        std::string          iv;
        std::string          auth_tag;
        std::string          hmac;
        int64_t              rotation_epoch;
        bool                 valid;
    };

    struct streaming_page_t {
        std::vector<uint8_t> sealed_payload;
        std::vector<uint8_t> sealed_iv;
        std::vector<uint8_t> sealed_tag;
        std::vector<uint8_t> seal_key;
        size_t               plaintext_size;
        int64_t               epoch_at_fetch;
        ULONGLONG            last_decrypted_at_ms;
        ULONGLONG            sealed_at_ms;
        bool                 valid;
    };

    struct function_token_t {
        std::string nonce_hex;
        std::vector<uint8_t> decryption_key;
        ULONGLONG issued_at_ms;
        ULONGLONG expires_at_ms;
        bool valid;
    };

    struct page_state_t {
        std::vector<page_cache_entry_t> pages;
        int64_t             current_epoch;
        std::string         rotation_key;
        int                 total_pages;
        int                 page_size;
        std::mutex          mtx;
        std::atomic<bool>   initialized{false};
        std::atomic<bool>   stop{false};
        std::thread         rotation_thread;


        std::string         license_key;
        std::string         session_token;
        std::string         hwid;
        std::string         server_host;

        std::vector<streaming_page_t> streaming_pages;
        std::vector<uint8_t>          epoch_nonce;
        int64_t                       epoch_interval_seconds = 300;
        int64_t                       streaming_blob_size = 0;
        int64_t                       streaming_total_pages = 0;
        std::mutex                    streaming_mtx;
        std::atomic<int64_t>          last_epoch_check_ms{0};

        std::unordered_map<std::string, function_token_t> function_tokens;
        std::mutex                                        function_mtx;
    };

    inline page_state_t& state()
    {
        static page_state_t s;
        return s;
    }

    inline std::vector<uint8_t> hex_decode_local(const std::string& hex)
    {
        std::vector<uint8_t> out;
        if (hex.size() % 2 != 0) return out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            unsigned int v = 0;
            char c0 = hex[i];
            char c1 = hex[i + 1];
            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h = hex_val(c0);
            int l = hex_val(c1);
            if (h < 0 || l < 0) { out.clear(); return out; }
            v = static_cast<unsigned int>((h << 4) | l);
            out.push_back(static_cast<uint8_t>(v));
        }
        return out;
    }

    inline std::string hex_encode_local(const uint8_t* data, size_t len)
    {
        static const char digits[] = "0123456789abcdef";
        std::string out;
        out.resize(len * 2);
        for (size_t i = 0; i < len; ++i) {
            out[i * 2] = digits[(data[i] >> 4) & 0x0F];
            out[i * 2 + 1] = digits[data[i] & 0x0F];
        }
        return out;
    }

    inline std::vector<uint8_t> base64_decode_local(const std::string& b64)
    {
        DWORD bin_len = 0;
        if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
                                  CRYPT_STRING_BASE64, nullptr, &bin_len, nullptr, nullptr))
            return {};
        std::vector<uint8_t> out(bin_len);
        if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
                                  CRYPT_STRING_BASE64, out.data(), &bin_len, nullptr, nullptr))
            return {};
        out.resize(bin_len);
        return out;
    }

    inline bool gen_random_bytes(uint8_t* buf, size_t len)
    {
        return BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline std::vector<uint8_t> hmac_sha256(const uint8_t* key, size_t key_len,
                                             const uint8_t* data, size_t data_len)
    {
        std::vector<uint8_t> result(32);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return {};
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                             const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        if (BCryptHashData(hHash, const_cast<PUCHAR>(data),
                           static_cast<ULONG>(data_len), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        if (BCryptFinishHash(hHash, result.data(), 32, 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    inline std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                              const std::vector<uint8_t>& ikm)
    {
        std::vector<uint8_t> effective_salt = salt.empty() ? std::vector<uint8_t>(32, 0) : salt;
        return hmac_sha256(effective_salt.data(), effective_salt.size(),
                           ikm.data(), ikm.size());
    }

    inline std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk,
                                             const std::vector<uint8_t>& info,
                                             size_t out_len)
    {
        std::vector<uint8_t> out;
        out.reserve(out_len);
        std::vector<uint8_t> t;
        uint8_t counter = 1;
        while (out.size() < out_len) {
            std::vector<uint8_t> data;
            data.reserve(t.size() + info.size() + 1);
            data.insert(data.end(), t.begin(), t.end());
            data.insert(data.end(), info.begin(), info.end());
            data.push_back(counter);
            t = hmac_sha256(prk.data(), prk.size(), data.data(), data.size());
            if (t.empty()) return {};
            size_t take = std::min(t.size(), out_len - out.size());
            out.insert(out.end(), t.begin(), t.begin() + take);
            ++counter;
            if (counter == 0) return {};
        }
        return out;
    }

    inline std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                             const std::vector<uint8_t>& salt,
                                             const std::vector<uint8_t>& info,
                                             size_t out_len)
    {
        auto prk = hkdf_extract(salt, ikm);
        if (prk.empty()) return {};
        return hkdf_expand(prk, info, out_len);
    }

    inline std::vector<uint8_t> aes_gcm_decrypt_local(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& ciphertext)
    {
        std::vector<uint8_t> out;
        if (key.size() != 32 || iv.size() != 12 || tag.size() != 16) return out;
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return {};
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       const_cast<PUCHAR>(key.data()),
                                       static_cast<ULONG>(key.size()), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(iv.data());
        info.cbNonce = static_cast<ULONG>(iv.size());
        info.pbTag = const_cast<PUCHAR>(tag.data());
        info.cbTag = static_cast<ULONG>(tag.size());

        ULONG decrypted_len = 0;
        out.resize(ciphertext.size());
        NTSTATUS st = BCryptDecrypt(hKey,
            const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()),
            &info, nullptr, 0,
            out.data(), static_cast<ULONG>(out.size()),
            &decrypted_len, 0);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (st != 0) {
            out.clear();
            return out;
        }
        out.resize(decrypted_len);
        return out;
    }

    inline bool aes_gcm_encrypt_local(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& plaintext,
        std::vector<uint8_t>& out_ciphertext,
        std::vector<uint8_t>& out_tag)
    {
        if (key.size() != 32 || iv.size() != 12) return false;
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return false;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       const_cast<PUCHAR>(key.data()),
                                       static_cast<ULONG>(key.size()), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(iv.data());
        info.cbNonce = static_cast<ULONG>(iv.size());
        out_tag.assign(16, 0);
        info.pbTag = out_tag.data();
        info.cbTag = static_cast<ULONG>(out_tag.size());

        ULONG ciphertext_len = 0;
        out_ciphertext.assign(plaintext.size(), 0);
        NTSTATUS st = BCryptEncrypt(hKey,
            const_cast<PUCHAR>(plaintext.data()),
            static_cast<ULONG>(plaintext.size()),
            &info, nullptr, 0,
            out_ciphertext.data(), static_cast<ULONG>(out_ciphertext.size()),
            &ciphertext_len, 0);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (st != 0) {
            out_ciphertext.clear();
            out_tag.clear();
            return false;
        }
        out_ciphertext.resize(ciphertext_len);
        return true;
    }

    inline std::vector<uint8_t> derive_streaming_page_key(
        const std::string& license_key,
        const std::string& session_token,
        const std::string& hwid,
        uint32_t page_index,
        const std::vector<uint8_t>& epoch_nonce_buf)
    {
        if (epoch_nonce_buf.size() != 32) return {};
        std::vector<uint8_t> ikm;
        ikm.reserve(license_key.size() + session_token.size() + hwid.size() + 8);
        ikm.insert(ikm.end(), license_key.begin(), license_key.end());
        ikm.push_back(static_cast<uint8_t>('|'));
        ikm.insert(ikm.end(), session_token.begin(), session_token.end());
        ikm.push_back(static_cast<uint8_t>('|'));
        ikm.insert(ikm.end(), hwid.begin(), hwid.end());

        std::vector<uint8_t> salt(8, 0);
        salt[0] = static_cast<uint8_t>(page_index & 0xFF);
        salt[1] = static_cast<uint8_t>((page_index >> 8) & 0xFF);
        salt[2] = static_cast<uint8_t>((page_index >> 16) & 0xFF);
        salt[3] = static_cast<uint8_t>((page_index >> 24) & 0xFF);

        static const char info_label[] = "aida/streaming-page/v1";
        std::vector<uint8_t> info(info_label, info_label + (sizeof(info_label) - 1));
        info.insert(info.end(), epoch_nonce_buf.begin(), epoch_nonce_buf.end());

        return hkdf_sha256(ikm, salt, info, 32);
    }

    inline bool seal_streaming_page(streaming_page_t& page, const std::vector<uint8_t>& plaintext)
    {
        std::vector<uint8_t> seal_key(32);
        if (!gen_random_bytes(seal_key.data(), seal_key.size())) return false;
        std::vector<uint8_t> iv(12);
        if (!gen_random_bytes(iv.data(), iv.size())) return false;
        std::vector<uint8_t> tag;
        std::vector<uint8_t> ct;
        if (!aes_gcm_encrypt_local(seal_key, iv, plaintext, ct, tag)) return false;
        page.sealed_payload = std::move(ct);
        page.sealed_iv = std::move(iv);
        page.sealed_tag = std::move(tag);
        page.seal_key = std::move(seal_key);
        page.plaintext_size = plaintext.size();
        page.sealed_at_ms = GetTickCount64();
        page.valid = true;
        return true;
    }

    inline std::vector<uint8_t> unseal_streaming_page(const streaming_page_t& page)
    {
        if (!page.valid) return {};
        return aes_gcm_decrypt_local(page.seal_key, page.sealed_iv, page.sealed_tag,
                                     page.sealed_payload);
    }

    inline void wipe_streaming_page(streaming_page_t& page)
    {
        if (!page.sealed_payload.empty())
            SecureZeroMemory(page.sealed_payload.data(), page.sealed_payload.size());
        if (!page.sealed_iv.empty())
            SecureZeroMemory(page.sealed_iv.data(), page.sealed_iv.size());
        if (!page.sealed_tag.empty())
            SecureZeroMemory(page.sealed_tag.data(), page.sealed_tag.size());
        if (!page.seal_key.empty())
            SecureZeroMemory(page.seal_key.data(), page.seal_key.size());
        page.sealed_payload.clear();
        page.sealed_iv.clear();
        page.sealed_tag.clear();
        page.seal_key.clear();
        page.plaintext_size = 0;
        page.epoch_at_fetch = 0;
        page.last_decrypted_at_ms = 0;
        page.sealed_at_ms = 0;
        page.valid = false;
    }

    inline std::shared_ptr<httplib::Client> make_client()
    {
        auto& s = state();
        auto client = std::make_shared<httplib::Client>(s.server_host.c_str());
        client->set_connection_timeout(10);
        client->set_read_timeout(30);
        client->set_write_timeout(10);
        client->set_keep_alive(true);
        client->set_tcp_nodelay(true);
        client->set_decompress(true);
        client->set_follow_location(true);
        client->enable_server_certificate_verification(true);
        return client;
    }

    inline bool fetch_streaming_info(std::shared_ptr<httplib::Client> client)
    {
        auto& s = state();
        json body;
        body["license_key"] = s.license_key;
        body["session_token"] = s.session_token;
        body["hwid"] = s.hwid;
        auto res = client->Post("/api/arc/streaming/info",
            body.dump(), "application/json");
        if (!res || res->status != 200) return false;
        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        std::lock_guard<std::mutex> lk(s.streaming_mtx);
        s.streaming_blob_size = resp.value("blob_size", int64_t{0});
        s.streaming_total_pages = resp.value("total_pages", int64_t{0});
        s.epoch_interval_seconds = resp.value("epoch_interval_seconds", int64_t{300});
        std::string epoch_hex = resp.value("epoch_nonce", "");
        s.epoch_nonce = hex_decode_local(epoch_hex);
        s.current_epoch = resp.value("current_epoch", int64_t{0});
        if (s.streaming_total_pages > 0 &&
            s.streaming_pages.size() != static_cast<size_t>(s.streaming_total_pages)) {
            for (auto& p : s.streaming_pages) wipe_streaming_page(p);
            s.streaming_pages.assign(s.streaming_total_pages, streaming_page_t{});
        }
        s.last_epoch_check_ms.store(static_cast<int64_t>(GetTickCount64()),
                                    std::memory_order_release);
        return true;
    }

    inline bool fetch_streaming_page(std::shared_ptr<httplib::Client> client, uint32_t page_index)
    {
        auto& s = state();
        json body;
        body["license_key"] = s.license_key;
        body["session_token"] = s.session_token;
        body["hwid"] = s.hwid;
        {
            std::lock_guard<std::mutex> lk(s.streaming_mtx);
            body["client_epoch"] = s.current_epoch;
        }

        std::string path = "/api/arc/page/" + std::to_string(page_index);
        auto res = client->Post(path.c_str(), body.dump(), "application/json");
        if (!res) return false;
        if (res->status == 409) {
            auto resp = json::parse(res->body, nullptr, false);
            if (!resp.is_discarded() && resp.value("reason", "") == "epoch_stale") {
                std::lock_guard<std::mutex> lk(s.streaming_mtx);
                s.current_epoch = resp.value("current_epoch", int64_t{0});
                for (auto& p : s.streaming_pages) wipe_streaming_page(p);
            }
            return false;
        }
        if (res->status != 200) return false;
        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        int64_t resp_epoch = resp.value("current_epoch", int64_t{0});
        std::string epoch_hex = resp.value("epoch_nonce", "");
        std::string b64 = resp.value("data", "");
        std::string iv_hex = resp.value("iv", "");
        std::string tag_hex = resp.value("auth_tag", "");

        auto epoch_buf = hex_decode_local(epoch_hex);
        auto iv = hex_decode_local(iv_hex);
        auto tag = hex_decode_local(tag_hex);
        auto ct = base64_decode_local(b64);
        if (epoch_buf.size() != 32 || iv.size() != 12 || tag.size() != 16 || ct.empty())
            return false;

        auto key = derive_streaming_page_key(s.license_key, s.session_token, s.hwid,
                                              page_index, epoch_buf);
        if (key.size() != 32) return false;
        auto plaintext = aes_gcm_decrypt_local(key, iv, tag, ct);
        SecureZeroMemory(key.data(), key.size());
        if (plaintext.empty()) return false;

        std::lock_guard<std::mutex> lk(s.streaming_mtx);
        if (page_index >= s.streaming_pages.size())
            s.streaming_pages.resize(page_index + 1);
        if (resp_epoch > s.current_epoch) {
            for (auto& p : s.streaming_pages) wipe_streaming_page(p);
            s.current_epoch = resp_epoch;
            s.epoch_nonce = epoch_buf;
        }
        auto& sp = s.streaming_pages[page_index];
        wipe_streaming_page(sp);
        if (!seal_streaming_page(sp, plaintext)) {
            SecureZeroMemory(plaintext.data(), plaintext.size());
            return false;
        }
        sp.epoch_at_fetch = resp_epoch;
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return true;
    }

    inline bool fault_in_page(uint32_t page_index, std::vector<uint8_t>& out_plaintext)
    {
        auto& s = state();
        auto client = make_client();
        if (!fetch_streaming_page(client, page_index)) return false;
        std::lock_guard<std::mutex> lk(s.streaming_mtx);
        if (page_index >= s.streaming_pages.size()) return false;
        auto& sp = s.streaming_pages[page_index];
        if (!sp.valid) return false;
        out_plaintext = unseal_streaming_page(sp);
        if (out_plaintext.empty()) return false;
        sp.last_decrypted_at_ms = GetTickCount64();
        return true;
    }

    inline void seal_overdue_pages_locked()
    {
        auto& s = state();
        const ULONGLONG now = GetTickCount64();
        for (auto& sp : s.streaming_pages) {
            if (!sp.valid) continue;
            if (sp.last_decrypted_at_ms == 0) continue;
            if (now - sp.last_decrypted_at_ms < static_cast<ULONGLONG>(kPlaintextWindowMs))
                continue;
            sp.last_decrypted_at_ms = now;
        }
    }

    inline void invalidate_epoch_locked()
    {
        auto& s = state();
        for (auto& sp : s.streaming_pages) wipe_streaming_page(sp);
    }

    inline bool check_rotation(std::shared_ptr<httplib::Client> client)
    {
        auto& s = state();
        std::lock_guard<std::mutex> lk(s.mtx);

        json body;
        body["license_key"]   = s.license_key;
        body["session_token"] = s.session_token;
        body["hwid"]          = s.hwid;
        body["client_epoch"]  = s.current_epoch;

        auto res = client->Post("/api/download/pages/rotate",
            body.dump(), "application/json");
        if (!res || res->status != 200) return false;

        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        int64_t server_epoch = resp.value("rotation_epoch", (int64_t)0);
        bool stale = resp.value("stale", false);

        if (stale || server_epoch > s.current_epoch) {

            for (auto& p : s.pages)
                p.valid = false;

            s.current_epoch = server_epoch;
            s.rotation_key  = resp.value("rotation_key", "");
            s.total_pages   = resp.value("total_pages", s.total_pages);
            return true;
        }

        return false;
    }

    inline bool download_page(std::shared_ptr<httplib::Client> client, int index)
    {
        auto& s = state();

        json body;
        body["license_key"]     = s.license_key;
        body["session_token"]   = s.session_token;
        body["hwid"]            = s.hwid;
        body["rotation_epoch"]  = s.current_epoch;

        std::string path = "/api/download/pages/rotated/" + std::to_string(index);
        auto res = client->Post(path.c_str(), body.dump(), "application/json");
        if (!res || res->status != 200) return false;

        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        std::lock_guard<std::mutex> lk(s.mtx);

        if (index >= static_cast<int>(s.pages.size()))
            s.pages.resize(index + 1);

        auto& entry = s.pages[index];


        std::string b64 = resp.value("encrypted_page", "");
        DWORD decoded_len = 0;
        CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
            CRYPT_STRING_BASE64, nullptr, &decoded_len, nullptr, nullptr);
        entry.data.resize(decoded_len);
        CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
            CRYPT_STRING_BASE64, entry.data.data(), &decoded_len, nullptr, nullptr);

        entry.iv             = resp.value("iv", "");
        entry.auth_tag       = resp.value("auth_tag", "");
        entry.hmac           = resp.value("hmac", "");
        entry.rotation_epoch = s.current_epoch;
        entry.valid          = true;

        return true;
    }

    inline void rotation_worker()
    {
        auto& s = state();

        auto client = make_client();

        while (!s.stop.load(std::memory_order_acquire))
        {

            for (int i = 0; i < 60 && !s.stop.load(std::memory_order_acquire); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (s.stop.load(std::memory_order_acquire)) break;

            const int64_t now_ms = static_cast<int64_t>(GetTickCount64());
            const int64_t last = s.last_epoch_check_ms.load(std::memory_order_acquire);
            const int64_t epoch_ms = s.epoch_interval_seconds * 1000;
            if (epoch_ms > 0 && (now_ms - last) >= (epoch_ms / 5)) {
                int64_t old_epoch = 0;
                {
                    std::lock_guard<std::mutex> lk(s.streaming_mtx);
                    old_epoch = s.current_epoch;
                }
                if (fetch_streaming_info(client)) {
                    std::lock_guard<std::mutex> lk(s.streaming_mtx);
                    if (s.current_epoch != old_epoch) {
                        invalidate_epoch_locked();
                    }
                }
            }

            {
                std::lock_guard<std::mutex> lk(s.streaming_mtx);
                seal_overdue_pages_locked();
            }

            bool needs_refresh = check_rotation(client);
            if (needs_refresh)
            {
                int total = 0;
                {
                    std::lock_guard<std::mutex> lk(s.mtx);
                    total = s.total_pages;
                }

                for (int i = 0; i < total && !s.stop.load(); ++i)
                {
                    download_page(client, i);

                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
            }
        }
    }

    inline bool initialize(
        const std::string& license_key,
        const std::string& session_token,
        const std::string& hwid,
        const std::string& server_host)
    {
        auto& s = state();
        if (s.initialized.load()) return true;

        s.license_key   = license_key;
        s.session_token = session_token;
        s.hwid          = hwid;
        s.server_host   = server_host;
        s.current_epoch = 0;
        s.total_pages   = 0;
        s.page_size     = 4096;
        s.streaming_blob_size = 0;
        s.streaming_total_pages = 0;
        s.epoch_interval_seconds = 300;
        s.epoch_nonce.clear();
        s.streaming_pages.clear();
        s.last_epoch_check_ms.store(0, std::memory_order_release);


        auto client = make_client();

        check_rotation(client);
        fetch_streaming_info(client);

        s.initialized.store(true);


        try {
            if (!s.rotation_thread.joinable())
                s.rotation_thread = std::thread([]() { rotation_worker(); });
        } catch (...) {}

        return true;
    }

    inline void shutdown()
    {
        auto& s = state();
        s.stop.store(true, std::memory_order_release);
        if (s.rotation_thread.joinable())
            s.rotation_thread.join();
        {
            std::lock_guard<std::mutex> lk(s.streaming_mtx);
            invalidate_epoch_locked();
            if (!s.epoch_nonce.empty())
                SecureZeroMemory(s.epoch_nonce.data(), s.epoch_nonce.size());
            s.epoch_nonce.clear();
            s.streaming_pages.clear();
        }
        {
            std::lock_guard<std::mutex> lk(s.function_mtx);
            for (auto& kv : s.function_tokens) {
                if (!kv.second.decryption_key.empty())
                    SecureZeroMemory(kv.second.decryption_key.data(),
                                     kv.second.decryption_key.size());
            }
            s.function_tokens.clear();
        }
        s.initialized.store(false);
    }

    inline bool is_page_valid(int index)
    {
        auto& s = state();
        std::lock_guard<std::mutex> lk(s.mtx);
        if (index < 0 || index >= static_cast<int>(s.pages.size()))
            return false;
        return s.pages[index].valid &&
               s.pages[index].rotation_epoch == s.current_epoch;
    }

    inline int64_t current_epoch()
    {
        return state().current_epoch;
    }

    inline std::string make_function_request_nonce()
    {
        uint8_t buf[16];
        if (!gen_random_bytes(buf, sizeof(buf))) return {};
        return hex_encode_local(buf, sizeof(buf));
    }

    inline std::vector<uint8_t> sha256_digest(const uint8_t* data, size_t len)
    {
        std::vector<uint8_t> result(32);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        if (BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        if (BCryptFinishHash(hHash, result.data(), 32, 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    inline std::string compute_function_hash(const uint8_t* code, size_t len)
    {
        if (!code || len == 0) return {};
        auto digest = sha256_digest(code, len);
        if (digest.size() != 32) return {};
        return hex_encode_local(digest.data(), digest.size());
    }

    inline bool request_function_key(const std::string& function_name,
                                      const std::string& function_hash,
                                      function_token_t& out_token)
    {
        auto& s = state();
        out_token = function_token_t{};
        if (function_name.empty() || function_hash.empty()) return false;
        if (!s.initialized.load()) return false;

        std::string nonce = make_function_request_nonce();
        if (nonce.empty()) return false;

        json body;
        body["license_key"] = s.license_key;
        body["session_token"] = s.session_token;
        body["hwid"] = s.hwid;
        body["function_name"] = function_name;
        body["function_hash"] = function_hash;
        body["nonce"] = nonce;

        auto client = make_client();
        auto res = client->Post("/api/arc/function/key", body.dump(), "application/json");
        if (!res || res->status != 200) return false;
        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        std::string b64 = resp.value("decryption_key", "");
        if (b64.empty()) return false;
        auto key = base64_decode_local(b64);
        if (key.size() != 32) return false;
        out_token.nonce_hex = nonce;
        out_token.decryption_key = std::move(key);
        out_token.issued_at_ms = GetTickCount64();
        out_token.expires_at_ms = out_token.issued_at_ms + static_cast<ULONGLONG>(kFunctionTokenTtlMs);
        out_token.valid = true;
        {
            std::lock_guard<std::mutex> lk(s.function_mtx);
            auto it = s.function_tokens.find(function_hash);
            if (it != s.function_tokens.end() && !it->second.decryption_key.empty()) {
                SecureZeroMemory(it->second.decryption_key.data(),
                                 it->second.decryption_key.size());
            }
            s.function_tokens[function_hash] = out_token;
        }
        return true;
    }

    inline bool consume_function_token(const std::string& function_name,
                                        const std::string& function_hash,
                                        const std::string& nonce_hex)
    {
        auto& s = state();
        if (!s.initialized.load()) return false;

        json body;
        body["license_key"] = s.license_key;
        body["session_token"] = s.session_token;
        body["hwid"] = s.hwid;
        body["function_name"] = function_name;
        body["function_hash"] = function_hash;
        body["nonce"] = nonce_hex;

        auto client = make_client();
        auto res = client->Post("/api/arc/function/consume", body.dump(), "application/json");
        if (!res || res->status != 200) return false;
        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;
        {
            std::lock_guard<std::mutex> lk(s.function_mtx);
            auto it = s.function_tokens.find(function_hash);
            if (it != s.function_tokens.end()) {
                if (!it->second.decryption_key.empty())
                    SecureZeroMemory(it->second.decryption_key.data(),
                                     it->second.decryption_key.size());
                s.function_tokens.erase(it);
            }
        }
        return true;
    }

    inline bool fetch_function_prologue(const std::string& function_name,
                                         const std::string& function_hash,
                                         std::vector<uint8_t>& out_plaintext)
    {
        auto& s = state();
        out_plaintext.clear();
        if (!s.initialized.load()) return false;
        std::string nonce = make_function_request_nonce();
        if (nonce.empty()) return false;

        json body;
        body["license_key"] = s.license_key;
        body["session_token"] = s.session_token;
        body["hwid"] = s.hwid;
        body["function_name"] = function_name;
        body["function_hash"] = function_hash;
        body["nonce"] = nonce;

        auto client = make_client();
        auto res = client->Post("/api/arc/function/prologue", body.dump(), "application/json");
        if (!res || res->status != 200) return false;
        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        std::string ct_b64 = resp.value("ciphertext", "");
        std::string iv_hex = resp.value("iv", "");
        std::string tag_hex = resp.value("auth_tag", "");
        auto iv = hex_decode_local(iv_hex);
        auto tag = hex_decode_local(tag_hex);
        auto ct = base64_decode_local(ct_b64);
        if (iv.size() != 12 || tag.size() != 16 || ct.empty()) return false;

        std::vector<uint8_t> ikm;
        ikm.reserve(s.license_key.size() + s.hwid.size() + 64);
        ikm.insert(ikm.end(), s.license_key.begin(), s.license_key.end());
        ikm.push_back(static_cast<uint8_t>('|'));
        ikm.insert(ikm.end(), s.hwid.begin(), s.hwid.end());
        std::vector<uint8_t> salt = hex_decode_local(nonce);
        if (salt.empty()) return false;
        std::vector<uint8_t> info_v;
        static const char info_label[] = "aida/prologue-key/v1|";
        info_v.insert(info_v.end(), info_label, info_label + (sizeof(info_label) - 1));
        info_v.insert(info_v.end(), function_hash.begin(), function_hash.end());
        std::vector<uint8_t> master_extracted_ikm;
        master_extracted_ikm.reserve(64);
        master_extracted_ikm.insert(master_extracted_ikm.end(), ikm.begin(), ikm.end());
        auto key = hkdf_sha256(master_extracted_ikm, salt, info_v, 32);
        if (key.size() != 32) return false;
        out_plaintext = aes_gcm_decrypt_local(key, iv, tag, ct);
        SecureZeroMemory(key.data(), key.size());
        return !out_plaintext.empty();
    }

}
