#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "customer_capsule.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

using json = nlohmann::json;

namespace aida::runtime::customer_capsule
{
    namespace
    {
        constexpr std::uint64_t kMaxCapsuleSize = 1024ull * 1024ull;
        constexpr const char* kProofPrefix = "aida-standalone-capsule-proof/v1";
        constexpr const char kFooterMagic[16] = {
            'A','I','D','A','_','C','A','P','S','U','L','E','_','V','1','\0'
        };

#pragma pack(push, 1)
        struct capsule_footer_t
        {
            char magic[16];
            std::uint32_t version;
            std::uint32_t footer_size;
            std::uint64_t capsule_size;
            std::uint64_t base_size;
            std::uint8_t base_sha256[32];
            std::uint8_t capsule_sha256[32];
        };
#pragma pack(pop)

        struct loaded_capsule_t
        {
            capsule_info_t info;
            std::string secret;
        };

        std::once_flag g_once;
        loaded_capsule_t g_capsule;

        std::string bytes_to_hex(const std::uint8_t* data, size_t size)
        {
            static const char hex[] = "0123456789abcdef";
            std::string out;
            out.reserve(size * 2);
            for (size_t i = 0; i < size; ++i)
            {
                out.push_back(hex[(data[i] >> 4) & 0x0F]);
                out.push_back(hex[data[i] & 0x0F]);
            }
            return out;
        }

        int hex_digit(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        }

        bool hex_to_bytes(const std::string& hex, std::string& out)
        {
            if (hex.empty() || (hex.size() % 2) != 0) return false;
            out.clear();
            out.reserve(hex.size() / 2);
            for (size_t i = 0; i < hex.size(); i += 2)
            {
                int hi = hex_digit(hex[i]);
                int lo = hex_digit(hex[i + 1]);
                if (hi < 0 || lo < 0) return false;
                out.push_back(static_cast<char>((hi << 4) | lo));
            }
            return true;
        }

        std::string trim_lower_hex64(const std::string& value)
        {
            std::string s;
            s.reserve(value.size());
            for (char c : value)
            {
                if (!std::isspace(static_cast<unsigned char>(c)))
                    s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
            if (s.size() != 64) return {};
            for (char c : s)
                if (hex_digit(c) < 0) return {};
            return s;
        }

        bool base64_decode(const std::string& b64, std::string& out)
        {
            DWORD needed = 0;
            if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
                                      CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr) || needed == 0)
                return false;
            std::vector<std::uint8_t> buf(needed);
            if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
                                      CRYPT_STRING_BASE64, buf.data(), &needed, nullptr, nullptr))
                return false;
            out.assign(reinterpret_cast<const char*>(buf.data()), needed);
            SecureZeroMemory(buf.data(), buf.size());
            return !out.empty();
        }

        bool read_exact_at(HANDLE file, std::uint64_t offset, void* dst, std::uint32_t size)
        {
            LARGE_INTEGER li{};
            li.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(file, li, nullptr, FILE_BEGIN)) return false;
            std::uint8_t* out = static_cast<std::uint8_t*>(dst);
            DWORD total = 0;
            while (total < size)
            {
                DWORD got = 0;
                if (!ReadFile(file, out + total, size - total, &got, nullptr) || got == 0)
                    return false;
                total += got;
            }
            return true;
        }

        bool hash_region(HANDLE file, std::uint64_t offset, std::uint64_t size, std::uint8_t out[32])
        {
            BCRYPT_ALG_HANDLE alg = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
                return false;
            if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0)
            {
                BCryptCloseAlgorithmProvider(alg, 0);
                return false;
            }
            LARGE_INTEGER li{};
            li.QuadPart = static_cast<LONGLONG>(offset);
            bool ok = SetFilePointerEx(file, li, nullptr, FILE_BEGIN) ? true : false;
            std::array<std::uint8_t, 64 * 1024> buf{};
            std::uint64_t remaining = size;
            while (ok && remaining > 0)
            {
                DWORD want = static_cast<DWORD>((std::min<std::uint64_t>)(buf.size(), remaining));
                DWORD got = 0;
                if (!ReadFile(file, buf.data(), want, &got, nullptr) || got == 0)
                {
                    ok = false;
                    break;
                }
                if (BCryptHashData(hash, buf.data(), got, 0) != 0)
                {
                    ok = false;
                    break;
                }
                remaining -= got;
            }
            if (ok && BCryptFinishHash(hash, out, 32, 0) != 0)
                ok = false;
            SecureZeroMemory(buf.data(), buf.size());
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return ok;
        }

        bool hmac_sha256_hex(const std::string& key, const std::string& data, std::string& out)
        {
            BCRYPT_ALG_HANDLE alg = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            std::uint8_t mac[32] = {};
            if (key.empty()) return false;
            if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                            BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
                return false;
            if (BCryptCreateHash(alg, &hash, nullptr, 0,
                                 reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
                                 static_cast<ULONG>(key.size()), 0) != 0)
            {
                BCryptCloseAlgorithmProvider(alg, 0);
                return false;
            }
            bool ok = BCryptHashData(hash,
                                     reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                                     static_cast<ULONG>(data.size()), 0) == 0
                && BCryptFinishHash(hash, mac, sizeof(mac), 0) == 0;
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            if (!ok) return false;
            out = bytes_to_hex(mac, sizeof(mac));
            SecureZeroMemory(mac, sizeof(mac));
            return true;
        }

        std::string random_hex(size_t bytes)
        {
            std::vector<std::uint8_t> buf(bytes);
            if (BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(buf.size()),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
                return {};
            std::string out = bytes_to_hex(buf.data(), buf.size());
            SecureZeroMemory(buf.data(), buf.size());
            return out;
        }

        bool valid_capsule_id(const std::string& id)
        {
            if (id.size() < 8 || id.size() > 128) return false;
            for (char c : id)
            {
                const unsigned char uc = static_cast<unsigned char>(c);
                if (std::isalnum(uc) || c == '_' || c == '-' || c == '.' || c == ':')
                    continue;
                return false;
            }
            return true;
        }

        std::string build_message(const char* action,
                                  const std::string& license_key,
                                  const std::string& hwid,
                                  const std::string& client_nonce,
                                  const std::string& session_token,
                                  const std::string& heartbeat_nonce,
                                  const std::string& heartbeat_count,
                                  const std::string& req_seq,
                                  const proof_fields_t& fields)
        {
            std::string msg;
            msg.reserve(512);
            msg += kProofPrefix;
            msg += '\n';
            msg += action;
            msg += '\n';
            msg += license_key;
            msg += '\n';
            if (std::string(action) == "validate")
            {
                msg += hwid;
                msg += '\n';
                msg += client_nonce;
                msg += '\n';
            }
            else
            {
                msg += session_token;
                msg += '\n';
                msg += hwid;
                msg += '\n';
                msg += heartbeat_nonce;
                msg += '\n';
                msg += heartbeat_count;
                msg += '\n';
                msg += req_seq;
                msg += '\n';
            }
            msg += fields.capsule_id;
            msg += '\n';
            msg += fields.base_sha256;
            msg += '\n';
            msg += fields.capsule_sha256;
            msg += '\n';
            msg += fields.proof_nonce;
            msg += '\n';
            msg += std::to_string(fields.proof_ts);
            return msg;
        }

        bool extract_secret(const json& j, std::string& out)
        {
            if (j.contains("secret_b64") && j["secret_b64"].is_string())
                return base64_decode(j["secret_b64"].get<std::string>(), out);
            if (j.contains("secret_hex") && j["secret_hex"].is_string())
                return hex_to_bytes(j["secret_hex"].get<std::string>(), out);
            if (j.contains("secret") && j["secret"].is_string())
            {
                out = j["secret"].get<std::string>();
                return out.size() >= 16;
            }
            return false;
        }

        loaded_capsule_t read_capsule()
        {
            loaded_capsule_t loaded{};
            wchar_t path[32768] = {};
            DWORD len = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path)));
            if (len == 0 || len >= _countof(path))
            {
                loaded.info.error = "module_path";
                return loaded;
            }
            HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                loaded.info.error = "open";
                return loaded;
            }
            LARGE_INTEGER li{};
            if (!GetFileSizeEx(file, &li) || li.QuadPart <= static_cast<LONGLONG>(sizeof(capsule_footer_t)))
            {
                loaded.info.error = "absent";
                CloseHandle(file);
                return loaded;
            }
            const std::uint64_t file_size = static_cast<std::uint64_t>(li.QuadPart);
            capsule_footer_t footer{};
            if (!read_exact_at(file, file_size - sizeof(footer), &footer, static_cast<std::uint32_t>(sizeof(footer))))
            {
                loaded.info.error = "footer_read";
                CloseHandle(file);
                return loaded;
            }
            if (std::memcmp(footer.magic, kFooterMagic, sizeof(footer.magic)) != 0)
            {
                loaded.info.error = "absent";
                CloseHandle(file);
                return loaded;
            }
            loaded.info.present = true;
            if (footer.version != 1 || footer.footer_size != sizeof(capsule_footer_t)
                || footer.capsule_size == 0 || footer.capsule_size > kMaxCapsuleSize
                || footer.base_size > file_size
                || footer.capsule_size > file_size - footer.base_size
                || footer.footer_size > file_size - footer.base_size - footer.capsule_size
                || footer.base_size + footer.capsule_size + footer.footer_size != file_size)
            {
                loaded.info.error = "footer_invalid";
                CloseHandle(file);
                return loaded;
            }
            std::uint8_t base_hash[32] = {};
            std::uint8_t capsule_hash[32] = {};
            if (!hash_region(file, 0, footer.base_size, base_hash)
                || !hash_region(file, footer.base_size, footer.capsule_size, capsule_hash))
            {
                loaded.info.error = "hash_failed";
                CloseHandle(file);
                return loaded;
            }
            if (std::memcmp(base_hash, footer.base_sha256, 32) != 0
                || std::memcmp(capsule_hash, footer.capsule_sha256, 32) != 0)
            {
                loaded.info.error = "hash_mismatch";
                CloseHandle(file);
                return loaded;
            }
            std::vector<std::uint8_t> capsule(static_cast<size_t>(footer.capsule_size));
            if (!read_exact_at(file, footer.base_size, capsule.data(), static_cast<std::uint32_t>(capsule.size())))
            {
                loaded.info.error = "capsule_read";
                CloseHandle(file);
                return loaded;
            }
            CloseHandle(file);
            auto parsed = json::parse(capsule.begin(), capsule.end(), nullptr, false);
            SecureZeroMemory(capsule.data(), capsule.size());
            if (parsed.is_discarded() || !parsed.is_object())
            {
                loaded.info.error = "json";
                return loaded;
            }
            const std::string capsule_id = parsed.value("capsule_id", "");
            if (!valid_capsule_id(capsule_id))
            {
                loaded.info.error = "capsule_id";
                return loaded;
            }
            const std::string base_hex = bytes_to_hex(base_hash, sizeof(base_hash));
            const std::string capsule_hex = bytes_to_hex(capsule_hash, sizeof(capsule_hash));
            if (parsed.contains("base_sha256") && trim_lower_hex64(parsed.value("base_sha256", "")) != base_hex)
            {
                loaded.info.error = "base_json_mismatch";
                return loaded;
            }
            if (parsed.contains("capsule_sha256") && trim_lower_hex64(parsed.value("capsule_sha256", "")) != capsule_hex)
            {
                loaded.info.error = "capsule_json_mismatch";
                return loaded;
            }
            if (!extract_secret(parsed, loaded.secret))
            {
                loaded.info.error = "secret";
                return loaded;
            }
            loaded.info.present = true;
            loaded.info.valid = true;
            loaded.info.capsule_id = capsule_id;
            loaded.info.base_sha256 = base_hex;
            loaded.info.capsule_sha256 = capsule_hex;
            loaded.info.error.clear();
            return loaded;
        }

        const loaded_capsule_t& get_loaded_capsule()
        {
            std::call_once(g_once, []() {
                g_capsule = read_capsule();
            });
            return g_capsule;
        }

        bool build_proof(const char* action,
                         const std::string& license_key,
                         const std::string& hwid,
                         const std::string& client_nonce,
                         const std::string& session_token,
                         const std::string& heartbeat_nonce,
                         const std::string& heartbeat_count,
                         const std::string& req_seq,
                         proof_fields_t& out)
        {
            const loaded_capsule_t& loaded = get_loaded_capsule();
            if (!loaded.info.present || !loaded.info.valid || loaded.secret.empty()) return false;
            proof_fields_t fields{};
            fields.capsule_id = loaded.info.capsule_id;
            fields.base_sha256 = loaded.info.base_sha256;
            fields.capsule_sha256 = loaded.info.capsule_sha256;
            fields.proof_nonce = random_hex(16);
            fields.proof_ts = static_cast<std::int64_t>(std::time(nullptr));
            if (fields.proof_nonce.empty() || fields.proof_ts <= 0) return false;
            std::string msg = build_message(action, license_key, hwid, client_nonce, session_token,
                                            heartbeat_nonce, heartbeat_count, req_seq, fields);
            if (!hmac_sha256_hex(loaded.secret, msg, fields.proof)) return false;
            out = std::move(fields);
            return true;
        }
    }

    const capsule_info_t& get_capsule_info()
    {
        return get_loaded_capsule().info;
    }

    bool build_validate_proof(const std::string& license_key,
                              const std::string& hwid,
                              const std::string& client_nonce,
                              proof_fields_t& out)
    {
        return build_proof("validate", license_key, hwid, client_nonce, {}, {}, {}, {}, out);
    }

    bool build_heartbeat_proof(const std::string& license_key,
                               const std::string& session_token,
                               const std::string& hwid,
                               const std::string& heartbeat_nonce,
                               std::uint32_t heartbeat_count,
                               const std::string& req_seq,
                               proof_fields_t& out)
    {
        return build_proof("heartbeat", license_key, hwid, {}, session_token, heartbeat_nonce,
                           std::to_string(heartbeat_count), req_seq, out);
    }
}
