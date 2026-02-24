#include "aida_pro.hpp"

#ifdef __NT__
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

#include <ctime>
#include <cstring>
#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/rand.h>

static const std::string& get_firebase_host()
{
    static const std::string host =
        OBFSTR("https://aida-license-prod-default-rtdb.europe-west1.firebasedatabase.app");
    return host;
}

static const std::string& get_hardcoded_firebase_api_key()
{
    VMP_VIRT("get_fb_key");
    static const std::string key = OBFBYTES("bWLmMKBhD3TE7iYMnKizIjOrt4jXd9R1m0CVCj6P");
    VMP_END;
    return key;
}

static std::string get_effective_firebase_api_key()
{
    VMP_MUT("get_eff_key");
    std::string key = get_hardcoded_firebase_api_key();
    
    if (key.find("XXXXXXX") != std::string::npos || key.empty())
    {
        key = g_settings.firebase_api_key;
    }
    VMP_END;
    return key;
}

static constexpr int64_t LICENSE_CACHE_DURATION_SEC = 7 * 24 * 3600;

std::string license_manager_t::compute_hmac(
    const std::string& key_str,
    const unsigned char* data, size_t data_len) const
{
    constexpr size_t BLOCK_SIZE = 64;
    constexpr size_t HASH_SIZE = 32;

    unsigned char key_block[BLOCK_SIZE] = {};
    if (key_str.size() > BLOCK_SIZE)
    {
        unsigned int olen = HASH_SIZE;
        EVP_Digest(key_str.data(), key_str.size(), key_block, &olen,
                   EVP_sha256(), nullptr);
    }
    else
    {
        std::memcpy(key_block, key_str.data(), key_str.size());
    }

    std::vector<unsigned char> inner_msg(BLOCK_SIZE + data_len);
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
        inner_msg[i] = key_block[i] ^ 0x36;
    if (data_len > 0)
        std::memcpy(inner_msg.data() + BLOCK_SIZE, data, data_len);

    unsigned char inner_hash[HASH_SIZE];
    unsigned int inner_len = HASH_SIZE;
    EVP_Digest(inner_msg.data(), inner_msg.size(), inner_hash, &inner_len,
               EVP_sha256(), nullptr);

    unsigned char outer_msg[BLOCK_SIZE + HASH_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
        outer_msg[i] = key_block[i] ^ 0x5C;
    std::memcpy(outer_msg + BLOCK_SIZE, inner_hash, HASH_SIZE);

    unsigned char result[HASH_SIZE];
    unsigned int result_len = HASH_SIZE;
    EVP_Digest(outer_msg, sizeof(outer_msg), result, &result_len,
               EVP_sha256(), nullptr);

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (size_t i = 0; i < HASH_SIZE; ++i)
        hex << std::setw(2) << static_cast<int>(result[i]);
    return hex.str();
}

license_manager_t& license_manager_t::instance()
{
    static license_manager_t inst;
    return inst;
}

std::string license_manager_t::encrypt_local(const std::string& plaintext) const
{
    VMP_VIRT("encrypt_local");
    std::string hwid = generate_hwid();

    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1)
    {
        uint64_t t = static_cast<uint64_t>(std::time(nullptr));
        for (size_t i = 0; i < sizeof(salt); ++i)
            salt[i] = static_cast<unsigned char>(
                (t >> ((i % 8) * 8)) ^ hwid[i % hwid.size()]);
    }

    std::string key_material = hwid;
    key_material.append(reinterpret_cast<const char*>(salt), sizeof(salt));
    unsigned char enc_key[32];
    unsigned int klen = 32;
    EVP_Digest(key_material.data(), key_material.size(),
               enc_key, &klen, EVP_sha256(), nullptr);

    std::vector<unsigned char> ct(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); ++i)
        ct[i] = static_cast<unsigned char>(plaintext[i]) ^ enc_key[i % 32];

    std::vector<unsigned char> hmac_input;
    hmac_input.insert(hmac_input.end(), salt, salt + sizeof(salt));
    hmac_input.insert(hmac_input.end(), ct.begin(), ct.end());

    std::string hmac_hex = compute_hmac(
        std::string(reinterpret_cast<const char*>(enc_key), 32),
        hmac_input.data(), hmac_input.size());

    std::vector<unsigned char> hmac_bytes;
    hmac_bytes.reserve(32);
    for (size_t i = 0; i + 1 < hmac_hex.size(); i += 2)
    {
        unsigned int bv = 0;
        std::istringstream(hmac_hex.substr(i, 2)) >> std::hex >> bv;
        hmac_bytes.push_back(static_cast<unsigned char>(bv));
    }

    std::vector<unsigned char> payload;
    payload.insert(payload.end(), salt, salt + sizeof(salt));
    payload.insert(payload.end(), ct.begin(), ct.end());
    payload.insert(payload.end(), hmac_bytes.begin(), hmac_bytes.end());

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned char b : payload)
        hex << std::setw(2) << static_cast<int>(b);

    VMP_END;
    return hex.str();
}

std::string license_manager_t::decrypt_local(const std::string& hex_input) const
{
    VMP_VIRT("decrypt_local");

    std::vector<unsigned char> raw;
    raw.reserve(hex_input.size() / 2);
    for (size_t i = 0; i + 1 < hex_input.size(); i += 2)
    {
        unsigned int bv = 0;
        std::istringstream(hex_input.substr(i, 2)) >> std::hex >> bv;
        raw.push_back(static_cast<unsigned char>(bv));
    }

    if (raw.size() < 48)
    {
        VMP_END;
        return decrypt_local_legacy(hex_input);
    }

    const unsigned char* salt = raw.data();
    size_t ct_len = raw.size() - 16 - 32;
    const unsigned char* ct = raw.data() + 16;
    const unsigned char* stored_hmac = raw.data() + 16 + ct_len;

    std::string hwid = generate_hwid();
    std::string key_material = hwid;
    key_material.append(reinterpret_cast<const char*>(salt), 16);
    unsigned char enc_key[32];
    unsigned int klen = 32;
    EVP_Digest(key_material.data(), key_material.size(),
               enc_key, &klen, EVP_sha256(), nullptr);

    std::vector<unsigned char> hmac_input;
    hmac_input.insert(hmac_input.end(), salt, salt + 16);
    hmac_input.insert(hmac_input.end(), ct, ct + ct_len);

    std::string computed_hex = compute_hmac(
        std::string(reinterpret_cast<const char*>(enc_key), 32),
        hmac_input.data(), hmac_input.size());

    std::ostringstream stored_hex;
    stored_hex << std::hex << std::setfill('0');
    for (size_t i = 0; i < 32; ++i)
        stored_hex << std::setw(2) << static_cast<int>(stored_hmac[i]);

    if (computed_hex != stored_hex.str())
    {
        VMP_END;
        return decrypt_local_legacy(hex_input);
    }

    std::string plaintext;
    plaintext.reserve(ct_len);
    for (size_t i = 0; i < ct_len; ++i)
        plaintext.push_back(static_cast<char>(ct[i] ^ enc_key[i % 32]));

    VMP_END;
    return plaintext;
}

std::string license_manager_t::decrypt_local_legacy(const std::string& ciphertext) const
{
    std::string cipher;
    cipher.reserve(ciphertext.size() / 2);
    for (size_t i = 0; i + 1 < ciphertext.size(); i += 2)
    {
        unsigned int byte_val = 0;
        std::istringstream(ciphertext.substr(i, 2)) >> std::hex >> byte_val;
        cipher.push_back(static_cast<char>(byte_val));
    }

    std::string hwid = generate_hwid();
    uint64_t key = 14695981039346656037ULL;
    for (char c : hwid)
    {
        key ^= static_cast<uint8_t>(c);
        key *= 1099511628211ULL;
    }

    std::string plain;
    plain.reserve(cipher.size());
    for (size_t i = 0; i < cipher.size(); ++i)
    {
        uint8_t kb = static_cast<uint8_t>((key >> ((i % 8) * 8)) & 0xFF);
        kb ^= static_cast<uint8_t>((i * 7 + 13) & 0xFF);
        plain.push_back(static_cast<char>(static_cast<uint8_t>(cipher[i]) ^ kb));
    }
    return plain;
}

static qstring get_config_path()
{
    qstring path = get_user_idadir();
    path.append(OBFSTR_C("/ai_assistant.cfg"));
    return path;
}

nlohmann::json license_manager_t::read_license_config() const
{
    qstring path = get_config_path();
    if (!qfileexist(path.c_str()))
        return nlohmann::json::object();

    FILE* fp = qfopen(path.c_str(), "rb");
    if (!fp)
        return nlohmann::json::object();

    file_janitor_t fj(fp);
    uint64 fs = qfsize(fp);
    if (fs == 0)
        return nlohmann::json::object();

    qstring data;
    data.resize(static_cast<size_t>(fs));
    if (qfread(fp, data.begin(), static_cast<size_t>(fs)) != static_cast<ssize_t>(fs))
        return nlohmann::json::object();

    try
    {
        nlohmann::json j = nlohmann::json::parse(data.c_str());
        
        std::string enc_blob = j.value(OBFSTR_C("license_blob"), std::string(""));
        if (!enc_blob.empty())
        {
            std::string decrypted = decrypt_local(enc_blob);
            try
            {
                nlohmann::json lic = nlohmann::json::parse(decrypted);
                
                for (auto it = lic.begin(); it != lic.end(); ++it)
                    j[it.key()] = it.value();
            }
            catch (...) {}
        }

        return j;
    }
    catch (...)
    {
        return nlohmann::json::object();
    }
}

bool license_manager_t::write_license_config(const nlohmann::json& config) const
{
    qstring path = get_config_path();

    nlohmann::json merged;
    {
        FILE* fp = qfopen(path.c_str(), "rb");
        if (fp)
        {
            file_janitor_t fj(fp);
            uint64 fs = qfsize(fp);
            if (fs > 0)
            {
                qstring data;
                data.resize(static_cast<size_t>(fs));
                if (qfread(fp, data.begin(), static_cast<size_t>(fs)) == static_cast<ssize_t>(fs))
                {
                    try { merged = nlohmann::json::parse(data.c_str()); }
                    catch (...) { merged = nlohmann::json::object(); }
                }
            }
        }
    }
    
    static const char* license_keys[] = {
        "license_key", "license_validated_at", "license_hwid", "license_plan"
    };

    nlohmann::json lic_data;
    for (const char* k : license_keys)
    {
        if (config.contains(k))
        {
            lic_data[k] = config[k];
            merged[k] = config[k];
        }
        else if (merged.contains(k))
        {
            lic_data[k] = merged[k];
        }
    }
    
    if (!lic_data.empty())
    {
        merged[OBFSTR("license_blob")] = encrypt_local(lic_data.dump());
    }
    
    for (auto it = config.begin(); it != config.end(); ++it)
    {
        bool is_license_key = false;
        for (const char* k : license_keys)
        {
            if (it.key() == k) { is_license_key = true; break; }
        }
        if (!is_license_key)
            merged[it.key()] = it.value();
    }

    std::string json_str = merged.dump(4);

    FILE* fp = qfopen(path.c_str(), "wb");
    if (!fp)
        return false;

    file_janitor_t fj(fp);
    size_t written = qfwrite(fp, json_str.c_str(), json_str.length());
    return written == json_str.length();
}

std::string license_manager_t::generate_hwid() const
{
    VMP_VIRT("generate_hwid");
    uint64_t hash = 14695981039346656037ULL;
    auto fnv_mix = [&hash](uint64_t val)
    {
        for (int i = 0; i < 8; ++i)
        {
            hash ^= (val >> (i * 8)) & 0xFF;
            hash *= 1099511628211ULL;
        }
    };

#ifdef __NT__

    DWORD volume_serial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial,
                          nullptr, nullptr, nullptr, 0);

                          
    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computer_name, &name_size);

    
    int cpu_info[4] = {};
    __cpuid(cpu_info, 0);
    int cpu_info_ext[4] = {};
    __cpuid(cpu_info_ext, 1);

    fnv_mix(static_cast<uint64_t>(volume_serial));
    fnv_mix(static_cast<uint64_t>(cpu_info[0]) << 32 |
            static_cast<uint64_t>(static_cast<unsigned>(cpu_info[1])));
    fnv_mix(static_cast<uint64_t>(cpu_info[2]) << 32 |
            static_cast<uint64_t>(static_cast<unsigned>(cpu_info[3])));
    fnv_mix(static_cast<uint64_t>(cpu_info_ext[0]) << 32 |
            static_cast<uint64_t>(static_cast<unsigned>(cpu_info_ext[3])));
    for (DWORD i = 0; i < name_size; ++i)
        fnv_mix(static_cast<uint64_t>(computer_name[i]));

        
    {
        ULONG buf_len = 0;
        GetAdaptersInfo(nullptr, &buf_len);
        if (buf_len > 0)
        {
            std::vector<BYTE> buf(buf_len);
            PIP_ADAPTER_INFO adapter = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
            if (GetAdaptersInfo(adapter, &buf_len) == NO_ERROR && adapter)
            {
                for (UINT i = 0; i < adapter->AddressLength; ++i)
                    fnv_mix(static_cast<uint64_t>(adapter->Address[i]));
            }
        }
    }
#else
    char hostname[256] = {};
    gethostname(hostname, sizeof(hostname));
    for (const char* p = hostname; *p; ++p)
        fnv_mix(static_cast<uint64_t>(static_cast<unsigned char>(*p)));

    struct utsname un = {};
    if (uname(&un) == 0)
    {
        for (const char* p = un.machine; *p; ++p)
            fnv_mix(static_cast<uint64_t>(static_cast<unsigned char>(*p)));
        for (const char* p = un.nodename; *p; ++p)
            fnv_mix(static_cast<uint64_t>(static_cast<unsigned char>(*p)));
    }

    std::ifstream mid("/etc/machine-id");
    if (mid.is_open())
    {
        std::string id_line;
        std::getline(mid, id_line);
        for (char c : id_line)
            fnv_mix(static_cast<uint64_t>(static_cast<unsigned char>(c)));
    }
#endif

    char buf[17];
    qsnprintf(buf, sizeof(buf), "%016llX",
              static_cast<unsigned long long>(hash));
    VMP_END;
    return buf;
}

bool license_manager_t::is_cache_valid(int64_t validated_at) const
{
    if (validated_at <= 0)
        return false;
    int64_t now = static_cast<int64_t>(std::time(nullptr));

    if (now < validated_at - 300)
        return false;

    int64_t last_known = m_last_known_time.load(std::memory_order_acquire);
    if (last_known > 0 && now < last_known - 300)
        return false;

    return (now - validated_at) < LICENSE_CACHE_DURATION_SEC;
}

bool license_manager_t::detect_clock_rollback() const
{
    VMP_VIRT("detect_rollback");
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int64_t last_known = m_last_known_time.load(std::memory_order_acquire);

    if (last_known > 0 && now < last_known - 300)
    {
        VMP_END;
        return true;
    }
    VMP_END;
    return false;
}

bool license_manager_t::validate_with_server(const std::string& key)
{
    VMP_ULTRA("validate_server");

#ifdef __NT__
    unsigned int _tsc_aux;
    uint64_t _tsc_start = __rdtscp(&_tsc_aux);
#endif

    if (!firebase_authenticate())
    {
        VMP_END;
        return false;
    }

    try
    {
        httplib::Client client(get_firebase_host());
        client.set_connection_timeout(10);
        client.set_read_timeout(15);
        client.set_write_timeout(10);

        {
            std::string host = get_firebase_host();
            if (host.find(OBFSTR("firebasedatabase.app")) == std::string::npos)
            {
                VMP_END;
                return false;
            }
        }

        std::string path = OBFSTR("/licenses/") + key + OBFSTR(".json");
        if (!m_id_token.empty())
            path += OBFSTR("?auth=") + m_id_token;
        auto res = client.Get(path);

        if (!res || res->status != 200)
        {
            VMP_END;
            return false;
        }

        if (res->body.empty() || res->body.size() > 8192)
        {
            VMP_END;
            return false;
        }

        auto j = nlohmann::json::parse(res->body, nullptr, false);
        if (j.is_null() || j.is_discarded() || !j.is_object())
        {
            VMP_END;
            return false;
        }

        if (!j.contains(OBFSTR_C("active"))
            || !j.contains(OBFSTR_C("expires"))
            || !j.contains(OBFSTR_C("plan")))
        {
            VMP_END;
            return false;
        }

        bool active = j.value(OBFSTR_C("active"), false);
        if (!active)
        {
            VMP_END;
            return false;
        }

        std::string expires = j.value(OBFSTR_C("expires"), std::string(""));
        if (!expires.empty())
        {
            time_t now = std::time(nullptr);
            struct tm tm_now;
#ifdef __NT__
            localtime_s(&tm_now, &now);
#else
            localtime_r(&now, &tm_now);
#endif
            char date_buf[11];
            std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", &tm_now);
            if (std::string(date_buf) > expires)
            {
                VMP_END;
                return false;
            }
        }

        std::string bound_hwid = j.value(OBFSTR_C("hwid"), std::string(""));
        std::string current_hwid = generate_hwid();

        if (bound_hwid.empty())
        {
            if (!bind_hwid_to_license(key, current_hwid))
            {
                VMP_END;
                return false;
            }
        }
        else if (bound_hwid != current_hwid)
        {
            VMP_END;
            return false;
        }

        m_plan = j.value(OBFSTR_C("plan"), std::string("standard"));

#ifdef __NT__
        {
            uint64_t _tsc_end = __rdtscp(&_tsc_aux);
            if ((_tsc_end - _tsc_start) > 150000000000ULL)
            {
                VMP_END;
                return false;
            }
        }
#endif

        VMP_END;
        return true;
    }
    catch (...)
    {
        VMP_END;
        return false;
    }
}
bool license_manager_t::bind_hwid_to_license(const std::string& key,
                                               const std::string& hwid)
{
    firebase_authenticate();

    try
    {
        httplib::Client client(get_firebase_host());
        client.set_connection_timeout(10);
        client.set_read_timeout(10);
        client.set_write_timeout(10);

        std::string path = OBFSTR("/licenses/") + key + OBFSTR(".json");
        if (!m_id_token.empty())
            path += OBFSTR("?auth=") + m_id_token;
        nlohmann::json patch;
        patch[OBFSTR("hwid")] = hwid;

        auto res = client.Patch(path, patch.dump(), OBFSTR_C("application/json"));
        return res && res->status == 200;
    }
    catch (...)
    {
        return false;
    }
}

bool license_manager_t::firebase_authenticate()
{
    VMP_ULTRA("firebase_auth");

    std::string secret = get_effective_firebase_api_key();
    if (secret.empty())
    {
        VMP_END;
        return true;
    }

    m_id_token = secret;

    VMP_END;
    return true;
}

bool license_manager_t::firebase_refresh_token_if_needed()
{
    VMP_ULTRA("firebase_refresh");

    if (m_id_token.empty())
    {
        std::string secret = get_effective_firebase_api_key();
        if (!secret.empty())
            m_id_token = secret;
    }

    VMP_END;
    return true;
}
bool license_manager_t::validate()
{
    VMP_ULTRA("validate_license");
    auto config = read_license_config();

    std::string key = config.value(OBFSTR_C("license_key"), std::string(""));
    if (key.empty())
    {
        VMP_END;
        return false;
    }

    int64_t validated_at = config.value(OBFSTR_C("license_validated_at"),
                                        static_cast<int64_t>(0));
    std::string stored_hwid = config.value(OBFSTR_C("license_hwid"),
                                            std::string(""));

    if (is_cache_valid(validated_at) && !stored_hwid.empty()
        && stored_hwid == generate_hwid())
    {
        m_plan = config.value(OBFSTR_C("license_plan"), std::string("standard"));
        m_valid = true;
        m_cached_key = key;
        m_last_known_time.store(
            static_cast<int64_t>(std::time(nullptr)), std::memory_order_release);

        {
            uint64_t nonce = 14695981039346656037ULL;
            for (char c : key)     { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
            for (char c : stored_hwid) { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
            nonce ^= static_cast<uint64_t>(validated_at);
            nonce *= 1099511628211ULL;

#ifdef __NT__
            nonce ^= static_cast<uint64_t>(GetCurrentProcessId());
            nonce *= 1099511628211ULL;
            nonce ^= static_cast<uint64_t>(GetTickCount64());
            nonce *= 1099511628211ULL;
#endif
            unsigned char rnd_entropy[8];
            if (RAND_bytes(rnd_entropy, sizeof(rnd_entropy)) == 1)
            {
                uint64_t rval = 0;
                std::memcpy(&rval, rnd_entropy, 8);
                nonce ^= rval;
                nonce *= 1099511628211ULL;
            }

            m_runtime_nonce.store(nonce, std::memory_order_release);

            uint64_t seed = (nonce ^ 0xA5A5A5A5A5A5A5A5ULL) * 0x5851F42D4C957F2DULL;
            m_integrity_seed.store(seed, std::memory_order_release);
        }

        VMP_END;
        return true;
    }

    if (validate_with_server(key))
    {
        nlohmann::json lic;
        lic[OBFSTR("license_key")] = key;
        lic[OBFSTR("license_validated_at")] =
            static_cast<int64_t>(std::time(nullptr));
        lic[OBFSTR("license_hwid")] = generate_hwid();
        lic[OBFSTR("license_plan")] = m_plan;
        write_license_config(lic);
        m_valid = true;
        m_cached_key = key;
        m_last_known_time.store(
            static_cast<int64_t>(std::time(nullptr)), std::memory_order_release);

        {
            int64_t ts = static_cast<int64_t>(std::time(nullptr));
            std::string hw = generate_hwid();
            uint64_t nonce = 14695981039346656037ULL;
            for (char c : key) { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
            for (char c : hw)  { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
            nonce ^= static_cast<uint64_t>(ts);
            nonce *= 1099511628211ULL;

#ifdef __NT__
            nonce ^= static_cast<uint64_t>(GetCurrentProcessId());
            nonce *= 1099511628211ULL;
            nonce ^= static_cast<uint64_t>(GetTickCount64());
            nonce *= 1099511628211ULL;
#endif
            unsigned char rnd_entropy[8];
            if (RAND_bytes(rnd_entropy, sizeof(rnd_entropy)) == 1)
            {
                uint64_t rval = 0;
                std::memcpy(&rval, rnd_entropy, 8);
                nonce ^= rval;
                nonce *= 1099511628211ULL;
            }

            m_runtime_nonce.store(nonce, std::memory_order_release);

            uint64_t seed = (nonce ^ 0xA5A5A5A5A5A5A5A5ULL) * 0x5851F42D4C957F2DULL;
            m_integrity_seed.store(seed, std::memory_order_release);
        }

        VMP_END;
        return true;
    }

    VMP_END;
    return false;
}

bool license_manager_t::is_valid() const
{
    return m_valid.load(std::memory_order_acquire)
        && m_runtime_nonce.load(std::memory_order_acquire) != 0;
}

std::string license_manager_t::get_plan() const
{
    return m_plan;
}

uint64_t license_manager_t::get_runtime_nonce() const
{
    return m_runtime_nonce.load(std::memory_order_acquire);
}

bool license_manager_t::show_activation_dialog()
{
    VMP_ULTRA("activation_dialog");
    qstring key_input;

    if (!ask_str(&key_input, 0,
                 OBFSTR_C("Enter your license key to activate the plugin:")))
    {
        VMP_END;
        return false;
    }

    key_input.trim2();
    if (key_input.empty())
    {
        warning(OBFSTR_C("No license key entered. "
                          "The plugin cannot load without a valid license."));
        VMP_END;
        return false;
    }

    std::string key(key_input.c_str());

    msg(OBFSTR_C("Validating license key, please wait...\n"));

    bool valid = validate_with_server(key);

    if (valid)
    {
        nlohmann::json lic;
        lic[OBFSTR("license_key")] = key;
        lic[OBFSTR("license_validated_at")] =
            static_cast<int64_t>(std::time(nullptr));
        lic[OBFSTR("license_hwid")] = generate_hwid();
        lic[OBFSTR("license_plan")] = m_plan;
        write_license_config(lic);

        m_valid = true;
        m_cached_key = key;
        m_last_known_time.store(
            static_cast<int64_t>(std::time(nullptr)), std::memory_order_release);

        {
            int64_t ts = static_cast<int64_t>(std::time(nullptr));
            std::string hw = generate_hwid();
            uint64_t nonce = 14695981039346656037ULL;
            for (char c : key) { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
            for (char c : hw)  { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
            nonce ^= static_cast<uint64_t>(ts);
            nonce *= 1099511628211ULL;

#ifdef __NT__
            nonce ^= static_cast<uint64_t>(GetCurrentProcessId());
            nonce *= 1099511628211ULL;
            nonce ^= static_cast<uint64_t>(GetTickCount64());
            nonce *= 1099511628211ULL;
#endif
            unsigned char rnd_entropy[8];
            if (RAND_bytes(rnd_entropy, sizeof(rnd_entropy)) == 1)
            {
                uint64_t rval = 0;
                std::memcpy(&rval, rnd_entropy, 8);
                nonce ^= rval;
                nonce *= 1099511628211ULL;
            }

            m_runtime_nonce.store(nonce, std::memory_order_release);

            uint64_t seed = (nonce ^ 0xA5A5A5A5A5A5A5A5ULL) * 0x5851F42D4C957F2DULL;
            m_integrity_seed.store(seed, std::memory_order_release);
        }

        info(OBFSTR_C("License activated successfully! Thank you for your purchase."));
        VMP_END;
        return true;
    }

    warning(OBFSTR_C("Invalid, expired, or hardware-mismatched license key.\n\n"
                      "Please verify:\n"
                      "- Your key is correct\n"
                      "- Your subscription is active\n"
                      "- This hardware is authorized"));
    VMP_END;
    return false;
}

static int idaapi license_revalidation_timer_cb(void* /*ud*/)
{
    VMP_VIRT("reval_timer_cb");
    auto& lm = license_manager_t::instance();

    if (!lm.verify_function_prologues())
    {
        lm.m_valid.store(false, std::memory_order_release);
        lm.m_runtime_nonce.store(0, std::memory_order_release);
        lm.m_integrity_seed.store(0, std::memory_order_release);
        VMP_END;
        return 7200000;
    }

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int64_t prev = lm.m_last_known_time.load(std::memory_order_acquire);
    if (now > prev)
        lm.m_last_known_time.store(now, std::memory_order_release);

    if (lm.detect_clock_rollback())
        lm.m_revalidation_pending.store(true, std::memory_order_release);

    if (lm.m_revalidation_pending.load(std::memory_order_acquire)
        || !lm.is_valid())
    {
        std::string key = lm.m_cached_key;
        if (!key.empty())
        {
            bool ok = lm.validate_with_server(key);
            if (!ok)
            {
                lm.m_valid.store(false, std::memory_order_release);
                lm.m_runtime_nonce.store(0, std::memory_order_release);
                lm.m_integrity_seed.store(0, std::memory_order_release);
            }
            lm.m_revalidation_pending.store(false, std::memory_order_release);
        }
    }

    VMP_END;
    return 7200000;
}

void license_manager_t::start_revalidation_timer()
{
    VMP_VIRT("start_reval_timer");
    m_last_known_time.store(
        static_cast<int64_t>(std::time(nullptr)), std::memory_order_release);

    register_timer(7200000, license_revalidation_timer_cb, nullptr);
    VMP_END;
}

bool license_manager_t::verify_integrity_inline() const
{
    VMP_ULTRA("verify_integrity");

    uint64_t nonce = m_runtime_nonce.load(std::memory_order_acquire);
    if (nonce == 0)
    {
        VMP_END;
        return false;
    }

    static const uint64_t bad_patterns[] = {
        0xFFFFFFFFFFFFFFFFULL,
        0xDEADBEEFCAFEBABEULL,
        0x0000000000000001ULL,
        0x9090909090909090ULL,
        0xCCCCCCCCCCCCCCCCULL,
    };
    for (uint64_t bad : bad_patterns)
    {
        if (nonce == bad)
        {
            VMP_END;
            return false;
        }
    }

    uint64_t seed = m_integrity_seed.load(std::memory_order_acquire);
    if (seed != 0)
    {
        uint64_t expected_relation = (nonce ^ 0xA5A5A5A5A5A5A5A5ULL) * 0x5851F42D4C957F2DULL;
        if (seed != expected_relation)
        {
            VMP_END;
            return false;
        }
    }

    if (!m_valid.load(std::memory_order_acquire))
    {
        VMP_END;
        return false;
    }

    VMP_END;
    return true;
}

uint64_t license_manager_t::compute_integrity_checksum() const
{
    VMP_VIRT("compute_checksum");

    uint64_t hash = 14695981039346656037ULL;

    uint64_t nonce = m_runtime_nonce.load(std::memory_order_acquire);
    for (int i = 0; i < 8; ++i)
    {
        hash ^= (nonce >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }

    hash ^= m_valid.load(std::memory_order_acquire) ? 0x5A : 0xA5;
    hash *= 1099511628211ULL;

    for (char c : m_plan)
    {
        hash ^= static_cast<uint8_t>(c);
        hash *= 1099511628211ULL;
    }

    VMP_END;
    return hash;
}

static uint64_t fnv1a_bytes(const uint8_t* data, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i)
    {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

void license_manager_t::snapshot_function_prologues()
{
    VMP_ULTRA("snap_prologues");

    using mfp_bool_const = bool (license_manager_t::*)() const;
    using mfp_uint64_const = uint64_t (license_manager_t::*)() const;
    using mfp_bool = bool (license_manager_t::*)();
    using mfp_bool_str = bool (license_manager_t::*)(const std::string&);
    using mfp_str_const = std::string (license_manager_t::*)() const;
    using mfp_void = void (license_manager_t::*)();

    const void* targets[PROLOGUE_HASH_COUNT] = {};

    {
        mfp_bool_const   fn0 = &license_manager_t::is_valid;
        mfp_bool_const   fn1 = &license_manager_t::verify_integrity_inline;
        mfp_uint64_const fn2 = &license_manager_t::compute_integrity_checksum;
        mfp_bool         fn3 = &license_manager_t::validate;
        mfp_bool_str     fn4 = &license_manager_t::validate_with_server;
        mfp_str_const    fn5 = &license_manager_t::generate_hwid;
        mfp_bool         fn6 = &license_manager_t::firebase_authenticate;
        mfp_bool         fn7 = &license_manager_t::show_activation_dialog;

        std::memcpy(&targets[0], &fn0, sizeof(void*));
        std::memcpy(&targets[1], &fn1, sizeof(void*));
        std::memcpy(&targets[2], &fn2, sizeof(void*));
        std::memcpy(&targets[3], &fn3, sizeof(void*));
        std::memcpy(&targets[4], &fn4, sizeof(void*));
        std::memcpy(&targets[5], &fn5, sizeof(void*));
        std::memcpy(&targets[6], &fn6, sizeof(void*));
        std::memcpy(&targets[7], &fn7, sizeof(void*));
    }

    for (size_t i = 0; i < PROLOGUE_HASH_COUNT; ++i)
    {
        if (targets[i] != nullptr)
            m_prologue_hashes[i] = fnv1a_bytes(
                reinterpret_cast<const uint8_t*>(targets[i]), PROLOGUE_BYTES);
        else
            m_prologue_hashes[i] = 0;
    }

    m_prologues_initialized = true;
    VMP_END;
}

bool license_manager_t::verify_function_prologues() const
{
    VMP_ULTRA("verify_prologues");

    if (!m_prologues_initialized)
    {
        VMP_END;
        return true;
    }

    const void* targets[PROLOGUE_HASH_COUNT] = {};

    {
        using mfp_bool_const = bool (license_manager_t::*)() const;
        using mfp_uint64_const = uint64_t (license_manager_t::*)() const;
        using mfp_bool = bool (license_manager_t::*)();
        using mfp_bool_str = bool (license_manager_t::*)(const std::string&);
        using mfp_str_const = std::string (license_manager_t::*)() const;

        mfp_bool_const   fn0 = &license_manager_t::is_valid;
        mfp_bool_const   fn1 = &license_manager_t::verify_integrity_inline;
        mfp_uint64_const fn2 = &license_manager_t::compute_integrity_checksum;
        mfp_bool         fn3 = &license_manager_t::validate;
        mfp_bool_str     fn4 = &license_manager_t::validate_with_server;
        mfp_str_const    fn5 = &license_manager_t::generate_hwid;
        mfp_bool         fn6 = &license_manager_t::firebase_authenticate;
        mfp_bool         fn7 = &license_manager_t::show_activation_dialog;

        std::memcpy(&targets[0], &fn0, sizeof(void*));
        std::memcpy(&targets[1], &fn1, sizeof(void*));
        std::memcpy(&targets[2], &fn2, sizeof(void*));
        std::memcpy(&targets[3], &fn3, sizeof(void*));
        std::memcpy(&targets[4], &fn4, sizeof(void*));
        std::memcpy(&targets[5], &fn5, sizeof(void*));
        std::memcpy(&targets[6], &fn6, sizeof(void*));
        std::memcpy(&targets[7], &fn7, sizeof(void*));
    }

    for (size_t i = 0; i < PROLOGUE_HASH_COUNT; ++i)
    {
        if (targets[i] == nullptr)
            continue;

        uint64_t current = fnv1a_bytes(
            reinterpret_cast<const uint8_t*>(targets[i]), PROLOGUE_BYTES);

        if (current != m_prologue_hashes[i])
        {
            VMP_END;
            return false;
        }
    }

    VMP_END;
    return true;
}