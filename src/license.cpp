#include "aida_pro.hpp"
#include "anti_re.hpp"

#ifdef __NT__
#include "driver_loader.hpp"
#endif

#ifdef __NT__
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "winhttp.lib")
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
#include <openssl/x509.h>

static std::string get_hardcoded_firebase_api_key()
{
    return OBFBYTES("bWLmMKBhD3TE7iYMnKizIjOrt4jXd9R1m0CVCj6P");
}

static std::string get_effective_firebase_api_key()
{
    std::string key = get_hardcoded_firebase_api_key();

    if (key.find("XXXXXXX") != std::string::npos || key.empty())
    {
        key = g_settings.firebase_api_key;
    }
    return key;
}

static std::string get_cloud_function_host()
{
    std::string h;
    h.reserve(58);
    h += OBFSTR("htt");
    h += OBFSTR("ps://");
    h += OBFSTR("europe");
    h += OBFSTR("-west1-");
    h += OBFSTR("aida-li");
    h += OBFSTR("cense-pr");
    h += OBFSTR("od.cloud");
    h += OBFSTR("functio");
    h += OBFSTR("ns.net");
    return h;
}

static bool is_supported_cloud_function_host(const std::string& host)
{
    return host.find(OBFSTR("cloudfunctions.net")) != std::string::npos
        || host.find(OBFSTR("run.app")) != std::string::npos;
}

static std::string get_firebase_auth_host()
{
    std::string h;
    h.reserve(39);
    h += OBFSTR("htt");
    h += OBFSTR("ps://");
    h += OBFSTR("identi");
    h += OBFSTR("tytool");
    h += OBFSTR("kit.go");
    h += OBFSTR("ogleap");
    h += OBFSTR("is.com");
    return h;
}

static std::string get_firebase_token_host()
{
    std::string h;
    h.reserve(35);
    h += OBFSTR("htt");
    h += OBFSTR("ps://");
    h += OBFSTR("secur");
    h += OBFSTR("etoke");
    h += OBFSTR("n.goo");
    h += OBFSTR("gleap");
    h += OBFSTR("is.com");
    return h;
}

static constexpr int64_t LICENSE_CACHE_DURATION_SEC = 24 * 3600;

static std::string get_server_signing_public_key_der_hex()
{
    std::string k;
    k.reserve(88);
    k += OBFSTR("302a3005");
    k += OBFSTR("06032b65");
    k += OBFSTR("70032100");
    k += OBFSTR("049ed74a");
    k += OBFSTR("6f0e1969");
    k += OBFSTR("8f759cc0");
    k += OBFSTR("63bbe0bc");
    k += OBFSTR("a0a9f7f7");
    k += OBFSTR("3c818adb");
    k += OBFSTR("814e9be8");
    k += OBFSTR("be03a648");
    return k;
}

static bool decode_hex_string(const std::string& text, std::vector<unsigned char>& out)
{
    if ((text.size() % 2) != 0)
        return false;

    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2)
    {
        unsigned int byte_value = 0;
        std::istringstream iss(text.substr(i, 2));
        iss >> std::hex >> byte_value;
        if (iss.fail())
            return false;
        out.push_back(static_cast<unsigned char>(byte_value));
    }
    return true;
}

#ifdef __NT__
static constexpr const char* LICENSE_DPAPI_PREFIX = "dpapi2:";

static std::string license_hex_encode(const unsigned char* data, size_t size)
{
    std::string out;
    out.reserve(size * 2);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i)
    {
        const unsigned char b = data[i];
        out.push_back(digits[(b >> 4) & 0x0F]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

static bool license_hex_decode(const std::string& text, std::vector<unsigned char>& out)
{
    return decode_hex_string(text, out);
}

static std::string protect_license_blob_dpapi(const std::string& plaintext, const std::string& hwid)
{
    if (plaintext.empty())
        return plaintext;

    DATA_BLOB input_blob{};
    input_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()));
    input_blob.cbData = static_cast<DWORD>(plaintext.size());

    std::string entropy = std::string("AiDA:license:v2:") + hwid;
    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = reinterpret_cast<BYTE*>(entropy.data());
    entropy_blob.cbData = static_cast<DWORD>(entropy.size());

    DATA_BLOB output_blob{};
    if (!CryptProtectData(&input_blob,
                          L"AiDA License",
                          &entropy_blob,
                          nullptr,
                          nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN,
                          &output_blob))
    {
        return "";
    }

    std::string protected_hex = license_hex_encode(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return std::string(LICENSE_DPAPI_PREFIX) + protected_hex;
}

static std::string unprotect_license_blob_dpapi(const std::string& encoded, const std::string& hwid)
{
    if (encoded.compare(0, std::strlen(LICENSE_DPAPI_PREFIX), LICENSE_DPAPI_PREFIX) != 0)
        return "";

    std::vector<unsigned char> protected_bytes;
    if (!license_hex_decode(encoded.substr(std::strlen(LICENSE_DPAPI_PREFIX)), protected_bytes))
        return "";

    DATA_BLOB input_blob{};
    input_blob.pbData = protected_bytes.data();
    input_blob.cbData = static_cast<DWORD>(protected_bytes.size());

    std::string entropy = std::string("AiDA:license:v2:") + hwid;
    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = reinterpret_cast<BYTE*>(entropy.data());
    entropy_blob.cbData = static_cast<DWORD>(entropy.size());

    DATA_BLOB output_blob{};
    if (!CryptUnprotectData(&input_blob,
                            nullptr,
                            &entropy_blob,
                            nullptr,
                            nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN,
                            &output_blob))
    {
        return "";
    }

    std::string plaintext(reinterpret_cast<const char*>(output_blob.pbData), output_blob.cbData);
    SecureZeroMemory(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return plaintext;
}
#endif

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

bool license_manager_t::verify_server_signature(const std::string& response_body,
                                                  const std::string& signature) const
{
    if (signature.empty() || response_body.empty())
        return false;

    std::vector<unsigned char> signature_bytes;
    if (!decode_hex_string(signature, signature_bytes) || signature_bytes.empty())
        return false;

    std::vector<unsigned char> public_key_der;
    if (!decode_hex_string(get_server_signing_public_key_der_hex(), public_key_der)
        || public_key_der.empty())
        return false;

    const unsigned char* der_ptr = public_key_der.data();
    EVP_PKEY* public_key = d2i_PUBKEY(nullptr, &der_ptr,
                                      static_cast<long>(public_key_der.size()));
    if (public_key == nullptr)
        return false;

    EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
    if (verify_ctx == nullptr)
    {
        EVP_PKEY_free(public_key);
        return false;
    }

    bool verified = false;
    if (EVP_DigestVerifyInit(verify_ctx, nullptr, nullptr, nullptr, public_key) == 1)
    {
        verified = EVP_DigestVerify(
            verify_ctx,
            signature_bytes.data(), signature_bytes.size(),
            reinterpret_cast<const unsigned char*>(response_body.data()),
            response_body.size()) == 1;
    }

    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(public_key);
    return verified;
}

void license_manager_t::secure_clear_string(std::string& s) const
{
    if (!s.empty())
    {
        volatile char* p = &s[0];
        for (size_t i = 0; i < s.size(); ++i)
            p[i] = 0;
        s.clear();
    }
}

license_manager_t& license_manager_t::instance()
{
    static license_manager_t inst;
    return inst;
}

std::string license_manager_t::encrypt_local(const std::string& plaintext) const
{
    std::string hwid = generate_hwid();

#ifdef __NT__
    if (std::string protected_blob = protect_license_blob_dpapi(plaintext, hwid);
        !protected_blob.empty())
    {
        return protected_blob;
    }
#endif

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

    return hex.str();
}

std::string license_manager_t::decrypt_local(const std::string& hex_input) const
{
#ifdef __NT__
    if (hex_input.compare(0, std::strlen(LICENSE_DPAPI_PREFIX), LICENSE_DPAPI_PREFIX) == 0)
    {
        std::string plaintext = unprotect_license_blob_dpapi(hex_input, generate_hwid());
        if (!plaintext.empty())
        {
            return plaintext;
        }
    }
#endif

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
        return decrypt_local_legacy(hex_input);
    }

    std::string plaintext;
    plaintext.reserve(ct_len);
    for (size_t i = 0; i < ct_len; ++i)
        plaintext.push_back(static_cast<char>(ct[i] ^ enc_key[i % 32]));

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
            if (decrypted.empty())
                return nlohmann::json::object();

            try
            {
                nlohmann::json lic = nlohmann::json::parse(decrypted);

                for (auto it = lic.begin(); it != lic.end(); ++it)
                    j[it.key()] = it.value();
            }
            catch (...)
            {
                return nlohmann::json::object();
            }
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

    for (const char* k : license_keys)
        merged.erase(k);

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
    return buf;
}

bool license_manager_t::detect_clock_rollback() const
{
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int64_t last_known = m_last_known_time.load(std::memory_order_acquire);

    if (last_known > 0 && now < last_known - 300)
        return true;

    return false;
}

bool license_manager_t::validate_with_server(const std::string& key)
{


    (void)key;
    return false;
}

bool license_manager_t::firebase_authenticate()
{
    std::string api_key = get_effective_firebase_api_key();
    if (api_key.empty())
        return false;

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (!m_id_token.empty() && now < m_token_expiry - 60)
        return true;

    if (!m_refresh_token.empty())
    {
        if (firebase_refresh_token_if_needed())
            return true;
    }

    try
    {
        std::string _auth_h = get_firebase_auth_host();
        httplib::Client client(_auth_h);
        obf::secure_wipe_string(_auth_h);
        client.set_connection_timeout(10);
        client.set_read_timeout(10);
        client.set_write_timeout(10);
        client.enable_server_certificate_verification(false); // FIXED

        std::string path = OBFSTR("/v1/accounts:signUp?key=") + api_key;

        nlohmann::json body;
        body[OBFSTR("returnSecureToken")] = true;

        auto res = client.Post(path, body.dump(), OBFSTR_C("application/json"));

        if (res && res->status == 200 && !res->body.empty())
        {
            auto j = nlohmann::json::parse(res->body, nullptr, false);
            if (!j.is_null() && !j.is_discarded())
            {
                std::string token = j.value(OBFSTR_C("idToken"), std::string(""));
                if (!token.empty())
                {
                    m_id_token = token;
                    m_refresh_token = j.value(OBFSTR_C("refreshToken"), std::string(""));
                    std::string expires_in = j.value(OBFSTR_C("expiresIn"), std::string("3600"));
                    try { m_token_expiry = now + std::stoll(expires_in); }
                    catch (...) { m_token_expiry = now + 3600; }
                    return true;
                }
            }
        }
    }
    catch (...) {}

    m_id_token = api_key;
    m_token_expiry = now + 3600;
    return true;
}

bool license_manager_t::firebase_refresh_token_if_needed()
{
    if (m_refresh_token.empty())
        return false;

    std::string api_key = get_effective_firebase_api_key();
    if (api_key.empty())
        return false;

    try
    {
        std::string _tok_h = get_firebase_token_host();
        httplib::Client client(_tok_h);
        obf::secure_wipe_string(_tok_h);
        client.set_connection_timeout(10);
        client.set_read_timeout(10);
        client.set_write_timeout(10);
        client.enable_server_certificate_verification(false); // FIXED

        std::string path = OBFSTR("/v1/token?key=") + api_key;

        nlohmann::json body;
        body[OBFSTR("grant_type")] = OBFSTR("refresh_token");
        body[OBFSTR("refresh_token")] = m_refresh_token;

        auto res = client.Post(path, body.dump(), OBFSTR_C("application/json"));
        if (!res || res->status != 200 || res->body.empty())
            return false;

        auto j = nlohmann::json::parse(res->body, nullptr, false);
        if (j.is_null() || j.is_discarded())
            return false;

        std::string token = j.value(OBFSTR_C("id_token"), std::string(""));
        if (token.empty())
            return false;

        m_id_token = token;
        m_refresh_token = j.value(OBFSTR_C("refresh_token"), m_refresh_token);
        std::string expires_in = j.value(OBFSTR_C("expires_in"), std::string("3600"));
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        try { m_token_expiry = now + std::stoll(expires_in); }
        catch (...) { m_token_expiry = now + 3600; }

        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool license_manager_t::validate()
{
    invalidate_runtime();

#ifdef __NT__
    if (!driver_loader::is_driver_loaded())
        return false;

#endif

    auto config = read_license_config();

    std::string key = config.value(OBFSTR_C("license_key"), std::string(""));
    if (key.empty())
        return false;

    std::string current_hwid = generate_hwid();

    if (validate_with_cloud_function(key, current_hwid))
    {
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        nlohmann::json lic;
        lic[OBFSTR("license_key")] = key;
        lic[OBFSTR("license_validated_at")] = now;
        lic[OBFSTR("license_hwid")] = current_hwid;
        lic[OBFSTR("license_plan")] = m_plan;
        lic[OBFSTR("license_server_sig")] = m_server_signature;

        nlohmann::json sig_payload;
        sig_payload[OBFSTR("status")]        = OBFSTR("valid");
        sig_payload[OBFSTR("license_key")]   = key;
        sig_payload[OBFSTR("hwid")]          = current_hwid;
        sig_payload[OBFSTR("plan")]          = m_plan;
        sig_payload[OBFSTR("session_token")] = m_server_session_token;
        sig_payload[OBFSTR("ttl")]           = m_server_ttl;
        sig_payload[OBFSTR("issued_at")]     = m_server_issued_at;
        sig_payload[OBFSTR("server_nonce")]  = m_session_id;
        sig_payload[OBFSTR("client_nonce")]  = m_client_nonce;
        lic[OBFSTR("license_sig_payload")] = sig_payload.dump();

        {
            nlohmann::json gate2_pl;
            gate2_pl[OBFSTR("status")]        = OBFSTR("valid");
            gate2_pl[OBFSTR("license_key")]   = key;
            gate2_pl[OBFSTR("hwid")]          = current_hwid;
            gate2_pl[OBFSTR("plan")]          = m_plan;
            gate2_pl[OBFSTR("session_token")] = m_server_session_token;
            gate2_pl[OBFSTR("ttl")]           = m_server_ttl;
            gate2_pl[OBFSTR("issued_at")]     = m_server_issued_at;
            gate2_pl[OBFSTR("server_nonce")]  = m_session_id;
            gate2_pl[OBFSTR("client_nonce")]  = m_client_nonce;
            if (!verify_server_signature(gate2_pl.dump(), m_server_signature))
            {
                invalidate_runtime();
                return false;
            }
        }

        check_dll_leak(current_hwid);

        write_license_config(lic);

        m_valid = true;
        m_cached_key = key;
        m_last_known_time.store(now, std::memory_order_release);
        m_online_validated_this_session.store(true, std::memory_order_release);
        m_consecutive_heartbeat_failures.store(0, std::memory_order_release);
        m_bound_hwid = current_hwid;

        compute_session_credentials(key, current_hwid, now, m_server_session_token,
                                    m_server_signature);

        if (m_sig_binding_tag.load(std::memory_order_acquire) == 0)
        {
            invalidate_runtime();
            return false;
        }

        return true;
    }


    discord_webhook::send_alert_async(
        OBFSTR("\xf0\x9f\x9a\xa8 FAILED ACTIVATION ATTEMPT (Possible DLL Leak)"),
        OBFSTR("**Someone attempted to activate a license on an unauthorized machine.**\n")
            + OBFSTR("**Attempted Key:** `") + key
            + OBFSTR("`\n**HWID:** `") + current_hwid + "`",
        discord_webhook::COLOR_RED);


    return false;
}

bool license_manager_t::is_valid() const
{
    if (anti_re::violation_latched())
        return false;

    return m_valid.load(std::memory_order_acquire)
        && m_runtime_nonce.load(std::memory_order_acquire) != 0
        && m_online_validated_this_session.load(std::memory_order_acquire)
        && m_sig_binding_tag.load(std::memory_order_acquire) != 0;
}

void license_manager_t::invalidate_runtime()
{
    m_valid.store(false, std::memory_order_release);
    m_nonce_canary.store(0, std::memory_order_release);
    m_runtime_nonce.store(0, std::memory_order_release);
    m_integrity_seed.store(0, std::memory_order_release);
    m_sig_binding_tag.store(0, std::memory_order_release);
    m_revalidation_pending.store(false, std::memory_order_release);
    m_online_validated_this_session.store(false, std::memory_order_release);
    m_consecutive_heartbeat_failures.store(0, std::memory_order_release);
    m_plan.clear();
    m_server_issued_at = 0;
    m_server_ttl = 3600;
    m_public_ip.clear();
    m_bound_hwid.clear();

    secure_clear_string(m_cached_key);
    secure_clear_string(m_server_session_token);
    secure_clear_string(m_session_id);
    secure_clear_string(m_id_token);
    secure_clear_string(m_refresh_token);
    secure_clear_string(m_client_nonce);
    secure_clear_string(m_server_signature);
    secure_clear_string(m_verified_signature);
    secure_clear_string(m_heartbeat_nonce);
}

std::string license_manager_t::get_plan() const
{
    return m_plan;
}

uint64_t license_manager_t::get_runtime_nonce() const
{
    if (anti_re::violation_latched())
        return 0;

    uint64_t raw = m_runtime_nonce.load(std::memory_order_acquire);
    uint64_t canary = m_nonce_canary.load(std::memory_order_acquire);
    return raw ^ canary;
}

uint64_t license_manager_t::get_sig_binding_tag() const
{
    if (anti_re::violation_latched())
        return 0;

    return m_sig_binding_tag.load(std::memory_order_acquire);
}

bool license_manager_t::show_activation_dialog()
{
    invalidate_runtime();

    qstring key_input;

    if (!ask_str(&key_input, 0,
                 OBFSTR_C("Enter your license key to activate AiDA:")))
        return false;


    key_input.trim2();
    if (key_input.empty())
    {
        warning(OBFSTR_C("No license key entered. "
                          "AiDA cannot load without a valid license."));
        return false;
    }

    std::string key(key_input.c_str());
    std::string current_hwid = generate_hwid();

    msg(OBFSTR_C("Validating license key with server, please wait...\n"));

    bool valid = validate_with_cloud_function(key, current_hwid);

    if (valid)
    {
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        nlohmann::json lic;
        lic[OBFSTR("license_key")] = key;
        lic[OBFSTR("license_validated_at")] = now;
        lic[OBFSTR("license_hwid")] = current_hwid;
        lic[OBFSTR("license_plan")] = m_plan;
        lic[OBFSTR("license_server_sig")] = m_server_signature;

        nlohmann::json sig_payload;
        sig_payload[OBFSTR("status")]        = OBFSTR("valid");
        sig_payload[OBFSTR("license_key")]   = key;
        sig_payload[OBFSTR("hwid")]          = current_hwid;
        sig_payload[OBFSTR("plan")]          = m_plan;
        sig_payload[OBFSTR("session_token")] = m_server_session_token;
        sig_payload[OBFSTR("ttl")]           = m_server_ttl;
        sig_payload[OBFSTR("issued_at")]     = m_server_issued_at;
        sig_payload[OBFSTR("server_nonce")]  = m_session_id;
        sig_payload[OBFSTR("client_nonce")]  = m_client_nonce;
        lic[OBFSTR("license_sig_payload")] = sig_payload.dump();

        {
            nlohmann::json gate2_pl;
            gate2_pl[OBFSTR("status")]        = OBFSTR("valid");
            gate2_pl[OBFSTR("license_key")]   = key;
            gate2_pl[OBFSTR("hwid")]          = current_hwid;
            gate2_pl[OBFSTR("plan")]          = m_plan;
            gate2_pl[OBFSTR("session_token")] = m_server_session_token;
            gate2_pl[OBFSTR("ttl")]           = m_server_ttl;
            gate2_pl[OBFSTR("issued_at")]     = m_server_issued_at;
            gate2_pl[OBFSTR("server_nonce")]  = m_session_id;
            gate2_pl[OBFSTR("client_nonce")]  = m_client_nonce;
            if (!verify_server_signature(gate2_pl.dump(), m_server_signature))
            {
                invalidate_runtime();
                return false;
            }
        }

        write_license_config(lic);

        m_valid = true;
        m_cached_key = key;
        m_bound_hwid = current_hwid;
        m_last_known_time.store(now, std::memory_order_release);
        m_online_validated_this_session.store(true, std::memory_order_release);
        m_consecutive_heartbeat_failures.store(0, std::memory_order_release);

        compute_session_credentials(key, current_hwid, now, m_server_session_token,
                                    m_server_signature);

        if (m_sig_binding_tag.load(std::memory_order_acquire) == 0)
        {
            invalidate_runtime();
            return false;
        }

        discord_webhook::send_alert_async(
            OBFSTR("\xe2\x9c\x85 LICENSE ACTIVATED"),
            OBFSTR("**A new license activation occurred.**\n**Plan:** `")
                + m_plan + OBFSTR("`\n**Key:** `") + key + "`",
            discord_webhook::COLOR_GREEN);

        check_dll_leak(current_hwid);

        info(OBFSTR_C("License activated successfully! Thank you for your purchase."));
        return true;
    }

    warning(OBFSTR_C("License validation failed.\n\n"
                      "Please verify:\n"
                      "- Your key is correct\n"
                      "- Your subscription is active\n"
                      "- This hardware is authorized\n"
                      "- You have an active internet connection"));

    if (!m_last_validation_error.empty())
    {
        msg(OBFSTR_C("AiDA license validation detail: %s\n"),
            m_last_validation_error.c_str());

        qstring detail_message = OBFSTR_C("License validation detail:\n");
        detail_message.append(m_last_validation_error.c_str());
        warning(OBFSTR_C("%s"), detail_message.c_str());
    }


    discord_webhook::send_alert_async(
        OBFSTR("\xf0\x9f\x9a\xa8 FAILED ACTIVATION ATTEMPT (Possible DLL Leak)"),
        OBFSTR("**Someone attempted to activate a license on an unauthorized machine.**\n")
            + OBFSTR("**Attempted Key:** `") + key
            + OBFSTR("`\n**HWID:** `") + current_hwid + "`",
        discord_webhook::COLOR_RED);

    return false;
}

static int idaapi license_revalidation_timer_cb(void* )
{
    auto& lm = license_manager_t::instance();

#ifdef __NT__
    if (!driver_loader::is_driver_loaded())
    {
        lm.invalidate_runtime();
        lm.terminate_plugin();
        return -1;
    }
#endif

    if (!lm.verify_function_prologues())
    {
        lm.invalidate_runtime();
        lm.terminate_plugin();
        return -1;
    }

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int64_t prev = lm.m_last_known_time.load(std::memory_order_acquire);
    if (now > prev)
        lm.m_last_known_time.store(now, std::memory_order_release);

    if (lm.detect_clock_rollback())
    {
        lm.invalidate_runtime();
        lm.terminate_plugin();
        return -1;
    }

    if (!lm.perform_heartbeat())
    {
        int failures = lm.m_consecutive_heartbeat_failures.load(std::memory_order_acquire);
        if (failures >= license_manager_t::MAX_HEARTBEAT_FAILURES)
        {
            lm.invalidate_runtime();
            lm.terminate_plugin();
            return -1;
        }
    }

    if (!lm.verify_integrity_inline())
    {
        lm.invalidate_runtime();
        lm.terminate_plugin();
        return -1;
    }

    if (lm.get_sig_binding_tag() == 0)
    {
        lm.invalidate_runtime();
        lm.terminate_plugin();
        return -1;
    }

    if (!lm.is_valid())
    {
        lm.terminate_plugin();
        return -1;
    }

    return license_manager_t::REVALIDATION_INTERVAL_MS;
}

void license_manager_t::start_revalidation_timer()
{
    m_last_known_time.store(
        static_cast<int64_t>(std::time(nullptr)), std::memory_order_release);

    register_timer(REVALIDATION_INTERVAL_MS, license_revalidation_timer_cb, nullptr);
}

std::string license_manager_t::generate_session_nonce() const
{
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1)
    {
        uint64_t t = static_cast<uint64_t>(std::time(nullptr));
        for (size_t i = 0; i < sizeof(buf); ++i)
            buf[i] = static_cast<unsigned char>(
                (t >> ((i % 8) * 8)) ^ static_cast<unsigned char>(i * 0x9E + 0x37));
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (size_t i = 0; i < sizeof(buf); ++i)
        hex << std::setw(2) << static_cast<int>(buf[i]);
    return hex.str();
}

bool license_manager_t::validate_with_cloud_function(const std::string& key,
                                                      const std::string& hwid)
{
#ifdef __NT__
    unsigned int _tsc_aux;
    uint64_t _tsc_start = __rdtscp(&_tsc_aux);
#endif

    m_last_validation_error.clear();

    auto fail_validation = [this](const std::string& reason) -> bool
    {
        m_last_validation_error = reason;
        return false;
    };

    try
    {
        std::string _cf_h = get_cloud_function_host();
        if (!is_supported_cloud_function_host(_cf_h))
        {
            obf::secure_wipe_string(_cf_h);
            return fail_validation(OBFSTR("Unsupported cloud function host"));
        }
        httplib::Client client(_cf_h);
        obf::secure_wipe_string(_cf_h);
        client.set_connection_timeout(15);
        client.set_read_timeout(20);
        client.set_write_timeout(10);
        client.set_follow_location(true);
        client.enable_server_certificate_verification(false); // FIXED

        m_client_nonce = generate_session_nonce();

        m_public_ip = discord_webhook::get_public_ip();

        nlohmann::json request_body;
        request_body[OBFSTR("action")] = OBFSTR("validate");
        request_body[OBFSTR("license_key")] = key;
        request_body[OBFSTR("hwid")] = hwid;
        request_body[OBFSTR("client_nonce")] = m_client_nonce;
        request_body[OBFSTR("plugin_version")] = AIDA_VERSION;
        request_body[OBFSTR("timestamp")] = static_cast<int64_t>(std::time(nullptr));
        request_body[OBFSTR("public_ip")] = m_public_ip;
        request_body[OBFSTR("mac_address")] = discord_webhook::get_mac_address();

        auto res = client.Post(
            OBFSTR_C("/validateLicense"),
            request_body.dump(),
            OBFSTR_C("application/json")
        );

        if (!res)
        {
            return fail_validation(
                std::string(OBFSTR("Transport error: "))
                + httplib::to_string(res.error()));
        }

        if (res->status != 200)
        {
            return fail_validation(
                std::string(OBFSTR("Unexpected HTTP status: "))
                + std::to_string(res->status));
        }

        if (res->body.empty() || res->body.size() > 16384)
            return fail_validation(OBFSTR("Response body missing or too large"));

        auto j = nlohmann::json::parse(res->body, nullptr, false);
        if (j.is_null() || j.is_discarded() || !j.is_object())
            return fail_validation(OBFSTR("Failed to parse server JSON response"));

        std::string status = j.value(OBFSTR_C("status"), std::string(""));
        if (status == OBFSTR("banned"))
        {
            std::string reason = j.value(OBFSTR_C("reason"), std::string("banned"));
            handle_ban_response(j);
            invalidate_runtime();
            return fail_validation(std::string(OBFSTR("Server rejected activation: ")) + reason);
        }
        if (status == OBFSTR("hwid_banned"))
        {
            m_hwid_banned.store(true, std::memory_order_release);
            m_ban_reason = j.value(OBFSTR_C("reason"), std::string("HWID banned"));
            discord_webhook::send_alert_async(
                OBFSTR("\xf0\x9f\x94\xa8 HWID BAN ENFORCED"),
                OBFSTR("**Banned HWID attempted to activate.**\n**Reason:** `")
                    + m_ban_reason + "`\n**Key:** `" + key + "`",
                discord_webhook::COLOR_RED);
            invalidate_runtime();
            return fail_validation(std::string(OBFSTR("HWID banned: ")) + m_ban_reason);
        }
        if (status == OBFSTR("ip_banned"))
        {
            m_ip_banned.store(true, std::memory_order_release);
            m_ban_reason = j.value(OBFSTR_C("reason"), std::string("IP banned"));
            discord_webhook::send_alert_async(
                OBFSTR("\xf0\x9f\x8c\x90 IP BAN ENFORCED"),
                OBFSTR("**Banned IP attempted to activate.**\n**Reason:** `")
                    + m_ban_reason + "`\n**Key:** `" + key + "`",
                discord_webhook::COLOR_RED);
            invalidate_runtime();
            return fail_validation(std::string(OBFSTR("IP banned: ")) + m_ban_reason);
        }
        if (status != OBFSTR("valid"))
        {
            std::string reason = j.value(OBFSTR_C("reason"), std::string("unknown_reason"));
            return fail_validation(
                std::string(OBFSTR("Server rejected activation: "))
                + status + OBFSTR(" (") + reason + OBFSTR(")"));
        }

        if (!j.contains(OBFSTR_C("plan"))
            || !j.contains(OBFSTR_C("license_key"))
            || !j.contains(OBFSTR_C("hwid"))
            || !j.contains(OBFSTR_C("session_token"))
            || !j.contains(OBFSTR_C("ttl"))
            || !j.contains(OBFSTR_C("issued_at"))
            || !j.contains(OBFSTR_C("server_nonce"))
            || !j.contains(OBFSTR_C("signature")))
            return fail_validation(OBFSTR("Server response missing required fields"));

        std::string echo_nonce = j.value(OBFSTR_C("client_nonce"), std::string(""));
        if (echo_nonce != m_client_nonce)
            return fail_validation(OBFSTR("Server client_nonce mismatch"));

        if (j.value(OBFSTR_C("license_key"), std::string("")) != key)
            return fail_validation(OBFSTR("Server license_key mismatch"));

        if (j.value(OBFSTR_C("hwid"), std::string("")) != hwid)
            return fail_validation(OBFSTR("Server HWID mismatch"));

        std::string server_sig = j.value(OBFSTR_C("signature"), std::string(""));
        nlohmann::json sig_payload;
        sig_payload[OBFSTR("status")]        = j[OBFSTR_C("status")];
        sig_payload[OBFSTR("license_key")]   = j[OBFSTR_C("license_key")];
        sig_payload[OBFSTR("hwid")]          = j[OBFSTR_C("hwid")];
        sig_payload[OBFSTR("plan")]          = j[OBFSTR_C("plan")];
        sig_payload[OBFSTR("session_token")] = j[OBFSTR_C("session_token")];
        sig_payload[OBFSTR("ttl")]           = j[OBFSTR_C("ttl")];
        sig_payload[OBFSTR("issued_at")]     = j[OBFSTR_C("issued_at")];
        sig_payload[OBFSTR("server_nonce")]  = j[OBFSTR_C("server_nonce")];
        sig_payload[OBFSTR("client_nonce")]  = j[OBFSTR_C("client_nonce")];

        if (!verify_server_signature(sig_payload.dump(), server_sig))
            return fail_validation(OBFSTR("Server signature verification failed"));

        m_plan = j.value(OBFSTR_C("plan"), std::string("standard"));
        m_server_session_token = j.value(OBFSTR_C("session_token"), std::string(""));
        m_server_ttl = j.value(OBFSTR_C("ttl"), static_cast<int64_t>(3600));
        m_server_issued_at = j.value(OBFSTR_C("issued_at"), static_cast<int64_t>(0));
        m_session_id = j.value(OBFSTR_C("server_nonce"), std::string(""));
        m_server_signature = server_sig;
        m_bound_hwid = hwid;

        if (m_server_session_token.empty())
            return fail_validation(OBFSTR("Server returned an empty session token"));

        if (m_server_ttl <= 0 || m_server_ttl > 86400)
            m_server_ttl = 3600;

        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (m_server_issued_at <= 0 || std::llabs(now - m_server_issued_at) > 300)
            return fail_validation(OBFSTR("Server timestamp drift exceeds allowed window"));

#ifdef __NT__
        {
            uint64_t _tsc_end = __rdtscp(&_tsc_aux);
            if ((_tsc_end - _tsc_start) > 150000000000ULL)
                return fail_validation(OBFSTR("Validation timing threshold exceeded"));
        }
#endif

        m_online_validated_this_session.store(true, std::memory_order_release);
        m_last_validation_error.clear();
        return true;
    }
    catch (...)
    {
        return fail_validation(OBFSTR("Unexpected exception during cloud validation"));
    }
}

uint64_t license_manager_t::derive_sig_binding_tag(
    const std::string& sig, uint64_t nonce) const
{
    if (sig.empty() || nonce == 0)
        return 0;

    uint64_t tag = 14695981039346656037ULL;
    for (char c : sig)
    {
        tag ^= static_cast<uint8_t>(c);
        tag *= 1099511628211ULL;
    }
    for (int i = 0; i < 8; ++i)
    {
        tag ^= (nonce >> (i * 8)) & 0xFF;
        tag *= 1099511628211ULL;
    }
    tag ^= 0xC0FFEE42DEADBEEFULL;
    tag *= 1099511628211ULL;

    if (tag == 0)
        tag = 0xB3A7C9D1E5F02468ULL;
    if (tag == nonce)
        tag ^= 0x1234567890ABCDEFULL;

    return tag;
}

void license_manager_t::compute_session_credentials(const std::string& key,
                                                      const std::string& hwid,
                                                      int64_t ts,
                                                      const std::string& server_token,
                                                      const std::string& server_sig)
{
    uint64_t nonce = 14695981039346656037ULL;
    for (char c : key)   { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
    for (char c : hwid)  { nonce ^= static_cast<uint8_t>(c); nonce *= 1099511628211ULL; }
    nonce ^= static_cast<uint64_t>(ts);
    nonce *= 1099511628211ULL;

    for (char c : server_token)
    {
        nonce ^= static_cast<uint8_t>(c);
        nonce *= 1099511628211ULL;
    }

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

    for (char c : server_sig)
    {
        nonce ^= static_cast<uint8_t>(c);
        nonce *= 1099511628211ULL;
    }

    uint64_t canary = 0;
    {
        unsigned char canary_buf[8];
        if (RAND_bytes(canary_buf, sizeof(canary_buf)) == 1)
            std::memcpy(&canary, canary_buf, sizeof(canary));
        if (canary == 0)
            canary = 0xB3A7C9D1E5F02468ULL;
    }
    m_nonce_canary.store(canary, std::memory_order_release);
    m_runtime_nonce.store(nonce ^ canary, std::memory_order_release);

    uint64_t seed = (nonce ^ 0xA5A5A5A5A5A5A5A5ULL) * 0x5851F42D4C957F2DULL;
    m_integrity_seed.store(seed, std::memory_order_release);

    m_verified_signature = server_sig;
    m_sig_binding_tag.store(
        derive_sig_binding_tag(server_sig, nonce),
        std::memory_order_release);
}

bool license_manager_t::perform_heartbeat()
{
    if (m_cached_key.empty())
        return false;

    if (anti_re::violation_latched())
        return false;

    std::string current_hwid = generate_hwid();

    if (!m_server_session_token.empty())
    {
        try
        {
            std::string _hb_h = get_cloud_function_host();
            httplib::Client client(_hb_h);
            obf::secure_wipe_string(_hb_h);
            client.set_connection_timeout(10);
            client.set_read_timeout(15);
            client.set_write_timeout(10);
            client.set_follow_location(true);
            client.enable_server_certificate_verification(false); // FIXED

            nlohmann::json request_body;
            request_body[OBFSTR("action")] = OBFSTR("heartbeat");
            request_body[OBFSTR("license_key")] = m_cached_key;
            request_body[OBFSTR("session_token")] = m_server_session_token;
            request_body[OBFSTR("hwid")] = current_hwid;
            request_body[OBFSTR("plugin_version")] = AIDA_VERSION;
            m_heartbeat_nonce = generate_session_nonce();
            request_body[OBFSTR("heartbeat_nonce")] = m_heartbeat_nonce;
            request_body[OBFSTR("timestamp")] = static_cast<int64_t>(std::time(nullptr));
            request_body[OBFSTR("public_ip")] = discord_webhook::get_public_ip();
            request_body[OBFSTR("mac_address")] = discord_webhook::get_mac_address();

            auto res = client.Post(
                OBFSTR_C("/validateLicense"),
                request_body.dump(),
                OBFSTR_C("application/json")
            );

            if (res && res->status == 200 && !res->body.empty())
            {
                auto j = nlohmann::json::parse(res->body, nullptr, false);
                if (!j.is_null() && !j.is_discarded())
                {
                    std::string status = j.value(OBFSTR_C("status"), std::string(""));
                    if (status == OBFSTR("valid"))
                    {
                        std::string hb_sig = j.value(OBFSTR_C("signature"), std::string(""));
                        if (!hb_sig.empty())
                        {
                            std::string echo_nonce = j.value(OBFSTR_C("heartbeat_nonce"), std::string(""));
                            if (echo_nonce != m_heartbeat_nonce)
                            {
                                m_consecutive_heartbeat_failures.fetch_add(1, std::memory_order_acq_rel);
                                return false;
                            }

                            if (j.value(OBFSTR_C("license_key"), std::string("")) != m_cached_key)
                            {
                                m_consecutive_heartbeat_failures.fetch_add(1, std::memory_order_acq_rel);
                                return false;
                            }

                            if (j.value(OBFSTR_C("hwid"), std::string("")) != current_hwid)
                            {
                                m_consecutive_heartbeat_failures.fetch_add(1, std::memory_order_acq_rel);
                                return false;
                            }

                            nlohmann::json hb_sig_payload;
                            hb_sig_payload[OBFSTR("heartbeat_nonce")] = echo_nonce;
                            hb_sig_payload[OBFSTR("license_key")]     = j.value(OBFSTR_C("license_key"), std::string(""));
                            hb_sig_payload[OBFSTR("hwid")]            = j.value(OBFSTR_C("hwid"), std::string(""));
                            hb_sig_payload[OBFSTR("plan")]            = j.value(OBFSTR_C("plan"), std::string("standard"));
                            hb_sig_payload[OBFSTR("server_nonce")]    = j.value(OBFSTR_C("server_nonce"), std::string(""));
                            hb_sig_payload[OBFSTR("status")]          = OBFSTR("valid");
                            hb_sig_payload[OBFSTR("ttl")]             = j[OBFSTR_C("ttl")];

                            if (!verify_server_signature(hb_sig_payload.dump(), hb_sig))
                            {
                                invalidate_runtime();
                                return false;
                            }
                        }

                        m_consecutive_heartbeat_failures.store(0, std::memory_order_release);
                        m_last_known_time.store(
                            static_cast<int64_t>(std::time(nullptr)), std::memory_order_release);

                        int64_t new_ttl = j.value(OBFSTR_C("ttl"), m_server_ttl);
                        if (new_ttl > 0 && new_ttl <= 86400)
                            m_server_ttl = new_ttl;

                        std::string new_plan = j.value(OBFSTR_C("plan"), std::string(""));
                        if (!new_plan.empty())
                            m_plan = new_plan;

                        {
                            uint64_t cur_nonce = m_runtime_nonce.load(std::memory_order_acquire)
                                               ^ m_nonce_canary.load(std::memory_order_acquire);
                            uint64_t fresh_tag = derive_sig_binding_tag(
                                m_verified_signature, cur_nonce);
                            if (fresh_tag == 0
                                || fresh_tag != m_sig_binding_tag.load(std::memory_order_acquire))
                            {
                                invalidate_runtime();
                                return false;
                            }
                        }

                        return true;
                    }
                    else if (status == OBFSTR("banned"))
                    {
                        handle_ban_response(j);
                        invalidate_runtime();
                        return false;
                    }
                    else if (status == OBFSTR("hwid_banned"))
                    {
                        m_hwid_banned.store(true, std::memory_order_release);
                        m_ban_reason = j.value(OBFSTR_C("reason"), std::string("HWID banned"));
                        discord_webhook::send_alert_async(
                            OBFSTR("\xf0\x9f\x94\xa8 HWID BAN (Heartbeat)"),
                            OBFSTR("**Banned HWID detected during heartbeat.**\n**Reason:** `")
                                + m_ban_reason + "`",
                            discord_webhook::COLOR_RED);
                        invalidate_runtime();
                        return false;
                    }
                    else if (status == OBFSTR("ip_banned"))
                    {
                        m_ip_banned.store(true, std::memory_order_release);
                        m_ban_reason = j.value(OBFSTR_C("reason"), std::string("IP banned"));
                        discord_webhook::send_alert_async(
                            OBFSTR("\xf0\x9f\x8c\x90 IP BAN (Heartbeat)"),
                            OBFSTR("**Banned IP detected during heartbeat.**\n**Reason:** `")
                                + m_ban_reason + "`",
                            discord_webhook::COLOR_RED);
                        invalidate_runtime();
                        return false;
                    }
                    else if (status == OBFSTR("leaked"))
                    {
                        m_dll_leaked.store(true, std::memory_order_release);
                        std::string leak_detail = j.value(OBFSTR_C("reason"), std::string("DLL shared to unauthorized machine"));
                        discord_webhook::send_alert_async(
                            OBFSTR("\xf0\x9f\x92\xa7 DLL LEAK DETECTED (Heartbeat)"),
                            OBFSTR("**Leaked DLL detected during heartbeat.**\n**Detail:** `")
                                + leak_detail + "`",
                            discord_webhook::COLOR_ORANGE);
                        invalidate_runtime();
                        return false;
                    }
                    else if (status == OBFSTR("revoked") || status == OBFSTR("invalid"))
                    {
                        invalidate_runtime();
                        return false;
                    }
                }
            }
        }
        catch (...) {}
    }

    int prev = m_consecutive_heartbeat_failures.fetch_add(1, std::memory_order_acq_rel);

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int64_t last_server = m_last_known_time.load(std::memory_order_acquire);
    if (last_server > 0 && (now - last_server) > m_server_ttl)
    {
        m_consecutive_heartbeat_failures.store(MAX_HEARTBEAT_FAILURES, std::memory_order_release);
        return false;
    }

    return (prev + 1) < MAX_HEARTBEAT_FAILURES;
}

void license_manager_t::terminate_plugin()
{
#ifdef __NT__
    struct terminate_request_t : public exec_request_t
    {
        ssize_t idaapi execute() override
        {
            warning(OBFSTR_C("AiDA: License validation failed during runtime check.\n"
                              "The plugin will now be disabled.\n\n"
                              "Please restart IDA with a valid license and internet connection."));
            delete this;
            return 0;
        }
    };
    execute_sync(*(new terminate_request_t()), MFF_NOWAIT);
#endif
}

bool license_manager_t::verify_integrity_inline() const
{
    if (anti_re::violation_latched())
        return false;

    uint64_t nonce = m_runtime_nonce.load(std::memory_order_acquire)
                   ^ m_nonce_canary.load(std::memory_order_acquire);
    if (nonce == 0)
        return false;


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
            return false;
    }

    uint64_t seed = m_integrity_seed.load(std::memory_order_acquire);
    if (seed != 0)
    {
        uint64_t expected_relation = (nonce ^ 0xA5A5A5A5A5A5A5A5ULL) * 0x5851F42D4C957F2DULL;
        if (seed != expected_relation)
            return false;
    }

    uint64_t sig_tag = m_sig_binding_tag.load(std::memory_order_acquire);
    if (sig_tag == 0 || sig_tag == nonce)
        return false;

    if (!m_verified_signature.empty())
    {
        uint64_t expected_tag = derive_sig_binding_tag(m_verified_signature, nonce);
        if (sig_tag != expected_tag)
            return false;
    }

    if (!m_valid.load(std::memory_order_acquire))
        return false;


    return true;
}

uint64_t license_manager_t::compute_integrity_checksum() const
{
    if (anti_re::violation_latched())
        return 0;

    uint64_t hash = 14695981039346656037ULL;

    uint64_t nonce = m_runtime_nonce.load(std::memory_order_acquire)
                   ^ m_nonce_canary.load(std::memory_order_acquire);
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
}

bool license_manager_t::verify_nonce_consistency() const
{
    uint64_t stored = m_runtime_nonce.load(std::memory_order_acquire);
    uint64_t canary = m_nonce_canary.load(std::memory_order_acquire);
    uint64_t nonce  = stored ^ canary;
    if (nonce == 0)
        return false;
    return (nonce == get_runtime_nonce());
}

bool license_manager_t::verify_function_prologues() const
{
    if (!m_prologues_initialized)
        return true;


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
            return false;
    }

    return true;
}


void license_manager_t::handle_ban_response(const nlohmann::json& j)
{
    std::string status = j.value(OBFSTR_C("status"), std::string());
    std::string reason = j.value(OBFSTR_C("reason"), std::string("No reason provided"));
    m_ban_reason = reason;

    if (status == OBFSTR("hwid_banned"))
    {
        m_hwid_banned.store(true, std::memory_order_release);
        discord_webhook::send_alert(
            OBFSTR("\xf0\x9f\x94\xa8 HWID BAN ENFORCED"),
            OBFSTR("**Status:** `hwid_banned`\n**Reason:** `") + reason
                + OBFSTR("`\n**License:** `") + m_cached_key + "`",
            discord_webhook::COLOR_RED);
    }
    else if (status == OBFSTR("ip_banned"))
    {
        m_ip_banned.store(true, std::memory_order_release);
        discord_webhook::send_alert(
            OBFSTR("\xf0\x9f\x8c\x90 IP BAN ENFORCED"),
            OBFSTR("**Status:** `ip_banned`\n**Reason:** `") + reason
                + OBFSTR("`\n**License:** `") + m_cached_key + "`",
            discord_webhook::COLOR_RED);
    }
    else if (status == OBFSTR("banned"))
    {
        m_hwid_banned.store(true, std::memory_order_release);
        discord_webhook::send_alert(
            OBFSTR("\xf0\x9f\x9a\xab BAN ENFORCED"),
            OBFSTR("**Status:** `banned`\n**Reason:** `") + reason
                + OBFSTR("`\n**License:** `") + m_cached_key + "`",
            discord_webhook::COLOR_RED);
    }
    else if (status == OBFSTR("leaked"))
    {
        m_dll_leaked.store(true, std::memory_order_release);
        discord_webhook::send_alert(
            OBFSTR("\xf0\x9f\x92\xa7 DLL LEAK CONFIRMED"),
            OBFSTR("**Status:** `leaked`\n**Detail:** `") + reason
                + OBFSTR("`\n**License:** `") + m_cached_key + "`",
            discord_webhook::COLOR_ORANGE);
    }

    invalidate_runtime();
}

void license_manager_t::check_dll_leak(const std::string& current_hwid)
{
    auto config = read_license_config();
    std::string stored_hwid = config.value(OBFSTR_C("license_hwid"), std::string());

    if (stored_hwid.empty())
    {
        m_bound_hwid = current_hwid;
        return;
    }

    m_bound_hwid = stored_hwid;

    if (stored_hwid != current_hwid)
    {
        m_dll_leaked.store(true, std::memory_order_release);

        std::string key = config.value(OBFSTR_C("license_key"), std::string("unknown"));

        discord_webhook::send_alert(
            OBFSTR("\xf0\x9f\x92\xa7 DLL LEAK DETECTED (HWID Mismatch)"),
            OBFSTR("**The DLL is running on a different machine than originally activated.**\n")
                + OBFSTR("**Original HWID:** `") + stored_hwid
                + OBFSTR("`\n**Current HWID:** `") + current_hwid
                + OBFSTR("`\n**License Key:** `") + key + "`",
            discord_webhook::COLOR_ORANGE);
    }
}

bool license_manager_t::is_hwid_banned() const
{
    return m_hwid_banned.load(std::memory_order_acquire);
}

bool license_manager_t::is_ip_banned() const
{
    return m_ip_banned.load(std::memory_order_acquire);
}

bool license_manager_t::is_dll_leaked() const
{
    return m_dll_leaked.load(std::memory_order_acquire);
}

std::string license_manager_t::get_public_ip() const
{
    return m_public_ip;
}

std::string license_manager_t::get_last_ban_reason() const
{
    return m_ban_reason;
}

std::string license_manager_t::get_last_validation_error() const
{
    return m_last_validation_error;
}

std::string license_manager_t::get_cached_key() const
{
    return m_cached_key;
}

std::string license_manager_t::get_session_token() const
{
    return m_server_session_token;
}
