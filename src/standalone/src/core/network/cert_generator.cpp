#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>

#include "cert_generator.hpp"
#include "helpers/diag_log.hpp"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <filesystem>
#include <fstream>
#include <mutex>
#include <vector>

#pragma comment(lib, "crypt32.lib")

namespace cert_generator {

static root_ca_t   g_root_ca;
static std::mutex   g_mutex;
static bool         g_initialized = false;


static std::unordered_map<std::string, ssl_ctx_ptr> g_ctx_cache;
static std::mutex g_ctx_mutex;


static bool add_ext(X509* cert, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
    if (!ext) return false;
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return true;
}

static bool add_ext_issuer(X509* issuer, X509* subject, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, subject, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
    if (!ext) return false;
    X509_add_ext(subject, ext, -1);
    X509_EXTENSION_free(ext);
    return true;
}

static bool set_serial_random(X509* cert) {
    ASN1_INTEGER* sn = ASN1_INTEGER_new();
    if (!sn) return false;

    BIGNUM* bn = BN_new();
    if (!bn) { ASN1_INTEGER_free(sn); return false; }

    BN_rand(bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    BN_to_ASN1_INTEGER(bn, sn);
    X509_set_serialNumber(cert, sn);

    BN_free(bn);
    ASN1_INTEGER_free(sn);
    return true;
}


bool generate_root_ca(root_ca_t& ca) {
    diag::log_tagged("cert", "generate_root_ca entry");

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) {
        diag::log_tagged("cert", "generate_root_ca EVP_PKEY_CTX_new_id failed");
        return false;
    }

    EVP_PKEY* raw_key = nullptr;
    bool ok = (EVP_PKEY_keygen_init(pctx) > 0) &&
              (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0) &&
              (EVP_PKEY_keygen(pctx, &raw_key) > 0);
    EVP_PKEY_CTX_free(pctx);
    diag::log_tagged_fmt("cert", "generate_root_ca keygen ok=%d raw_key=%p", (int)ok, raw_key);
    if (!ok || !raw_key) {
        diag::log_tagged("cert", "generate_root_ca keygen failed");
        return false;
    }

    ca.key.reset(raw_key);

    X509* raw_cert = X509_new();
    if (!raw_cert) {
        diag::log_tagged("cert", "generate_root_ca X509_new failed");
        return false;
    }
    ca.cert.reset(raw_cert);

    X509_set_version(raw_cert, 2);
    set_serial_random(raw_cert);
    diag::log_tagged("cert", "generate_root_ca set version=2 and random serial");

    X509_gmtime_adj(X509_getm_notBefore(raw_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(raw_cert), 10L * 365 * 24 * 3600);

    X509_set_pubkey(raw_cert, raw_key);

    X509_NAME* name = const_cast<X509_NAME*>(X509_get_subject_name(raw_cert));
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("AiDA Network Proxy CA"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("AiDA"), -1, -1, 0);
    diag::log_tagged("cert", "generate_root_ca set subject CN=AiDA Network Proxy CA O=AiDA");

    X509_set_issuer_name(raw_cert, name);

    add_ext(raw_cert, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(raw_cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_ext(raw_cert, NID_subject_key_identifier, "hash");
    add_ext(raw_cert, NID_authority_key_identifier, "keyid:always");
    diag::log_tagged("cert", "generate_root_ca extensions added");

    int sign_rc = X509_sign(raw_cert, raw_key, EVP_sha256());
    diag::log_tagged_fmt("cert", "generate_root_ca X509_sign rc=%d", sign_rc);
    if (sign_rc <= 0) {
        diag::log_tagged("cert", "generate_root_ca X509_sign failed");
        return false;
    }

    ca.valid = true;
    diag::log_tagged("cert", "generate_root_ca success");
    return true;
}


static bool read_file_bytes(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream in(std::filesystem::u8path(path), std::ios::binary | std::ios::ate);
    if (!in) return false;
    std::streamsize sz = in.tellg();
    if (sz <= 0 || sz > (std::streamsize)(64 * 1024 * 1024)) return false;
    in.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    if (!in.read(reinterpret_cast<char*>(out.data()), sz)) return false;
    return true;
}

static bool write_file_bytes(const std::string& path, const uint8_t* data, size_t len) {
    std::ofstream out(std::filesystem::u8path(path), std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return out.good();
}

bool load_root_ca(const std::string& key_path, const std::string& cert_path, root_ca_t& ca) {
    diag::log_tagged_fmt("cert", "load_root_ca entry key_path=%s cert_path=%s", key_path.c_str(), cert_path.c_str());
    std::vector<uint8_t> key_bytes;
    if (!read_file_bytes(key_path, key_bytes) || key_bytes.empty()) {
        diag::log_tagged_fmt("cert", "load_root_ca read key file failed path=%s", key_path.c_str());
        return false;
    }
    diag::log_tagged_fmt("cert", "load_root_ca key file read size=%zu", key_bytes.size());

    BIO* kbio = BIO_new_mem_buf(key_bytes.data(), static_cast<int>(key_bytes.size()));
    if (!kbio) {
        diag::log_tagged("cert", "load_root_ca BIO_new_mem_buf for key failed");
        return false;
    }
    EVP_PKEY* raw_key = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
    BIO_free(kbio);
    diag::log_tagged_fmt("cert", "load_root_ca PEM_read_bio_PrivateKey raw_key=%p", raw_key);
    if (!raw_key) {
        diag::log_tagged("cert", "load_root_ca PEM_read_bio_PrivateKey failed");
        return false;
    }
    ca.key.reset(raw_key);

    std::vector<uint8_t> cert_bytes;
    if (!read_file_bytes(cert_path, cert_bytes) || cert_bytes.empty()) {
        diag::log_tagged_fmt("cert", "load_root_ca read cert file failed path=%s", cert_path.c_str());
        return false;
    }
    diag::log_tagged_fmt("cert", "load_root_ca cert file read size=%zu", cert_bytes.size());

    BIO* cbio = BIO_new_mem_buf(cert_bytes.data(), static_cast<int>(cert_bytes.size()));
    if (!cbio) {
        diag::log_tagged("cert", "load_root_ca BIO_new_mem_buf for cert failed");
        return false;
    }
    X509* raw_cert = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
    BIO_free(cbio);
    diag::log_tagged_fmt("cert", "load_root_ca PEM_read_bio_X509 raw_cert=%p", raw_cert);
    if (!raw_cert) {
        diag::log_tagged("cert", "load_root_ca PEM_read_bio_X509 failed");
        return false;
    }
    ca.cert.reset(raw_cert);

    ca.valid = true;
    diag::log_tagged("cert", "load_root_ca success");
    return true;
}

bool save_root_ca(const root_ca_t& ca, const std::string& key_path, const std::string& cert_path) {
    diag::log_tagged_fmt("cert", "save_root_ca entry key_path=%s cert_path=%s ca_valid=%d", key_path.c_str(), cert_path.c_str(), (int)ca.valid);
    if (!ca.valid) {
        diag::log_tagged("cert", "save_root_ca ca not valid");
        return false;
    }

    std::filesystem::path kp(std::filesystem::u8path(key_path));
    if (kp.has_parent_path())
        std::filesystem::create_directories(kp.parent_path());

    BIO* kbio = BIO_new(BIO_s_mem());
    if (!kbio) {
        diag::log_tagged("cert", "save_root_ca BIO_new for key failed");
        return false;
    }
    int wrote = PEM_write_bio_PrivateKey(kbio, ca.key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    diag::log_tagged_fmt("cert", "save_root_ca PEM_write_bio_PrivateKey wrote=%d", wrote);
    if (!wrote) {
        BIO_free(kbio);
        diag::log_tagged("cert", "save_root_ca PEM_write_bio_PrivateKey failed");
        return false;
    }
    BUF_MEM* km = nullptr;
    BIO_get_mem_ptr(kbio, &km);
    if (!km || km->length == 0 ||
        !write_file_bytes(key_path, reinterpret_cast<const uint8_t*>(km->data), km->length)) {
        BIO_free(kbio);
        diag::log_tagged_fmt("cert", "save_root_ca write key file failed path=%s", key_path.c_str());
        return false;
    }
    diag::log_tagged_fmt("cert", "save_root_ca key file written len=%zu path=%s", km->length, key_path.c_str());
    BIO_free(kbio);

    std::filesystem::path cp(std::filesystem::u8path(cert_path));
    if (cp.has_parent_path())
        std::filesystem::create_directories(cp.parent_path());

    BIO* cbio = BIO_new(BIO_s_mem());
    if (!cbio) {
        diag::log_tagged("cert", "save_root_ca BIO_new for cert failed");
        return false;
    }
    wrote = PEM_write_bio_X509(cbio, ca.cert.get());
    diag::log_tagged_fmt("cert", "save_root_ca PEM_write_bio_X509 wrote=%d", wrote);
    if (!wrote) {
        BIO_free(cbio);
        diag::log_tagged("cert", "save_root_ca PEM_write_bio_X509 failed");
        return false;
    }
    BUF_MEM* cm = nullptr;
    BIO_get_mem_ptr(cbio, &cm);
    if (!cm || cm->length == 0 ||
        !write_file_bytes(cert_path, reinterpret_cast<const uint8_t*>(cm->data), cm->length)) {
        BIO_free(cbio);
        diag::log_tagged_fmt("cert", "save_root_ca write cert file failed path=%s", cert_path.c_str());
        return false;
    }
    diag::log_tagged_fmt("cert", "save_root_ca cert file written len=%zu path=%s", cm->length, cert_path.c_str());
    BIO_free(cbio);

    diag::log_tagged("cert", "save_root_ca success");
    return true;
}


bool install_root_ca(const root_ca_t& ca) {
    diag::log_tagged_fmt("cert", "install_root_ca entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert) {
        diag::log_tagged("cert", "install_root_ca ca not valid or cert null");
        return false;
    }

    int der_len = i2d_X509(ca.cert.get(), nullptr);
    diag::log_tagged_fmt("cert", "install_root_ca DER encode len=%d", der_len);
    if (der_len <= 0) {
        diag::log_tagged("cert", "install_root_ca i2d_X509 failed");
        return false;
    }

    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_X509(ca.cert.get(), &p);

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    diag::log_tagged_fmt("cert", "install_root_ca CertOpenStore store=%p", store);
    if (!store) {
        diag::log_tagged("cert", "install_root_ca CertOpenStore failed");
        return false;
    }

    BOOL ok = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der.data(), static_cast<DWORD>(der.size()), CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    CertCloseStore(store, 0);
    diag::log_tagged_fmt("cert", "install_root_ca CertAddEncodedCertificateToStore ok=%d", (int)ok);
    return ok != FALSE;
}

bool remove_root_ca(const root_ca_t& ca) {
    diag::log_tagged_fmt("cert", "remove_root_ca entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert) {
        diag::log_tagged("cert", "remove_root_ca ca not valid or cert null");
        return false;
    }

    int der_len = i2d_X509(ca.cert.get(), nullptr);
    diag::log_tagged_fmt("cert", "remove_root_ca DER encode len=%d", der_len);
    if (der_len <= 0) {
        diag::log_tagged("cert", "remove_root_ca i2d_X509 failed");
        return false;
    }

    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_X509(ca.cert.get(), &p);

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    diag::log_tagged_fmt("cert", "remove_root_ca CertOpenStore store=%p", store);
    if (!store) {
        diag::log_tagged("cert", "remove_root_ca CertOpenStore failed");
        return false;
    }

    CERT_BLOB blob;
    blob.cbData = static_cast<DWORD>(der.size());
    blob.pbData = der.data();

    bool deleted = false;
    PCCERT_CONTEXT found = nullptr;
    while ((found = CertEnumCertificatesInStore(store, found)) != nullptr) {
        if (found->cbCertEncoded == blob.cbData &&
            memcmp(found->pbCertEncoded, blob.pbData, blob.cbData) == 0) {
            diag::log_tagged("cert", "remove_root_ca found matching cert deleting");
            CertDeleteCertificateFromStore(CertDuplicateCertificateContext(found));
            CertFreeCertificateContext(found);
            deleted = true;
            break;
        }
    }

    CertCloseStore(store, 0);
    diag::log_tagged_fmt("cert", "remove_root_ca done deleted=%d", (int)deleted);
    return true;
}

bool is_root_ca_installed(const root_ca_t& ca) {
    diag::log_tagged_fmt("cert", "is_root_ca_installed entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert) {
        diag::log_tagged("cert", "is_root_ca_installed ca not valid or cert null returning false");
        return false;
    }

    int der_len = i2d_X509(ca.cert.get(), nullptr);
    diag::log_tagged_fmt("cert", "is_root_ca_installed DER encode len=%d", der_len);
    if (der_len <= 0) {
        diag::log_tagged("cert", "is_root_ca_installed i2d_X509 failed");
        return false;
    }

    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_X509(ca.cert.get(), &p);

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    diag::log_tagged_fmt("cert", "is_root_ca_installed CertOpenStore store=%p", store);
    if (!store) {
        diag::log_tagged("cert", "is_root_ca_installed CertOpenStore failed");
        return false;
    }

    bool found_it = false;
    PCCERT_CONTEXT found = nullptr;
    while ((found = CertEnumCertificatesInStore(store, found)) != nullptr) {
        if (found->cbCertEncoded == static_cast<DWORD>(der.size()) &&
            memcmp(found->pbCertEncoded, der.data(), der.size()) == 0) {
            found_it = true;
            CertFreeCertificateContext(found);
            break;
        }
    }

    CertCloseStore(store, 0);
    diag::log_tagged_fmt("cert", "is_root_ca_installed result=%d", (int)found_it);
    return found_it;
}


bool generate_server_cert(const std::string& domain, const root_ca_t& ca, server_cert_t& out) {
    diag::log_tagged_fmt("cert", "generate_server_cert entry domain=%s ca_valid=%d", domain.c_str(), (int)ca.valid);
    if (!ca.valid) {
        diag::log_tagged("cert", "generate_server_cert ca not valid");
        return false;
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) {
        diag::log_tagged("cert", "generate_server_cert EVP_PKEY_CTX_new_id failed");
        return false;
    }

    EVP_PKEY* raw_key = nullptr;
    bool ok = (EVP_PKEY_keygen_init(pctx) > 0) &&
              (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0) &&
              (EVP_PKEY_keygen(pctx, &raw_key) > 0);
    EVP_PKEY_CTX_free(pctx);
    diag::log_tagged_fmt("cert", "generate_server_cert keygen ok=%d raw_key=%p domain=%s", (int)ok, raw_key, domain.c_str());
    if (!ok || !raw_key) {
        diag::log_tagged_fmt("cert", "generate_server_cert keygen failed domain=%s", domain.c_str());
        return false;
    }

    out.key.reset(raw_key);

    X509* raw_cert = X509_new();
    if (!raw_cert) {
        diag::log_tagged("cert", "generate_server_cert X509_new failed");
        return false;
    }
    out.cert.reset(raw_cert);

    X509_set_version(raw_cert, 2);
    set_serial_random(raw_cert);
    diag::log_tagged_fmt("cert", "generate_server_cert set version=2 random serial domain=%s", domain.c_str());

    X509_gmtime_adj(X509_getm_notBefore(raw_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(raw_cert), 365L * 24 * 3600);

    X509_set_pubkey(raw_cert, raw_key);

    X509_NAME* subject = const_cast<X509_NAME*>(X509_get_subject_name(raw_cert));
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0);
    diag::log_tagged_fmt("cert", "generate_server_cert set CN=%s", domain.c_str());

    X509_set_issuer_name(raw_cert, X509_get_subject_name(ca.cert.get()));

    add_ext_issuer(ca.cert.get(), raw_cert, NID_basic_constraints, "critical,CA:FALSE");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_ext_key_usage, "serverAuth");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_subject_key_identifier, "hash");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_authority_key_identifier, "keyid:always");

    std::string san_value = "DNS:" + domain;
    bool wildcard_added = false;
    if (domain.find('*') == std::string::npos && domain.find('.') != std::string::npos) {
        san_value += ",DNS:*." + domain;
        wildcard_added = true;
    }
    diag::log_tagged_fmt("cert", "generate_server_cert SAN=%s wildcard_added=%d", san_value.c_str(), (int)wildcard_added);
    add_ext_issuer(ca.cert.get(), raw_cert, NID_subject_alt_name, san_value.c_str());

    int sign_rc = X509_sign(raw_cert, ca.key.get(), EVP_sha256());
    diag::log_tagged_fmt("cert", "generate_server_cert X509_sign rc=%d domain=%s", sign_rc, domain.c_str());
    if (sign_rc <= 0) {
        diag::log_tagged_fmt("cert", "generate_server_cert X509_sign failed domain=%s", domain.c_str());
        return false;
    }

    out.valid = true;
    diag::log_tagged_fmt("cert", "generate_server_cert success domain=%s", domain.c_str());
    return true;
}


SSL_CTX* get_ssl_ctx_for_domain(const std::string& domain, const root_ca_t& ca) {
    diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain entry domain=%s", domain.c_str());
    constexpr size_t kMaxCacheEntries = 1024;
    std::lock_guard<std::mutex> lock(g_ctx_mutex);

    auto it = g_ctx_cache.find(domain);
    if (it != g_ctx_cache.end()) {
        diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain cache hit domain=%s ctx=%p", domain.c_str(), it->second.get());
        return it->second.get();
    }
    diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain cache miss domain=%s cache_size=%zu", domain.c_str(), g_ctx_cache.size());

    if (g_ctx_cache.size() >= kMaxCacheEntries) {
        diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain cache full evicting one entry max=%zu", kMaxCacheEntries);
        g_ctx_cache.erase(g_ctx_cache.begin());
    }

    server_cert_t srv;
    bool cert_ok = generate_server_cert(domain, ca, srv);
    diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain generate_server_cert domain=%s ok=%d", domain.c_str(), (int)cert_ok);
    if (!cert_ok) {
        diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain generate_server_cert failed domain=%s", domain.c_str());
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain SSL_CTX_new ctx=%p domain=%s", ctx, domain.c_str());
    if (!ctx) {
        diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain SSL_CTX_new failed domain=%s", domain.c_str());
        return nullptr;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_use_certificate(ctx, srv.cert.get());
    SSL_CTX_use_PrivateKey(ctx, srv.key.get());
    diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain configured SSL_CTX domain=%s", domain.c_str());

    X509_up_ref(ca.cert.get());
    SSL_CTX_add_extra_chain_cert(ctx, ca.cert.get());

    g_ctx_cache[domain] = ssl_ctx_ptr(ctx);
    diag::log_tagged_fmt("cert", "get_ssl_ctx_for_domain cached and returning ctx=%p domain=%s cache_size=%zu", ctx, domain.c_str(), g_ctx_cache.size());
    return ctx;
}

void clear_ssl_ctx_cache() {
    diag::log_tagged("cert", "clear_ssl_ctx_cache entry");
    std::lock_guard<std::mutex> lock(g_ctx_mutex);
    size_t count = g_ctx_cache.size();
    g_ctx_cache.clear();
    diag::log_tagged_fmt("cert", "clear_ssl_ctx_cache cleared count=%zu", count);
}


std::string get_ca_storage_dir() {
    diag::log_tagged("cert", "get_ca_storage_dir entry");
    char appdata[MAX_PATH] = {};
    HRESULT hr = SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata);
    diag::log_tagged_fmt("cert", "get_ca_storage_dir SHGetFolderPathA hr=0x%lx appdata=%s", hr, appdata);
    if (hr != S_OK) {
        diag::log_tagged("cert", "get_ca_storage_dir SHGetFolderPathA failed");
        return {};
    }
    std::string dir = std::string(appdata) + "\\AiDA\\Standalone\\proxy";
    std::filesystem::create_directories(dir);
    diag::log_tagged_fmt("cert", "get_ca_storage_dir result=%s", dir.c_str());
    return dir;
}


bool initialize() {
    diag::log_tagged("cert", "initialize entry");
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initialized) {
        diag::log_tagged("cert", "initialize already initialized skip");
        return true;
    }

    std::string dir = get_ca_storage_dir();
    diag::log_tagged_fmt("cert", "initialize storage_dir=%s", dir.c_str());
    if (dir.empty()) {
        diag::log_tagged("cert", "initialize get_ca_storage_dir failed");
        return false;
    }

    std::string key_path = dir + "\\ca_key.pem";
    std::string cert_path = dir + "\\ca_cert.pem";
    bool key_exists = std::filesystem::exists(key_path);
    bool cert_exists = std::filesystem::exists(cert_path);
    diag::log_tagged_fmt("cert", "initialize key_exists=%d cert_exists=%d key_path=%s", (int)key_exists, (int)cert_exists, key_path.c_str());

    if (key_exists && cert_exists) {
        diag::log_tagged("cert", "initialize loading existing CA from disk");
        if (load_root_ca(key_path, cert_path, g_root_ca)) {
            g_initialized = true;
            diag::log_tagged("cert", "initialize loaded existing CA success");
            return true;
        }
        diag::log_tagged("cert", "initialize load_root_ca failed will generate new");
    } else {
        diag::log_tagged("cert", "initialize no existing CA files generating new");
    }

    bool gen_ok = generate_root_ca(g_root_ca);
    diag::log_tagged_fmt("cert", "initialize generate_root_ca ok=%d", (int)gen_ok);
    if (!gen_ok) {
        diag::log_tagged("cert", "initialize generate_root_ca failed");
        return false;
    }
    bool save_ok = save_root_ca(g_root_ca, key_path, cert_path);
    diag::log_tagged_fmt("cert", "initialize save_root_ca ok=%d", (int)save_ok);

    g_initialized = true;
    diag::log_tagged("cert", "initialize complete");
    return true;
}

void shutdown() {
    diag::log_tagged("cert", "shutdown entry");
    std::lock_guard<std::mutex> lock(g_mutex);
    clear_ssl_ctx_cache();
    g_root_ca = root_ca_t{};
    g_initialized = false;
    diag::log_tagged("cert", "shutdown complete");
}

const root_ca_t& get_root_ca() {
    return g_root_ca;
}

bool is_ready() {
    return g_initialized && g_root_ca.valid;
}

}
