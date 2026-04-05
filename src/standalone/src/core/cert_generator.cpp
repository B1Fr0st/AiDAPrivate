#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>

#include "cert_generator.hpp"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <filesystem>
#include <mutex>

#pragma comment(lib, "crypt32.lib")

namespace cert_generator {

static root_ca_t   g_root_ca;
static std::mutex   g_mutex;
static bool         g_initialized = false;

// SSL_CTX cache keyed by domain
static std::unordered_map<std::string, ssl_ctx_ptr> g_ctx_cache;
static std::mutex g_ctx_mutex;

// ─── Helpers ──────────────────────────────────────────────────────

static bool add_ext(X509* cert, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_noinit(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_nid_conf(nid, &ctx, value);
    if (!ext) return false;
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return true;
}

static bool add_ext_issuer(X509* issuer, X509* subject, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_noinit(&ctx);
    X509V3_set_ctx(&ctx, issuer, subject, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_nid_conf(nid, &ctx, value);
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

// ─── Root CA Generation ───────────────────────────────────────────

bool generate_root_ca(root_ca_t& ca) {
    // Generate RSA 2048 key
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) return false;

    EVP_PKEY* raw_key = nullptr;
    bool ok = (EVP_PKEY_keygen_init(pctx) > 0) &&
              (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0) &&
              (EVP_PKEY_keygen(pctx, &raw_key) > 0);
    EVP_PKEY_CTX_free(pctx);
    if (!ok || !raw_key) return false;

    ca.key.reset(raw_key);

    // Create self-signed X509 certificate
    X509* raw_cert = X509_new();
    if (!raw_cert) return false;
    ca.cert.reset(raw_cert);

    X509_set_version(raw_cert, 2); // v3
    set_serial_random(raw_cert);

    // Validity: 10 years
    X509_gmtime_adj(X509_getm_notBefore(raw_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(raw_cert), 10L * 365 * 24 * 3600);

    X509_set_pubkey(raw_cert, raw_key);

    // Subject: CN=AiDA Network Proxy CA
    X509_NAME* name = X509_get_subject_name(raw_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("AiDA Network Proxy CA"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("AiDA"), -1, -1, 0);

    // Self-signed: issuer = subject
    X509_set_issuer_name(raw_cert, name);

    // Extensions
    add_ext(raw_cert, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(raw_cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_ext(raw_cert, NID_subject_key_identifier, "hash");
    add_ext(raw_cert, NID_authority_key_identifier, "keyid:always");

    // Sign with SHA-256
    if (X509_sign(raw_cert, raw_key, EVP_sha256()) <= 0) return false;

    ca.valid = true;
    return true;
}

// ─── PEM I/O ──────────────────────────────────────────────────────

bool load_root_ca(const std::string& key_path, const std::string& cert_path, root_ca_t& ca) {
    FILE* kf = nullptr;
    fopen_s(&kf, key_path.c_str(), "rb");
    if (!kf) return false;

    EVP_PKEY* raw_key = PEM_read_PrivateKey(kf, nullptr, nullptr, nullptr);
    fclose(kf);
    if (!raw_key) return false;
    ca.key.reset(raw_key);

    FILE* cf = nullptr;
    fopen_s(&cf, cert_path.c_str(), "rb");
    if (!cf) return false;

    X509* raw_cert = PEM_read_X509(cf, nullptr, nullptr, nullptr);
    fclose(cf);
    if (!raw_cert) return false;
    ca.cert.reset(raw_cert);

    ca.valid = true;
    return true;
}

bool save_root_ca(const root_ca_t& ca, const std::string& key_path, const std::string& cert_path) {
    if (!ca.valid) return false;

    // Ensure directory exists
    std::filesystem::path kp(key_path);
    if (kp.has_parent_path())
        std::filesystem::create_directories(kp.parent_path());

    FILE* kf = nullptr;
    fopen_s(&kf, key_path.c_str(), "wb");
    if (!kf) return false;

    // Write private key (encrypted with AES-256-CBC using a derived passphrase)
    // For simplicity, we write unencrypted here — DPAPI encryption is handled
    // at the file level by standalone_settings
    int ret = PEM_write_PrivateKey(kf, ca.key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    fclose(kf);
    if (!ret) return false;

    FILE* cf = nullptr;
    fopen_s(&cf, cert_path.c_str(), "wb");
    if (!cf) return false;

    ret = PEM_write_X509(cf, ca.cert.get());
    fclose(cf);
    return ret > 0;
}

// ─── Windows Certificate Store ────────────────────────────────────

bool install_root_ca(const root_ca_t& ca) {
    if (!ca.valid || !ca.cert) return false;

    // Encode cert to DER
    int der_len = i2d_X509(ca.cert.get(), nullptr);
    if (der_len <= 0) return false;

    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_X509(ca.cert.get(), &p);

    // Open ROOT store
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    if (!store) return false;

    BOOL ok = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der.data(), static_cast<DWORD>(der.size()), CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    CertCloseStore(store, 0);
    return ok != FALSE;
}

bool remove_root_ca(const root_ca_t& ca) {
    if (!ca.valid || !ca.cert) return false;

    int der_len = i2d_X509(ca.cert.get(), nullptr);
    if (der_len <= 0) return false;

    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_X509(ca.cert.get(), &p);

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    if (!store) return false;

    PCCERT_CONTEXT found = CertFindCertificateInStore(store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_EXISTING,
        nullptr, nullptr);

    // Search by exact DER match
    CERT_BLOB blob;
    blob.cbData = static_cast<DWORD>(der.size());
    blob.pbData = der.data();

    found = nullptr;
    while ((found = CertEnumCertificatesInStore(store, found)) != nullptr) {
        if (found->cbCertEncoded == blob.cbData &&
            memcmp(found->pbCertEncoded, blob.pbData, blob.cbData) == 0) {
            CertDeleteCertificateFromStore(CertDuplicateCertificateContext(found));
            CertFreeCertificateContext(found);
            break;
        }
    }

    CertCloseStore(store, 0);
    return true;
}

bool is_root_ca_installed(const root_ca_t& ca) {
    if (!ca.valid || !ca.cert) return false;

    int der_len = i2d_X509(ca.cert.get(), nullptr);
    if (der_len <= 0) return false;

    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_X509(ca.cert.get(), &p);

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    if (!store) return false;

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
    return found_it;
}

// ─── Server Certificate Generation ───────────────────────────────

bool generate_server_cert(const std::string& domain, const root_ca_t& ca, server_cert_t& out) {
    if (!ca.valid) return false;

    // Generate RSA 2048 key for server
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) return false;

    EVP_PKEY* raw_key = nullptr;
    bool ok = (EVP_PKEY_keygen_init(pctx) > 0) &&
              (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0) &&
              (EVP_PKEY_keygen(pctx, &raw_key) > 0);
    EVP_PKEY_CTX_free(pctx);
    if (!ok || !raw_key) return false;

    out.key.reset(raw_key);

    // Create X509 cert
    X509* raw_cert = X509_new();
    if (!raw_cert) return false;
    out.cert.reset(raw_cert);

    X509_set_version(raw_cert, 2); // v3
    set_serial_random(raw_cert);

    // Validity: 1 year
    X509_gmtime_adj(X509_getm_notBefore(raw_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(raw_cert), 365L * 24 * 3600);

    X509_set_pubkey(raw_cert, raw_key);

    // Subject: CN=<domain>
    X509_NAME* subject = X509_get_subject_name(raw_cert);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0);

    // Issuer: from root CA
    X509_set_issuer_name(raw_cert, X509_get_subject_name(ca.cert.get()));

    // Extensions
    add_ext_issuer(ca.cert.get(), raw_cert, NID_basic_constraints, "critical,CA:FALSE");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_ext_key_usage, "serverAuth");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_subject_key_identifier, "hash");
    add_ext_issuer(ca.cert.get(), raw_cert, NID_authority_key_identifier, "keyid:always");

    // SAN (Subject Alternative Name) - critical for modern browsers
    std::string san_value = "DNS:" + domain;
    // Also add wildcard if this is a plain domain (not already wildcard)
    if (domain.find('*') == std::string::npos && domain.find('.') != std::string::npos) {
        san_value += ",DNS:*." + domain;
    }
    add_ext_issuer(ca.cert.get(), raw_cert, NID_subject_alt_name, san_value.c_str());

    // Sign with root CA key
    if (X509_sign(raw_cert, ca.key.get(), EVP_sha256()) <= 0) return false;

    out.valid = true;
    return true;
}

// ─── SSL_CTX Cache ────────────────────────────────────────────────

SSL_CTX* get_ssl_ctx_for_domain(const std::string& domain, const root_ca_t& ca) {
    std::lock_guard<std::mutex> lock(g_ctx_mutex);

    auto it = g_ctx_cache.find(domain);
    if (it != g_ctx_cache.end()) return it->second.get();

    // Generate cert for this domain
    server_cert_t srv;
    if (!generate_server_cert(domain, ca, srv)) return nullptr;

    // Create SSL_CTX
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return nullptr;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_use_certificate(ctx, srv.cert.get());
    SSL_CTX_use_PrivateKey(ctx, srv.key.get());

    // Add CA cert to chain
    X509_up_ref(ca.cert.get());
    SSL_CTX_add_extra_chain_cert(ctx, ca.cert.get());

    g_ctx_cache[domain] = ssl_ctx_ptr(ctx);
    return ctx;
}

void clear_ssl_ctx_cache() {
    std::lock_guard<std::mutex> lock(g_ctx_mutex);
    g_ctx_cache.clear();
}

// ─── Storage Path ─────────────────────────────────────────────────

std::string get_ca_storage_dir() {
    char appdata[MAX_PATH] = {};
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata) != S_OK)
        return {};
    std::string dir = std::string(appdata) + "\\AiDA\\Standalone\\proxy";
    std::filesystem::create_directories(dir);
    return dir;
}

// ─── Initialize / Shutdown ────────────────────────────────────────

bool initialize() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initialized) return true;

    std::string dir = get_ca_storage_dir();
    if (dir.empty()) return false;

    std::string key_path = dir + "\\ca_key.pem";
    std::string cert_path = dir + "\\ca_cert.pem";

    // Try loading existing CA
    if (std::filesystem::exists(key_path) && std::filesystem::exists(cert_path)) {
        if (load_root_ca(key_path, cert_path, g_root_ca)) {
            g_initialized = true;
            return true;
        }
    }

    // Generate new CA
    if (!generate_root_ca(g_root_ca)) return false;
    save_root_ca(g_root_ca, key_path, cert_path);

    g_initialized = true;
    return true;
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_mutex);
    clear_ssl_ctx_cache();
    g_root_ca = root_ca_t{};
    g_initialized = false;
}

const root_ca_t& get_root_ca() {
    return g_root_ca;
}

bool is_ready() {
    return g_initialized && g_root_ca.valid;
}

} // namespace cert_generator
