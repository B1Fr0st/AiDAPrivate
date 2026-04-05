#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

namespace cert_generator {

// Cleanup helpers using unique_ptr with custom deleters
struct evp_pkey_deleter { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
struct x509_deleter     { void operator()(X509* p) const { if (p) X509_free(p); } };
struct ssl_ctx_deleter  { void operator()(SSL_CTX* p) const { if (p) SSL_CTX_free(p); } };

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
using x509_ptr     = std::unique_ptr<X509, x509_deleter>;
using ssl_ctx_ptr  = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;

struct root_ca_t {
    evp_pkey_ptr key;
    x509_ptr     cert;
    bool         valid = false;
};

struct server_cert_t {
    evp_pkey_ptr key;
    x509_ptr     cert;
    bool         valid = false;
};

// Generate a new RSA 2048-bit root CA certificate
// CN = "AiDA Network Proxy CA", validity = 10 years
bool generate_root_ca(root_ca_t& ca);

// Load root CA from PEM files (key + cert)
bool load_root_ca(const std::string& key_path, const std::string& cert_path, root_ca_t& ca);

// Save root CA to PEM files
bool save_root_ca(const root_ca_t& ca, const std::string& key_path, const std::string& cert_path);

// Install root CA into Windows certificate store (CurrentUser\Root)
bool install_root_ca(const root_ca_t& ca);

// Remove root CA from Windows certificate store
bool remove_root_ca(const root_ca_t& ca);

// Check if our root CA is installed in the Windows certificate store
bool is_root_ca_installed(const root_ca_t& ca);

// Generate a server certificate for a specific domain, signed by the root CA
// The cert will have a SAN (Subject Alternative Name) matching the domain
bool generate_server_cert(const std::string& domain, const root_ca_t& ca, server_cert_t& out);

// Get or create an SSL_CTX for a specific domain (cached)
SSL_CTX* get_ssl_ctx_for_domain(const std::string& domain, const root_ca_t& ca);

// Clear the SSL_CTX cache
void clear_ssl_ctx_cache();

// Get the appdata path for CA storage
std::string get_ca_storage_dir();

// Initialize the cert generator (loads or generates root CA)
bool initialize();

// Shutdown and clean up
void shutdown();

// Get the root CA (valid after initialize())
const root_ca_t& get_root_ca();

// Is the cert generator initialized and ready?
bool is_ready();

} // namespace cert_generator
