#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

namespace cert_generator {


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


bool generate_root_ca(root_ca_t& ca);


bool generate_public_ca_certificate_der(const std::string& common_name, std::uint32_t validity_days,
                                        std::vector<uint8_t>& out, std::string& subject_cn);


bool load_root_ca(const std::string& key_path, const std::string& cert_path, root_ca_t& ca);


bool save_root_ca(const root_ca_t& ca, const std::string& key_path, const std::string& cert_path);


std::string spki_sha256_base64(const root_ca_t& ca);


bool export_ca_certificate_der(const root_ca_t& ca, std::vector<uint8_t>& out);


bool export_ca_certificate_pem(const root_ca_t& ca, std::string& out);


bool install_root_ca(const root_ca_t& ca);


bool remove_root_ca(const root_ca_t& ca);


bool is_root_ca_installed(const root_ca_t& ca);


bool generate_server_cert(const std::string& domain, const root_ca_t& ca, server_cert_t& out);


SSL_CTX* get_ssl_ctx_for_domain(const std::string& domain, const root_ca_t& ca);


void clear_ssl_ctx_cache();


std::string get_ca_storage_dir();


bool initialize();


void shutdown();


const root_ca_t& get_root_ca();


bool is_ready();

}
