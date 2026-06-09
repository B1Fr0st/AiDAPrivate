#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>

#include "cert_generator.hpp"
#include "../infra/work_queue.hpp"
#include "helpers/diag_log.hpp"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cctype>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#pragma comment(lib, "crypt32.lib")

namespace cert_generator {

static root_ca_t   g_root_ca;
static std::mutex   g_mutex;
static bool         g_initialized = false;


static std::unordered_map<std::string, ssl_ctx_ptr> g_ctx_cache;
static std::mutex g_ctx_mutex;

static constexpr char kProtectedKeyPrefix[] = "AIDA-DPAPI-CAKEY-v1\n";
static constexpr char kPrivateKeyEntropy[] = "AiDA:standalone:proxy:ca-key:v1";
static constexpr DWORD kCertStoreQueryTimeoutMs = 3000;
static constexpr DWORD kCertStoreMutationTimeoutMs = 5000;
static constexpr long kCertStoreMaxDetachedWorkers = 4;
static std::atomic<long> g_cert_store_workers{0};

struct cert_store_result_t {
    bool ok = false;
    DWORD gle = ERROR_SUCCESS;
    DWORD detail = 0;
};

struct cert_store_async_state_t {
    std::atomic<bool> done{false};
    std::atomic<int> ok{0};
    std::atomic<DWORD> gle{ERROR_TIMEOUT};
    std::atomic<DWORD> detail{0};
    std::atomic<unsigned long long> elapsed_ms{0};
};

template <typename Fn>
static bool run_cert_store_operation_bounded(const char* op_name,
                                             DWORD timeout_ms,
                                             Fn fn,
                                             DWORD* gle_out = nullptr,
                                             DWORD* detail_out = nullptr) {
    const long active = g_cert_store_workers.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (active > kCertStoreMaxDetachedWorkers) {
        g_cert_store_workers.fetch_sub(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("cert", "%s refused active_workers=%ld limit=%ld",
            op_name, active, kCertStoreMaxDetachedWorkers);
        if (gle_out) *gle_out = ERROR_BUSY;
        if (detail_out) *detail_out = static_cast<DWORD>(active);
        return false;
    }

    auto state = std::make_shared<cert_store_async_state_t>();
    std::string op = op_name ? op_name : "cert_store_operation";
    try {
        if (!work_queue::post([state, op, fn = std::move(fn)]() mutable {
            const ULONGLONG t0 = GetTickCount64();
            diag::log_tagged_fmt("cert", "%s worker_entry tid=%lu active_workers=%ld",
                op.c_str(),
                static_cast<unsigned long>(GetCurrentThreadId()),
                g_cert_store_workers.load(std::memory_order_acquire));
            cert_store_result_t result;
            try {
                result = fn();
            } catch (...) {
                result.ok = false;
                result.gle = ERROR_OPERATION_ABORTED;
                result.detail = 0;
                diag::log_tagged_fmt("cert", "%s worker_exception tid=%lu",
                    op.c_str(), static_cast<unsigned long>(GetCurrentThreadId()));
            }
            const ULONGLONG elapsed = GetTickCount64() - t0;
            state->ok.store(result.ok ? 1 : 0, std::memory_order_release);
            state->gle.store(result.gle, std::memory_order_release);
            state->detail.store(result.detail, std::memory_order_release);
            state->elapsed_ms.store(static_cast<unsigned long long>(elapsed), std::memory_order_release);
            diag::log_tagged_fmt("cert", "%s worker_exit ok=%d gle=%lu detail=%lu elapsed_ms=%llu",
                op.c_str(),
                result.ok ? 1 : 0,
                static_cast<unsigned long>(result.gle),
                static_cast<unsigned long>(result.detail),
                static_cast<unsigned long long>(elapsed));
            g_cert_store_workers.fetch_sub(1, std::memory_order_acq_rel);
            state->done.store(true, std::memory_order_release);
        })) {
            DWORD start_gle = ERROR_NOT_READY;
            g_cert_store_workers.fetch_sub(1, std::memory_order_acq_rel);
            diag::log_tagged_fmt("cert", "%s worker_post_failed gle=%lu",
                op.c_str(),
                static_cast<unsigned long>(start_gle));
            if (gle_out) *gle_out = start_gle;
            if (detail_out) *detail_out = 0;
            return false;
        }
    } catch (const std::exception& ex) {
        g_cert_store_workers.fetch_sub(1, std::memory_order_acq_rel);
        DWORD start_gle = GetLastError();
        if (start_gle == ERROR_SUCCESS)
            start_gle = ERROR_NOT_ENOUGH_MEMORY;
        diag::log_tagged_fmt("cert", "%s worker_post_failed err=%s gle=%lu",
            op.c_str(), ex.what(), static_cast<unsigned long>(start_gle));
        if (gle_out) *gle_out = start_gle;
        if (detail_out) *detail_out = 0;
        return false;
    } catch (...) {
        g_cert_store_workers.fetch_sub(1, std::memory_order_acq_rel);
        DWORD start_gle = GetLastError();
        if (start_gle == ERROR_SUCCESS)
            start_gle = ERROR_NOT_ENOUGH_MEMORY;
        diag::log_tagged_fmt("cert", "%s worker_post_failed err=unknown gle=%lu",
            op.c_str(), static_cast<unsigned long>(start_gle));
        if (gle_out) *gle_out = start_gle;
        if (detail_out) *detail_out = 0;
        return false;
    }

    const ULONGLONG wait_start = GetTickCount64();
    for (;;) {
        if (state->done.load(std::memory_order_acquire)) {
            const DWORD gle = state->gle.load(std::memory_order_acquire);
            const DWORD detail = state->detail.load(std::memory_order_acquire);
            const bool ok = state->ok.load(std::memory_order_acquire) != 0;
            if (gle_out) *gle_out = gle;
            if (detail_out) *detail_out = detail;
            diag::log_tagged_fmt("cert", "%s completed ok=%d gle=%lu detail=%lu wait_ms=%llu worker_ms=%llu",
                op.c_str(),
                ok ? 1 : 0,
                static_cast<unsigned long>(gle),
                static_cast<unsigned long>(detail),
                static_cast<unsigned long long>(GetTickCount64() - wait_start),
                state->elapsed_ms.load(std::memory_order_acquire));
            return ok;
        }
        const ULONGLONG elapsed = GetTickCount64() - wait_start;
        if (elapsed >= timeout_ms) {
            if (gle_out) *gle_out = ERROR_TIMEOUT;
            if (detail_out) *detail_out = static_cast<DWORD>(elapsed > 0xFFFFFFFFULL ? 0xFFFFFFFFUL : elapsed);
            diag::log_tagged_fmt("cert", "%s timeout timeout_ms=%lu waited_ms=%llu active_workers=%ld",
                op.c_str(),
                static_cast<unsigned long>(timeout_ms),
                static_cast<unsigned long long>(elapsed),
                g_cert_store_workers.load(std::memory_order_acquire));
            return false;
        }
        const DWORD remaining = static_cast<DWORD>(timeout_ms - static_cast<DWORD>(elapsed));
        Sleep(std::min<DWORD>(remaining, 25));
    }
}


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

static bool valid_common_name(const std::string& cn) {
    if (cn.empty() || cn.size() > 128)
        return false;
    for (unsigned char c : cn) {
        if (c < 0x20 || c > 0x7E)
            return false;
    }
    return true;
}

bool generate_public_ca_certificate_der(const std::string& common_name, std::uint32_t validity_days,
                                        std::vector<uint8_t>& out, std::string& subject_cn) {
    const ULONGLONG t0 = GetTickCount64();
    out.clear();
    subject_cn.clear();
    std::string cn = common_name.empty() ? "AiDA Generated CA" : common_name;
    if (!valid_common_name(cn)) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der rejected cn_len=%zu elapsed_ms=%llu",
            cn.size(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }
    const std::uint32_t days = validity_days == 0 ? 3650u : std::min<std::uint32_t>(validity_days, 3650u);
    diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der entry cn_len=%zu days=%u",
        cn.size(), days);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der EVP_PKEY_CTX_new_id failed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    EVP_PKEY* raw_key = nullptr;
    bool ok = (EVP_PKEY_keygen_init(pctx) > 0) &&
              (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0) &&
              (EVP_PKEY_keygen(pctx, &raw_key) > 0);
    EVP_PKEY_CTX_free(pctx);
    evp_pkey_ptr key(raw_key);
    diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der keygen ok=%d elapsed_ms=%llu",
        ok ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!ok || !key)
        return false;

    x509_ptr cert(X509_new());
    if (!cert) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der X509_new failed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    X509_set_version(cert.get(), 2);
    if (!set_serial_random(cert.get())) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der serial failed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), static_cast<long>(days) * 24L * 3600L);
    if (X509_set_pubkey(cert.get(), key.get()) != 1) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der pubkey failed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    X509_NAME* name = const_cast<X509_NAME*>(X509_get_subject_name(cert.get()));
    if (!name ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("AiDA"), -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert.get(), name) != 1) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der subject failed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    if (!add_ext(cert.get(), NID_basic_constraints, "critical,CA:TRUE") ||
        !add_ext(cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign") ||
        !add_ext(cert.get(), NID_subject_key_identifier, "hash") ||
        !add_ext(cert.get(), NID_authority_key_identifier, "keyid:always")) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der extension failed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    const int sign_rc = X509_sign(cert.get(), key.get(), EVP_sha256());
    diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der sign rc=%d elapsed_ms=%llu",
        sign_rc,
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (sign_rc <= 0)
        return false;

    const int der_len = i2d_X509(cert.get(), nullptr);
    if (der_len <= 0) {
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der der_size failed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }
    out.resize(static_cast<size_t>(der_len));
    unsigned char* p = out.data();
    const int wrote = i2d_X509(cert.get(), &p);
    if (wrote != der_len) {
        out.clear();
        diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der der_write failed wrote=%d expected=%d elapsed_ms=%llu",
            wrote,
            der_len,
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }
    subject_cn = cn;
    diag::log_tagged_fmt("cert", "generate_public_ca_certificate_der success der_len=%d elapsed_ms=%llu",
        der_len,
        static_cast<unsigned long long>(GetTickCount64() - t0));
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

static void secure_zero_bytes(std::vector<uint8_t>& bytes) {
    if (!bytes.empty())
        SecureZeroMemory(bytes.data(), bytes.size());
}

static bool has_protected_key_prefix(const std::vector<uint8_t>& bytes) {
    constexpr size_t prefix_len = sizeof(kProtectedKeyPrefix) - 1;
    return bytes.size() >= prefix_len &&
        std::memcmp(bytes.data(), kProtectedKeyPrefix, prefix_len) == 0;
}

static bool protect_private_key_pem(const std::vector<uint8_t>& pem, std::vector<uint8_t>& out) {
    out.clear();
    if (pem.empty() || pem.size() > static_cast<size_t>((std::numeric_limits<DWORD>::max)()))
        return false;

    DATA_BLOB input_blob{
        static_cast<DWORD>(pem.size()),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(pem.data()))
    };
    DATA_BLOB entropy_blob{
        static_cast<DWORD>(sizeof(kPrivateKeyEntropy) - 1),
        reinterpret_cast<BYTE*>(const_cast<char*>(kPrivateKeyEntropy))
    };
    DATA_BLOB output_blob{};
    if (!CryptProtectData(&input_blob, L"AiDA Proxy Root CA Key", &entropy_blob,
                          nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output_blob)) {
        diag::log_tagged_fmt("cert", "protect_private_key_pem CryptProtectData failed gle=%lu", GetLastError());
        return false;
    }

    constexpr size_t prefix_len = sizeof(kProtectedKeyPrefix) - 1;
    out.assign(kProtectedKeyPrefix, kProtectedKeyPrefix + prefix_len);
    out.insert(out.end(), output_blob.pbData, output_blob.pbData + output_blob.cbData);
    SecureZeroMemory(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return true;
}

static bool unprotect_private_key_pem(const std::vector<uint8_t>& protected_bytes, std::vector<uint8_t>& pem) {
    pem.clear();
    constexpr size_t prefix_len = sizeof(kProtectedKeyPrefix) - 1;
    if (protected_bytes.size() <= prefix_len || !has_protected_key_prefix(protected_bytes))
        return false;

    const size_t cipher_len = protected_bytes.size() - prefix_len;
    if (cipher_len > static_cast<size_t>((std::numeric_limits<DWORD>::max)()))
        return false;

    DATA_BLOB input_blob{
        static_cast<DWORD>(cipher_len),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(protected_bytes.data() + prefix_len))
    };
    DATA_BLOB entropy_blob{
        static_cast<DWORD>(sizeof(kPrivateKeyEntropy) - 1),
        reinterpret_cast<BYTE*>(const_cast<char*>(kPrivateKeyEntropy))
    };
    DATA_BLOB output_blob{};
    if (!CryptUnprotectData(&input_blob, nullptr, &entropy_blob, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output_blob)) {
        diag::log_tagged_fmt("cert", "unprotect_private_key_pem CryptUnprotectData failed gle=%lu", GetLastError());
        return false;
    }

    pem.assign(output_blob.pbData, output_blob.pbData + output_blob.cbData);
    SecureZeroMemory(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return !pem.empty();
}

static bool write_protected_private_key_pem(const std::string& key_path, const std::vector<uint8_t>& pem) {
    std::vector<uint8_t> protected_bytes;
    if (!protect_private_key_pem(pem, protected_bytes))
        return false;
    bool ok = write_file_bytes(key_path, protected_bytes.data(), protected_bytes.size());
    secure_zero_bytes(protected_bytes);
    return ok;
}

static bool encode_private_key_pem(const root_ca_t& ca, std::vector<uint8_t>& out) {
    out.clear();
    if (!ca.valid || !ca.key)
        return false;

    BIO* kbio = BIO_new(BIO_s_mem());
    if (!kbio)
        return false;

    int wrote = PEM_write_bio_PrivateKey(kbio, ca.key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    diag::log_tagged_fmt("cert", "encode_private_key_pem PEM_write_bio_PrivateKey wrote=%d", wrote);
    if (!wrote) {
        BIO_free(kbio);
        return false;
    }

    BUF_MEM* km = nullptr;
    BIO_get_mem_ptr(kbio, &km);
    if (!km || km->length == 0) {
        BIO_free(kbio);
        return false;
    }

    out.assign(reinterpret_cast<const uint8_t*>(km->data),
               reinterpret_cast<const uint8_t*>(km->data) + km->length);
    SecureZeroMemory(km->data, km->length);
    BIO_free(kbio);
    return true;
}

static EVP_PKEY* read_private_key_from_pem(const std::vector<uint8_t>& pem) {
    if (pem.empty() || pem.size() > static_cast<size_t>(INT_MAX))
        return nullptr;
    BIO* kbio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!kbio)
        return nullptr;
    EVP_PKEY* raw_key = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
    BIO_free(kbio);
    return raw_key;
}

static X509* read_certificate_from_pem(const std::vector<uint8_t>& pem) {
    if (pem.empty() || pem.size() > static_cast<size_t>(INT_MAX))
        return nullptr;
    BIO* cbio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!cbio)
        return nullptr;
    X509* raw_cert = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
    BIO_free(cbio);
    return raw_cert;
}

static bool encode_x509_der(X509* cert, std::vector<uint8_t>& out) {
    out.clear();
    if (!cert)
        return false;
    int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0)
        return false;
    out.resize(static_cast<size_t>(der_len));
    uint8_t* p = out.data();
    int written = i2d_X509(cert, &p);
    if (written != der_len) {
        out.clear();
        return false;
    }
    return true;
}

static bool base64_encode_no_newlines(const uint8_t* data, size_t len, std::string& out) {
    out.clear();
    if (!data || len == 0 || len > static_cast<size_t>(INT_MAX))
        return false;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    if (!b64 || !bmem) {
        if (b64) BIO_free(b64);
        if (bmem) BIO_free(bmem);
        return false;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, bmem);
    int wrote = BIO_write(chain, data, static_cast<int>(len));
    if (wrote != static_cast<int>(len) || BIO_flush(chain) != 1) {
        BIO_free_all(chain);
        return false;
    }

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bmem, &bptr);
    if (!bptr || !bptr->data || bptr->length == 0) {
        BIO_free_all(chain);
        return false;
    }

    out.assign(bptr->data, bptr->length);
    BIO_free_all(chain);
    return true;
}

bool load_root_ca(const std::string& key_path, const std::string& cert_path, root_ca_t& ca) {
    diag::log_tagged_fmt("cert", "load_root_ca entry key_path=%s cert_path=%s", key_path.c_str(), cert_path.c_str());
    std::vector<uint8_t> key_bytes;
    if (!read_file_bytes(key_path, key_bytes) || key_bytes.empty()) {
        diag::log_tagged_fmt("cert", "load_root_ca read key file failed path=%s", key_path.c_str());
        return false;
    }
    diag::log_tagged_fmt("cert", "load_root_ca key file read size=%zu", key_bytes.size());

    bool key_protected = has_protected_key_prefix(key_bytes);
    std::vector<uint8_t> key_pem;
    if (key_protected) {
        if (!unprotect_private_key_pem(key_bytes, key_pem)) {
            diag::log_tagged("cert", "load_root_ca DPAPI private key unwrap failed");
            return false;
        }
        diag::log_tagged_fmt("cert", "load_root_ca DPAPI private key unwrapped pem_size=%zu", key_pem.size());
    } else {
        key_pem = key_bytes;
        diag::log_tagged("cert", "load_root_ca using legacy plaintext private key PEM");
    }

    evp_pkey_ptr parsed_key(read_private_key_from_pem(key_pem));
    diag::log_tagged_fmt("cert", "load_root_ca PEM_read_bio_PrivateKey raw_key=%p", parsed_key.get());
    if (!parsed_key) {
        secure_zero_bytes(key_pem);
        if (!key_protected)
            secure_zero_bytes(key_bytes);
        diag::log_tagged("cert", "load_root_ca PEM_read_bio_PrivateKey failed");
        return false;
    }

    std::vector<uint8_t> cert_bytes;
    if (!read_file_bytes(cert_path, cert_bytes) || cert_bytes.empty()) {
        diag::log_tagged_fmt("cert", "load_root_ca read cert file failed path=%s", cert_path.c_str());
        secure_zero_bytes(key_pem);
        if (!key_protected)
            secure_zero_bytes(key_bytes);
        return false;
    }
    diag::log_tagged_fmt("cert", "load_root_ca cert file read size=%zu", cert_bytes.size());

    x509_ptr parsed_cert(read_certificate_from_pem(cert_bytes));
    diag::log_tagged_fmt("cert", "load_root_ca PEM_read_bio_X509 raw_cert=%p", parsed_cert.get());
    if (!parsed_cert) {
        secure_zero_bytes(key_pem);
        if (!key_protected)
            secure_zero_bytes(key_bytes);
        diag::log_tagged("cert", "load_root_ca PEM_read_bio_X509 failed");
        return false;
    }

    if (X509_check_private_key(parsed_cert.get(), parsed_key.get()) != 1) {
        secure_zero_bytes(key_pem);
        if (!key_protected)
            secure_zero_bytes(key_bytes);
        diag::log_tagged("cert", "load_root_ca certificate/private key mismatch");
        return false;
    }

    if (!key_protected) {
        if (!write_protected_private_key_pem(key_path, key_pem)) {
            secure_zero_bytes(key_pem);
            secure_zero_bytes(key_bytes);
            diag::log_tagged("cert", "load_root_ca legacy private key migration failed");
            return false;
        }
        diag::log_tagged("cert", "load_root_ca legacy private key migrated to DPAPI storage");
        secure_zero_bytes(key_bytes);
    }

    ca.key = std::move(parsed_key);
    ca.cert = std::move(parsed_cert);

    ca.valid = true;
    secure_zero_bytes(key_pem);
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

    std::vector<uint8_t> key_pem;
    if (!encode_private_key_pem(ca, key_pem)) {
        diag::log_tagged("cert", "save_root_ca encode private key PEM failed");
        return false;
    }
    bool key_ok = write_protected_private_key_pem(key_path, key_pem);
    size_t key_len = key_pem.size();
    secure_zero_bytes(key_pem);
    if (!key_ok) {
        diag::log_tagged_fmt("cert", "save_root_ca write protected key file failed path=%s", key_path.c_str());
        return false;
    }
    diag::log_tagged_fmt("cert", "save_root_ca protected key file written pem_len=%zu path=%s", key_len, key_path.c_str());

    std::filesystem::path cp(std::filesystem::u8path(cert_path));
    if (cp.has_parent_path())
        std::filesystem::create_directories(cp.parent_path());

    BIO* cbio = BIO_new(BIO_s_mem());
    if (!cbio) {
        diag::log_tagged("cert", "save_root_ca BIO_new for cert failed");
        return false;
    }
    int wrote = PEM_write_bio_X509(cbio, ca.cert.get());
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

std::string spki_sha256_base64(const root_ca_t& ca) {
    diag::log_tagged_fmt("cert", "spki_sha256_base64 entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert)
        return {};

    const X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(ca.cert.get());
    if (!pubkey) {
        diag::log_tagged("cert", "spki_sha256_base64 X509_get_X509_PUBKEY failed");
        return {};
    }

    int der_len = i2d_X509_PUBKEY(pubkey, nullptr);
    diag::log_tagged_fmt("cert", "spki_sha256_base64 SPKI DER len=%d", der_len);
    if (der_len <= 0)
        return {};

    std::vector<uint8_t> der(static_cast<size_t>(der_len));
    uint8_t* p = der.data();
    int written = i2d_X509_PUBKEY(pubkey, &p);
    if (written != der_len) {
        diag::log_tagged_fmt("cert", "spki_sha256_base64 i2d_X509_PUBKEY written=%d expected=%d", written, der_len);
        return {};
    }

    uint8_t digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digest_len = 0;
    int rc = EVP_Digest(der.data(), der.size(), digest, &digest_len, EVP_sha256(), nullptr);
    if (rc != 1 || digest_len != 32) {
        diag::log_tagged_fmt("cert", "spki_sha256_base64 EVP_Digest failed rc=%d digest_len=%u", rc, digest_len);
        return {};
    }

    std::string encoded;
    if (!base64_encode_no_newlines(digest, digest_len, encoded)) {
        diag::log_tagged("cert", "spki_sha256_base64 base64 encode failed");
        return {};
    }
    diag::log_tagged_fmt("cert", "spki_sha256_base64 success len=%zu", encoded.size());
    return encoded;
}

bool export_ca_certificate_der(const root_ca_t& ca, std::vector<uint8_t>& out) {
    diag::log_tagged_fmt("cert", "export_ca_certificate_der entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert) {
        out.clear();
        return false;
    }
    bool ok = encode_x509_der(ca.cert.get(), out);
    diag::log_tagged_fmt("cert", "export_ca_certificate_der ok=%d len=%zu", (int)ok, out.size());
    return ok;
}

bool export_ca_certificate_pem(const root_ca_t& ca, std::string& out) {
    diag::log_tagged_fmt("cert", "export_ca_certificate_pem entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    out.clear();
    if (!ca.valid || !ca.cert)
        return false;

    BIO* cbio = BIO_new(BIO_s_mem());
    if (!cbio)
        return false;

    int wrote = PEM_write_bio_X509(cbio, ca.cert.get());
    diag::log_tagged_fmt("cert", "export_ca_certificate_pem PEM_write_bio_X509 wrote=%d", wrote);
    if (!wrote) {
        BIO_free(cbio);
        return false;
    }

    BUF_MEM* cm = nullptr;
    BIO_get_mem_ptr(cbio, &cm);
    if (!cm || !cm->data || cm->length == 0) {
        BIO_free(cbio);
        return false;
    }

    out.assign(cm->data, cm->length);
    BIO_free(cbio);
    diag::log_tagged_fmt("cert", "export_ca_certificate_pem success len=%zu", out.size());
    return true;
}


bool install_root_ca(const root_ca_t& ca) {
    const ULONGLONG t0 = GetTickCount64();
    diag::log_tagged_fmt("cert", "install_root_ca entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert) {
        diag::log_tagged("cert", "install_root_ca ca not valid or cert null");
        return false;
    }

    std::vector<uint8_t> der;
    if (!encode_x509_der(ca.cert.get(), der)) {
        diag::log_tagged("cert", "install_root_ca i2d_X509 failed");
        return false;
    }
    diag::log_tagged_fmt("cert", "install_root_ca DER encode len=%zu", der.size());

    DWORD op_gle = ERROR_SUCCESS;
    DWORD op_detail = 0;
    bool ok = run_cert_store_operation_bounded("install_root_ca",
        kCertStoreMutationTimeoutMs,
        [der]() -> cert_store_result_t {
            cert_store_result_t result;
            SetLastError(ERROR_SUCCESS);
            HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
            const DWORD open_gle = GetLastError();
            diag::log_tagged_fmt("cert", "install_root_ca CertOpenStore store=%p gle=%lu tid=%lu",
                store,
                static_cast<unsigned long>(open_gle),
                static_cast<unsigned long>(GetCurrentThreadId()));
            if (!store) {
                result.gle = open_gle;
                return result;
            }

            SetLastError(ERROR_SUCCESS);
            diag::log_tagged_fmt("cert", "install_root_ca CertAddEncodedCertificateToStore enter der_len=%zu tid=%lu",
                der.size(),
                static_cast<unsigned long>(GetCurrentThreadId()));
            BOOL add_ok = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                der.data(), static_cast<DWORD>(der.size()), CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
            const DWORD add_gle = GetLastError();
            diag::log_tagged_fmt("cert", "install_root_ca CertAddEncodedCertificateToStore exit ok=%d gle=%lu tid=%lu",
                static_cast<int>(add_ok),
                static_cast<unsigned long>(add_gle),
                static_cast<unsigned long>(GetCurrentThreadId()));
            SetLastError(ERROR_SUCCESS);
            const BOOL close_ok = CertCloseStore(store, 0);
            const DWORD close_gle = GetLastError();
            diag::log_tagged_fmt("cert", "install_root_ca CertCloseStore ok=%d gle=%lu tid=%lu",
                static_cast<int>(close_ok),
                static_cast<unsigned long>(close_gle),
                static_cast<unsigned long>(GetCurrentThreadId()));
            result.ok = add_ok != FALSE && close_ok != FALSE;
            result.gle = add_ok != FALSE ? close_gle : add_gle;
            result.detail = static_cast<DWORD>(der.size());
            return result;
        },
        &op_gle,
        &op_detail);
    diag::log_tagged_fmt("cert", "install_root_ca result=%d gle=%lu detail=%lu elapsed_ms=%llu",
        ok ? 1 : 0,
        static_cast<unsigned long>(op_gle),
        static_cast<unsigned long>(op_detail),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return ok;
}

bool remove_root_ca(const root_ca_t& ca) {
    const ULONGLONG t0 = GetTickCount64();
    diag::log_tagged_fmt("cert", "remove_root_ca entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert) {
        diag::log_tagged("cert", "remove_root_ca ca not valid or cert null");
        return false;
    }

    std::vector<uint8_t> der;
    if (!encode_x509_der(ca.cert.get(), der)) {
        diag::log_tagged("cert", "remove_root_ca i2d_X509 failed");
        return false;
    }
    diag::log_tagged_fmt("cert", "remove_root_ca DER encode len=%zu", der.size());

    DWORD op_gle = ERROR_SUCCESS;
    DWORD op_detail = 0;
    bool ok = run_cert_store_operation_bounded("remove_root_ca",
        kCertStoreMutationTimeoutMs,
        [der]() -> cert_store_result_t {
            cert_store_result_t result;
            SetLastError(ERROR_SUCCESS);
            HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
            const DWORD open_gle = GetLastError();
            diag::log_tagged_fmt("cert", "remove_root_ca CertOpenStore store=%p gle=%lu tid=%lu",
                store,
                static_cast<unsigned long>(open_gle),
                static_cast<unsigned long>(GetCurrentThreadId()));
            if (!store) {
                result.gle = open_gle;
                return result;
            }

            CERT_BLOB blob;
            blob.cbData = static_cast<DWORD>(der.size());
            blob.pbData = const_cast<BYTE*>(der.data());

            bool deleted = false;
            DWORD enumerated = 0;
            PCCERT_CONTEXT found = nullptr;
            while ((found = CertEnumCertificatesInStore(store, found)) != nullptr) {
                ++enumerated;
                if (found->cbCertEncoded == blob.cbData &&
                    memcmp(found->pbCertEncoded, blob.pbData, blob.cbData) == 0) {
                    diag::log_tagged_fmt("cert", "remove_root_ca found matching cert enumerated=%lu tid=%lu",
                        static_cast<unsigned long>(enumerated),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                    SetLastError(ERROR_SUCCESS);
                    PCCERT_CONTEXT duplicate = CertDuplicateCertificateContext(found);
                    const BOOL delete_ok = duplicate ? CertDeleteCertificateFromStore(duplicate) : FALSE;
                    const DWORD delete_gle = duplicate ? GetLastError() : ERROR_INVALID_HANDLE;
                    diag::log_tagged_fmt("cert", "remove_root_ca CertDeleteCertificateFromStore ok=%d gle=%lu tid=%lu",
                        static_cast<int>(delete_ok),
                        static_cast<unsigned long>(delete_gle),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                    CertFreeCertificateContext(found);
                    deleted = delete_ok != FALSE;
                    result.gle = delete_gle;
                    break;
                }
            }
            SetLastError(ERROR_SUCCESS);
            const BOOL close_ok = CertCloseStore(store, 0);
            const DWORD close_gle = GetLastError();
            diag::log_tagged_fmt("cert", "remove_root_ca CertCloseStore ok=%d gle=%lu deleted=%d enumerated=%lu tid=%lu",
                static_cast<int>(close_ok),
                static_cast<unsigned long>(close_gle),
                deleted ? 1 : 0,
                static_cast<unsigned long>(enumerated),
                static_cast<unsigned long>(GetCurrentThreadId()));
            result.ok = close_ok != FALSE;
            if (result.gle == ERROR_SUCCESS)
                result.gle = close_gle;
            result.detail = enumerated;
            return result;
        },
        &op_gle,
        &op_detail);
    diag::log_tagged_fmt("cert", "remove_root_ca result=%d gle=%lu enumerated=%lu elapsed_ms=%llu",
        ok ? 1 : 0,
        static_cast<unsigned long>(op_gle),
        static_cast<unsigned long>(op_detail),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return ok;
}

bool is_root_ca_installed(const root_ca_t& ca) {
    const ULONGLONG t0 = GetTickCount64();
    diag::log_tagged_fmt("cert", "is_root_ca_installed entry ca_valid=%d ca_cert=%p", (int)ca.valid, ca.cert.get());
    if (!ca.valid || !ca.cert) {
        diag::log_tagged("cert", "is_root_ca_installed ca not valid or cert null returning false");
        return false;
    }

    std::vector<uint8_t> der;
    if (!encode_x509_der(ca.cert.get(), der)) {
        diag::log_tagged("cert", "is_root_ca_installed i2d_X509 failed");
        return false;
    }
    diag::log_tagged_fmt("cert", "is_root_ca_installed DER encode len=%zu", der.size());

    DWORD op_gle = ERROR_SUCCESS;
    DWORD op_detail = 0;
    bool found_it = run_cert_store_operation_bounded("is_root_ca_installed",
        kCertStoreQueryTimeoutMs,
        [der]() -> cert_store_result_t {
            cert_store_result_t result;
            SetLastError(ERROR_SUCCESS);
            HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
            const DWORD open_gle = GetLastError();
            diag::log_tagged_fmt("cert", "is_root_ca_installed CertOpenStore store=%p gle=%lu tid=%lu",
                store,
                static_cast<unsigned long>(open_gle),
                static_cast<unsigned long>(GetCurrentThreadId()));
            if (!store) {
                result.gle = open_gle;
                return result;
            }

            bool found_match = false;
            DWORD enumerated = 0;
            PCCERT_CONTEXT found = nullptr;
            while ((found = CertEnumCertificatesInStore(store, found)) != nullptr) {
                ++enumerated;
                if (found->cbCertEncoded == static_cast<DWORD>(der.size()) &&
                    memcmp(found->pbCertEncoded, der.data(), der.size()) == 0) {
                    found_match = true;
                    CertFreeCertificateContext(found);
                    break;
                }
            }
            SetLastError(ERROR_SUCCESS);
            const BOOL close_ok = CertCloseStore(store, 0);
            const DWORD close_gle = GetLastError();
            diag::log_tagged_fmt("cert", "is_root_ca_installed CertCloseStore ok=%d gle=%lu found=%d enumerated=%lu tid=%lu",
                static_cast<int>(close_ok),
                static_cast<unsigned long>(close_gle),
                found_match ? 1 : 0,
                static_cast<unsigned long>(enumerated),
                static_cast<unsigned long>(GetCurrentThreadId()));
            result.ok = found_match && close_ok != FALSE;
            result.gle = close_gle;
            result.detail = enumerated;
            return result;
        },
        &op_gle,
        &op_detail);
    diag::log_tagged_fmt("cert", "is_root_ca_installed result=%d gle=%lu enumerated=%lu elapsed_ms=%llu",
        found_it ? 1 : 0,
        static_cast<unsigned long>(op_gle),
        static_cast<unsigned long>(op_detail),
        static_cast<unsigned long long>(GetTickCount64() - t0));
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
    if (!save_ok) {
        diag::log_tagged("cert", "initialize save_root_ca failed");
        g_root_ca = root_ca_t{};
        return false;
    }

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
