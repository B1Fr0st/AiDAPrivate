#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <bcrypt.h>
#include <intrin.h>
#include <nmmintrin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace binary_protocol {

constexpr uint32_t BINARY_REQUEST_MAGIC  = 0x41494442u;
constexpr uint32_t BINARY_RESPONSE_MAGIC = 0x42494441u;
constexpr uint16_t BINARY_PROTOCOL_VERSION = 0x0001u;

constexpr uint16_t BINARY_OP_PAGE_FETCH  = 1u;
constexpr uint16_t BINARY_OP_PAGE_COUNT  = 2u;
constexpr uint16_t BINARY_OP_HEARTBEAT   = 3u;

constexpr uint16_t BINARY_STATUS_OK            = 0u;
constexpr uint16_t BINARY_STATUS_AUTH_FAIL     = 1u;
constexpr uint16_t BINARY_STATUS_SERVER_ERROR  = 2u;
constexpr uint16_t BINARY_STATUS_BAD_REQUEST   = 3u;
constexpr uint16_t BINARY_STATUS_NOT_FOUND     = 4u;
constexpr uint16_t BINARY_STATUS_RATE_LIMITED  = 5u;
constexpr uint16_t BINARY_STATUS_PIN_FAIL      = 6u;

#pragma pack(push, 1)
struct binary_request_header_t
{
    uint32_t magic;
    uint16_t version;
    uint16_t op;
    uint64_t session_nonce;
    uint32_t payload_len;
    uint32_t crc32c;
};

struct binary_response_header_t
{
    uint32_t magic;
    uint16_t version;
    uint16_t status;
    uint64_t session_nonce_echo;
    uint32_t payload_len;
    uint32_t crc32c;
};
#pragma pack(pop)

namespace detail {

inline std::mutex& state_mtx()
{
    static std::mutex m;
    return m;
}

inline std::array<uint8_t, 32>& pinned_spki_primary()
{
    static std::array<uint8_t, 32> p{};
    return p;
}

inline std::array<uint8_t, 32>& pinned_spki_secondary()
{
    static std::array<uint8_t, 32> p{};
    return p;
}

inline std::atomic<bool>& pin_primary_set()
{
    static std::atomic<bool> a{false};
    return a;
}

inline std::atomic<bool>& pin_secondary_set()
{
    static std::atomic<bool> a{false};
    return a;
}

inline std::atomic<bool>& allow_self_signed_for_test()
{
    static std::atomic<bool> a{false};
    return a;
}

inline std::string& last_error_storage()
{
    static std::string s;
    return s;
}

inline void set_last_error(const std::string& err)
{
    std::lock_guard<std::mutex> lk(state_mtx());
    last_error_storage() = err;
}

inline int ensure_winsock()
{
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    static int wsa_rc = WSASYSNOTREADY;
    BOOL pending = FALSE;
    InitOnceBeginInitialize(&once, 0, &pending, nullptr);
    if (pending)
    {
        WSADATA wsa{};
        wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
        InitOnceComplete(&once, 0, nullptr);
    }
    return wsa_rc;
}

inline void ensure_openssl_init()
{
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    BOOL pending = FALSE;
    InitOnceBeginInitialize(&once, 0, &pending, nullptr);
    if (pending)
    {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
        InitOnceComplete(&once, 0, nullptr);
    }
}

inline uint32_t crc32c_compute(const uint8_t* data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i = 0;
    while (i + 8 <= len)
    {
        uint64_t v;
        std::memcpy(&v, data + i, 8);
        crc = static_cast<uint32_t>(_mm_crc32_u64(crc, v));
        i += 8;
    }
    while (i + 4 <= len)
    {
        uint32_t v;
        std::memcpy(&v, data + i, 4);
        crc = _mm_crc32_u32(crc, v);
        i += 4;
    }
    while (i < len)
    {
        crc = _mm_crc32_u8(crc, data[i]);
        ++i;
    }
    return crc ^ 0xFFFFFFFFu;
}

inline uint64_t siphash24_keyed(const uint8_t* in, size_t inlen, const uint8_t k[16])
{
    uint64_t k0, k1;
    std::memcpy(&k0, k, 8);
    std::memcpy(&k1, k + 8, 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    auto sip_round = [&]() {
        v0 += v1; v1 = _rotl64(v1, 13); v1 ^= v0; v0 = _rotl64(v0, 32);
        v2 += v3; v3 = _rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = _rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = _rotl64(v1, 17); v1 ^= v2; v2 = _rotl64(v2, 32);
    };

    const size_t blocks = inlen / 8;
    for (size_t i = 0; i < blocks; ++i)
    {
        uint64_t m;
        std::memcpy(&m, in + i * 8, 8);
        v3 ^= m;
        sip_round();
        sip_round();
        v0 ^= m;
    }
    uint64_t b = static_cast<uint64_t>(inlen) << 56;
    const uint8_t* tail = in + blocks * 8;
    const size_t left = inlen & 7;
    for (size_t i = 0; i < left; ++i)
        b |= static_cast<uint64_t>(tail[i]) << (i * 8);
    v3 ^= b;
    sip_round();
    sip_round();
    v0 ^= b;
    v2 ^= 0xFF;
    sip_round();
    sip_round();
    sip_round();
    sip_round();
    return v0 ^ v1 ^ v2 ^ v3;
}

inline bool hkdf_sha256_expand(const uint8_t* ikm, size_t ikm_len,
                               const uint8_t* salt, size_t salt_len,
                               const uint8_t* info, size_t info_len,
                               uint8_t* out, size_t out_len)
{
    uint8_t prk[32] = {};
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), salt, static_cast<int>(salt_len),
              ikm, ikm_len, prk, &prk_len) || prk_len != 32)
        return false;

    uint8_t t_block[32] = {};
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < out_len)
    {
        std::vector<uint8_t> input;
        input.reserve(32 + info_len + 1);
        if (counter > 1)
            input.insert(input.end(), t_block, t_block + 32);
        if (info_len > 0)
            input.insert(input.end(), info, info + info_len);
        input.push_back(counter);

        unsigned int t_len = 32;
        if (!HMAC(EVP_sha256(), prk, 32, input.data(), input.size(),
                  t_block, &t_len) || t_len != 32)
        {
            SecureZeroMemory(prk, sizeof(prk));
            SecureZeroMemory(t_block, sizeof(t_block));
            return false;
        }
        size_t copy_len = (out_len - produced) > 32 ? 32 : (out_len - produced);
        std::memcpy(out + produced, t_block, copy_len);
        produced += copy_len;
        ++counter;
    }
    SecureZeroMemory(prk, sizeof(prk));
    SecureZeroMemory(t_block, sizeof(t_block));
    return true;
}

inline bool derive_protocol_key(const std::string& session_token,
                                const std::string& hwid,
                                uint8_t out_key[32])
{
    std::vector<uint8_t> ikm;
    ikm.reserve(session_token.size() + hwid.size());
    ikm.insert(ikm.end(), session_token.begin(), session_token.end());
    ikm.insert(ikm.end(), hwid.begin(), hwid.end());

    static const uint8_t info_str[] = "binary-proto-v1";
    static const uint8_t salt[] = {
        0x41, 0x49, 0x44, 0x42, 0x2D, 0x53, 0x41, 0x4C,
        0x54, 0x2D, 0x76, 0x31, 0x2D, 0x32, 0x30, 0x32
    };

    bool ok = hkdf_sha256_expand(ikm.data(), ikm.size(),
                                 salt, sizeof(salt),
                                 info_str, sizeof(info_str) - 1,
                                 out_key, 32);
    if (!ikm.empty())
        SecureZeroMemory(ikm.data(), ikm.size());
    return ok;
}

inline bool chacha20_poly1305_encrypt(const uint8_t key[32],
                                      const uint8_t nonce[12],
                                      const uint8_t* aad, size_t aad_len,
                                      const uint8_t* plaintext, size_t plaintext_len,
                                      std::vector<uint8_t>& ciphertext_out,
                                      uint8_t tag_out[16])
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        int outlen = 0;
        if (aad_len > 0)
        {
            if (EVP_EncryptUpdate(ctx, nullptr, &outlen, aad, static_cast<int>(aad_len)) != 1) break;
        }
        ciphertext_out.resize(plaintext_len);
        if (plaintext_len > 0)
        {
            if (EVP_EncryptUpdate(ctx, ciphertext_out.data(), &outlen,
                                  plaintext, static_cast<int>(plaintext_len)) != 1) break;
        }
        int finlen = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext_out.data() + outlen, &finlen) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_out) != 1) break;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

inline bool chacha20_poly1305_decrypt(const uint8_t key[32],
                                      const uint8_t nonce[12],
                                      const uint8_t* aad, size_t aad_len,
                                      const uint8_t* ciphertext, size_t ciphertext_len,
                                      const uint8_t tag[16],
                                      std::vector<uint8_t>& plaintext_out)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        int outlen = 0;
        if (aad_len > 0)
        {
            if (EVP_DecryptUpdate(ctx, nullptr, &outlen, aad, static_cast<int>(aad_len)) != 1) break;
        }
        plaintext_out.resize(ciphertext_len);
        if (ciphertext_len > 0)
        {
            if (EVP_DecryptUpdate(ctx, plaintext_out.data(), &outlen,
                                  ciphertext, static_cast<int>(ciphertext_len)) != 1) break;
        }
        int finlen = 0;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                const_cast<uint8_t*>(tag)) != 1) break;
        if (EVP_DecryptFinal_ex(ctx, plaintext_out.data() + outlen, &finlen) != 1)
        {
            plaintext_out.clear();
            break;
        }
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

inline uint64_t make_session_nonce(const std::string& session_token)
{
    uint8_t k[16] = {};
    if (!session_token.empty())
    {
        size_t copy = session_token.size() < sizeof(k) ? session_token.size() : sizeof(k);
        std::memcpy(k, session_token.data(), copy);
    }
    uint64_t ts = static_cast<uint64_t>(__rdtsc());
    uint8_t buf[24] = {};
    std::memcpy(buf, &ts, 8);
    if (!session_token.empty())
    {
        size_t copy = session_token.size() < 16 ? session_token.size() : 16;
        std::memcpy(buf + 8, session_token.data(), copy);
    }
    return siphash24_keyed(buf, sizeof(buf), k);
}

inline void nonce_to_chacha_iv(uint64_t session_nonce, uint8_t out[12])
{
    std::memset(out, 0, 12);
    std::memcpy(out, &session_nonce, 8);
    out[8] = 0xA1;
    out[9] = 0xDA;
    out[10] = 0xC0;
    out[11] = 0xDE;
}

inline bool spki_hash_from_x509(X509* cert, uint8_t out_hash[32])
{
    if (!cert) return false;
    int der_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), nullptr);
    if (der_len <= 0) return false;
    std::vector<uint8_t> der(static_cast<size_t>(der_len));
    uint8_t* p = der.data();
    int written = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &p);
    if (written != der_len) return false;
    unsigned int hash_len = 0;
    int rc = EVP_Digest(der.data(), der.size(), out_hash, &hash_len, EVP_sha256(), nullptr);
    return rc == 1 && hash_len == 32;
}

struct connect_target_t
{
    int family = AF_INET;
    sockaddr_storage sa = {};
    int sa_len = 0;
};

inline bool resolve_addr_simple(const std::string& host, int port,
                                std::vector<connect_target_t>& out)
{
    char port_str[8] = {};
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%d", port);
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str, &hints, &res);
    if (rc != 0 || !res) return false;
    for (addrinfo* ai = res; ai; ai = ai->ai_next)
    {
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) continue;
        if (!ai->ai_addr || ai->ai_addrlen == 0) continue;
        if (ai->ai_addrlen > sizeof(sockaddr_storage)) continue;
        connect_target_t t{};
        t.family = ai->ai_family;
        t.sa_len = static_cast<int>(ai->ai_addrlen);
        std::memcpy(&t.sa, ai->ai_addr, ai->ai_addrlen);
        out.push_back(t);
    }
    freeaddrinfo(res);
    std::stable_sort(out.begin(), out.end(),
                     [](const connect_target_t& a, const connect_target_t& b) {
                         return (a.family == AF_INET) && (b.family != AF_INET);
                     });
    return !out.empty();
}

inline int poll_socket_event(SOCKET s, short events, int wait_ms)
{
    if (wait_ms < 0) wait_ms = 0;
    WSAPOLLFD pfd = {};
    pfd.fd = s;
    pfd.events = events;
    return WSAPoll(&pfd, 1, wait_ms);
}

struct tls_session_t
{
    SOCKET sock = INVALID_SOCKET;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    ~tls_session_t() { teardown(); }
    void teardown()
    {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = nullptr; }
        if (ctx) { SSL_CTX_free(ctx); ctx = nullptr; }
        if (sock != INVALID_SOCKET) { closesocket(sock); sock = INVALID_SOCKET; }
    }
};

inline bool tls_send_all(tls_session_t& sess, const uint8_t* data, size_t len, int deadline_ms_remaining_fn)
{
    while (len > 0)
    {
        int n = SSL_write(sess.ssl, data, static_cast<int>(len));
        if (n > 0)
        {
            data += n;
            len -= static_cast<size_t>(n);
            continue;
        }
        int err = SSL_get_error(sess.ssl, n);
        short events = POLLOUT;
        if (err == SSL_ERROR_WANT_READ) events = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) events = POLLOUT;
        else return false;
        int p = poll_socket_event(sess.sock, events, deadline_ms_remaining_fn);
        if (p <= 0) return false;
    }
    return true;
}

inline bool tls_recv_exact(tls_session_t& sess, uint8_t* out, size_t need, int deadline_ms_remaining_fn)
{
    size_t total = 0;
    while (total < need)
    {
        int n = SSL_read(sess.ssl, out + total, static_cast<int>(need - total));
        if (n > 0)
        {
            total += static_cast<size_t>(n);
            continue;
        }
        if (n == 0) return false;
        int err = SSL_get_error(sess.ssl, n);
        short events = POLLIN;
        if (err == SSL_ERROR_WANT_READ) events = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) events = POLLOUT;
        else if (err == SSL_ERROR_ZERO_RETURN) return false;
        else return false;
        int p = poll_socket_event(sess.sock, events, deadline_ms_remaining_fn);
        if (p <= 0) return false;
    }
    return true;
}

inline bool establish_tls(const std::string& host, int port, int timeout_sec,
                          tls_session_t& sess, std::string& err_out)
{
    if (ensure_winsock() != 0)
    {
        err_out = "winsock_init_failed";
        return false;
    }
    ensure_openssl_init();

    std::vector<connect_target_t> addrs;
    if (!resolve_addr_simple(host, port, addrs))
    {
        err_out = "dns_failed";
        return false;
    }

    auto request_start = std::chrono::steady_clock::now();
    auto request_deadline = request_start + std::chrono::seconds(timeout_sec);
    auto remaining_ms = [&]() -> int {
        auto now = std::chrono::steady_clock::now();
        if (now >= request_deadline) return 0;
        return static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(request_deadline - now).count());
    };

    SOCKET sock = INVALID_SOCKET;
    std::string connect_errors;
    for (const auto& addr : addrs)
    {
        if (remaining_ms() <= 0)
        {
            connect_errors += "deadline_pre_connect;";
            break;
        }
        sock = socket(addr.family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            connect_errors += "socket_fail_" + std::to_string(WSAGetLastError()) + ";";
            continue;
        }
        u_long nb = 1;
        ioctlsocket(sock, FIONBIO, &nb);
        int conn_rc = ::connect(sock, reinterpret_cast<const sockaddr*>(&addr.sa), addr.sa_len);
        if (conn_rc == SOCKET_ERROR)
        {
            int wsa = WSAGetLastError();
            if (wsa != WSAEWOULDBLOCK)
            {
                connect_errors += "connect_immediate_" + std::to_string(wsa) + ";";
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            int p = poll_socket_event(sock, POLLOUT, remaining_ms());
            if (p <= 0)
            {
                connect_errors += "connect_timeout;";
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            int so_err = 0;
            int so_len = static_cast<int>(sizeof(so_err));
            getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_len);
            if (so_err != 0)
            {
                connect_errors += "connect_so_err_" + std::to_string(so_err) + ";";
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
        }
        break;
    }

    if (sock == INVALID_SOCKET)
    {
        err_out = "connect_failed:" + connect_errors;
        return false;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        closesocket(sock);
        err_out = "ssl_ctx_new_failed";
        return false;
    }
    SSL_CTX_set_keylog_callback(ctx, nullptr);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    SSL* ssl = SSL_new(ctx);
    if (!ssl)
    {
        SSL_CTX_free(ctx);
        closesocket(sock);
        err_out = "ssl_new_failed";
        return false;
    }
    SSL_set_fd(ssl, static_cast<int>(sock));
    SSL_set_tlsext_host_name(ssl, host.c_str());

    for (;;)
    {
        int rc = SSL_connect(ssl);
        if (rc == 1) break;
        int err = SSL_get_error(ssl, rc);
        short events = 0;
        if (err == SSL_ERROR_WANT_READ) events = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) events = POLLOUT;
        else
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            closesocket(sock);
            err_out = "ssl_connect_failed_" + std::to_string(err);
            return false;
        }
        int p = poll_socket_event(sock, events, remaining_ms());
        if (p <= 0)
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            closesocket(sock);
            err_out = "ssl_connect_timeout";
            return false;
        }
    }

    sess.sock = sock;
    sess.ctx = ctx;
    sess.ssl = ssl;
    return true;
}

inline bool verify_pinned_spki(SSL* ssl, std::string& err_out)
{
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (!cert)
    {
        err_out = "no_peer_cert";
        return false;
    }
    uint8_t computed[32] = {};
    bool got = spki_hash_from_x509(cert, computed);
    X509_free(cert);
    if (!got)
    {
        err_out = "spki_extract_failed";
        return false;
    }

    if (allow_self_signed_for_test().load())
        return true;

    bool primary_ok = pin_primary_set().load();
    bool secondary_ok = pin_secondary_set().load();
    if (!primary_ok && !secondary_ok)
    {
        err_out = "no_pin_configured";
        return false;
    }

    auto safe_eq = [](const uint8_t a[32], const uint8_t b[32]) -> bool {
        unsigned char acc = 0;
        for (int i = 0; i < 32; ++i) acc |= static_cast<unsigned char>(a[i] ^ b[i]);
        return acc == 0;
    };

    if (primary_ok && safe_eq(computed, pinned_spki_primary().data()))
        return true;
    if (secondary_ok && safe_eq(computed, pinned_spki_secondary().data()))
        return true;

    err_out = "spki_pin_mismatch";
    return false;
}

}

inline const char* last_error()
{
    std::lock_guard<std::mutex> lk(detail::state_mtx());
    return detail::last_error_storage().c_str();
}

inline bool set_pinned_spki_sha256(const uint8_t pin[32])
{
    if (!pin) return false;
    std::lock_guard<std::mutex> lk(detail::state_mtx());
    std::memcpy(detail::pinned_spki_primary().data(), pin, 32);
    detail::pin_primary_set().store(true);
    return true;
}

inline bool set_secondary_spki_sha256(const uint8_t pin[32])
{
    if (!pin) return false;
    std::lock_guard<std::mutex> lk(detail::state_mtx());
    std::memcpy(detail::pinned_spki_secondary().data(), pin, 32);
    detail::pin_secondary_set().store(true);
    return true;
}

inline void clear_pinned_spki()
{
    std::lock_guard<std::mutex> lk(detail::state_mtx());
    detail::pin_primary_set().store(false);
    detail::pin_secondary_set().store(false);
    detail::pinned_spki_primary().fill(0);
    detail::pinned_spki_secondary().fill(0);
}

inline void set_allow_self_signed_for_test(bool allow)
{
    detail::allow_self_signed_for_test().store(allow);
}

inline bool neutralize_keylog_env()
{
    BOOL r1 = SetEnvironmentVariableW(L"SSLKEYLOGFILE", nullptr);
    BOOL r2 = SetEnvironmentVariableA("SSLKEYLOGFILE", nullptr);

    wchar_t test_buf_w[8] = {};
    DWORD got_w = GetEnvironmentVariableW(L"SSLKEYLOGFILE", test_buf_w, 8);
    char test_buf_a[8] = {};
    DWORD got_a = GetEnvironmentVariableA("SSLKEYLOGFILE", test_buf_a, 8);

    bool ok = (r1 != 0 || r2 != 0) && got_w == 0 && got_a == 0;
    if (!ok)
    {
        detail::set_last_error("keylog_neutralize_failed");
        return false;
    }
    return true;
}

inline bool pack_request_body(const std::string& license_key,
                              const std::string& session_token,
                              const std::string& hwid,
                              const std::string& proof_token,
                              uint16_t op,
                              uint32_t page_index,
                              uint64_t issued_at,
                              std::vector<uint8_t>& out_body)
{
    if (license_key.size() > 0x10000) return false;
    if (session_token.size() > 0x10000) return false;
    if (hwid.size() > 0x10000) return false;
    if (proof_token.size() > 0x10000) return false;

    out_body.clear();

    auto put_u32 = [&](uint32_t v) {
        uint8_t b[4];
        std::memcpy(b, &v, 4);
        out_body.insert(out_body.end(), b, b + 4);
    };
    auto put_u64 = [&](uint64_t v) {
        uint8_t b[8];
        std::memcpy(b, &v, 8);
        out_body.insert(out_body.end(), b, b + 8);
    };
    auto put_str = [&](const std::string& s) {
        put_u32(static_cast<uint32_t>(s.size()));
        out_body.insert(out_body.end(), s.begin(), s.end());
    };

    put_str(license_key);
    put_str(session_token);
    put_str(hwid);
    put_str(proof_token);

    if (op == BINARY_OP_PAGE_FETCH)
    {
        put_u32(page_index);
        put_u64(issued_at);
    }
    return true;
}

inline bool send_request(uint16_t op,
                         const std::string& license_key,
                         const std::string& session_token,
                         const std::string& hwid,
                         const std::string& proof_token,
                         uint32_t page_index,
                         uint64_t issued_at,
                         const std::string& host,
                         int port,
                         const std::string& path,
                         int timeout_sec,
                         std::vector<uint8_t>& response_payload_out,
                         uint16_t& status_out)
{
    response_payload_out.clear();
    status_out = BINARY_STATUS_SERVER_ERROR;

    std::vector<uint8_t> raw_body;
    if (!pack_request_body(license_key, session_token, hwid, proof_token,
                           op, page_index, issued_at, raw_body))
    {
        detail::set_last_error("pack_request_failed");
        return false;
    }

    uint8_t key[32] = {};
    if (!detail::derive_protocol_key(session_token, hwid, key))
    {
        detail::set_last_error("derive_key_failed");
        return false;
    }

    uint64_t session_nonce = detail::make_session_nonce(session_token);
    uint8_t chacha_iv[12];
    detail::nonce_to_chacha_iv(session_nonce, chacha_iv);

    binary_request_header_t aad = {};
    aad.magic = BINARY_REQUEST_MAGIC;
    aad.version = BINARY_PROTOCOL_VERSION;
    aad.op = op;
    aad.session_nonce = session_nonce;
    aad.payload_len = 0;
    aad.crc32c = 0;

    std::vector<uint8_t> ciphertext;
    uint8_t tag[16] = {};
    bool enc_ok = detail::chacha20_poly1305_encrypt(
        key, chacha_iv,
        reinterpret_cast<const uint8_t*>(&aad), sizeof(aad) - 8,
        raw_body.data(), raw_body.size(),
        ciphertext, tag);

    SecureZeroMemory(key, sizeof(key));
    if (!raw_body.empty())
        SecureZeroMemory(raw_body.data(), raw_body.size());

    if (!enc_ok)
    {
        detail::set_last_error("encrypt_failed");
        return false;
    }

    std::vector<uint8_t> wire_payload;
    wire_payload.reserve(ciphertext.size() + 16);
    wire_payload.insert(wire_payload.end(), ciphertext.begin(), ciphertext.end());
    wire_payload.insert(wire_payload.end(), tag, tag + 16);

    binary_request_header_t hdr = {};
    hdr.magic = BINARY_REQUEST_MAGIC;
    hdr.version = BINARY_PROTOCOL_VERSION;
    hdr.op = op;
    hdr.session_nonce = session_nonce;
    hdr.payload_len = static_cast<uint32_t>(wire_payload.size());
    hdr.crc32c = 0;

    {
        std::vector<uint8_t> crc_buf;
        crc_buf.reserve(sizeof(hdr) - 4 + wire_payload.size());
        crc_buf.insert(crc_buf.end(),
                       reinterpret_cast<const uint8_t*>(&hdr),
                       reinterpret_cast<const uint8_t*>(&hdr) + sizeof(hdr) - 4);
        crc_buf.insert(crc_buf.end(), wire_payload.begin(), wire_payload.end());
        hdr.crc32c = detail::crc32c_compute(crc_buf.data(), crc_buf.size());
    }

    detail::tls_session_t sess;
    std::string tls_err;
    if (!detail::establish_tls(host, port, timeout_sec, sess, tls_err))
    {
        detail::set_last_error(tls_err);
        return false;
    }

    std::string pin_err;
    if (!detail::verify_pinned_spki(sess.ssl, pin_err))
    {
        detail::set_last_error(pin_err);
        return false;
    }

    auto request_start = std::chrono::steady_clock::now();
    auto request_deadline = request_start + std::chrono::seconds(timeout_sec);
    auto remaining_ms = [&]() -> int {
        auto now = std::chrono::steady_clock::now();
        if (now >= request_deadline) return 0;
        return static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(request_deadline - now).count());
    };

    std::string http_req;
    http_req.reserve(256 + wire_payload.size() + sizeof(hdr));
    http_req += "POST ";
    http_req += path;
    http_req += " HTTP/1.1\r\nHost: ";
    http_req += host;
    if (port != 443)
    {
        http_req += ":";
        http_req += std::to_string(port);
    }
    http_req += "\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: ";
    http_req += std::to_string(sizeof(hdr) + wire_payload.size());
    http_req += "\r\nX-AIDB-Magic: 1\r\n\r\n";

    std::vector<uint8_t> request_buf;
    request_buf.reserve(http_req.size() + sizeof(hdr) + wire_payload.size());
    request_buf.insert(request_buf.end(), http_req.begin(), http_req.end());
    request_buf.insert(request_buf.end(),
                       reinterpret_cast<const uint8_t*>(&hdr),
                       reinterpret_cast<const uint8_t*>(&hdr) + sizeof(hdr));
    request_buf.insert(request_buf.end(), wire_payload.begin(), wire_payload.end());

    int rem = remaining_ms();
    if (!detail::tls_send_all(sess, request_buf.data(), request_buf.size(), rem))
    {
        detail::set_last_error("send_failed");
        return false;
    }

    std::vector<uint8_t> raw_resp;
    raw_resp.reserve(8192);
    uint8_t recv_buf[4096];
    for (;;)
    {
        int n = SSL_read(sess.ssl, recv_buf, sizeof(recv_buf));
        if (n > 0)
        {
            raw_resp.insert(raw_resp.end(), recv_buf, recv_buf + n);
            if (raw_resp.size() > 16 * 1024 * 1024) break;
            continue;
        }
        if (n == 0) break;
        int err = SSL_get_error(sess.ssl, n);
        short events = POLLIN;
        if (err == SSL_ERROR_WANT_READ) events = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) events = POLLOUT;
        else if (err == SSL_ERROR_ZERO_RETURN) break;
        else break;
        int p = detail::poll_socket_event(sess.sock, events, remaining_ms());
        if (p <= 0) break;
    }

    sess.teardown();

    auto crlf2 = std::search(raw_resp.begin(), raw_resp.end(),
                             std::begin("\r\n\r\n"), std::end("\r\n\r\n") - 1);
    if (crlf2 == raw_resp.end())
    {
        detail::set_last_error("no_http_header");
        return false;
    }
    size_t header_len = static_cast<size_t>(crlf2 - raw_resp.begin()) + 4;

    std::string headers(reinterpret_cast<const char*>(raw_resp.data()), header_len - 4);
    int http_status = 0;
    {
        auto first_line_end = headers.find("\r\n");
        std::string status_line = headers.substr(0, first_line_end);
        auto sp1 = status_line.find(' ');
        if (sp1 != std::string::npos)
            http_status = atoi(status_line.c_str() + sp1 + 1);
    }

    bool chunked = false;
    {
        std::string lower = headers;
        for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        if (lower.find("transfer-encoding: chunked") != std::string::npos) chunked = true;
    }

    std::vector<uint8_t> body_bytes;
    if (header_len < raw_resp.size())
    {
        if (chunked)
        {
            size_t pos = header_len;
            while (pos < raw_resp.size())
            {
                size_t crlf = pos;
                while (crlf + 1 < raw_resp.size() &&
                       !(raw_resp[crlf] == '\r' && raw_resp[crlf + 1] == '\n'))
                    ++crlf;
                if (crlf + 1 >= raw_resp.size()) break;
                std::string sz_str(reinterpret_cast<const char*>(raw_resp.data() + pos), crlf - pos);
                long chunk_size = strtol(sz_str.c_str(), nullptr, 16);
                if (chunk_size <= 0) break;
                pos = crlf + 2;
                if (pos + static_cast<size_t>(chunk_size) > raw_resp.size()) break;
                body_bytes.insert(body_bytes.end(),
                                  raw_resp.begin() + pos,
                                  raw_resp.begin() + pos + chunk_size);
                pos += static_cast<size_t>(chunk_size) + 2;
            }
        }
        else
        {
            body_bytes.assign(raw_resp.begin() + header_len, raw_resp.end());
        }
    }

    if (http_status < 200 || http_status >= 600)
    {
        detail::set_last_error("http_status_" + std::to_string(http_status));
        return false;
    }

    if (body_bytes.size() < sizeof(binary_response_header_t) + 16)
    {
        detail::set_last_error("response_too_short");
        return false;
    }

    binary_response_header_t resp_hdr = {};
    std::memcpy(&resp_hdr, body_bytes.data(), sizeof(resp_hdr));
    if (resp_hdr.magic != BINARY_RESPONSE_MAGIC)
    {
        detail::set_last_error("bad_response_magic");
        return false;
    }
    if (resp_hdr.version != BINARY_PROTOCOL_VERSION)
    {
        detail::set_last_error("bad_response_version");
        return false;
    }
    if (resp_hdr.session_nonce_echo != session_nonce)
    {
        detail::set_last_error("nonce_mismatch");
        return false;
    }
    if (sizeof(resp_hdr) + resp_hdr.payload_len > body_bytes.size())
    {
        detail::set_last_error("payload_truncated");
        return false;
    }

    {
        binary_response_header_t crc_copy = resp_hdr;
        crc_copy.crc32c = 0;
        std::vector<uint8_t> crc_buf;
        crc_buf.reserve(sizeof(crc_copy) - 4 + resp_hdr.payload_len);
        crc_buf.insert(crc_buf.end(),
                       reinterpret_cast<const uint8_t*>(&crc_copy),
                       reinterpret_cast<const uint8_t*>(&crc_copy) + sizeof(crc_copy) - 4);
        crc_buf.insert(crc_buf.end(),
                       body_bytes.begin() + sizeof(resp_hdr),
                       body_bytes.begin() + sizeof(resp_hdr) + resp_hdr.payload_len);
        uint32_t expected = detail::crc32c_compute(crc_buf.data(), crc_buf.size());
        if (expected != resp_hdr.crc32c)
        {
            detail::set_last_error("response_crc_mismatch");
            return false;
        }
    }

    status_out = resp_hdr.status;
    if (resp_hdr.status != BINARY_STATUS_OK)
    {
        detail::set_last_error("server_status_" + std::to_string(resp_hdr.status));
        response_payload_out.clear();
        return false;
    }

    if (resp_hdr.payload_len < 16)
    {
        detail::set_last_error("response_payload_no_tag");
        return false;
    }

    const uint8_t* enc_body = body_bytes.data() + sizeof(resp_hdr);
    size_t enc_len = resp_hdr.payload_len - 16;
    const uint8_t* recv_tag = enc_body + enc_len;

    uint8_t resp_key[32] = {};
    if (!detail::derive_protocol_key(session_token, hwid, resp_key))
    {
        detail::set_last_error("derive_key_failed_resp");
        return false;
    }

    binary_response_header_t resp_aad = resp_hdr;
    resp_aad.crc32c = 0;
    resp_aad.payload_len = 0;

    std::vector<uint8_t> plain_resp;
    bool dec_ok = detail::chacha20_poly1305_decrypt(
        resp_key, chacha_iv,
        reinterpret_cast<const uint8_t*>(&resp_aad), sizeof(resp_aad) - 8,
        enc_body, enc_len,
        recv_tag,
        plain_resp);

    SecureZeroMemory(resp_key, sizeof(resp_key));

    if (!dec_ok)
    {
        detail::set_last_error("response_decrypt_failed");
        return false;
    }

    response_payload_out = std::move(plain_resp);
    detail::set_last_error("");
    return true;
}

inline bool unpack_response_uint32(const std::vector<uint8_t>& payload, size_t offset, uint32_t& out)
{
    if (offset + 4 > payload.size()) return false;
    std::memcpy(&out, payload.data() + offset, 4);
    return true;
}

inline bool unpack_response_uint64(const std::vector<uint8_t>& payload, size_t offset, uint64_t& out)
{
    if (offset + 8 > payload.size()) return false;
    std::memcpy(&out, payload.data() + offset, 8);
    return true;
}

inline bool unpack_response_bytes(const std::vector<uint8_t>& payload,
                                  size_t offset, size_t len,
                                  std::vector<uint8_t>& out)
{
    if (offset + len > payload.size()) return false;
    out.assign(payload.begin() + offset, payload.begin() + offset + len);
    return true;
}

inline constexpr uint8_t k_baked_spki_pin_primary[32] = {
    0xb7, 0xc5, 0x13, 0x79, 0xa4, 0xea, 0xfa, 0xa1,
    0x6c, 0xd5, 0x81, 0x2f, 0x91, 0x54, 0x81, 0x16,
    0xd1, 0x55, 0x58, 0xa0, 0x8e, 0x6d, 0x0b, 0x9a,
    0xe3, 0x21, 0x7d, 0x12, 0xf1, 0x7d, 0x1c, 0x26
};

inline constexpr uint8_t k_baked_spki_pin_secondary[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

inline bool initialize_with_baked_pin()
{
    detail::ensure_winsock();
    detail::ensure_openssl_init();
    if (!set_pinned_spki_sha256(k_baked_spki_pin_primary)) return false;
    bool secondary_nonzero = false;
    for (int i = 0; i < 32; ++i)
    {
        if (k_baked_spki_pin_secondary[i] != 0)
        {
            secondary_nonzero = true;
            break;
        }
    }
    if (secondary_nonzero)
        set_secondary_spki_sha256(k_baked_spki_pin_secondary);
    neutralize_keylog_env();
    return true;
}

}
}
