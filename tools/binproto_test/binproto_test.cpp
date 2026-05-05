#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#include "binary_protocol.hpp"

static int g_pass = 0;
static int g_fail = 0;

static void check_true(const char* name, bool cond, const char* extra = nullptr)
{
    if (cond)
    {
        ++g_pass;
        std::printf("  [PASS] %s%s%s\n", name, extra ? " -- " : "", extra ? extra : "");
    }
    else
    {
        ++g_fail;
        std::printf("  [FAIL] %s%s%s\n", name, extra ? " -- " : "", extra ? extra : "");
    }
}

static void section(const char* name)
{
    std::printf("\n========== %s ==========\n", name);
}

namespace test_constants {
    static const char* kLicenseKey = "AIDA-TEST-LIC-12345";
    static const char* kSessionToken = "test-session-token-67890";
    static const char* kHwid = "TEST-HWID-CAFEBABE";
    static const char* kProofToken = "test-proof-token-deadbeef";
    static const uint32_t kPageIndex = 7;
    static const uint64_t kIssuedAt = 0x68240000;
    static const char* kPagePayload = "MOCK_PAGE_BYTES_FOR_BINPROTO_TEST_!!";
}

struct mock_server_state_t
{
    SOCKET listen_sock = INVALID_SOCKET;
    int port = 0;
    SSL_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    std::atomic<bool> running{false};
    std::atomic<bool> stop_flag{false};
    std::thread accept_thread;
    std::vector<uint8_t> spki_hash;
    std::vector<uint8_t> last_response_check_payload;
    std::vector<uint8_t> last_request_decrypted;
    std::atomic<int> requests_handled{0};
    std::atomic<int> auth_failures{0};
};

static bool generate_self_signed_rsa(EVP_PKEY*& pkey_out, X509*& cert_out)
{
    pkey_out = nullptr;
    cert_out = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) return false;
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    if (EVP_PKEY_keygen(pctx, &pkey_out) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    EVP_PKEY_CTX_free(pctx);

    X509* x = X509_new();
    if (!x) { EVP_PKEY_free(pkey_out); pkey_out = nullptr; return false; }
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), static_cast<long>(60L * 60L * 24L * 30L));
    X509_set_pubkey(x, pkey_out);

    X509_NAME* name = const_cast<X509_NAME*>(X509_get_subject_name(x));
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("AiDABinprotoTest"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    if (!X509_sign(x, pkey_out, EVP_sha256()))
    {
        X509_free(x);
        EVP_PKEY_free(pkey_out);
        pkey_out = nullptr;
        return false;
    }
    cert_out = x;
    return true;
}

static bool spki_hash_from_x509(X509* cert, uint8_t out_hash[32])
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

static bool send_full_tls(SSL* ssl, const uint8_t* data, size_t len)
{
    while (len > 0)
    {
        int n = SSL_write(ssl, data, static_cast<int>(len));
        if (n <= 0) return false;
        data += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

static int recv_n_tls(SSL* ssl, uint8_t* out, int len)
{
    int total = 0;
    while (total < len)
    {
        int n = SSL_read(ssl, out + total, len - total);
        if (n <= 0) return total;
        total += n;
    }
    return total;
}

static std::vector<uint8_t> read_full_tls(SSL* ssl, size_t cap)
{
    std::vector<uint8_t> out;
    out.reserve(cap);
    uint8_t buf[4096];
    for (;;)
    {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        out.insert(out.end(), buf, buf + n);
        if (out.size() >= cap) break;
    }
    return out;
}

static bool hkdf_sha256_expand(const uint8_t* ikm, size_t ikm_len,
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

static bool derive_protocol_key(const std::string& session_token,
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
    if (!ikm.empty()) SecureZeroMemory(ikm.data(), ikm.size());
    return ok;
}

static bool chacha_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* ct, size_t ct_len,
                           const uint8_t tag[16],
                           std::vector<uint8_t>& plain)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        int outl = 0;
        if (aad_len > 0)
        {
            if (EVP_DecryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len)) != 1) break;
        }
        plain.resize(ct_len);
        if (ct_len > 0)
        {
            if (EVP_DecryptUpdate(ctx, plain.data(), &outl, ct, static_cast<int>(ct_len)) != 1) break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) break;
        int finlen = 0;
        if (EVP_DecryptFinal_ex(ctx, plain.data() + outl, &finlen) != 1) { plain.clear(); break; }
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool chacha_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* pt, size_t pt_len,
                           std::vector<uint8_t>& ct,
                           uint8_t tag_out[16])
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        int outl = 0;
        if (aad_len > 0)
        {
            if (EVP_EncryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len)) != 1) break;
        }
        ct.resize(pt_len);
        if (pt_len > 0)
        {
            if (EVP_EncryptUpdate(ctx, ct.data(), &outl, pt, static_cast<int>(pt_len)) != 1) break;
        }
        int finl = 0;
        if (EVP_EncryptFinal_ex(ctx, ct.data() + outl, &finl) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_out) != 1) break;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static void server_handle_connection(mock_server_state_t* state, SOCKET client)
{
    SSL* ssl = SSL_new(state->ctx);
    if (!ssl)
    {
        closesocket(client);
        return;
    }
    SSL_set_fd(ssl, static_cast<int>(client));
    if (SSL_accept(ssl) != 1)
    {
        SSL_free(ssl);
        closesocket(client);
        ++state->auth_failures;
        return;
    }

    std::vector<uint8_t> raw;
    raw.reserve(8192);
    uint8_t buf[4096];
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline)
    {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0)
        {
            raw.insert(raw.end(), buf, buf + n);
            auto crlf2 = std::search(raw.begin(), raw.end(),
                                     std::begin("\r\n\r\n"), std::end("\r\n\r\n") - 1);
            if (crlf2 != raw.end())
            {
                size_t header_end = static_cast<size_t>(crlf2 - raw.begin()) + 4;
                std::string headers(reinterpret_cast<const char*>(raw.data()), header_end - 4);
                std::string lower = headers;
                for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
                size_t cl_pos = lower.find("content-length:");
                size_t expected_len = 0;
                if (cl_pos != std::string::npos)
                    expected_len = static_cast<size_t>(std::strtoul(lower.c_str() + cl_pos + 15, nullptr, 10));
                if (raw.size() >= header_end + expected_len) break;
            }
        }
        else
        {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                Sleep(1);
                continue;
            }
            break;
        }
    }

    auto crlf2 = std::search(raw.begin(), raw.end(),
                             std::begin("\r\n\r\n"), std::end("\r\n\r\n") - 1);
    if (crlf2 == raw.end())
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }
    size_t header_end = static_cast<size_t>(crlf2 - raw.begin()) + 4;
    if (raw.size() < header_end + sizeof(anti_tamper::binary_protocol::binary_request_header_t))
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }

    const uint8_t* body = raw.data() + header_end;
    anti_tamper::binary_protocol::binary_request_header_t req_hdr = {};
    std::memcpy(&req_hdr, body, sizeof(req_hdr));
    if (req_hdr.magic != anti_tamper::binary_protocol::BINARY_REQUEST_MAGIC)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }

    if (sizeof(req_hdr) + req_hdr.payload_len > raw.size() - header_end)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }
    const uint8_t* enc_body = body + sizeof(req_hdr);
    size_t enc_len = req_hdr.payload_len - 16;
    const uint8_t* recv_tag = enc_body + enc_len;

    uint8_t key[32] = {};
    derive_protocol_key(test_constants::kSessionToken, test_constants::kHwid, key);

    uint8_t nonce[12] = {};
    std::memcpy(nonce, &req_hdr.session_nonce, 8);
    nonce[8] = 0xA1;
    nonce[9] = 0xDA;
    nonce[10] = 0xC0;
    nonce[11] = 0xDE;

    anti_tamper::binary_protocol::binary_request_header_t aad_hdr = req_hdr;
    aad_hdr.crc32c = 0;
    aad_hdr.payload_len = 0;
    std::vector<uint8_t> plain_req;
    bool dec_ok = chacha_decrypt(key, nonce,
                                 reinterpret_cast<const uint8_t*>(&aad_hdr), sizeof(aad_hdr) - 8,
                                 enc_body, enc_len, recv_tag, plain_req);
    SecureZeroMemory(key, sizeof(key));

    if (!dec_ok)
    {
        ++state->auth_failures;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }

    state->last_request_decrypted = plain_req;

    std::vector<uint8_t> plain_resp;
    {
        const char* page_bytes = test_constants::kPagePayload;
        uint32_t page_size = static_cast<uint32_t>(std::strlen(page_bytes));
        uint32_t total_pages = 42;
        uint64_t blob_size = 0x12345678ULL;

        plain_resp.resize(0);
        plain_resp.insert(plain_resp.end(),
                          reinterpret_cast<const uint8_t*>(&total_pages),
                          reinterpret_cast<const uint8_t*>(&total_pages) + 4);
        plain_resp.insert(plain_resp.end(),
                          reinterpret_cast<const uint8_t*>(&blob_size),
                          reinterpret_cast<const uint8_t*>(&blob_size) + 8);
        plain_resp.insert(plain_resp.end(),
                          reinterpret_cast<const uint8_t*>(&page_size),
                          reinterpret_cast<const uint8_t*>(&page_size) + 4);

        std::vector<uint8_t> page_ct(page_size);
        for (uint32_t i = 0; i < page_size; ++i)
            page_ct[i] = static_cast<uint8_t>(page_bytes[i] ^ 0x55);

        uint8_t iv12[12] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6};
        uint8_t tag16[16] = {};
        for (int i = 0; i < 16; ++i) tag16[i] = static_cast<uint8_t>(i + 0x80);

        plain_resp.insert(plain_resp.end(), page_ct.begin(), page_ct.end());
        plain_resp.insert(plain_resp.end(), iv12, iv12 + 12);
        plain_resp.insert(plain_resp.end(), tag16, tag16 + 16);
    }

    state->last_response_check_payload = plain_resp;

    uint8_t resp_key[32] = {};
    derive_protocol_key(test_constants::kSessionToken, test_constants::kHwid, resp_key);

    anti_tamper::binary_protocol::binary_response_header_t resp_aad = {};
    resp_aad.magic = anti_tamper::binary_protocol::BINARY_RESPONSE_MAGIC;
    resp_aad.version = anti_tamper::binary_protocol::BINARY_PROTOCOL_VERSION;
    resp_aad.status = anti_tamper::binary_protocol::BINARY_STATUS_OK;
    resp_aad.session_nonce_echo = req_hdr.session_nonce;
    resp_aad.payload_len = 0;
    resp_aad.crc32c = 0;

    std::vector<uint8_t> resp_ct;
    uint8_t resp_tag[16] = {};
    bool enc_ok = chacha_encrypt(resp_key, nonce,
                                 reinterpret_cast<const uint8_t*>(&resp_aad), sizeof(resp_aad) - 8,
                                 plain_resp.data(), plain_resp.size(),
                                 resp_ct, resp_tag);
    SecureZeroMemory(resp_key, sizeof(resp_key));
    if (!enc_ok)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }

    std::vector<uint8_t> wire_payload;
    wire_payload.reserve(resp_ct.size() + 16);
    wire_payload.insert(wire_payload.end(), resp_ct.begin(), resp_ct.end());
    wire_payload.insert(wire_payload.end(), resp_tag, resp_tag + 16);

    anti_tamper::binary_protocol::binary_response_header_t resp_hdr = resp_aad;
    resp_hdr.payload_len = static_cast<uint32_t>(wire_payload.size());
    {
        std::vector<uint8_t> crc_buf;
        crc_buf.insert(crc_buf.end(),
                       reinterpret_cast<const uint8_t*>(&resp_hdr),
                       reinterpret_cast<const uint8_t*>(&resp_hdr) + sizeof(resp_hdr) - 4);
        crc_buf.insert(crc_buf.end(), wire_payload.begin(), wire_payload.end());
        resp_hdr.crc32c = anti_tamper::binary_protocol::detail::crc32c_compute(
            crc_buf.data(), crc_buf.size());
    }

    char http_resp[256];
    int hlen = std::snprintf(http_resp, sizeof(http_resp),
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
        static_cast<unsigned>(sizeof(resp_hdr) + wire_payload.size()));

    std::vector<uint8_t> out_buf;
    out_buf.reserve(static_cast<size_t>(hlen) + sizeof(resp_hdr) + wire_payload.size());
    out_buf.insert(out_buf.end(), http_resp, http_resp + hlen);
    out_buf.insert(out_buf.end(),
                   reinterpret_cast<const uint8_t*>(&resp_hdr),
                   reinterpret_cast<const uint8_t*>(&resp_hdr) + sizeof(resp_hdr));
    out_buf.insert(out_buf.end(), wire_payload.begin(), wire_payload.end());

    send_full_tls(ssl, out_buf.data(), out_buf.size());
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client);
    ++state->requests_handled;
}

static void server_accept_loop(mock_server_state_t* state)
{
    state->running.store(true);
    while (!state->stop_flag.load())
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(state->listen_sock, &rfds);
        timeval tv = { 0, 200000 };
        int sel = select(0, &rfds, nullptr, nullptr, &tv);
        if (sel < 0) break;
        if (sel == 0) continue;
        sockaddr_in client_addr = {};
        int client_len = sizeof(client_addr);
        SOCKET client = accept(state->listen_sock,
                               reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client == INVALID_SOCKET) continue;
        std::thread(server_handle_connection, state, client).detach();
    }
    state->running.store(false);
}

static bool start_mock_server(mock_server_state_t& state)
{
    if (!generate_self_signed_rsa(state.pkey, state.cert))
    {
        std::printf("server: cert generation failed\n");
        return false;
    }
    state.spki_hash.resize(32);
    if (!spki_hash_from_x509(state.cert, state.spki_hash.data()))
    {
        std::printf("server: spki hash failed\n");
        return false;
    }

    state.ctx = SSL_CTX_new(TLS_server_method());
    if (!state.ctx)
    {
        std::printf("server: SSL_CTX_new failed\n");
        return false;
    }
    if (SSL_CTX_use_certificate(state.ctx, state.cert) != 1)
    {
        std::printf("server: use_certificate failed\n");
        return false;
    }
    if (SSL_CTX_use_PrivateKey(state.ctx, state.pkey) != 1)
    {
        std::printf("server: use_PrivateKey failed\n");
        return false;
    }
    SSL_CTX_set_min_proto_version(state.ctx, TLS1_2_VERSION);

    state.listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (state.listen_sock == INVALID_SOCKET)
    {
        std::printf("server: socket() failed wsa=%d\n", WSAGetLastError());
        return false;
    }
    BOOL reuse = TRUE;
    setsockopt(state.listen_sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = 0;
    if (bind(state.listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0)
    {
        std::printf("server: bind() failed wsa=%d\n", WSAGetLastError());
        return false;
    }
    int bind_len = sizeof(bind_addr);
    if (getsockname(state.listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), &bind_len) != 0)
    {
        std::printf("server: getsockname() failed\n");
        return false;
    }
    state.port = ntohs(bind_addr.sin_port);
    if (listen(state.listen_sock, 4) != 0)
    {
        std::printf("server: listen() failed\n");
        return false;
    }

    state.accept_thread = std::thread(server_accept_loop, &state);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!state.running.load() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    return state.running.load();
}

static void stop_mock_server(mock_server_state_t& state)
{
    state.stop_flag.store(true);
    if (state.accept_thread.joinable())
        state.accept_thread.join();
    if (state.listen_sock != INVALID_SOCKET)
    {
        closesocket(state.listen_sock);
        state.listen_sock = INVALID_SOCKET;
    }
    if (state.ctx) { SSL_CTX_free(state.ctx); state.ctx = nullptr; }
    if (state.cert) { X509_free(state.cert); state.cert = nullptr; }
    if (state.pkey) { EVP_PKEY_free(state.pkey); state.pkey = nullptr; }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    WSADATA wsa = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::printf("WSAStartup failed\n");
        return 1;
    }

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    section("BINPROTO TEST");

    mock_server_state_t server;
    bool started = start_mock_server(server);
    check_true("mock server starts", started);
    if (!started)
    {
        WSACleanup();
        std::printf("FATAL: mock server did not start\n");
        return 2;
    }
    std::printf("  mock server listening on 127.0.0.1:%d, SPKI hash bytes: ", server.port);
    for (int i = 0; i < 8; ++i) std::printf("%02x", server.spki_hash[i]);
    std::printf("...\n");

    section("PIN ACCEPTANCE PATH");
    {
        anti_tamper::binary_protocol::clear_pinned_spki();
        bool pin_set = anti_tamper::binary_protocol::set_pinned_spki_sha256(server.spki_hash.data());
        check_true("set_pinned_spki_sha256 returns true", pin_set);

        std::vector<uint8_t> resp_payload;
        uint16_t status = 0;
        bool sent = anti_tamper::binary_protocol::send_request(
            anti_tamper::binary_protocol::BINARY_OP_PAGE_FETCH,
            test_constants::kLicenseKey,
            test_constants::kSessionToken,
            test_constants::kHwid,
            test_constants::kProofToken,
            test_constants::kPageIndex,
            test_constants::kIssuedAt,
            "127.0.0.1",
            server.port,
            "/api/download/arc/page-binary/" + std::to_string(test_constants::kPageIndex),
            10,
            resp_payload,
            status);

        if (!sent)
            std::printf("    last_error: %s\n", anti_tamper::binary_protocol::last_error());
        check_true("send_request succeeds with valid pin", sent);
        check_true("response status == OK",
                   status == anti_tamper::binary_protocol::BINARY_STATUS_OK);

        bool payload_match = (resp_payload == server.last_response_check_payload);
        check_true("client decrypted payload matches server", payload_match);
        if (resp_payload.size() >= 16)
        {
            uint32_t total_pages = 0;
            std::memcpy(&total_pages, resp_payload.data(), 4);
            uint64_t blob_size = 0;
            std::memcpy(&blob_size, resp_payload.data() + 4, 8);
            uint32_t page_size = 0;
            std::memcpy(&page_size, resp_payload.data() + 12, 4);
            char detail[160] = {};
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "total_pages=%u blob=%llu page_size=%u",
                total_pages, static_cast<unsigned long long>(blob_size), page_size);
            check_true("response fields are sane",
                       total_pages == 42 && blob_size == 0x12345678ULL && page_size > 0,
                       detail);
        }
        else
        {
            check_true("response payload size >= 16", false);
        }

        bool req_round_trip = false;
        if (server.last_request_decrypted.size() > 0)
        {
            const uint8_t* p = server.last_request_decrypted.data();
            size_t off = 0;
            auto read_str = [&](std::string& out) -> bool {
                if (off + 4 > server.last_request_decrypted.size()) return false;
                uint32_t len = 0;
                std::memcpy(&len, p + off, 4);
                off += 4;
                if (off + len > server.last_request_decrypted.size()) return false;
                out.assign(reinterpret_cast<const char*>(p + off), len);
                off += len;
                return true;
            };
            std::string lk, st, hw, pt;
            bool a = read_str(lk);
            bool b = read_str(st);
            bool c = read_str(hw);
            bool d = read_str(pt);
            uint32_t pidx = 0;
            uint64_t issued = 0;
            bool e = false;
            if (a && b && c && d && off + 12 <= server.last_request_decrypted.size())
            {
                std::memcpy(&pidx, p + off, 4);
                off += 4;
                std::memcpy(&issued, p + off, 8);
                off += 8;
                e = true;
            }
            req_round_trip = a && b && c && d && e &&
                             lk == test_constants::kLicenseKey &&
                             st == test_constants::kSessionToken &&
                             hw == test_constants::kHwid &&
                             pt == test_constants::kProofToken &&
                             pidx == test_constants::kPageIndex &&
                             issued == test_constants::kIssuedAt;
        }
        check_true("server received correctly-formed request body", req_round_trip);
    }

    section("PIN FAILURE PATH");
    {
        anti_tamper::binary_protocol::clear_pinned_spki();
        uint8_t zero_pin[32] = {};
        bool pin_set = anti_tamper::binary_protocol::set_pinned_spki_sha256(zero_pin);
        check_true("set zero-pin", pin_set);

        std::vector<uint8_t> resp_payload;
        uint16_t status = 0;
        bool sent = anti_tamper::binary_protocol::send_request(
            anti_tamper::binary_protocol::BINARY_OP_PAGE_FETCH,
            test_constants::kLicenseKey,
            test_constants::kSessionToken,
            test_constants::kHwid,
            test_constants::kProofToken,
            test_constants::kPageIndex,
            test_constants::kIssuedAt,
            "127.0.0.1",
            server.port,
            "/api/download/arc/page-binary/" + std::to_string(test_constants::kPageIndex),
            5,
            resp_payload,
            status);

        check_true("send_request fails with wrong pin", !sent);
        const char* err = anti_tamper::binary_protocol::last_error();
        bool err_match = err && std::strcmp(err, "spki_pin_mismatch") == 0;
        check_true("last_error == spki_pin_mismatch", err_match, err ? err : "(null)");
    }

    section("KEYLOG NEUTRALIZATION");
    {
        SetEnvironmentVariableA("SSLKEYLOGFILE", "C:\\fake\\path\\keys.log");
        char before[260] = {};
        DWORD got_before = GetEnvironmentVariableA("SSLKEYLOGFILE", before, sizeof(before));
        check_true("env var was set before neutralize",
                   got_before > 0 && std::strcmp(before, "C:\\fake\\path\\keys.log") == 0);

        bool neut = anti_tamper::binary_protocol::neutralize_keylog_env();
        check_true("neutralize_keylog_env returns true", neut);

        char after[260] = {};
        DWORD got_after = GetEnvironmentVariableA("SSLKEYLOGFILE", after, sizeof(after));
        check_true("env var GONE after neutralize", got_after == 0);

        wchar_t after_w[260] = {};
        DWORD got_after_w = GetEnvironmentVariableW(L"SSLKEYLOGFILE", after_w, 260);
        check_true("wide env var GONE after neutralize", got_after_w == 0);
    }

    section("REQUEST-CRC SHIELDING");
    {
        uint8_t buf[64] = {};
        for (int i = 0; i < 64; ++i) buf[i] = static_cast<uint8_t>(i + 1);
        uint32_t crc1 = anti_tamper::binary_protocol::detail::crc32c_compute(buf, 64);
        buf[37] ^= 0x01;
        uint32_t crc2 = anti_tamper::binary_protocol::detail::crc32c_compute(buf, 64);
        check_true("crc32c detects single-bit flip", crc1 != crc2);
    }

    stop_mock_server(server);
    WSACleanup();

    std::printf("\n========== RESULT ==========\n");
    std::printf("PASS=%d FAIL=%d\n", g_pass, g_fail);
    if (g_fail == 0)
    {
        std::printf("BINPROTO_TEST_PASSED\n");
        return 0;
    }
    std::printf("BINPROTO_TEST_FAILED\n");
    return 1;
}
