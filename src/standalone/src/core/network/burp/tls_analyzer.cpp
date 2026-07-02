#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>

#ifdef small
#undef small
#endif

#include "tls_analyzer.hpp"

#include "findings_db.hpp"
#include "issue.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <cstdint>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace aida {
namespace burp {
namespace tls_analyzer {

namespace {

using json = nlohmann::json;

std::string lower_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string redact_endpoint(std::string value)
{
    const std::size_t scheme = value.find("://");
    const std::size_t authority_start = scheme == std::string::npos ? 0 : scheme + 3;
    const std::size_t authority_end = value.find_first_of("/?#", authority_start);
    const std::size_t bounded_authority_end = authority_end == std::string::npos ? value.size() : authority_end;
    const std::size_t at = value.find('@', authority_start);
    if (at != std::string::npos && at < bounded_authority_end)
        value.replace(authority_start, at - authority_start, "[REDACTED]");
    const std::size_t query = value.find('?', authority_start);
    if (query != std::string::npos)
        value.erase(query + 1).append("[REDACTED]");
    const std::size_t fragment = value.find('#', authority_start);
    if (fragment != std::string::npos)
        value.erase(fragment + 1).append("[REDACTED]");
    return value;
}

std::uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::uint64_t fnv1a64(const void* data, std::size_t size)
{
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::uint64_t h = 1469598103934665603ull;
    for (std::size_t i = 0; i < size; ++i) {
        h ^= bytes[i];
        h *= 1099511628211ull;
    }
    return h;
}

std::string hex64(std::uint64_t value)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = kHex[value & 0x0f];
        value >>= 4;
    }
    return out;
}

std::string bytes_hex(const std::vector<unsigned char>& bytes)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0f]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

std::string sha256_hex(const void* data, std::size_t size)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_len = 0;
    DWORD hash_len = 0;
    DWORD cb = 0;
    std::vector<unsigned char> object;
    std::vector<unsigned char> digest;
    std::string out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0) {
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_len), sizeof(object_len), &cb, 0) >= 0 &&
            BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0) >= 0) {
            object.resize(object_len);
            digest.resize(hash_len);
            if (BCryptCreateHash(alg, &hash, object.data(), object_len, nullptr, 0, 0) >= 0 &&
                BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(size), 0) >= 0 &&
                BCryptFinishHash(hash, digest.data(), hash_len, 0) >= 0) {
                out = bytes_hex(digest);
            }
        }
    }
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    if (out.empty())
        out = hex64(fnv1a64(data, size));
    return out;
}

bool valid_host(const std::string& host)
{
    if (host.empty() || host.size() > 253)
        return false;
    for (unsigned char c : host) {
        if (std::isspace(c) || c == '/' || c == '\\' || c == '@')
            return false;
    }
    return true;
}

std::wstring utf8_to_wide(const std::string& value)
{
    if (value.empty())
        return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0)
        needed = MultiByteToWideChar(CP_ACP, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0)
        return {};
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed) <= 0)
        MultiByteToWideChar(CP_ACP, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed);
    return out;
}

std::string wide_to_utf8(const std::wstring& value)
{
    if (value.empty())
        return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

bool expired()
{
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return mcp_standalone::current_call_cancelled() || (deadline != 0 && GetTickCount64() >= deadline);
}

DWORD timeout_ms(DWORD fallback)
{
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline == 0)
        return fallback;
    const std::uint64_t now = GetTickCount64();
    if (deadline <= now)
        return 1;
    return static_cast<DWORD>(std::max<std::uint64_t>(1, std::min<std::uint64_t>(fallback, deadline - now)));
}

std::once_flag& wsa_once()
{
    static std::once_flag flag;
    return flag;
}

int& wsa_status()
{
    static int status = WSANOTINITIALISED;
    return status;
}

bool ensure_winsock()
{
    std::call_once(wsa_once(), []() {
        WSADATA wsa{};
        wsa_status() = WSAStartup(MAKEWORD(2, 2), &wsa);
    });
    return wsa_status() == 0;
}

bool connect_socket(const std::string& host, std::uint16_t port, DWORD timeout, SOCKET& out_sock, std::string& error)
{
    out_sock = INVALID_SOCKET;
    if (!ensure_winsock()) {
        error = "WSAStartup failed " + std::to_string(wsa_status());
        return false;
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* resolved = nullptr;
    const std::string port_text = std::to_string(port);
    const int gai = getaddrinfo(host.c_str(), port_text.c_str(), &hints, &resolved);
    if (gai != 0) {
        error = "getaddrinfo failed " + std::to_string(gai);
        return false;
    }
    for (addrinfo* ai = resolved; ai; ai = ai->ai_next) {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (rc == SOCKET_ERROR) {
            const int e = WSAGetLastError();
            if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEINVAL) {
                closesocket(s);
                continue;
            }
        }
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(s, &writefds);
        timeval tv{static_cast<long>(timeout / 1000), static_cast<long>((timeout % 1000) * 1000)};
        rc = select(0, nullptr, &writefds, nullptr, &tv);
        if (rc > 0 && FD_ISSET(s, &writefds)) {
            int soerr = 0;
            int soerr_len = sizeof(soerr);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &soerr_len);
            if (soerr == 0) {
                DWORD t = timeout;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
                out_sock = s;
                freeaddrinfo(resolved);
                return true;
            }
        }
        closesocket(s);
    }
    freeaddrinfo(resolved);
    error = "connect timeout or refused";
    return false;
}

bool send_all(SOCKET s, const std::uint8_t* data, std::size_t size, DWORD timeout, std::string& error)
{
    std::size_t sent = 0;
    while (sent < size) {
        if (expired()) {
            error = "cancelled_or_deadline";
            return false;
        }
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(s, &writefds);
        timeval tv{static_cast<long>(timeout / 1000), static_cast<long>((timeout % 1000) * 1000)};
        if (select(0, nullptr, &writefds, nullptr, &tv) <= 0) {
            error = "send timeout";
            return false;
        }
        const int n = send(s, reinterpret_cast<const char*>(data + sent), static_cast<int>(std::min<std::size_t>(size - sent, 8192)), 0);
        if (n <= 0) {
            error = "send failed " + std::to_string(WSAGetLastError());
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

bool recv_some(SOCKET s, std::vector<std::uint8_t>& out, DWORD timeout, std::size_t max_bytes, std::string& error)
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(s, &readfds);
    timeval tv{static_cast<long>(timeout / 1000), static_cast<long>((timeout % 1000) * 1000)};
    const int sr = select(0, &readfds, nullptr, nullptr, &tv);
    if (sr <= 0) {
        error = "receive timeout";
        return false;
    }
    std::vector<std::uint8_t> buf(std::min<std::size_t>(max_bytes, 8192));
    const int n = recv(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
    if (n <= 0) {
        error = n == 0 ? "connection closed" : "recv failed " + std::to_string(WSAGetLastError());
        return false;
    }
    out.insert(out.end(), buf.begin(), buf.begin() + n);
    return true;
}

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void put_u24(std::vector<std::uint8_t>& out, std::uint32_t value)
{
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

struct probe_profile_t
{
    std::string label;
    std::uint16_t record_version = 0x0301;
    std::uint16_t client_version = 0x0303;
    std::vector<std::uint16_t> supported_versions;
    std::vector<std::uint16_t> ciphers;
    std::vector<std::uint8_t> compressions;
    bool sni = true;
    bool alpn = false;
};

struct probe_result_t
{
    std::string label;
    bool connected = false;
    bool sent = false;
    bool got_server_hello = false;
    bool server_hello_done = false;
    bool got_alert = false;
    std::uint8_t alert_level = 0;
    std::uint8_t alert_description = 0;
    std::uint16_t record_version = 0;
    std::uint16_t server_version = 0;
    std::uint16_t selected_version = 0;
    std::uint16_t cipher_suite = 0;
    std::uint8_t compression = 0xff;
    std::vector<std::uint16_t> extensions;
    std::size_t bytes_received = 0;
    std::string error;
    std::uint64_t elapsed_ms = 0;
};

std::string version_name(std::uint16_t version)
{
    switch (version) {
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    default: {
        std::ostringstream os;
        os << "0x" << std::hex << std::setw(4) << std::setfill('0') << version;
        return os.str();
    }
    }
}

std::string cipher_name(std::uint16_t cipher)
{
    switch (cipher) {
    case 0x1301: return "TLS_AES_128_GCM_SHA256";
    case 0x1302: return "TLS_AES_256_GCM_SHA384";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    case 0x009E: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0x009F: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
    case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
    case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
    case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
    default: {
        std::ostringstream os;
        os << "0x" << std::hex << std::setw(4) << std::setfill('0') << cipher;
        return os.str();
    }
    }
}

std::string cipher_strength(std::uint16_t cipher)
{
    const std::string name = lower_ascii(cipher_name(cipher));
    if (name.find("null") != std::string::npos || name.find("anon") != std::string::npos ||
        name.find("export") != std::string::npos || name.find("rc4") != std::string::npos ||
        name.find("3des") != std::string::npos)
        return "weak";
    if (name.find("cbc") != std::string::npos)
        return "legacy";
    if (name.find("gcm") != std::string::npos || name.find("chacha20") != std::string::npos)
        return "strong";
    return "unknown";
}

std::string key_exchange(const std::string& cipher)
{
    const std::string lower = lower_ascii(cipher);
    if (lower.find("tls_aes_") == 0 || lower.find("tls_chacha20_") == 0)
        return "TLS1.3";
    if (lower.find("ecdhe") != std::string::npos)
        return "ECDHE";
    if (lower.find("dhe") != std::string::npos)
        return "DHE";
    if (lower.find("rsa") != std::string::npos)
        return "RSA";
    return "unknown";
}

bool has_pfs(const std::string& cipher)
{
    const std::string kx = key_exchange(cipher);
    return kx == "TLS1.3" || kx == "ECDHE" || kx == "DHE";
}

void add_extension(std::vector<std::uint8_t>& extensions, std::uint16_t type, const std::vector<std::uint8_t>& data)
{
    put_u16(extensions, type);
    put_u16(extensions, static_cast<std::uint16_t>(data.size()));
    extensions.insert(extensions.end(), data.begin(), data.end());
}

std::vector<std::uint8_t> build_client_hello(const std::string& host, const probe_profile_t& profile)
{
    std::vector<std::uint8_t> body;
    put_u16(body, profile.client_version);
    for (int i = 0; i < 32; ++i)
        body.push_back(static_cast<std::uint8_t>((i * 17 + profile.label.size()) & 0xff));
    body.push_back(0);
    put_u16(body, static_cast<std::uint16_t>(profile.ciphers.size() * 2));
    for (std::uint16_t cipher : profile.ciphers)
        put_u16(body, cipher);
    const auto compressions = profile.compressions.empty() ? std::vector<std::uint8_t>{0} : profile.compressions;
    body.push_back(static_cast<std::uint8_t>(compressions.size()));
    body.insert(body.end(), compressions.begin(), compressions.end());
    std::vector<std::uint8_t> extensions;
    if (profile.sni && !host.empty()) {
        std::vector<std::uint8_t> sni;
        std::vector<std::uint8_t> hn(host.begin(), host.end());
        put_u16(sni, static_cast<std::uint16_t>(hn.size() + 3));
        sni.push_back(0);
        put_u16(sni, static_cast<std::uint16_t>(hn.size()));
        sni.insert(sni.end(), hn.begin(), hn.end());
        add_extension(extensions, 0, sni);
    }
    add_extension(extensions, 10, {0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18});
    add_extension(extensions, 11, {0x01, 0x00});
    add_extension(extensions, 13, {0x00, 0x0a, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05});
    if (profile.alpn)
        add_extension(extensions, 16, {0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'});
    if (!profile.supported_versions.empty()) {
        std::vector<std::uint8_t> versions;
        versions.push_back(static_cast<std::uint8_t>(profile.supported_versions.size() * 2));
        for (std::uint16_t version : profile.supported_versions)
            put_u16(versions, version);
        add_extension(extensions, 43, versions);
    }
    put_u16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    std::vector<std::uint8_t> handshake;
    handshake.push_back(0x01);
    put_u24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    std::vector<std::uint8_t> record;
    record.push_back(0x16);
    put_u16(record, profile.record_version);
    put_u16(record, static_cast<std::uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

bool parse_server_hello(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t length, probe_result_t& result)
{
    if (offset + length > data.size() || length < 38)
        return false;
    std::size_t p = offset;
    result.server_version = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
    p += 2 + 32;
    if (p >= offset + length)
        return false;
    const std::uint8_t sid_len = data[p++];
    if (p + sid_len + 3 > offset + length)
        return false;
    p += sid_len;
    result.cipher_suite = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
    p += 2;
    result.compression = data[p++];
    if (p + 2 <= offset + length) {
        const std::size_t ext_len = (static_cast<std::size_t>(data[p]) << 8) | data[p + 1];
        p += 2;
        const std::size_t ext_end = std::min<std::size_t>(offset + length, p + ext_len);
        while (p + 4 <= ext_end) {
            const std::uint16_t type = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
            const std::size_t elen = (static_cast<std::size_t>(data[p + 2]) << 8) | data[p + 3];
            p += 4;
            result.extensions.push_back(type);
            if (type == 43 && elen >= 2 && p + 2 <= ext_end)
                result.selected_version = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
            if (p + elen > ext_end)
                break;
            p += elen;
        }
    }
    result.got_server_hello = true;
    return true;
}

void parse_records(const std::vector<std::uint8_t>& data, probe_result_t& result)
{
    std::size_t offset = 0;
    while (offset + 5 <= data.size()) {
        const std::uint8_t type = data[offset];
        const std::uint16_t version = static_cast<std::uint16_t>((data[offset + 1] << 8) | data[offset + 2]);
        const std::size_t length = (static_cast<std::size_t>(data[offset + 3]) << 8) | data[offset + 4];
        offset += 5;
        if (offset + length > data.size())
            break;
        result.record_version = version;
        if (type == 21 && length >= 2) {
            result.got_alert = true;
            result.alert_level = data[offset];
            result.alert_description = data[offset + 1];
        } else if (type == 22) {
            std::size_t hp = offset;
            const std::size_t end = offset + length;
            while (hp + 4 <= end) {
                const std::uint8_t htype = data[hp++];
                const std::size_t hlen = (static_cast<std::size_t>(data[hp]) << 16) | (static_cast<std::size_t>(data[hp + 1]) << 8) | data[hp + 2];
                hp += 3;
                if (hp + hlen > end)
                    break;
                if (htype == 2)
                    parse_server_hello(data, hp, hlen, result);
                if (htype == 14)
                    result.server_hello_done = true;
                hp += hlen;
            }
        }
        offset += length;
    }
}

probe_result_t raw_probe(const std::string& host, std::uint16_t port, const probe_profile_t& profile)
{
    probe_result_t result;
    result.label = profile.label;
    const std::uint64_t started = GetTickCount64();
    SOCKET s = INVALID_SOCKET;
    std::string error;
    const DWORD timeout = timeout_ms(4500);
    if (!connect_socket(host, port, timeout, s, error)) {
        result.error = error;
        result.elapsed_ms = GetTickCount64() - started;
        return result;
    }
    result.connected = true;
    const auto hello = build_client_hello(host, profile);
    if (!send_all(s, hello.data(), hello.size(), timeout, error)) {
        closesocket(s);
        result.error = error;
        result.elapsed_ms = GetTickCount64() - started;
        return result;
    }
    result.sent = true;
    std::vector<std::uint8_t> data;
    while (!expired() && data.size() < 32768) {
        std::string recv_error;
        if (!recv_some(s, data, timeout_ms(2500), 8192, recv_error)) {
            if (data.empty())
                result.error = recv_error;
            break;
        }
        parse_records(data, result);
        if (result.got_alert || result.got_server_hello)
            break;
    }
    result.bytes_received = data.size();
    result.elapsed_ms = GetTickCount64() - started;
    closesocket(s);
    return result;
}

probe_profile_t profile(std::string label, std::uint16_t legacy, std::vector<std::uint16_t> supported = {})
{
    probe_profile_t out;
    out.label = std::move(label);
    out.record_version = legacy <= 0x0301 ? 0x0301 : 0x0303;
    out.client_version = legacy;
    out.supported_versions = std::move(supported);
    out.ciphers = {0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0x009E, 0x009F, 0x003C, 0x003D, 0x002F, 0x0035};
    out.compressions = {0};
    return out;
}

json probe_json(const probe_result_t& result)
{
    json out;
    out["label"] = result.label;
    out["connected"] = result.connected;
    out["sent"] = result.sent;
    out["got_server_hello"] = result.got_server_hello;
    out["server_hello_done"] = result.server_hello_done;
    out["bytes_received"] = static_cast<std::uint64_t>(result.bytes_received);
    out["elapsed_ms"] = result.elapsed_ms;
    if (!result.error.empty())
        out["error"] = result.error;
    if (result.got_alert) {
        out["alert_level"] = result.alert_level;
        out["alert_description"] = result.alert_description;
    }
    if (result.got_server_hello) {
        const std::uint16_t selected = result.selected_version ? result.selected_version : result.server_version;
        out["record_version"] = version_name(result.record_version);
        out["server_version"] = version_name(result.server_version);
        out["selected_version"] = version_name(selected);
        out["selected_version_code"] = selected;
        out["cipher_suite"] = cipher_name(result.cipher_suite);
        out["cipher_suite_code"] = result.cipher_suite;
        out["cipher_strength"] = cipher_strength(result.cipher_suite);
        out["compression"] = result.compression == 0 ? "null" : std::to_string(result.compression);
        json extensions = json::array();
        for (std::uint16_t ext : result.extensions)
            extensions.push_back(ext);
        out["extensions"] = extensions;
    }
    return out;
}

std::string filetime_string(const FILETIME& filetime)
{
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&filetime, &st))
        return {};
    char buffer[64] = {};
    std::snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

long long filetime_to_unix_seconds(const FILETIME& ft)
{
    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    if (uli.QuadPart < 116444736000000000ull)
        return 0;
    return static_cast<long long>((uli.QuadPart - 116444736000000000ull) / 10000000ull);
}

std::string cert_name(const CERT_NAME_BLOB& name)
{
    DWORD needed = CertNameToStrA(X509_ASN_ENCODING, const_cast<CERT_NAME_BLOB*>(&name), CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, nullptr, 0);
    if (needed <= 1)
        return {};
    std::string out(needed, '\0');
    CertNameToStrA(X509_ASN_ENCODING, const_cast<CERT_NAME_BLOB*>(&name), CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, out.data(), needed);
    while (!out.empty() && out.back() == '\0')
        out.pop_back();
    return out;
}

std::string algorithm_name(const char* oid)
{
    if (!oid)
        return {};
    const std::string value = oid;
    if (value == szOID_RSA_SHA256RSA)
        return "SHA256withRSA";
    if (value == szOID_RSA_SHA384RSA)
        return "SHA384withRSA";
    if (value == szOID_RSA_SHA512RSA)
        return "SHA512withRSA";
    if (value == szOID_ECDSA_SHA256)
        return "SHA256withECDSA";
    if (value == szOID_ECDSA_SHA384)
        return "SHA384withECDSA";
    if (value == szOID_ECDSA_SHA512)
        return "SHA512withECDSA";
    if (value == szOID_RSA_RSA)
        return "RSA";
    if (value == szOID_ECC_PUBLIC_KEY)
        return "ECDSA";
    return value;
}

std::vector<std::string> san_entries(PCCERT_CONTEXT cert)
{
    std::vector<std::string> out;
    if (!cert || !cert->pCertInfo)
        return out;
    PCERT_EXTENSION ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2, cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (!ext)
        return out;
    void* decoded = nullptr;
    DWORD decoded_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &decoded_size) || !decoded)
        return out;
    auto* info = static_cast<CERT_ALT_NAME_INFO*>(decoded);
    for (DWORD i = 0; i < info->cAltEntry; ++i) {
        const CERT_ALT_NAME_ENTRY& entry = info->rgAltEntry[i];
        if (entry.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && entry.pwszDNSName) {
            out.push_back(wide_to_utf8(entry.pwszDNSName));
        } else if (entry.dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS && entry.IPAddress.pbData && entry.IPAddress.cbData > 0) {
            out.push_back("ip_hash64:" + hex64(fnv1a64(entry.IPAddress.pbData, entry.IPAddress.cbData)));
        }
    }
    LocalFree(decoded);
    return out;
}

bool has_sct_extension(PCCERT_CONTEXT cert)
{
    if (!cert || !cert->pCertInfo)
        return false;
    return CertFindExtension("1.3.6.1.4.1.11129.2.4.2", cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension) != nullptr;
}

json cert_json(PCCERT_CONTEXT cert, const std::string& host, bool check_chain, bool check_ct_logs)
{
    json out;
    if (!cert || !cert->pCertInfo)
        return out;
    out["subject"] = cert_name(cert->pCertInfo->Subject);
    out["issuer"] = cert_name(cert->pCertInfo->Issuer);
    out["not_before"] = filetime_string(cert->pCertInfo->NotBefore);
    out["not_after"] = filetime_string(cert->pCertInfo->NotAfter);
    const long long now = static_cast<long long>(std::time(nullptr));
    const long long not_after = filetime_to_unix_seconds(cert->pCertInfo->NotAfter);
    out["days_remaining"] = not_after > now ? (not_after - now) / 86400 : -((now - not_after + 86399) / 86400);
    out["signature_algorithm"] = algorithm_name(cert->pCertInfo->SignatureAlgorithm.pszObjId);
    out["signature_algorithm_oid"] = cert->pCertInfo->SignatureAlgorithm.pszObjId ? cert->pCertInfo->SignatureAlgorithm.pszObjId : "";
    out["public_key_algorithm_oid"] = cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId ? cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId : "";
    const DWORD bits = CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo);
    out["key_bits"] = bits;
    out["key_type"] = algorithm_name(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId) + (bits ? " " + std::to_string(bits) : std::string());
    out["san_entries"] = san_entries(cert);
    out["sha256"] = sha256_hex(cert->pbCertEncoded, cert->cbCertEncoded);
    out["encoded_length"] = static_cast<std::uint64_t>(cert->cbCertEncoded);
    out["sct_extension_present"] = check_ct_logs ? has_sct_extension(cert) : false;
    out["ct_logs"] = out["sct_extension_present"];
    out["ocsp_stapling"] = false;
    out["ocsp_evidence"] = "WinHTTP certificate context does not expose a stapled OCSP response; cache-only chain revocation evidence is reported when available";

    if (check_chain) {
        CERT_CHAIN_PARA chain_para{};
        chain_para.cbSize = sizeof(chain_para);
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        const DWORD chain_flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
        if (CertGetCertificateChain(nullptr, cert, nullptr, cert->hCertStore, &chain_para, chain_flags, nullptr, &chain) && chain) {
            out["chain_status"] = chain->TrustStatus.dwErrorStatus;
            out["chain_info_status"] = chain->TrustStatus.dwInfoStatus;
            out["revocation_cache_only_checked"] = true;
            HTTPSPolicyCallbackData ssl{};
            ssl.cbStruct = sizeof(ssl);
            ssl.dwAuthType = AUTHTYPE_SERVER;
            ssl.fdwChecks = 0;
            std::wstring whost = utf8_to_wide(host);
            ssl.pwszServerName = whost.empty() ? nullptr : const_cast<LPWSTR>(whost.c_str());
            CERT_CHAIN_POLICY_PARA policy_para{};
            policy_para.cbSize = sizeof(policy_para);
            policy_para.pvExtraPolicyPara = &ssl;
            CERT_CHAIN_POLICY_STATUS policy_status{};
            policy_status.cbSize = sizeof(policy_status);
            if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy_para, &policy_status)) {
                out["ssl_policy_error"] = policy_status.dwError;
                out["name_valid"] = policy_status.dwError == 0;
                out["chain_valid"] = chain->TrustStatus.dwErrorStatus == 0 && policy_status.dwError == 0;
            } else {
                out["ssl_policy_verify_error"] = GetLastError();
                out["chain_valid"] = false;
            }
            CertFreeCertificateChain(chain);
        } else {
            out["chain_error"] = GetLastError();
            out["revocation_cache_only_checked"] = true;
            out["chain_valid"] = false;
        }
    }
    return out;
}

struct winhttp_handle_t
{
    HINTERNET h = nullptr;
    explicit winhttp_handle_t(HINTERNET handle = nullptr) : h(handle) {}
    ~winhttp_handle_t() { if (h) WinHttpCloseHandle(h); }
    winhttp_handle_t(const winhttp_handle_t&) = delete;
    winhttp_handle_t& operator=(const winhttp_handle_t&) = delete;
};

std::map<std::string, std::string> parse_headers(const std::wstring& raw)
{
    std::map<std::string, std::string> out;
    const std::string text = wide_to_utf8(raw);
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t end = text.find("\r\n", pos);
        if (end == std::string::npos)
            end = text.size();
        const std::string line = text.substr(pos, end - pos);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = lower_ascii(line.substr(0, colon));
            std::string value = line.substr(colon + 1);
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
                value.erase(value.begin());
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
                value.pop_back();
            out[key] = value;
        }
        pos = end + 2;
    }
    return out;
}

long long hsts_max_age(const std::string& value)
{
    const std::string lower = lower_ascii(value);
    const std::string marker = "max-age=";
    const std::size_t pos = lower.find(marker);
    if (pos == std::string::npos)
        return -1;
    std::size_t p = pos + marker.size();
    long long out = 0;
    bool any = false;
    while (p < lower.size() && std::isdigit(static_cast<unsigned char>(lower[p]))) {
        any = true;
        out = out * 10 + (lower[p] - '0');
        ++p;
    }
    return any ? out : -1;
}

json hsts_json(const std::string& value)
{
    json out;
    out["present"] = !value.empty();
    if (!value.empty())
        out["value"] = value;
    out["max_age"] = value.empty() ? 0 : hsts_max_age(value);
    out["include_subdomains"] = lower_ascii(value).find("includesubdomains") != std::string::npos;
    out["preload"] = lower_ascii(value).find("preload") != std::string::npos;
    if (value.empty())
        out["status"] = "warn";
    else if (out["max_age"].get<long long>() < 31536000 || !out["include_subdomains"].get<bool>() || !out["preload"].get<bool>())
        out["status"] = "warn";
    else
        out["status"] = "pass";
    return out;
}

json winhttp_assess(const std::string& host, std::uint16_t port, bool check_chain, bool check_ct_logs)
{
    json out;
    out["source"] = "winhttp_certificate_context";
    const std::wstring whost = utf8_to_wide(host);
    winhttp_handle_t session(WinHttpOpen(L"AiDA-DefensiveTLS/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.h) {
        out["error"] = "WinHttpOpen failed";
        out["gle"] = GetLastError();
        return out;
    }
    const DWORD t = timeout_ms(6000);
    WinHttpSetTimeouts(session.h, t, t, t, t);
    winhttp_handle_t connect(WinHttpConnect(session.h, whost.c_str(), static_cast<INTERNET_PORT>(port), 0));
    if (!connect.h) {
        out["error"] = "WinHttpConnect failed";
        out["gle"] = GetLastError();
        return out;
    }
    winhttp_handle_t request(WinHttpOpenRequest(connect.h, L"HEAD", L"/", nullptr, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!request.h) {
        out["error"] = "WinHttpOpenRequest failed";
        out["gle"] = GetLastError();
        return out;
    }
    WinHttpSetTimeouts(request.h, t, t, t, t);
    if (!WinHttpSendRequest(request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.h, nullptr)) {
        out["error"] = "WinHttpSendRequest/ReceiveResponse failed";
        out["gle"] = GetLastError();
        return out;
    }
    DWORD status = 0;
    DWORD status_len = sizeof(status);
    if (WinHttpQueryHeaders(request.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &status_len, nullptr))
        out["http_status"] = status;
    DWORD header_len = 0;
    WinHttpQueryHeaders(request.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &header_len, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && header_len > 0) {
        std::wstring raw(header_len / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(request.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, raw.data(), &header_len, WINHTTP_NO_HEADER_INDEX)) {
            raw.resize(header_len / sizeof(wchar_t));
            const auto headers = parse_headers(raw);
            const auto it = headers.find("strict-transport-security");
            out["hsts"] = hsts_json(it == headers.end() ? std::string() : it->second);
        }
    }
    if (!out.contains("hsts"))
        out["hsts"] = hsts_json({});
    PCCERT_CONTEXT cert = nullptr;
    DWORD cert_len = sizeof(cert);
    if (WinHttpQueryOption(request.h, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &cert_len) && cert) {
        out["certificate"] = cert_json(cert, host, check_chain, check_ct_logs);
        CertFreeCertificateContext(cert);
    } else {
        out["certificate_error"] = GetLastError();
    }
    return out;
}

std::string grade_for_score(int score)
{
    if (score >= 90)
        return "A";
    if (score >= 70)
        return "B";
    if (score >= 50)
        return "C";
    if (score >= 30)
        return "D";
    return "F";
}

void persist_issue(const std::string& type_key,
                   const std::string& name,
                   const std::string& description,
                   const std::string& remediation,
                   severity_t severity,
                   const std::string& host,
                   std::uint16_t port,
                   const std::string& marker)
{
    issue_t issue;
    issue.type_key = type_key;
    issue.name = name;
    issue.description = description;
    issue.remediation = remediation;
    issue.severity = severity;
    issue.confidence = confidence_t::firm;
    issue.scheme = "https";
    issue.host = host;
    issue.port = port;
    issue.path = "/";
    issue.parameter = sha256_hex(marker.data(), marker.size());
    issue.seen_ms = now_ms();
    evidence_t evidence;
    evidence.marker = marker;
    evidence.response_raw = marker;
    issue.evidence.push_back(std::move(evidence));
    issue_t db_issue = issue;
    db_issue.id = 0;
    findings_db::upsert(std::move(db_issue));
    issue_store::add(std::move(issue));
}

}

nlohmann::json analyze_host(const std::string& host,
                            std::uint16_t port,
                            bool check_chain,
                            bool check_ct_logs,
                            bool persist_findings,
                            std::string& error)
{
    diag::log_tagged_fmt("defensive", "tls_analyze host=%s port=%u chain=%d ct=%d",
        redact_endpoint(host).c_str(), static_cast<unsigned>(port), check_chain ? 1 : 0, check_ct_logs ? 1 : 0);
    if (!valid_host(host)) {
        error = "invalid_host";
        return json::object();
    }
    if (port == 0) {
        error = "invalid_port";
        return json::object();
    }

    std::vector<probe_profile_t> profiles;
    probe_profile_t tls10 = profile("tls10", 0x0301);
    tls10.ciphers = {0x002F, 0x0035, 0x000A};
    profiles.push_back(tls10);
    probe_profile_t tls11 = profile("tls11", 0x0302);
    tls11.ciphers = {0x002F, 0x0035, 0x003C, 0x003D};
    profiles.push_back(tls11);
    profiles.push_back(profile("tls12", 0x0303));
    profiles.push_back(profile("tls13", 0x0303, {0x0304, 0x0303}));

    json raw_probes = json::array();
    std::map<std::string, bool> protocol_enabled;
    std::map<std::string, probe_result_t> probe_by_label;
    std::map<std::uint16_t, probe_result_t> selected_ciphers;
    bool weak_protocol = false;
    bool modern_protocol = false;
    bool weak_cipher = false;
    bool legacy_cipher = false;

    for (const auto& item : profiles) {
        if (expired()) {
            error = "cancelled_or_deadline";
            return json::object();
        }
        probe_result_t result = raw_probe(host, port, item);
        probe_by_label[item.label] = result;
        const std::uint16_t selected = result.selected_version ? result.selected_version : result.server_version;
        if (result.got_server_hello) {
            protocol_enabled[version_name(selected)] = true;
            selected_ciphers[result.cipher_suite] = result;
            if (selected == 0x0301 || selected == 0x0302)
                weak_protocol = true;
            if (selected == 0x0303 || selected == 0x0304)
                modern_protocol = true;
            const std::string strength = cipher_strength(result.cipher_suite);
            weak_cipher = weak_cipher || strength == "weak";
            legacy_cipher = legacy_cipher || strength == "legacy";
        }
        raw_probes.push_back(probe_json(result));
    }

    json protocols = json::array();
    const std::array<std::pair<const char*, bool>, 4> protocol_order = {{
        {"TLS 1.3", true}, {"TLS 1.2", true}, {"TLS 1.1", false}, {"TLS 1.0", false}
    }};
    for (const auto& item : protocol_order) {
        json p;
        p["name"] = item.first;
        const bool is_enabled = protocol_enabled[item.first];
        p["enabled"] = is_enabled;
        p["status"] = item.second ? (is_enabled ? "pass" : "warn") : (is_enabled ? "fail" : "pass");
        protocols.push_back(std::move(p));
    }

    json ciphers = json::array();
    for (const auto& item : selected_ciphers) {
        const std::string name = cipher_name(item.first);
        json c;
        c["name"] = name;
        c["code"] = item.first;
        c["key_exchange"] = key_exchange(name);
        c["pfs"] = has_pfs(name);
        c["strength"] = cipher_strength(item.first);
        c["status"] = c["strength"] == "weak" || !c["pfs"].get<bool>() ? "fail" : (c["strength"] == "legacy" ? "warn" : "pass");
        if (!c["pfs"].get<bool>())
            c["issue"] = "No forward secrecy";
        ciphers.push_back(std::move(c));
    }

    json cert_assessment = winhttp_assess(host, port, check_chain, check_ct_logs);
    json certificate = cert_assessment.value("certificate", json::object());
    json hsts = cert_assessment.value("hsts", hsts_json({}));
    json issues = json::array();
    int score = 100;

    if (weak_protocol) {
        score -= 25;
        issues.push_back({{"severity", "high"}, {"description", "TLS 1.0 or TLS 1.1 is supported"}, {"cwe", "CWE-327"}});
        if (persist_findings)
            persist_issue("defensive.tls.weak_protocol", "Weak TLS protocol supported", "TLS 1.0 or TLS 1.1 is supported", "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or TLS 1.3", severity_t::high, host, port, "weak_protocol");
    }
    if (!modern_protocol) {
        score -= 20;
        issues.push_back({{"severity", "high"}, {"description", "No TLS 1.2 or TLS 1.3 evidence from bounded probes"}, {"cwe", "CWE-326"}});
        if (persist_findings)
            persist_issue("defensive.tls.no_modern_protocol", "No modern TLS protocol evidence", "No TLS 1.2 or TLS 1.3 support was observed", "Enable TLS 1.2 or TLS 1.3 with modern AEAD cipher suites", severity_t::high, host, port, "no_modern_protocol");
    }
    if (weak_cipher) {
        score -= 20;
        issues.push_back({{"severity", "high"}, {"description", "Weak cipher suite was negotiated"}, {"cwe", "CWE-327"}});
        if (persist_findings)
            persist_issue("defensive.tls.weak_cipher", "Weak TLS cipher negotiated", "A weak cipher suite was negotiated by a bounded probe", "Disable weak, export, RC4, 3DES, and anonymous cipher suites", severity_t::high, host, port, "weak_cipher");
    } else if (legacy_cipher) {
        score -= 10;
        issues.push_back({{"severity", "medium"}, {"description", "Legacy CBC cipher suite was negotiated"}, {"cwe", "CWE-327"}});
        if (persist_findings)
            persist_issue("defensive.tls.legacy_cipher", "Legacy TLS cipher negotiated", "A CBC cipher suite was negotiated by a bounded probe", "Prefer AEAD cipher suites such as AES-GCM or CHACHA20-POLY1305", severity_t::medium, host, port, "legacy_cipher");
    }
    if (!certificate.empty()) {
        if (certificate.value("chain_valid", true) == false) {
            score -= 20;
            issues.push_back({{"severity", "high"}, {"description", "Certificate chain or hostname validation failed"}, {"cwe", "CWE-295"}});
            if (persist_findings)
                persist_issue("defensive.tls.certificate_chain", "TLS certificate validation finding", "Certificate chain or hostname validation failed", "Serve a valid certificate chain matching the requested hostname", severity_t::high, host, port, "certificate_chain_invalid");
        }
        if (certificate.value("days_remaining", 1ll) < 0) {
            score -= 20;
            issues.push_back({{"severity", "critical"}, {"description", "TLS certificate is expired"}, {"cwe", "CWE-298"}});
            if (persist_findings)
                persist_issue("defensive.tls.certificate_expired", "Expired TLS certificate", "TLS certificate is expired", "Renew and deploy a valid certificate", severity_t::critical, host, port, "certificate_expired");
        } else if (certificate.value("days_remaining", 90ll) < 14) {
            score -= 5;
            issues.push_back({{"severity", "low"}, {"description", "TLS certificate expires within 14 days"}, {"cwe", "CWE-298"}});
        }
    } else {
        score -= 15;
        issues.push_back({{"severity", "medium"}, {"description", "Certificate context could not be collected with WinHTTP"}, {"cwe", "CWE-295"}});
    }
    if (!hsts.value("present", false)) {
        score -= 5;
        issues.push_back({{"severity", "medium"}, {"description", "HSTS header was not observed on HTTPS root"}, {"cwe", "CWE-319"}});
    } else if (hsts.value("status", std::string()) == "warn") {
        score -= 3;
        issues.push_back({{"severity", "low"}, {"description", "HSTS is present but lacks one-year max-age, includeSubDomains, or preload"}, {"cwe", "CWE-319"}});
    }

    score = std::max(0, std::min(100, score));
    json out;
    out["host"] = host;
    out["port"] = port;
    out["grade"] = grade_for_score(score);
    out["score"] = score;
    out["protocols"] = protocols;
    out["cipher_suites"] = ciphers;
    out["certificate"] = certificate;
    out["hsts"] = hsts;
    out["issues"] = issues;
    out["protocol_probes"] = raw_probes;
    out["certificate_assessment"] = cert_assessment;
    out["safe_bounded_probes"] = true;
    out["global_tls_policy_modified"] = false;
    out["assessment_limitations"] = "Protocol and cipher evidence comes from bounded raw ClientHello probes. Certificate and HSTS evidence comes from WinHTTP without disabling certificate validation.";
    return out;
}

}
}
}
