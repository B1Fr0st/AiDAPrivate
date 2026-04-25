

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include "mcp_client.hpp"
#include "auth_store.hpp"
#include "event_bus.hpp"
#include "anti-tamper/webhook.hpp"

#include <httplib.h>
#include <openssl/evp.h>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <thread>
#include <unordered_map>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Crypt32.lib")

extern mcp_client::manager_t s_mcp_client_mgr;

namespace mcp_client
{


static std::mutex& global_mutex()
{
    static std::mutex m;
    return m;
}

static std::string& global_last_error_ref()
{
    static std::string s;
    return s;
}

static void set_global_last_error(const std::string& text)
{
    std::lock_guard<std::mutex> lk(global_mutex());
    global_last_error_ref() = text;
    if (!text.empty()) {
        const std::string line = std::string("[mcp.oauth] ") + text;
        anti_tamper::webhook::write_log("mcp.oauth", line.c_str());
    }
}

const std::string& last_error()
{
    std::lock_guard<std::mutex> lk(global_mutex());
    return global_last_error_ref();
}


static std::string sanitize_utf8(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size();) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result += static_cast<char>(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            result += input[i]; result += input[i + 1]; i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            result += input[i]; result += input[i + 1]; result += input[i + 2]; i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            result += input[i]; result += input[i + 1]; result += input[i + 2]; result += input[i + 3]; i += 4;
        } else {
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

static std::string json_dump_safe(const json& j, int indent = -1)
{
    try { return j.dump(indent); }
    catch (...) { return "{}"; }
}


struct parsed_url_t
{
    std::string scheme;
    std::string host_with_port;
    std::string host;
    int         port = 0;
    bool        is_https = true;
    std::string path;
    std::string origin;
};

static bool parse_url_full(const std::string& url, parsed_url_t& out)
{
    std::string work = url;
    out = parsed_url_t{};

    if (work.rfind("https://", 0) == 0) {
        out.scheme = "https";
        out.is_https = true;
        out.port = 443;
        work = work.substr(8);
    } else if (work.rfind("http://", 0) == 0) {
        out.scheme = "http";
        out.is_https = false;
        out.port = 80;
        work = work.substr(7);
    } else {
        out.scheme = "https";
        out.is_https = true;
        out.port = 443;
    }

    auto slash = work.find('/');
    std::string authority;
    if (slash == std::string::npos) {
        authority = work;
        out.path = "/";
    } else {
        authority = work.substr(0, slash);
        out.path = work.substr(slash);
        if (out.path.empty()) out.path = "/";
    }

    if (authority.empty()) return false;

    auto colon = authority.find(':');
    if (colon != std::string::npos) {
        out.host = authority.substr(0, colon);
        out.port = std::atoi(authority.c_str() + colon + 1);
        if (out.port <= 0) out.port = out.is_https ? 443 : 80;
    } else {
        out.host = authority;
    }

    out.host_with_port = authority;
    out.origin = out.scheme + "://" + authority;
    return !out.host.empty();
}

static bool parse_url(const std::string& url, std::string& host_out, std::string& path_out)
{
    parsed_url_t p;
    if (!parse_url_full(url, p)) {
        host_out = url;
        path_out = "/";
        return true;
    }
    host_out = p.scheme + "://" + p.host_with_port;
    path_out = p.path;
    return true;
}

static int64_t now_unix_seconds()
{
    return static_cast<int64_t>(std::time(nullptr));
}


static bool secure_random_bytes(unsigned char* out, size_t length)
{
    NTSTATUS rc = BCryptGenRandom(nullptr, out, static_cast<ULONG>(length),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return rc == 0;
}

static std::string base64url_encode(const unsigned char* data, size_t length)
{
    static const char kCharset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((length + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= length) {
        const unsigned int v = (static_cast<unsigned int>(data[i]) << 16)
            | (static_cast<unsigned int>(data[i + 1]) << 8)
            | static_cast<unsigned int>(data[i + 2]);
        out.push_back(kCharset[(v >> 18) & 0x3F]);
        out.push_back(kCharset[(v >> 12) & 0x3F]);
        out.push_back(kCharset[(v >> 6) & 0x3F]);
        out.push_back(kCharset[v & 0x3F]);
        i += 3;
    }
    if (i < length) {
        const size_t left = length - i;
        unsigned int v = static_cast<unsigned int>(data[i]) << 16;
        if (left == 2)
            v |= static_cast<unsigned int>(data[i + 1]) << 8;
        out.push_back(kCharset[(v >> 18) & 0x3F]);
        out.push_back(kCharset[(v >> 12) & 0x3F]);
        if (left == 2)
            out.push_back(kCharset[(v >> 6) & 0x3F]);
    }
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    return out;
}

static std::string generate_pkce_verifier()
{
    static const char kVerifierCharset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    constexpr size_t kLen = 43;
    unsigned char rnd[kLen];
    if (!secure_random_bytes(rnd, kLen))
        return {};
    const size_t charset_len = std::strlen(kVerifierCharset);
    std::string out;
    out.reserve(kLen);
    for (size_t i = 0; i < kLen; ++i)
        out.push_back(kVerifierCharset[rnd[i] % charset_len]);
    return out;
}

static std::string sha256_base64url(const std::string& input)
{
    unsigned char digest[32] = {};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return {};
    std::string out;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1
        && EVP_DigestUpdate(ctx, input.data(), input.size()) == 1) {
        unsigned int dl = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &dl) == 1)
            out = base64url_encode(digest, dl);
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

static std::string generate_state_token()
{
    unsigned char rnd[32] = {};
    if (!secure_random_bytes(rnd, sizeof(rnd)))
        return {};
    return base64url_encode(rnd, sizeof(rnd));
}

static std::string url_encode(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            char buf[4];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%%%02X", c);
            out.append(buf);
        }
    }
    return out;
}


static bool ensure_winsock()
{
    static std::once_flag once;
    static int rc = 0;
    std::call_once(once, []() {
        WSADATA wsa{};
        rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    });
    return rc == 0;
}

static bool open_browser(const std::string& url)
{
    const int wlen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(),
        static_cast<int>(url.size()), nullptr, 0);
    if (wlen <= 0)
        return false;
    std::wstring wurl(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), static_cast<int>(url.size()),
        wurl.data(), wlen);
    HINSTANCE rc = ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr,
        nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}


struct callback_listener_t
{
    SOCKET            sock = INVALID_SOCKET;
    std::thread       worker;
    std::atomic<bool> stop{false};
    int               bound_port = 0;
};

static std::map<std::string, std::string>
parse_query_string(const std::string& query)
{
    std::map<std::string, std::string> out;
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        const std::string pair = query.substr(pos, amp - pos);
        const size_t eq = pair.find('=');
        std::string key = (eq == std::string::npos) ? pair : pair.substr(0, eq);
        std::string val = (eq == std::string::npos) ? std::string{} : pair.substr(eq + 1);
        std::string decoded;
        decoded.reserve(val.size());
        for (size_t i = 0; i < val.size(); ++i) {
            if (val[i] == '+') {
                decoded.push_back(' ');
            } else if (val[i] == '%' && i + 2 < val.size()) {
                const std::string hex = val.substr(i + 1, 2);
                try {
                    decoded.push_back(static_cast<char>(std::stoi(hex, nullptr, 16)));
                } catch (...) {
                    decoded.push_back(val[i]);
                    continue;
                }
                i += 2;
            } else {
                decoded.push_back(val[i]);
            }
        }
        out[key] = decoded;
        pos = amp + 1;
    }
    return out;
}

static std::string build_callback_response_html_success()
{
    return std::string(
        "<!doctype html><html><head><title>AiDA MCP Authorization Successful</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;"
        "justify-content:center;align-items:center;height:100vh;margin:0;"
        "background:#131010;color:#f1ecec}.container{text-align:center;padding:2rem}"
        "h1{color:#4ade80;margin-bottom:1rem}p{color:#b7b1b1}</style></head><body>"
        "<div class=\"container\"><h1>Authorization Successful</h1>"
        "<p>You can close this window and return to AiDA.</p></div>"
        "<script>setTimeout(function(){window.close();},2000);</script></body></html>");
}

static std::string build_callback_response_html_failure(const std::string& reason)
{
    std::string esc;
    esc.reserve(reason.size() + 16);
    for (char c : reason) {
        switch (c) {
            case '<': esc += "&lt;"; break;
            case '>': esc += "&gt;"; break;
            case '&': esc += "&amp;"; break;
            case '"': esc += "&quot;"; break;
            default: esc.push_back(c); break;
        }
    }
    return std::string(
        "<!doctype html><html><head><title>AiDA MCP Authorization Failed</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;"
        "justify-content:center;align-items:center;height:100vh;margin:0;"
        "background:#131010;color:#f1ecec}.container{text-align:center;padding:2rem}"
        "h1{color:#fc533a;margin-bottom:1rem}p{color:#b7b1b1}.error{color:#ff917b;"
        "font-family:monospace;margin-top:1rem;padding:1rem;background:#3c140d;"
        "border-radius:0.5rem}</style></head><body><div class=\"container\">"
        "<h1>Authorization Failed</h1><p>An error occurred during authorization.</p>"
        "<div class=\"error\">") + esc
        + "</div></div></body></html>";
}

static void send_listener_response(SOCKET client, int status, const std::string& body)
{
    std::string status_text;
    switch (status) {
        case 200: status_text = "OK"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        default: status_text = "OK"; break;
    }
    std::string resp = "HTTP/1.1 " + std::to_string(status) + " " + status_text + "\r\n";
    resp += "Content-Type: text/html; charset=utf-8\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n";
    resp += "Server: AiDA/1.0\r\n";
    resp += "\r\n";
    resp += body;
    ::send(client, resp.data(), static_cast<int>(resp.size()), 0);
}

static void oauth_listener_thread(oauth_state_t* state, std::shared_ptr<callback_listener_t> ctx)
{
    while (!ctx->stop.load() && !state->cancelled.load()) {
        WSAPOLLFD pfd{};
        pfd.fd = ctx->sock;
        pfd.events = POLLIN;
        int rc = WSAPoll(&pfd, 1, 250);
        if (rc <= 0)
            continue;

        sockaddr_storage cli{};
        int cli_len = sizeof(cli);
        SOCKET client = accept(ctx->sock, reinterpret_cast<sockaddr*>(&cli), &cli_len);
        if (client == INVALID_SOCKET)
            continue;

        DWORD tv = 5000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
            reinterpret_cast<const char*>(&tv), sizeof(tv));

        std::string raw;
        raw.reserve(2048);
        char buf[1024];
        for (int i = 0; i < 32; ++i) {
            int n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0)
                break;
            raw.append(buf, n);
            if (raw.find("\r\n\r\n") != std::string::npos)
                break;
            if (raw.size() > 16384)
                break;
        }

        const size_t first_space = raw.find(' ');
        const size_t second_space = (first_space == std::string::npos)
            ? std::string::npos
            : raw.find(' ', first_space + 1);
        if (first_space == std::string::npos || second_space == std::string::npos) {
            send_listener_response(client, 400,
                build_callback_response_html_failure("malformed request"));
            closesocket(client);
            continue;
        }

        const std::string target = raw.substr(first_space + 1, second_space - first_space - 1);
        const size_t qpos = target.find('?');
        const std::string path_part = (qpos == std::string::npos) ? target : target.substr(0, qpos);
        const std::string query_str = (qpos == std::string::npos) ? std::string{} : target.substr(qpos + 1);

        if (path_part != "/mcp/oauth/callback" && path_part != "/auth/callback") {
            send_listener_response(client, 404,
                build_callback_response_html_failure("not found"));
            closesocket(client);
            continue;
        }

        const auto params = parse_query_string(query_str);

        const auto err_it = params.find("error");
        if (err_it != params.end()) {
            std::string detail = err_it->second;
            const auto desc_it = params.find("error_description");
            if (desc_it != params.end())
                detail += ": " + desc_it->second;
            state->error = detail;
            send_listener_response(client, 200,
                build_callback_response_html_failure(detail));
            closesocket(client);
            state->done.store(true);
            return;
        }

        const auto code_it = params.find("code");
        const auto state_it = params.find("state");
        if (code_it == params.end() || state_it == params.end()) {
            state->error = "missing code or state";
            send_listener_response(client, 400,
                build_callback_response_html_failure("missing code or state"));
            closesocket(client);
            state->done.store(true);
            return;
        }

        if (state_it->second != state->state_token) {
            state->error = "state mismatch (csrf)";
            send_listener_response(client, 400,
                build_callback_response_html_failure("state mismatch"));
            closesocket(client);
            state->done.store(true);
            return;
        }

        state->received_code = code_it->second;
        send_listener_response(client, 200,
            build_callback_response_html_success());
        closesocket(client);
        state->done.store(true);
        return;
    }
}

static bool start_oauth_listener(oauth_state_t& state)
{
    if (!ensure_winsock()) {
        state.error = "winsock init failed";
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        state.error = "socket() failed wsa=" + std::to_string(WSAGetLastError());
        return false;
    }

    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        const int wsa = WSAGetLastError();
        closesocket(s);
        state.error = "bind 127.0.0.1:0 failed wsa=" + std::to_string(wsa);
        return false;
    }

    sockaddr_in bound_addr{};
    int bound_len = sizeof(bound_addr);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound_addr), &bound_len) == SOCKET_ERROR) {
        const int wsa = WSAGetLastError();
        closesocket(s);
        state.error = "getsockname failed wsa=" + std::to_string(wsa);
        return false;
    }
    state.callback_port = ntohs(bound_addr.sin_port);

    if (listen(s, 4) == SOCKET_ERROR) {
        const int wsa = WSAGetLastError();
        closesocket(s);
        state.error = "listen failed wsa=" + std::to_string(wsa);
        return false;
    }

    auto ctx = std::make_shared<callback_listener_t>();
    ctx->sock = s;
    ctx->bound_port = state.callback_port;
    auto holder = std::make_unique<std::shared_ptr<callback_listener_t>>(ctx);

    state.listener_handle = holder.release();
    ctx->worker = std::thread(oauth_listener_thread, &state, ctx);
    return true;
}

static void stop_oauth_listener(oauth_state_t& state)
{
    if (!state.listener_handle)
        return;
    std::unique_ptr<std::shared_ptr<callback_listener_t>> holder(
        static_cast<std::shared_ptr<callback_listener_t>*>(state.listener_handle));
    state.listener_handle = nullptr;
    (*holder)->stop.store(true);
    if ((*holder)->sock != INVALID_SOCKET) {
        closesocket((*holder)->sock);
        (*holder)->sock = INVALID_SOCKET;
    }
    if ((*holder)->worker.joinable())
        (*holder)->worker.join();
}


static httplib::Result do_https_get(const parsed_url_t& url, const httplib::Headers& hdrs)
{
    httplib::Client cli(url.origin);
    cli.set_connection_timeout(15);
    cli.set_read_timeout(30);
    cli.set_write_timeout(15);
    cli.enable_server_certificate_verification(false);
    cli.set_follow_location(true);
    return cli.Get(url.path, hdrs);
}

static httplib::Result do_https_post(const std::string& origin, const std::string& path,
                                     const httplib::Headers& hdrs,
                                     const std::string& body, const std::string& content_type)
{
    httplib::Client cli(origin);
    cli.set_connection_timeout(15);
    cli.set_read_timeout(30);
    cli.set_write_timeout(15);
    cli.enable_server_certificate_verification(false);
    cli.set_follow_location(true);
    return cli.Post(path.c_str(), hdrs, body, content_type.c_str());
}


static bool fetch_oauth_metadata(const parsed_url_t& server_url,
                                 std::string& token_endpoint,
                                 std::string& authorization_endpoint,
                                 std::string& registration_endpoint)
{
    const std::string well_known_path = "/.well-known/oauth-authorization-server";
    parsed_url_t metadata_url = server_url;
    metadata_url.path = well_known_path;

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };
    auto res = do_https_get(metadata_url, headers);
    if (!res || res->status < 200 || res->status >= 300) {
        return false;
    }

    json doc = json::parse(res->body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) return false;

    if (doc.contains("token_endpoint") && doc["token_endpoint"].is_string())
        token_endpoint = doc["token_endpoint"].get<std::string>();
    if (doc.contains("authorization_endpoint") && doc["authorization_endpoint"].is_string())
        authorization_endpoint = doc["authorization_endpoint"].get<std::string>();
    if (doc.contains("registration_endpoint") && doc["registration_endpoint"].is_string())
        registration_endpoint = doc["registration_endpoint"].get<std::string>();

    return !token_endpoint.empty() && !authorization_endpoint.empty();
}

static bool register_dynamic_client(const std::string& registration_endpoint,
                                    const std::string& redirect_uri,
                                    std::string& client_id_out,
                                    std::string& client_secret_out,
                                    std::string& error_out)
{
    parsed_url_t reg;
    if (!parse_url_full(registration_endpoint, reg)) {
        error_out = "invalid registration_endpoint url";
        return false;
    }

    json req = {
        { "redirect_uris", json::array({ redirect_uri }) },
        { "client_name", "AiDA Standalone" },
        { "client_uri", "https://aidapro.net" },
        { "grant_types", json::array({ "authorization_code", "refresh_token" }) },
        { "response_types", json::array({ "code" }) },
        { "token_endpoint_auth_method", "none" }
    };

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };

    auto res = do_https_post(reg.origin, reg.path, headers, req.dump(), "application/json");
    if (!res) {
        error_out = "registration unreachable: " + httplib::to_string(res.error());
        return false;
    }
    if (res->status < 200 || res->status >= 300) {
        error_out = "registration status=" + std::to_string(res->status)
            + " body=" + res->body.substr(0, 256);
        return false;
    }

    json doc = json::parse(res->body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        error_out = "registration response not json";
        return false;
    }

    if (!doc.contains("client_id") || !doc["client_id"].is_string()) {
        error_out = "registration response missing client_id";
        return false;
    }
    client_id_out = doc["client_id"].get<std::string>();
    if (doc.contains("client_secret") && doc["client_secret"].is_string())
        client_secret_out = doc["client_secret"].get<std::string>();
    return true;
}

static std::string build_authorize_url(const std::string& authorize_endpoint,
                                       const std::string& client_id,
                                       const std::string& redirect_uri,
                                       const std::string& scope,
                                       const std::string& code_challenge,
                                       const std::string& state_token)
{
    std::string url = authorize_endpoint;
    url += (authorize_endpoint.find('?') == std::string::npos) ? "?" : "&";
    url += "response_type=code";
    url += "&client_id=" + url_encode(client_id);
    url += "&redirect_uri=" + url_encode(redirect_uri);
    if (!scope.empty()) url += "&scope=" + url_encode(scope);
    url += "&code_challenge=" + url_encode(code_challenge);
    url += "&code_challenge_method=S256";
    url += "&state=" + url_encode(state_token);
    return url;
}

static bool exchange_authorization_code(const std::string& token_endpoint,
                                        const std::string& client_id,
                                        const std::string& client_secret,
                                        const std::string& redirect_uri,
                                        const std::string& code,
                                        const std::string& code_verifier,
                                        std::string& access_out,
                                        std::string& refresh_out,
                                        int64_t& expires_in_out,
                                        std::string& scope_out,
                                        std::string& error_out)
{
    parsed_url_t te;
    if (!parse_url_full(token_endpoint, te)) {
        error_out = "invalid token_endpoint url";
        return false;
    }

    std::string body = "grant_type=authorization_code";
    body += "&code=" + url_encode(code);
    body += "&redirect_uri=" + url_encode(redirect_uri);
    body += "&client_id=" + url_encode(client_id);
    body += "&code_verifier=" + url_encode(code_verifier);
    if (!client_secret.empty())
        body += "&client_secret=" + url_encode(client_secret);

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };

    auto res = do_https_post(te.origin, te.path, headers, body,
        "application/x-www-form-urlencoded");
    if (!res) {
        error_out = "token endpoint unreachable: " + httplib::to_string(res.error());
        return false;
    }
    if (res->status < 200 || res->status >= 300) {
        error_out = "token endpoint status=" + std::to_string(res->status)
            + " body=" + res->body.substr(0, 256);
        return false;
    }
    json doc = json::parse(res->body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        error_out = "token response not json";
        return false;
    }

    access_out = doc.value("access_token", std::string{});
    refresh_out = doc.value("refresh_token", std::string{});
    expires_in_out = doc.value("expires_in", static_cast<int64_t>(3600));
    scope_out = doc.value("scope", std::string{});
    if (access_out.empty()) {
        error_out = "token response missing access_token";
        return false;
    }
    return true;
}

static bool refresh_authorization_token(const std::string& token_endpoint,
                                        const std::string& client_id,
                                        const std::string& client_secret,
                                        const std::string& refresh_token,
                                        std::string& access_out,
                                        std::string& refresh_out,
                                        int64_t& expires_in_out,
                                        std::string& scope_out,
                                        std::string& error_out)
{
    parsed_url_t te;
    if (!parse_url_full(token_endpoint, te)) {
        error_out = "invalid token_endpoint url";
        return false;
    }

    std::string body = "grant_type=refresh_token";
    body += "&refresh_token=" + url_encode(refresh_token);
    body += "&client_id=" + url_encode(client_id);
    if (!client_secret.empty())
        body += "&client_secret=" + url_encode(client_secret);

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };

    auto res = do_https_post(te.origin, te.path, headers, body,
        "application/x-www-form-urlencoded");
    if (!res) {
        error_out = "refresh endpoint unreachable: " + httplib::to_string(res.error());
        return false;
    }
    if (res->status < 200 || res->status >= 300) {
        error_out = "refresh endpoint status=" + std::to_string(res->status)
            + " body=" + res->body.substr(0, 256);
        return false;
    }
    json doc = json::parse(res->body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        error_out = "refresh response not json";
        return false;
    }
    access_out = doc.value("access_token", std::string{});
    refresh_out = doc.value("refresh_token", refresh_token);
    expires_in_out = doc.value("expires_in", static_cast<int64_t>(3600));
    scope_out = doc.value("scope", std::string{});
    if (access_out.empty()) {
        error_out = "refresh response missing access_token";
        return false;
    }
    return true;
}


static std::string mcp_auth_key(const std::string& server_name)
{
    return std::string("mcp:") + server_name;
}

static bool load_mcp_auth(const std::string& server_name, aida::auth::auth_info_t& out)
{
    return aida::auth::store::get(mcp_auth_key(server_name), out);
}

static bool save_mcp_auth(const std::string& server_name, const aida::auth::auth_info_t& info)
{
    return aida::auth::store::set(mcp_auth_key(server_name), info);
}

static bool delete_mcp_auth(const std::string& server_name)
{
    return aida::auth::store::remove(mcp_auth_key(server_name));
}


client_t::client_t() = default;

client_t::~client_t()
{
    disconnect();
}

client_t::client_t(client_t&& o) noexcept
{
    std::lock_guard<std::mutex> lk(o._mtx);
    _cfg              = std::move(o._cfg);
    _state            = o._state;
    _server_name_str  = std::move(o._server_name_str);
    _server_version   = std::move(o._server_version);
    _last_error       = std::move(o._last_error);
    _cached_tools     = std::move(o._cached_tools);
    _next_id          = o._next_id;
    _transport_mode   = o._transport_mode;
    _sse_session_id   = std::move(o._sse_session_id);
    _sse_post_path    = std::move(o._sse_post_path);
    _streamable_session_id = std::move(o._streamable_session_id);
    _oauth_status     = o._oauth_status;
    _oauth_token_endpoint = std::move(o._oauth_token_endpoint);
    _oauth_authorization_endpoint = std::move(o._oauth_authorization_endpoint);
    _oauth_registration_endpoint = std::move(o._oauth_registration_endpoint);
    _oauth_resource_metadata_url = std::move(o._oauth_resource_metadata_url);
    _oauth_realm      = std::move(o._oauth_realm);
    _child_process    = o._child_process;
    _child_stdin_w    = o._child_stdin_w;
    _child_stdout_r   = o._child_stdout_r;
    o._child_process  = nullptr;
    o._child_stdin_w  = nullptr;
    o._child_stdout_r = nullptr;
    o._state          = connection_state_t::disconnected;
    o._oauth_status   = oauth_status_t::not_required;
    o._transport_mode = transport_mode_t::auto_detect;
}

client_t& client_t::operator=(client_t&& o) noexcept
{
    if (this != &o) {
        disconnect();
        std::lock_guard<std::mutex> lk(o._mtx);
        std::lock_guard<std::mutex> lk2(_mtx);
        _cfg              = std::move(o._cfg);
        _state            = o._state;
        _server_name_str  = std::move(o._server_name_str);
        _server_version   = std::move(o._server_version);
        _last_error       = std::move(o._last_error);
        _cached_tools     = std::move(o._cached_tools);
        _next_id          = o._next_id;
        _transport_mode   = o._transport_mode;
        _sse_session_id   = std::move(o._sse_session_id);
        _sse_post_path    = std::move(o._sse_post_path);
        _streamable_session_id = std::move(o._streamable_session_id);
        _oauth_status     = o._oauth_status;
        _oauth_token_endpoint = std::move(o._oauth_token_endpoint);
        _oauth_authorization_endpoint = std::move(o._oauth_authorization_endpoint);
        _oauth_registration_endpoint = std::move(o._oauth_registration_endpoint);
        _oauth_resource_metadata_url = std::move(o._oauth_resource_metadata_url);
        _oauth_realm      = std::move(o._oauth_realm);
        _child_process    = o._child_process;
        _child_stdin_w    = o._child_stdin_w;
        _child_stdout_r   = o._child_stdout_r;
        o._child_process  = nullptr;
        o._child_stdin_w  = nullptr;
        o._child_stdout_r = nullptr;
        o._state          = connection_state_t::disconnected;
        o._oauth_status   = oauth_status_t::not_required;
        o._transport_mode = transport_mode_t::auto_detect;
    }
    return *this;
}

bool client_t::connect(const server_config_t& cfg)
{
    std::lock_guard<std::mutex> lk(_mtx);


    if (_state == connection_state_t::connected)
    {

        _mtx.unlock();
        disconnect();
        _mtx.lock();
    }

    _cfg   = cfg;
    _state = connection_state_t::connecting;
    _last_error.clear();
    _cached_tools.clear();
    _transport_mode = transport_mode_t::auto_detect;
    _sse_session_id.clear();
    _streamable_session_id.clear();
    _sse_post_path.clear();
    _oauth_status = oauth_status_t::not_required;


    if (_cfg.transport == transport_type_t::stdio) {
        if (!launch_stdio_process()) {
            _state = connection_state_t::error;
            return false;
        }
        _transport_mode = transport_mode_t::stdio_local;
        return perform_initialize_locked();
    }

    return perform_remote_handshake();
}

bool client_t::perform_remote_handshake()
{
    parsed_url_t purl;
    if (!parse_url_full(_cfg.url, purl)) {
        _last_error = "Invalid MCP server URL: " + _cfg.url;
        _state = connection_state_t::error;
        return false;
    }

    httplib::Headers probe_headers = {
        { "Content-Type", "application/json" },
        { "Accept", "text/event-stream, application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };
    if (!_cfg.api_key.empty())
        probe_headers.emplace("Authorization", "Bearer " + _cfg.api_key);
    aida::auth::auth_info_t stored;
    if (load_mcp_auth(_cfg.name, stored) && !stored.access.empty()) {
        if (!_cfg.api_key.empty()) {
            for (auto it = probe_headers.begin(); it != probe_headers.end();) {
                if (it->first == "Authorization") it = probe_headers.erase(it);
                else ++it;
            }
        }
        probe_headers.emplace("Authorization", "Bearer " + stored.access);
    }

    json init_req = rpc_request("initialize", {
        {"protocolVersion", "2024-11-05"},
        {"capabilities", {{"roots", {{"listChanged", true}}}, {"sampling", json::object()}}},
        {"clientInfo", {
            {"name", "AiDA Standalone"},
            {"version", "1.0.0"}
        }}
    });
    const std::string init_body = json_dump_safe(init_req);

    auto streamable_res = do_https_post(purl.origin, purl.path, probe_headers,
        init_body, "application/json");

    if (streamable_res) {
        const int sc = streamable_res->status;
        const std::string& sb = streamable_res->body;
        if (sc == 401 || sc == 403) {
            std::string www_auth;
            for (const auto& h : streamable_res->headers) {
                if (_stricmp(h.first.c_str(), "WWW-Authenticate") == 0) {
                    www_auth = h.second;
                    break;
                }
            }
            detect_oauth_metadata(www_auth);
            _oauth_status = oauth_status_t::needs_auth;
            _last_error = "MCP server requires OAuth authentication";
            _state = connection_state_t::error;
            return false;
        }
        if (sc >= 200 && sc < 300) {
            json response = json::parse(sb, nullptr, false);
            if (!response.is_discarded() && response.is_object()) {
                _transport_mode = transport_mode_t::streamable_http;
                for (const auto& h : streamable_res->headers) {
                    if (_stricmp(h.first.c_str(), "Mcp-Session-Id") == 0) {
                        _streamable_session_id = h.second;
                        break;
                    }
                }
                if (response.contains("error")) {
                    _last_error = response["error"].value("message", "Initialize error");
                    _state = connection_state_t::error;
                    return false;
                }
                if (response.contains("result")) {
                    const auto& result = response["result"];
                    if (result.contains("serverInfo")) {
                        _server_name_str = result["serverInfo"].value("name", _cfg.name);
                        _server_version  = result["serverInfo"].value("version", "");
                    }
                }
                if (_server_name_str.empty()) _server_name_str = _cfg.name;
                json notif;
                notif["jsonrpc"] = "2.0";
                notif["method"]  = "notifications/initialized";
                try { send_rpc(notif); } catch (...) {}
                _state = connection_state_t::connected;
                _oauth_status = stored.access.empty() ? oauth_status_t::not_required : oauth_status_t::authenticated;
                return true;
            }
        }
        if (sc != 405 && sc != 406 && sc != 404) {
            _last_error = "StreamableHTTP HTTP " + std::to_string(sc) + ": " + sb.substr(0, 256);
        }
    } else {
        _last_error = "StreamableHTTP request failed: " + httplib::to_string(streamable_res.error());
    }

    _transport_mode = transport_mode_t::sse_legacy;
    _sse_post_path = purl.path;
    if (_sse_post_path.empty() || _sse_post_path == "/") _sse_post_path = "/message";

    return perform_initialize_locked();
}

bool client_t::detect_oauth_metadata(const std::string& www_authenticate_hdr)
{
    parsed_url_t server_url;
    if (!parse_url_full(_cfg.url, server_url)) return false;

    if (!www_authenticate_hdr.empty()) {
        const std::string lower = [&]() {
            std::string s = www_authenticate_hdr;
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
            return s;
        }();
        size_t realm_pos = lower.find("realm=");
        if (realm_pos != std::string::npos) {
            size_t start = realm_pos + 6;
            if (start < www_authenticate_hdr.size() && www_authenticate_hdr[start] == '"') start++;
            size_t end = www_authenticate_hdr.size();
            for (size_t i = start; i < www_authenticate_hdr.size(); ++i) {
                if (www_authenticate_hdr[i] == '"' || www_authenticate_hdr[i] == ',') { end = i; break; }
            }
            _oauth_realm = www_authenticate_hdr.substr(start, end - start);
        }
        size_t resource_pos = lower.find("resource_metadata=");
        if (resource_pos != std::string::npos) {
            size_t start = resource_pos + 18;
            if (start < www_authenticate_hdr.size() && www_authenticate_hdr[start] == '"') start++;
            size_t end = www_authenticate_hdr.size();
            for (size_t i = start; i < www_authenticate_hdr.size(); ++i) {
                if (www_authenticate_hdr[i] == '"' || www_authenticate_hdr[i] == ',') { end = i; break; }
            }
            _oauth_resource_metadata_url = www_authenticate_hdr.substr(start, end - start);
        }
    }

    std::string te, ae, re;
    if (fetch_oauth_metadata(server_url, te, ae, re)) {
        _oauth_token_endpoint = te;
        _oauth_authorization_endpoint = ae;
        _oauth_registration_endpoint = re;
        return true;
    }
    return false;
}

bool client_t::perform_initialize_locked()
{
    json init_req = rpc_request("initialize", {
        {"protocolVersion", "2024-11-05"},
        {"capabilities", {}},
        {"clientInfo", {
            {"name", "AiDA Standalone"},
            {"version", "1.0.0"}
        }}
    });

    json response;
    try {
        response = send_rpc(init_req);
    } catch (const std::exception& e) {
        _last_error = std::string("Initialize failed: ") + e.what();
        _state = connection_state_t::error;
        kill_stdio_process();
        return false;
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "Unknown initialization error");
        _state = connection_state_t::error;
        kill_stdio_process();
        return false;
    }


    if (response.contains("result")) {
        const auto& result = response["result"];
        if (result.contains("serverInfo")) {
            _server_name_str = result["serverInfo"].value("name", _cfg.name);
            _server_version  = result["serverInfo"].value("version", "");
        }
    }

    if (_server_name_str.empty())
        _server_name_str = _cfg.name;


    json notif;
    notif["jsonrpc"] = "2.0";
    notif["method"]  = "notifications/initialized";
    try {
        send_rpc(notif);
    } catch (...) {

    }

    _state = connection_state_t::connected;
    return true;
}

void client_t::disconnect()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state == connection_state_t::disconnected)
        return;

    kill_stdio_process();
    _state = connection_state_t::disconnected;
    _cached_tools.clear();
    _streamable_session_id.clear();
    _sse_session_id.clear();
    _sse_post_path.clear();
}

bool client_t::reconnect()
{
    server_config_t cfg;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        cfg = _cfg;
    }
    disconnect();
    return connect(cfg);
}

std::vector<remote_tool_t> client_t::list_tools()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        _last_error = "Not connected";
        return {};
    }

    json req = rpc_request("tools/list");
    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        _last_error = std::string("tools/list failed: ") + e.what();
        return _cached_tools;
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "tools/list error");
        return _cached_tools;
    }

    _cached_tools.clear();
    if (response.contains("result") && response["result"].contains("tools")) {
        for (const auto& t : response["result"]["tools"]) {
            remote_tool_t tool;
            tool.server_name  = _server_name_str;
            tool.name         = t.value("name", "");
            tool.description  = t.value("description", "");
            if (t.contains("inputSchema"))
                tool.input_schema = t["inputSchema"];
            if (t.contains("annotations"))
                tool.annotations = t["annotations"];
            if (!tool.name.empty())
                _cached_tools.push_back(std::move(tool));
        }
    }

    return _cached_tools;
}

call_result_t client_t::call_tool(const std::string& tool_name, const json& arguments)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return call_result_t::error("Not connected to " + _cfg.name);

    json req = rpc_request("tools/call", {
        {"name", tool_name},
        {"arguments", arguments}
    });

    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        return call_result_t::error(std::string("tools/call failed: ") + e.what());
    }

    if (response.contains("error")) {
        return call_result_t::error(
            response["error"].value("message", "Tool execution error"));
    }

    if (!response.contains("result"))
        return call_result_t::error("Empty result from server");

    const auto& result = response["result"];


    std::string text;
    json data;
    if (result.contains("content") && result["content"].is_array()) {
        for (const auto& block : result["content"]) {
            if (block.value("type", "") == "text") {
                if (!text.empty()) text += "\n";
                text += block.value("text", "");
            } else {

                if (data.is_null()) data = json::array();
                data.push_back(block);
            }
        }
    }

    bool is_error = result.value("isError", false);
    if (is_error)
        return call_result_t::error(text.empty() ? "Tool returned error" : text);

    return call_result_t::ok(sanitize_utf8(text), data);
}

std::vector<remote_resource_t> client_t::list_resources()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return {};

    json req = rpc_request("resources/list");
    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        _last_error = std::string("resources/list failed: ") + e.what();
        return {};
    }

    std::vector<remote_resource_t> resources;
    if (response.contains("result") && response["result"].contains("resources")) {
        for (const auto& r : response["result"]["resources"]) {
            remote_resource_t res;
            res.server_name = _server_name_str;
            res.uri         = r.value("uri", "");
            res.name        = r.value("name", "");
            res.description = r.value("description", "");
            res.mime_type   = r.value("mimeType", "");
            if (!res.uri.empty())
                resources.push_back(std::move(res));
        }
    }

    return resources;
}

std::string client_t::read_resource(const std::string& uri)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return {};

    json req = rpc_request("resources/read", {{"uri", uri}});
    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        _last_error = std::string("resources/read failed: ") + e.what();
        return {};
    }

    if (response.contains("result") && response["result"].contains("contents")) {
        const auto& contents = response["result"]["contents"];
        if (contents.is_array() && !contents.empty()) {
            return contents[0].value("text", json_dump_safe(contents[0]));
        }
    }

    return {};
}

bool client_t::is_connected() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _state == connection_state_t::connected;
}

connection_state_t client_t::state() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _state;
}

const std::string& client_t::server_name() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _server_name_str;
}

const std::string& client_t::last_error() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _last_error;
}

const server_config_t& client_t::config() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _cfg;
}

const std::vector<remote_tool_t>& client_t::cached_tools() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _cached_tools;
}

oauth_status_t client_t::oauth_status() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _oauth_status;
}

transport_mode_t client_t::active_transport_mode() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _transport_mode;
}


json client_t::rpc_request(const std::string& method, const json& params)
{

    json req;
    req["jsonrpc"] = "2.0";
    req["method"]  = method;


    if (method.find("notifications/") == std::string::npos)
        req["id"] = _next_id++;

    if (!params.is_null() && !params.empty())
        req["params"] = params;

    return req;
}

json client_t::send_rpc(const json& request)
{

    switch (_cfg.transport) {
    case transport_type_t::http_sse:
        return send_http(request);
    case transport_type_t::stdio:
        return send_stdio(request);
    default:
        throw std::runtime_error("Unsupported transport type");
    }
}

bool client_t::ensure_access_token_fresh_locked()
{
    if (_cfg.transport == transport_type_t::stdio) return true;

    aida::auth::auth_info_t info;
    if (!load_mcp_auth(_cfg.name, info)) return true;
    if (info.kind != aida::auth::auth_kind_t::oauth) return true;
    if (info.access.empty()) return true;
    if (info.expires_unix == 0) return true;

    const int64_t now = now_unix_seconds();
    if (now < info.expires_unix - 30) return true;

    return refresh_access_token_locked();
}

bool client_t::refresh_access_token_locked()
{
    aida::auth::auth_info_t info;
    if (!load_mcp_auth(_cfg.name, info) || info.kind != aida::auth::auth_kind_t::oauth) {
        _oauth_status = oauth_status_t::needs_auth;
        return false;
    }
    if (info.refresh.empty()) {
        _oauth_status = oauth_status_t::needs_auth;
        return false;
    }

    std::string token_endpoint = info.metadata.value("token_endpoint", std::string{});
    std::string client_id      = info.metadata.value("client_id", std::string{});
    std::string client_secret  = info.metadata.value("client_secret", std::string{});

    if (token_endpoint.empty() || client_id.empty()) {
        _oauth_status = oauth_status_t::needs_auth;
        return false;
    }

    std::string new_access, new_refresh, new_scope, err;
    int64_t expires_in = 3600;

    if (!refresh_authorization_token(token_endpoint, client_id, client_secret,
            info.refresh, new_access, new_refresh, expires_in, new_scope, err)) {
        _last_error = err;
        _oauth_status = oauth_status_t::needs_auth;
        return false;
    }

    info.access = new_access;
    info.refresh = new_refresh;
    info.expires_unix = now_unix_seconds() + expires_in;
    if (!new_scope.empty()) info.metadata["scope"] = new_scope;
    save_mcp_auth(_cfg.name, info);
    _oauth_status = oauth_status_t::authenticated;
    return true;
}


json client_t::send_http(const json& request)
{
    ensure_access_token_fresh_locked();

    parsed_url_t purl;
    if (!parse_url_full(_cfg.url, purl))
        throw std::runtime_error("Invalid MCP server URL: " + _cfg.url);

    httplib::Headers headers = {
        {"Content-Type", "application/json"}
    };
    if (_transport_mode == transport_mode_t::streamable_http)
        headers.emplace("Accept", "text/event-stream, application/json");
    else
        headers.emplace("Accept", "application/json");
    headers.emplace("User-Agent", "AiDA-MCP/1.0");

    aida::auth::auth_info_t stored;
    if (load_mcp_auth(_cfg.name, stored) && !stored.access.empty()) {
        headers.emplace("Authorization", "Bearer " + stored.access);
    } else if (!_cfg.api_key.empty()) {
        headers.emplace("Authorization", "Bearer " + _cfg.api_key);
    }

    if (!_streamable_session_id.empty())
        headers.emplace("Mcp-Session-Id", _streamable_session_id);

    const std::string body = json_dump_safe(request);

    std::string post_path = purl.path;
    if (_transport_mode == transport_mode_t::sse_legacy && !_sse_post_path.empty())
        post_path = _sse_post_path;

    auto res = do_https_post(purl.origin, post_path, headers, body, "application/json");
    if (!res)
        throw std::runtime_error("HTTP request failed: " + httplib::to_string(res.error()));

    if (res->status == 401 || res->status == 403) {
        std::string www_auth;
        for (const auto& h : res->headers) {
            if (_stricmp(h.first.c_str(), "WWW-Authenticate") == 0) {
                www_auth = h.second;
                break;
            }
        }
        detect_oauth_metadata(www_auth);
        _oauth_status = oauth_status_t::needs_auth;
        throw std::runtime_error("HTTP " + std::to_string(res->status)
            + ": MCP server requires OAuth authentication");
    }

    if (res->status < 200 || res->status >= 300)
        throw std::runtime_error("HTTP " + std::to_string(res->status) + ": " + res->body);


    json response = json::parse(res->body, nullptr, false);
    if (response.is_discarded()) {
        const std::string& body_text = res->body;
        size_t pos = 0;
        while (pos < body_text.size()) {
            size_t nl = body_text.find('\n', pos);
            if (nl == std::string::npos) nl = body_text.size();
            std::string line = body_text.substr(pos, nl - pos);
            pos = nl + 1;
            if (line.size() >= 6 && line.compare(0, 6, "data: ") == 0) {
                std::string data_part = line.substr(6);
                if (data_part == "[DONE]") continue;
                json maybe = json::parse(data_part, nullptr, false);
                if (!maybe.is_discarded() && maybe.is_object()) {
                    if (maybe.contains("method") && !maybe.contains("id")) {
                        process_notification(maybe);
                        continue;
                    }
                    return maybe;
                }
            }
        }
        throw std::runtime_error("Invalid JSON response from MCP server");
    }

    if (response.is_object() && response.contains("method") && !response.contains("id")) {
        process_notification(response);
        return json::object();
    }

    return response;
}

void client_t::process_notification(const json& notif)
{
    if (!notif.is_object() || !notif.contains("method")) return;
    const std::string method = notif.value("method", std::string{});

    if (method == "notifications/tools/list_changed"
        || method == "notifications/resources/list_changed"
        || method == "notifications/prompts/list_changed") {
        if (method == "notifications/tools/list_changed") {
            json req = rpc_request("tools/list");
            json response;
            try {
                response = send_rpc(req);
            } catch (const std::exception& e) {
                _last_error = std::string("tools/list refresh failed: ") + e.what();
                return;
            }
            if (response.contains("result") && response["result"].contains("tools")) {
                _cached_tools.clear();
                for (const auto& t : response["result"]["tools"]) {
                    remote_tool_t tool;
                    tool.server_name  = _server_name_str;
                    tool.name         = t.value("name", "");
                    tool.description  = t.value("description", "");
                    if (t.contains("inputSchema")) tool.input_schema = t["inputSchema"];
                    if (t.contains("annotations")) tool.annotations = t["annotations"];
                    if (!tool.name.empty()) _cached_tools.push_back(std::move(tool));
                }
            }
        }

        aida::events::mcp_tools_changed_t payload;
        payload.server_name = _server_name_str.empty() ? _cfg.name : _server_name_str;
        payload.tool_count = static_cast<int>(_cached_tools.size());
        aida::events::publish(aida::events::event_mcp_tools_changed, payload);
    }
}

bool client_t::poll_notifications()
{
    std::lock_guard<std::mutex> lk(_mtx);
    if (_state != connection_state_t::connected) return false;
    if (_cfg.transport != transport_type_t::stdio) return false;
    if (!_child_stdout_r) return false;

    DWORD bytes_avail = 0;
    if (!PeekNamedPipe(static_cast<HANDLE>(_child_stdout_r), nullptr, 0, nullptr, &bytes_avail, nullptr))
        return false;
    if (bytes_avail == 0) return false;

    std::string line;
    try {
        line = read_line_from_stdout();
    } catch (...) {
        return false;
    }
    if (line.empty()) return false;
    json maybe = json::parse(line, nullptr, false);
    if (maybe.is_discarded() || !maybe.is_object()) return false;
    if (maybe.contains("method") && !maybe.contains("id")) {
        process_notification(maybe);
        return true;
    }
    return false;
}


bool client_t::launch_stdio_process()
{


    if (_cfg.command.empty()) {
        _last_error = "No command specified for stdio transport";
        return false;
    }


    std::string cmdline = _cfg.command;
    for (const auto& arg : _cfg.args)
        cmdline += " " + arg;


    std::vector<wchar_t> env_block;
    if (!_cfg.env.empty()) {

        wchar_t* current_env = GetEnvironmentStringsW();
        if (current_env) {

            const wchar_t* p = current_env;
            while (*p) {
                size_t len = wcslen(p) + 1;
                env_block.insert(env_block.end(), p, p + len);
                p += len;
            }
            FreeEnvironmentStringsW(current_env);
        }

        for (const auto& [key, val] : _cfg.env) {
            std::wstring entry;
            entry.reserve(key.size() + val.size() + 2);
            for (char c : key)   entry += static_cast<wchar_t>(c);
            entry += L'=';
            for (char c : val)   entry += static_cast<wchar_t>(c);
            entry += L'\0';
            env_block.insert(env_block.end(), entry.begin(), entry.end());
        }
        env_block.push_back(L'\0');
    }


    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE stdin_read  = nullptr, stdin_write  = nullptr;
    HANDLE stdout_read = nullptr, stdout_write = nullptr;

    if (!CreatePipe(&stdin_read, &stdin_write, &sa, 0) ||
        !CreatePipe(&stdout_read, &stdout_write, &sa, 0))
    {
        _last_error = "Failed to create pipes for stdio transport";
        if (stdin_read)   CloseHandle(stdin_read);
        if (stdin_write)  CloseHandle(stdin_write);
        if (stdout_read)  CloseHandle(stdout_read);
        if (stdout_write) CloseHandle(stdout_write);
        return false;
    }


    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput   = stdin_read;
    si.hStdOutput  = stdout_write;
    si.hStdError   = GetStdHandle(STD_ERROR_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};


    std::wstring wcmdline;
    wcmdline.reserve(cmdline.size() + 1);
    for (char c : cmdline) wcmdline += static_cast<wchar_t>(c);

    BOOL created = CreateProcessW(
        nullptr,
        wcmdline.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        env_block.empty() ? nullptr : env_block.data(),
        nullptr,
        &si, &pi
    );


    CloseHandle(stdin_read);
    CloseHandle(stdout_write);

    if (!created) {
        _last_error = "Failed to launch MCP server process: " + cmdline;
        CloseHandle(stdin_write);
        CloseHandle(stdout_read);
        return false;
    }

    CloseHandle(pi.hThread);
    _child_process  = pi.hProcess;
    _child_stdin_w  = stdin_write;
    _child_stdout_r = stdout_read;


    Sleep(200);


    DWORD exit_code = 0;
    if (GetExitCodeProcess(static_cast<HANDLE>(_child_process), &exit_code) &&
        exit_code != STILL_ACTIVE)
    {
        _last_error = "MCP server process exited immediately (code " + std::to_string(exit_code) + ")";
        kill_stdio_process();
        return false;
    }

    return true;
}

void client_t::kill_stdio_process()
{


    if (_child_stdin_w) {
        CloseHandle(static_cast<HANDLE>(_child_stdin_w));
        _child_stdin_w = nullptr;
    }
    if (_child_stdout_r) {
        CloseHandle(static_cast<HANDLE>(_child_stdout_r));
        _child_stdout_r = nullptr;
    }
    if (_child_process) {
        TerminateProcess(static_cast<HANDLE>(_child_process), 0);
        WaitForSingleObject(static_cast<HANDLE>(_child_process), 3000);
        CloseHandle(static_cast<HANDLE>(_child_process));
        _child_process = nullptr;
    }
}

std::string client_t::read_line_from_stdout()
{

    if (!_child_stdout_r)
        throw std::runtime_error("stdio: no stdout handle");

    std::string line;
    char ch;
    DWORD read_bytes;

    while (true) {
        BOOL ok = ReadFile(static_cast<HANDLE>(_child_stdout_r), &ch, 1, &read_bytes, nullptr);
        if (!ok || read_bytes == 0) {
            if (line.empty())
                throw std::runtime_error("stdio: child process closed stdout");
            break;
        }
        if (ch == '\n')
            break;
        if (ch != '\r')
            line += ch;
    }

    return line;
}

void client_t::write_to_stdin(const std::string& data)
{

    if (!_child_stdin_w)
        throw std::runtime_error("stdio: no stdin handle");

    std::string msg = data + "\n";
    DWORD written;
    BOOL ok = WriteFile(
        static_cast<HANDLE>(_child_stdin_w),
        msg.c_str(),
        static_cast<DWORD>(msg.size()),
        &written, nullptr
    );
    if (!ok)
        throw std::runtime_error("stdio: failed to write to child stdin");
}

json client_t::send_stdio(const json& request)
{


    const std::string body = json_dump_safe(request);
    write_to_stdin(body);


    if (!request.contains("id"))
        return json::object();

    while (true) {
        std::string response_str = read_line_from_stdout();

        json response = json::parse(response_str, nullptr, false);
        if (response.is_discarded())
            throw std::runtime_error("stdio: invalid JSON response");

        if (response.is_object() && response.contains("method") && !response.contains("id")) {
            process_notification(response);
            continue;
        }
        return response;
    }
}


manager_t::manager_t()  = default;
manager_t::~manager_t() { disconnect_all(); }

void manager_t::add_server(const server_config_t& cfg)
{
    std::lock_guard<std::mutex> lk(_mtx);


    for (auto& e : _entries) {
        if (e.cfg.name == cfg.name) {
            e.cfg = cfg;
            return;
        }
    }

    _entries.push_back({cfg, client_t{}});
}

void manager_t::remove_server(const std::string& name)
{
    std::lock_guard<std::mutex> lk(_mtx);

    auto it = std::find_if(_entries.begin(), _entries.end(),
        [&](const entry_t& e) { return e.cfg.name == name; });

    if (it != _entries.end()) {
        it->client.disconnect();
        _entries.erase(it);
    }
}

void manager_t::connect_all()
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.enabled && e.cfg.auto_connect &&
            e.client.state() != connection_state_t::connected)
        {
            e.client.connect(e.cfg);
            if (e.client.is_connected())
                e.client.list_tools();
        }
    }
}

void manager_t::disconnect_all()
{
    std::lock_guard<std::mutex> lk(_mtx);
    for (auto& e : _entries)
        e.client.disconnect();
}

bool manager_t::connect_server(const std::string& name)
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.name == name) {
            bool ok = e.client.connect(e.cfg);
            if (ok) e.client.list_tools();
            return ok;
        }
    }
    return false;
}

void manager_t::disconnect_server(const std::string& name)
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.name == name) {
            e.client.disconnect();
            return;
        }
    }
}

std::vector<remote_tool_t> manager_t::get_all_tools()
{
    std::lock_guard<std::mutex> lk(_mtx);

    std::vector<remote_tool_t> all;
    for (auto& e : _entries) {
        if (e.client.is_connected()) {
            const auto& tools = e.client.cached_tools();
            all.insert(all.end(), tools.begin(), tools.end());
        }
    }
    return all;
}

call_result_t manager_t::call_tool(const std::string& qualified_name, const json& arguments)
{
    std::lock_guard<std::mutex> lk(_mtx);


    size_t sep = qualified_name.find("::");
    if (sep != std::string::npos) {
        std::string server = qualified_name.substr(0, sep);
        std::string tool   = qualified_name.substr(sep + 2);

        for (auto& e : _entries) {
            if (e.cfg.name == server && e.client.is_connected())
                return e.client.call_tool(tool, arguments);
        }
        return call_result_t::error("MCP server '" + server + "' not found or not connected");
    }


    for (auto& e : _entries) {
        if (!e.client.is_connected()) continue;
        for (const auto& t : e.client.cached_tools()) {
            if (t.name == qualified_name)
                return e.client.call_tool(qualified_name, arguments);
        }
    }

    return call_result_t::error("MCP tool '" + qualified_name + "' not found on any connected server");
}

size_t manager_t::tool_count() const
{
    std::lock_guard<std::mutex> lk(_mtx);

    size_t count = 0;
    for (const auto& e : _entries) {
        if (e.client.is_connected())
            count += e.client.cached_tools().size();
    }
    return count;
}

std::vector<remote_resource_t> manager_t::get_all_resources()
{
    std::lock_guard<std::mutex> lk(_mtx);

    std::vector<remote_resource_t> all;
    for (auto& e : _entries) {
        if (e.client.is_connected()) {
            auto res = e.client.list_resources();
            all.insert(all.end(), res.begin(), res.end());
        }
    }
    return all;
}

std::string manager_t::read_resource(const std::string& server_name, const std::string& uri)
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.name == server_name && e.client.is_connected())
            return e.client.read_resource(uri);
    }
    return {};
}

std::vector<manager_t::server_status_t> manager_t::get_status() const
{
    std::lock_guard<std::mutex> lk(_mtx);

    std::vector<server_status_t> result;
    result.reserve(_entries.size());

    for (const auto& e : _entries) {
        result.push_back({
            e.cfg.name,
            e.client.state(),
            e.client.last_error(),
            e.client.cached_tools().size(),
            e.client.oauth_status()
        });
    }

    return result;
}

void manager_t::poll()
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (!e.cfg.enabled || !e.cfg.auto_connect)
            continue;

        auto st = e.client.state();
        if (st == connection_state_t::error ||
            st == connection_state_t::disconnected)
        {

            if (e.client.oauth_status() == oauth_status_t::needs_auth
                || e.client.oauth_status() == oauth_status_t::needs_client_registration)
                continue;

            e.client.connect(e.cfg);
            if (e.client.is_connected())
                e.client.list_tools();
        }

        if (e.client.is_connected()) {
            e.client.poll_notifications();
        }
    }
}

bool manager_t::refresh_tools(const std::string& name)
{
    std::lock_guard<std::mutex> lk(_mtx);
    for (auto& e : _entries) {
        if (e.cfg.name != name) continue;
        if (!e.client.is_connected()) return false;
        auto tools = e.client.list_tools();
        aida::events::mcp_tools_changed_t payload;
        payload.server_name = name;
        payload.tool_count = static_cast<int>(tools.size());
        aida::events::publish(aida::events::event_mcp_tools_changed, payload);
        return true;
    }
    return false;
}

bool manager_t::find_config(const std::string& name, server_config_t& out) const
{
    std::lock_guard<std::mutex> lk(_mtx);
    for (const auto& e : _entries) {
        if (e.cfg.name == name) {
            out = e.cfg;
            return true;
        }
    }
    return false;
}


bool supports_oauth(const std::string& server_name)
{
    server_config_t cfg;
    if (!::s_mcp_client_mgr.find_config(server_name, cfg)) return false;
    if (cfg.transport != transport_type_t::http_sse) return false;
    return cfg.oauth_enabled;
}

bool has_stored_tokens(const std::string& server_name)
{
    aida::auth::auth_info_t info;
    if (!load_mcp_auth(server_name, info)) return false;
    return !info.access.empty();
}

oauth_status_t auth_status(const std::string& server_name)
{
    aida::auth::auth_info_t info;
    if (!load_mcp_auth(server_name, info) || info.access.empty())
        return oauth_status_t::needs_auth;
    if (info.expires_unix == 0) return oauth_status_t::authenticated;
    const int64_t now = now_unix_seconds();
    if (now >= info.expires_unix) return oauth_status_t::needs_auth;
    return oauth_status_t::authenticated;
}


bool start_auth(const std::string& server_name, oauth_state_t& out_state)
{
    out_state.server_name = server_name;
    out_state.done.store(false);
    out_state.cancelled.store(false);
    out_state.error.clear();
    out_state.received_code.clear();
    out_state.deadline_unix = now_unix_seconds() + 300;

    if (!supports_oauth(server_name)) {
        out_state.error = "MCP server does not support OAuth (not remote/HTTP, or oauth disabled)";
        set_global_last_error(out_state.error);
        return false;
    }

    server_config_t cfg;
    if (!::s_mcp_client_mgr.find_config(server_name, cfg)) {
        out_state.error = "MCP server '" + server_name + "' not registered";
        set_global_last_error(out_state.error);
        return false;
    }

    parsed_url_t purl;
    if (!parse_url_full(cfg.url, purl)) {
        out_state.error = "Invalid MCP server URL: " + cfg.url;
        set_global_last_error(out_state.error);
        return false;
    }

    out_state.code_verifier = generate_pkce_verifier();
    if (out_state.code_verifier.empty()) {
        out_state.error = "PKCE verifier generation failed";
        set_global_last_error(out_state.error);
        return false;
    }
    out_state.code_challenge = sha256_base64url(out_state.code_verifier);
    if (out_state.code_challenge.empty()) {
        out_state.error = "PKCE challenge derivation failed";
        set_global_last_error(out_state.error);
        return false;
    }
    out_state.state_token = generate_state_token();
    if (out_state.state_token.empty()) {
        out_state.error = "state token generation failed";
        set_global_last_error(out_state.error);
        return false;
    }

    if (!start_oauth_listener(out_state)) {
        set_global_last_error(out_state.error);
        return false;
    }

    if (!cfg.oauth_redirect_uri.empty()) {
        out_state.redirect_uri = cfg.oauth_redirect_uri;
    } else {
        out_state.redirect_uri = "http://127.0.0.1:" + std::to_string(out_state.callback_port)
            + "/mcp/oauth/callback";
    }

    std::string te = out_state.token_endpoint;
    std::string ae = out_state.authorization_endpoint;
    std::string re = out_state.registration_endpoint;
    if (te.empty() || ae.empty()) {
        if (!fetch_oauth_metadata(purl, te, ae, re)) {
            stop_oauth_listener(out_state);
            out_state.error = "OAuth metadata discovery failed for " + cfg.url;
            set_global_last_error(out_state.error);
            return false;
        }
    }
    out_state.token_endpoint = te;
    out_state.authorization_endpoint = ae;
    out_state.registration_endpoint = re;
    out_state.scope = cfg.oauth_scope;

    aida::auth::auth_info_t existing;
    bool have_existing = load_mcp_auth(server_name, existing);

    out_state.client_id = !cfg.oauth_client_id.empty()
        ? cfg.oauth_client_id
        : (have_existing ? existing.metadata.value("client_id", std::string{}) : std::string{});
    out_state.client_secret = !cfg.oauth_client_secret.empty()
        ? cfg.oauth_client_secret
        : (have_existing ? existing.metadata.value("client_secret", std::string{}) : std::string{});

    if (out_state.client_id.empty()) {
        if (re.empty()) {
            stop_oauth_listener(out_state);
            out_state.error = "Server does not support dynamic client registration. Please provide oauth_client_id in config.";
            set_global_last_error(out_state.error);
            return false;
        }
        std::string err;
        std::string new_cid, new_csec;
        if (!register_dynamic_client(re, out_state.redirect_uri, new_cid, new_csec, err)) {
            stop_oauth_listener(out_state);
            out_state.error = "dynamic client registration failed: " + err;
            set_global_last_error(out_state.error);
            return false;
        }
        out_state.client_id = new_cid;
        out_state.client_secret = new_csec;
    }

    out_state.authorization_url = build_authorize_url(
        out_state.authorization_endpoint,
        out_state.client_id,
        out_state.redirect_uri,
        out_state.scope,
        out_state.code_challenge,
        out_state.state_token);

    if (!open_browser(out_state.authorization_url)) {
        anti_tamper::webhook::write_log("mcp.oauth",
            "[mcp.oauth] ShellExecuteW open browser failed; user must open authorization_url manually");
    }

    set_global_last_error({});
    return true;
}

oauth_status_t poll_auth(oauth_state_t& state)
{
    if (state.cancelled.load()) {
        stop_oauth_listener(state);
        return oauth_status_t::failed;
    }

    const int64_t now = now_unix_seconds();
    if (state.deadline_unix != 0 && now > state.deadline_unix && !state.done.load()) {
        state.error = "OAuth flow timed out";
        set_global_last_error(state.error);
        stop_oauth_listener(state);
        return oauth_status_t::failed;
    }

    if (!state.done.load()) return oauth_status_t::authenticating;

    stop_oauth_listener(state);

    if (!state.error.empty()) {
        set_global_last_error(state.error);
        aida::events::oauth_failed_t fail;
        fail.provider_id = mcp_auth_key(state.server_name);
        fail.error = state.error;
        aida::events::publish(aida::events::event_oauth_failed, fail);
        return oauth_status_t::failed;
    }

    if (state.received_code.empty()) {
        state.error = "callback completed without code";
        set_global_last_error(state.error);
        return oauth_status_t::failed;
    }

    if (!finish_auth(state.server_name, state.received_code)) {
        state.error = last_error();
        return oauth_status_t::failed;
    }

    aida::events::oauth_completed_t ok;
    ok.provider_id = mcp_auth_key(state.server_name);
    aida::events::publish(aida::events::event_oauth_completed, ok);
    return oauth_status_t::authenticated;
}

bool finish_auth(const std::string& server_name, const std::string& authorization_code)
{
    aida::auth::auth_info_t pending;
    bool have_pending = load_mcp_auth(server_name, pending);

    server_config_t cfg;
    if (!::s_mcp_client_mgr.find_config(server_name, cfg)) {
        set_global_last_error("MCP server '" + server_name + "' not registered for finish_auth");
        return false;
    }

    std::string token_endpoint = have_pending ? pending.metadata.value("token_endpoint", std::string{}) : std::string{};
    std::string client_id      = have_pending ? pending.metadata.value("client_id", std::string{}) : std::string{};
    std::string client_secret  = have_pending ? pending.metadata.value("client_secret", std::string{}) : std::string{};
    std::string redirect_uri   = have_pending ? pending.metadata.value("redirect_uri", std::string{}) : std::string{};
    std::string code_verifier  = have_pending ? pending.metadata.value("code_verifier", std::string{}) : std::string{};

    if (token_endpoint.empty() || client_id.empty() || redirect_uri.empty() || code_verifier.empty()) {
        set_global_last_error("finish_auth requires staged metadata; use trigger_auth_flow or start_auth which stages it");
        return false;
    }

    std::string access, refresh, scope, err;
    int64_t expires_in = 3600;
    if (!exchange_authorization_code(token_endpoint, client_id, client_secret,
            redirect_uri, authorization_code, code_verifier,
            access, refresh, expires_in, scope, err)) {
        set_global_last_error(err);
        return false;
    }

    aida::auth::auth_info_t info = pending;
    info.kind = aida::auth::auth_kind_t::oauth;
    info.access = access;
    info.refresh = refresh;
    info.expires_unix = now_unix_seconds() + expires_in;
    info.metadata["mcp_endpoint"] = cfg.url;
    info.metadata["client_id"] = client_id;
    if (!client_secret.empty()) info.metadata["client_secret"] = client_secret;
    info.metadata["token_endpoint"] = token_endpoint;
    info.metadata["redirect_uri"] = redirect_uri;
    if (!scope.empty()) info.metadata["scope"] = scope;
    if (info.metadata.contains("code_verifier")) info.metadata.erase("code_verifier");

    if (!save_mcp_auth(server_name, info)) {
        set_global_last_error("auth_store::set failed: " + aida::auth::store::last_error());
        return false;
    }
    set_global_last_error({});
    return true;
}

bool remove_auth(const std::string& server_name)
{
    if (!delete_mcp_auth(server_name)) {
        set_global_last_error("auth_store::remove failed: " + aida::auth::store::last_error());
        return false;
    }
    set_global_last_error({});
    return true;
}

bool cancel_auth(oauth_state_t& state)
{
    state.cancelled.store(true);
    stop_oauth_listener(state);
    return true;
}


bool trigger_auth_flow(const std::string& server_name, auth_completion_callback_t on_complete)
{
    auto state = std::make_shared<oauth_state_t>();
    state->server_name = server_name;

    if (!start_auth(server_name, *state)) {
        if (on_complete) on_complete(server_name, oauth_status_t::failed, last_error());
        return false;
    }

    aida::auth::auth_info_t stage;
    load_mcp_auth(server_name, stage);
    stage.kind = aida::auth::auth_kind_t::oauth;
    stage.metadata["token_endpoint"] = state->token_endpoint;
    stage.metadata["authorization_endpoint"] = state->authorization_endpoint;
    if (!state->registration_endpoint.empty())
        stage.metadata["registration_endpoint"] = state->registration_endpoint;
    stage.metadata["client_id"] = state->client_id;
    if (!state->client_secret.empty())
        stage.metadata["client_secret"] = state->client_secret;
    stage.metadata["redirect_uri"] = state->redirect_uri;
    stage.metadata["code_verifier"] = state->code_verifier;
    if (!state->scope.empty()) stage.metadata["scope"] = state->scope;
    save_mcp_auth(server_name, stage);

    std::thread worker([state, on_complete, server_name]() {
        for (;;) {
            oauth_status_t st = poll_auth(*state);
            if (st == oauth_status_t::authenticating) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }
            if (on_complete) {
                std::string err;
                if (st != oauth_status_t::authenticated) err = state->error.empty() ? last_error() : state->error;
                on_complete(server_name, st, err);
            }
            return;
        }
    });
    worker.detach();
    return true;
}

}
