

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
#include "../anti-tamper/mcp_posture.hpp"
#include "../infra/work_queue.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../../helpers/diag_log.hpp"

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

namespace file_browser { extern std::string current_dir; }

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

static std::uint64_t mcp_log_hash(const std::string& text)
{
    std::uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : text) {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

static std::wstring utf8_to_wide_string(const std::string& text)
{
    if (text.empty())
        return {};
    const int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (wlen <= 0)
        return {};
    std::wstring out(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), wlen);
    return out;
}

static bool directory_exists_w(const std::wstring& path)
{
    if (path.empty())
        return false;
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
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

static std::string lower_ascii_copy(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

static std::string redact_labeled_log_text(std::string text)
{
    static const char* labels[] = {
        "token", "access_token", "refresh_token", "password", "passwd", "pass",
        "secret", "client_secret", "api_key", "apikey", "authorization",
        "cookie", "set-cookie", "license", "session"
    };
    for (const char* label : labels) {
        std::string lowered = lower_ascii_copy(text);
        std::size_t pos = 0;
        const std::string needle(label);
        while ((pos = lowered.find(needle, pos)) != std::string::npos) {
            std::size_t value_start = pos + needle.size();
            while (value_start < text.size() && (text[value_start] == ' ' || text[value_start] == '\t' ||
                   text[value_start] == ':' || text[value_start] == '=' || text[value_start] == '"' ||
                   text[value_start] == '\'')) {
                ++value_start;
            }
            if (value_start >= text.size()) {
                pos += needle.size();
                continue;
            }
            std::size_t value_end = value_start;
            while (value_end < text.size()) {
                const char c = text[value_end];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' ||
                    c == '\'' || c == ',' || c == ';' || c == '&' || c == '}')
                    break;
                ++value_end;
            }
            if (value_end > value_start) {
                text.replace(value_start, value_end - value_start, "<redacted>");
                lowered = lower_ascii_copy(text);
                pos = value_start + 10;
            } else {
                pos += needle.size();
            }
        }
    }
    return text;
}

static std::string compact_log_text(std::string text, size_t cap)
{
    text = sanitize_utf8(text);
    text = redact_labeled_log_text(std::move(text));
    for (char& c : text) {
        if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
    }
    if (text.size() > cap)
        text = text.substr(0, cap) + "...(truncated)";
    return text;
}

static unsigned first_byte_or_zero(const std::string& text)
{
    if (text.empty())
        return 0;
    return static_cast<unsigned>(static_cast<unsigned char>(text.front()));
}

static std::string rpc_error_summary_for_log(const json& err)
{
    if (!err.is_object())
        return "type=" + std::string(err.type_name());
    std::string message;
    if (err.contains("message") && err["message"].is_string())
        message = compact_log_text(err["message"].get<std::string>(), 500);
    std::string data_type = "missing";
    std::size_t data_size = 0;
    if (err.contains("data")) {
        data_type = err["data"].type_name();
        if (err["data"].is_array() || err["data"].is_object())
            data_size = err["data"].size();
    }
    long long code = 0;
    bool has_code = false;
    if (err.contains("code") && err["code"].is_number_integer()) {
        code = err["code"].get<long long>();
        has_code = true;
    }
    std::ostringstream oss;
    oss << "code=" << (has_code ? std::to_string(code) : "missing")
        << " message='" << message << "'"
        << " data_type=" << data_type
        << " data_size=" << data_size;
    return oss.str();
}

static std::string request_method_for_log(const json& request)
{
    if (request.is_object() && request.contains("method") && request["method"].is_string())
        return request["method"].get<std::string>();
    return {};
}

static json initialize_params(bool include_interactive_capabilities)
{
    json capabilities = json::object();
    if (include_interactive_capabilities) {
        capabilities["roots"] = {{"listChanged", true}};
        capabilities["sampling"] = json::object();
    }

    json client_info = json::object();
    client_info["name"] = "AiDA Standalone";
    client_info["version"] = "1.0.0";

    json params = json::object();
    params["protocolVersion"] = "2024-11-05";
    params["capabilities"] = std::move(capabilities);
    params["clientInfo"] = std::move(client_info);
    return params;
}

static std::string sanitize_identifier(const std::string& input)
{
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        const unsigned char uc = static_cast<unsigned char>(c);
        const bool keep = (uc >= '0' && uc <= '9')
                       || (uc >= 'A' && uc <= 'Z')
                       || (uc >= 'a' && uc <= 'z')
                       || uc == '_'
                       || uc == '-';
        out.push_back(keep ? static_cast<char>(uc) : '_');
    }
    return out;
}

static std::string make_qualified_tool_name(const std::string& server, const std::string& tool)
{
    return sanitize_identifier(server) + "_" + sanitize_identifier(tool);
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
    if (url.empty())
        return false;
    if (!aida::burp::camoufox::ensure_ready()) {
        anti_tamper::webhook::write_log("mcp.oauth",
            "[mcp.oauth] Camoufox ensure_ready failed; refusing default-browser fallback");
        return false;
    }
    const bool opened = aida::burp::camoufox::navigate(url, "domcontentloaded", 45000);
    anti_tamper::webhook::write_log("mcp.oauth",
        opened
            ? "[mcp.oauth] authorization_url opened in Camoufox"
            : "[mcp.oauth] Camoufox navigate failed; refusing default-browser fallback");
    return opened;
}


struct callback_listener_t
{
    SOCKET            sock = INVALID_SOCKET;
    std::atomic<bool> worker_done{true};
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
    ctx->worker_done.store(false, std::memory_order_release);
    oauth_state_t* state_ptr = &state;
    if (!work_queue::post([state_ptr, ctx]() {
            oauth_listener_thread(state_ptr, ctx);
            ctx->worker_done.store(true, std::memory_order_release);
        }))
    {
        ctx->worker_done.store(true, std::memory_order_release);
        return false;
    }
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
    while (!(*holder)->worker_done.load(std::memory_order_acquire))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
}


static httplib::Result do_https_get(const parsed_url_t& url, const httplib::Headers& hdrs)
{
    httplib::Client cli(url.origin);
    cli.set_connection_timeout(15);
    cli.set_read_timeout(30);
    cli.set_write_timeout(15);
    cli.enable_server_certificate_verification(url.is_https);
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
    const bool is_https_origin = origin.rfind("https://", 0) == 0;
    cli.enable_server_certificate_verification(is_https_origin);
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
    _child_process_id = o._child_process_id;
    o._child_process  = nullptr;
    o._child_stdin_w  = nullptr;
    o._child_stdout_r = nullptr;
    o._child_process_id = 0;
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
        _child_process_id = o._child_process_id;
        o._child_process  = nullptr;
        o._child_stdin_w  = nullptr;
        o._child_stdout_r = nullptr;
        o._child_process_id = 0;
        o._state          = connection_state_t::disconnected;
        o._oauth_status   = oauth_status_t::not_required;
        o._transport_mode = transport_mode_t::auto_detect;
    }
    return *this;
}

bool client_t::connect(const server_config_t& cfg)
{
    if (!anti_tamper::mcp_posture::is_runtime_trusted_server(cfg, true)) {
        std::lock_guard<std::mutex> lk(_mtx);
        _cfg = cfg;
        _state = connection_state_t::error;
        _last_error = "MCP posture blocked this server";
        diag::log_tagged_fmt("mcp",
            "connect_blocked_mcp_posture name_hash=0x%016llX name_len=%zu transport=%d",
            static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
            cfg.name.size(),
            static_cast<int>(cfg.transport));
        return false;
    }

    bool need_disconnect = false;
    {
        std::lock_guard<std::mutex> peek(_mtx);
        need_disconnect = (_state == connection_state_t::connected);
    }
    if (need_disconnect) disconnect();
    std::lock_guard<std::mutex> lk(_mtx);
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

    json init_req = rpc_request("initialize", initialize_params(true));
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
                json notif_resp;
                send_rpc(notif_resp, notif);
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
    json init_req = rpc_request("initialize", initialize_params(false));

    json response;
    if (!send_rpc(response, init_req)) {
        const std::string inner = _last_error;
        _last_error = "Initialize failed: " + inner;
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
    json notif_resp;
    send_rpc(notif_resp, notif);

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
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "tools/list failed: " + inner;
        return _cached_tools;
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "tools/list error");
        return _cached_tools;
    }

    std::vector<remote_tool_t> next_tools;
    if (response.contains("result") && response["result"].contains("tools")) {
        const std::string server_label = _server_name_str.empty() ? _cfg.name : _server_name_str;
        for (const auto& t : response["result"]["tools"]) {
            remote_tool_t tool;
            tool.server_name   = server_label;
            tool.original_name = t.value("name", "");
            if (tool.original_name.empty()) continue;
            tool.name         = make_qualified_tool_name(server_label, tool.original_name);
            tool.description  = t.value("description", "");
            if (!anti_tamper::mcp_posture::is_remote_tool_metadata_trusted(server_label, tool.original_name, tool.description)) {
                _last_error = "tools/list blocked by MCP tool metadata posture";
                _cached_tools.clear();
                return _cached_tools;
            }
            if (t.contains("inputSchema"))
                tool.input_schema = t["inputSchema"];
            if (t.contains("annotations"))
                tool.annotations = t["annotations"];
            next_tools.push_back(std::move(tool));
        }
    }

    _cached_tools = std::move(next_tools);
    return _cached_tools;
}

call_result_t client_t::call_tool(const std::string& tool_name, const json& arguments)
{
    diag::log_tagged_fmt("mcp", "call_tool enter server='%s' tool='%s'",
        _cfg.name.c_str(), tool_name.c_str());
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        diag::log_tagged_fmt("mcp", "call_tool FAILED not_connected server='%s'", _cfg.name.c_str());
        return call_result_t::error("Not connected to " + _cfg.name);
    }

    json req = rpc_request("tools/call", {
        {"name", tool_name},
        {"arguments", arguments}
    });

    json response;
    if (!send_rpc(response, req)) {
        diag::log_tagged_fmt("mcp", "call_tool RPC_FAILED server='%s' tool='%s' error='%s'",
            _cfg.name.c_str(), tool_name.c_str(), _last_error.c_str());
        return call_result_t::error("tools/call failed: " + _last_error);
    }

    if (response.contains("error")) {
        std::string err_msg = response["error"].value("message", "Tool execution error");
        diag::log_tagged_fmt("mcp", "call_tool ERROR server='%s' tool='%s' msg='%s'",
            _cfg.name.c_str(), tool_name.c_str(), err_msg.c_str());
        return call_result_t::error(err_msg);
    }

    if (!response.contains("result")) {
        diag::log_tagged_fmt("mcp", "call_tool EMPTY_RESULT server='%s' tool='%s'",
            _cfg.name.c_str(), tool_name.c_str());
        return call_result_t::error("Empty result from server");
    }

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
    if (is_error) {
        diag::log_tagged_fmt("mcp", "call_tool TOOL_ERROR server='%s' tool='%s' text_len=%zu",
            _cfg.name.c_str(), tool_name.c_str(), text.size());
        return call_result_t::error(text.empty() ? "Tool returned error" : text);
    }

    diag::log_tagged_fmt("mcp", "call_tool SUCCESS server='%s' tool='%s' text_len=%zu",
        _cfg.name.c_str(), tool_name.c_str(), text.size());
    return call_result_t::ok(sanitize_utf8(text), data);
}

std::vector<remote_resource_t> client_t::list_resources()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return {};

    json req = rpc_request("resources/list");
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "resources/list failed: " + inner;
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
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "resources/read failed: " + inner;
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

std::vector<remote_prompt_t> client_t::list_prompts()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        _last_error = "Not connected";
        return {};
    }

    json req = rpc_request("prompts/list");
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "prompts/list failed: " + inner;
        return {};
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "prompts/list error");
        return {};
    }

    std::vector<remote_prompt_t> prompts;
    if (response.contains("result") && response["result"].contains("prompts")) {
        for (const auto& p : response["result"]["prompts"]) {
            remote_prompt_t pr;
            pr.server_name = _server_name_str;
            pr.name        = p.value("name", "");
            pr.description = p.value("description", "");
            if (p.contains("arguments") && p["arguments"].is_array()) {
                for (const auto& a : p["arguments"]) {
                    prompt_argument_t arg;
                    arg.name        = a.value("name", "");
                    arg.description = a.value("description", "");
                    arg.required    = a.value("required", false);
                    if (!arg.name.empty())
                        pr.arguments.push_back(std::move(arg));
                }
            }
            if (!pr.name.empty())
                prompts.push_back(std::move(pr));
        }
    }

    return prompts;
}

std::string client_t::get_prompt(const std::string& prompt_name,
                                 const std::map<std::string, std::string>& arguments)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        _last_error = "Not connected";
        return {};
    }

    json args_obj = json::object();
    for (const auto& kv : arguments)
        args_obj[kv.first] = kv.second;

    json params = json::object();
    params["name"] = prompt_name;
    if (!arguments.empty())
        params["arguments"] = args_obj;

    json req = rpc_request("prompts/get", params);
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "prompts/get failed: " + inner;
        return {};
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "prompts/get error");
        return {};
    }

    if (!response.contains("result"))
        return {};

    const auto& result = response["result"];
    std::string accumulated;
    if (result.contains("messages") && result["messages"].is_array()) {
        for (const auto& msg : result["messages"]) {
            if (!msg.contains("content")) continue;
            const auto& content = msg["content"];
            if (content.is_object()) {
                if (content.value("type", "") == "text") {
                    if (!accumulated.empty()) accumulated += "\n";
                    accumulated += content.value("text", "");
                }
            } else if (content.is_array()) {
                for (const auto& block : content) {
                    if (block.value("type", "") == "text") {
                        if (!accumulated.empty()) accumulated += "\n";
                        accumulated += block.value("text", "");
                    }
                }
            }
        }
    }

    return accumulated;
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

std::uint32_t client_t::child_process_id() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _child_process_id;
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

bool client_t::send_rpc(json& out, const json& request)
{
    switch (_cfg.transport) {
    case transport_type_t::http_sse:
        return send_http(out, request);
    case transport_type_t::stdio:
        return send_stdio(out, request);
    default:
        _last_error = "Unsupported transport type";
        return false;
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


bool client_t::send_http(json& out, const json& request)
{
    ensure_access_token_fresh_locked();

    parsed_url_t purl;
    if (!parse_url_full(_cfg.url, purl)) {
        _last_error = "Invalid MCP server URL: " + _cfg.url;
        return false;
    }

    const std::string body = json_dump_safe(request);
    std::string post_path = purl.path;
    if (_transport_mode == transport_mode_t::sse_legacy && !_sse_post_path.empty())
        post_path = _sse_post_path;

    auto build_headers = [this]() {
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
        return headers;
    };

    auto res = do_https_post(purl.origin, post_path, build_headers(), body, "application/json");

    if (res && (res->status == 401 || res->status == 403)) {
        bool refreshed = false;
        {
            aida::auth::auth_info_t info;
            if (load_mcp_auth(_cfg.name, info)
                && info.kind == aida::auth::auth_kind_t::oauth
                && !info.refresh.empty()) {
                refreshed = refresh_access_token_locked();
            }
        }
        if (refreshed) {
            res = do_https_post(purl.origin, post_path, build_headers(), body, "application/json");
        }
    }

    if (!res) {
        _last_error = "HTTP request failed: " + httplib::to_string(res.error());
        return false;
    }

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
        _last_error = "HTTP " + std::to_string(res->status)
            + ": MCP server requires OAuth authentication";
        return false;
    }

    if (res->status < 200 || res->status >= 300) {
        _last_error = "HTTP " + std::to_string(res->status) + ": " + res->body;
        return false;
    }


    json response = json::parse(res->body, nullptr, false);
    if (response.is_discarded()) {
        const std::string& body_text = res->body;
        size_t pos = 0;
        while (pos < body_text.size()) {
            size_t nl = body_text.find('\n', pos);
            if (nl == std::string::npos) nl = body_text.size();
            std::string line = body_text.substr(pos, nl - pos);
            pos = nl + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            if (!line.empty() && line.front() == ':') continue;
            const size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            const std::string field = line.substr(0, colon);
            if (field != "data") continue;
            size_t val_start = colon + 1;
            if (val_start < line.size() && line[val_start] == ' ') ++val_start;
            std::string data_part = line.substr(val_start);
            if (data_part == "[DONE]") continue;
            json maybe = json::parse(data_part, nullptr, false);
            if (!maybe.is_discarded() && maybe.is_object()) {
                if (maybe.contains("method") && !maybe.contains("id")) {
                    process_notification(maybe);
                    continue;
                }
                if (maybe.contains("method") && maybe.contains("id")) {
                    json inbound_response;
                    if (dispatch_inbound_request(maybe, inbound_response))
                        send_inbound_response(inbound_response);
                    continue;
                }
                out = std::move(maybe);
                return true;
            }
        }
        _last_error = "Invalid JSON response from MCP server";
        return false;
    }

    if (response.is_object() && response.contains("method") && !response.contains("id")) {
        process_notification(response);
        out = json::object();
        return true;
    }

    if (response.is_object() && response.contains("method") && response.contains("id")) {
        json inbound_response;
        if (dispatch_inbound_request(response, inbound_response))
            send_inbound_response(inbound_response);
        out = json::object();
        return true;
    }

    out = std::move(response);
    return true;
}

static std::string encode_file_uri_path(const std::string& abs_path)
{
    std::string normalized;
    normalized.reserve(abs_path.size());
    for (char c : abs_path) {
        if (c == '\\') normalized.push_back('/');
        else           normalized.push_back(c);
    }

    std::string out;
    out.reserve(normalized.size() * 3);
    for (unsigned char c : normalized) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
            || c == '~' || c == '/' || c == ':') {
            out.push_back(static_cast<char>(c));
        } else {
            char buf[4];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%%%02X", c);
            out.append(buf);
        }
    }
    return out;
}

json client_t::build_roots_list_result() const
{
    std::string workspace_path = file_browser::current_dir;
    if (workspace_path.empty()) {
        char buf[MAX_PATH] = {};
        if (GetCurrentDirectoryA(MAX_PATH, buf) > 0)
            workspace_path = buf;
    }

    json roots = json::array();
    if (!workspace_path.empty()) {
        const std::string encoded = encode_file_uri_path(workspace_path);
        std::string uri;
        uri.reserve(encoded.size() + 8);
        uri += "file:///";
        if (!encoded.empty() && encoded.front() == '/')
            uri += encoded.substr(1);
        else
            uri += encoded;

        json entry;
        entry["uri"]  = uri;
        entry["name"] = "AiDA workspace";
        roots.push_back(std::move(entry));
    }

    json result;
    result["roots"] = std::move(roots);
    return result;
}

bool client_t::dispatch_inbound_request(const json& request, json& response_out)
{
    if (!request.is_object() || !request.contains("method") || !request.contains("id"))
        return false;

    const std::string method = request.value("method", std::string{});
    const json& id_val = request["id"];

    json response;
    response["jsonrpc"] = "2.0";
    response["id"]      = id_val;

    if (method == "roots/list") {
        response["result"] = build_roots_list_result();
    } else if (method == "ping") {
        response["result"] = json::object();
    } else {
        json err;
        err["code"]    = -32601;
        err["message"] = std::string("Method not found: ") + method;
        response["error"] = std::move(err);
    }

    response_out = std::move(response);
    return true;
}

bool client_t::post_outbound_http_message(const json& message)
{
    parsed_url_t purl;
    if (!parse_url_full(_cfg.url, purl))
        return false;

    std::string post_path = purl.path;
    if (_transport_mode == transport_mode_t::sse_legacy && !_sse_post_path.empty())
        post_path = _sse_post_path;

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

    const std::string body = json_dump_safe(message);
    auto res = do_https_post(purl.origin, post_path, headers, body, "application/json");
    return res && res->status >= 200 && res->status < 300;
}

void client_t::send_inbound_response(const json& response)
{
    if (_cfg.transport == transport_type_t::stdio) {
        const std::string body = json_dump_safe(response);
        write_to_stdin(body);
        return;
    }
    if (_cfg.transport == transport_type_t::http_sse) {
        post_outbound_http_message(response);
    }
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
            if (!send_rpc(response, req)) {
                const std::string inner = _last_error;
                _last_error = "tools/list refresh failed: " + inner;
                return;
            }
            if (response.contains("result") && response["result"].contains("tools")) {
                std::vector<remote_tool_t> next_tools;
                const std::string server_label = _server_name_str.empty() ? _cfg.name : _server_name_str;
                for (const auto& t : response["result"]["tools"]) {
                    remote_tool_t tool;
                    tool.server_name   = server_label;
                    tool.original_name = t.value("name", "");
                    if (tool.original_name.empty()) continue;
                    tool.name          = make_qualified_tool_name(server_label, tool.original_name);
                    tool.description   = t.value("description", "");
                    if (!anti_tamper::mcp_posture::is_remote_tool_metadata_trusted(server_label, tool.original_name, tool.description)) {
                        _last_error = "tools/list refresh blocked by MCP tool metadata posture";
                        _cached_tools.clear();
                        return;
                    }
                    if (t.contains("inputSchema")) tool.input_schema = t["inputSchema"];
                    if (t.contains("annotations")) tool.annotations = t["annotations"];
                    next_tools.push_back(std::move(tool));
                }
                _cached_tools = std::move(next_tools);
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
    if (!read_line_from_stdout(line))
        return false;
    if (line.empty()) return false;
    json maybe = json::parse(line, nullptr, false);
    if (maybe.is_discarded() || !maybe.is_object()) return false;
    if (maybe.contains("method") && !maybe.contains("id")) {
        process_notification(maybe);
        return true;
    }
    if (maybe.contains("method") && maybe.contains("id")) {
        json inbound_response;
        if (dispatch_inbound_request(maybe, inbound_response))
            send_inbound_response(inbound_response);
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

    if (!anti_tamper::mcp_posture::is_runtime_trusted_server(_cfg, true)) {
        _last_error = "MCP posture blocked stdio launch";
        diag::log_tagged_fmt("mcp_stdio",
            "launch_blocked_mcp_posture server_hash=0x%016llX name_len=%zu",
            static_cast<unsigned long long>(mcp_log_hash(_cfg.name)),
            _cfg.name.size());
        return false;
    }


    std::string cmdline = _cfg.command;
    for (const auto& arg : _cfg.args)
        cmdline += " " + arg;

    std::wstring current_directory;
    auto cwd_it = _cfg.env.find("AIDA_CAMOUFOX_WORKING_DIR");
    if (cwd_it != _cfg.env.end() && !cwd_it->second.empty()) {
        current_directory = utf8_to_wide_string(cwd_it->second);
        if (!directory_exists_w(current_directory)) {
            _last_error = "Invalid MCP stdio working directory";
            diag::log_tagged_fmt("mcp_stdio",
                "launch_invalid_working_dir server_hash=0x%016llX name_len=%zu cwd_hash=0x%016llX cwd_len=%zu",
                static_cast<unsigned long long>(mcp_log_hash(_cfg.name)),
                _cfg.name.size(),
                static_cast<unsigned long long>(mcp_log_hash(cwd_it->second)),
                cwd_it->second.size());
            return false;
        }
    }

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
    if (!cmdline.empty()) {
        const int wlen = MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(),
            static_cast<int>(cmdline.size()), nullptr, 0);
        if (wlen <= 0) {
            _last_error = "Failed to convert command line to UTF-16: " + cmdline;
            CloseHandle(stdin_read);
            CloseHandle(stdin_write);
            CloseHandle(stdout_read);
            CloseHandle(stdout_write);
            return false;
        }
        wcmdline.resize(static_cast<size_t>(wlen));
        MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(), static_cast<int>(cmdline.size()),
            wcmdline.data(), wlen);
    }

    BOOL created = CreateProcessW(
        nullptr,
        wcmdline.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        env_block.empty() ? nullptr : env_block.data(),
        current_directory.empty() ? nullptr : current_directory.c_str(),
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
    _child_process_id = pi.dwProcessId;
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
        _child_process_id = 0;
    }
}

bool client_t::read_line_from_stdout(std::string& out)
{
    out.clear();

    if (!_child_stdout_r) {
        _last_error = "stdio: no stdout handle";
        return false;
    }

    char ch;
    DWORD read_bytes;

    while (true) {
        BOOL ok = ReadFile(static_cast<HANDLE>(_child_stdout_r), &ch, 1, &read_bytes, nullptr);
        if (!ok || read_bytes == 0) {
            if (out.empty()) {
                _last_error = "stdio: child process closed stdout";
                return false;
            }
            break;
        }
        if (ch == '\n')
            break;
        if (ch != '\r')
            out += ch;
    }

    return true;
}

bool client_t::write_to_stdin(const std::string& data)
{
    if (!_child_stdin_w) {
        _last_error = "stdio: no stdin handle";
        return false;
    }

    std::string msg = data + "\n";
    DWORD written;
    BOOL ok = WriteFile(
        static_cast<HANDLE>(_child_stdin_w),
        msg.c_str(),
        static_cast<DWORD>(msg.size()),
        &written, nullptr
    );
    if (!ok) {
        _last_error = "stdio: failed to write to child stdin";
        return false;
    }
    return true;
}

bool client_t::send_stdio(json& out, const json& request)
{
    const std::string body = json_dump_safe(request);
    const std::string method = request_method_for_log(request);
    diag::log_tagged_fmt("mcp_stdio", "send request server='%s' method='%s' has_id=%d body_bytes=%zu",
        _cfg.name.c_str(), method.c_str(), request.contains("id") ? 1 : 0, body.size());
    if (!write_to_stdin(body)) {
        diag::log_tagged_fmt("mcp_stdio", "send write_failed server='%s' method='%s' err='%s'",
            _cfg.name.c_str(), method.c_str(), compact_log_text(_last_error, 500).c_str());
        return false;
    }

    if (!request.contains("id")) {
        out = json::object();
        return true;
    }

    while (true) {
        std::string response_str;
        if (!read_line_from_stdout(response_str)) {
            diag::log_tagged_fmt("mcp_stdio", "recv failed server='%s' method='%s' err='%s'",
                _cfg.name.c_str(), method.c_str(), compact_log_text(_last_error, 500).c_str());
            return false;
        }
        diag::log_tagged_fmt("mcp_stdio", "recv line server='%s' method='%s' bytes=%zu",
            _cfg.name.c_str(), method.c_str(), response_str.size());

        json response = json::parse(response_str, nullptr, false);
        if (response.is_discarded()) {
            _last_error = "stdio: invalid JSON response";
            diag::log_tagged_fmt("mcp_stdio", "recv invalid_json server='%s' method='%s' bytes=%zu first_byte=0x%02X",
                _cfg.name.c_str(), method.c_str(), response_str.size(),
                first_byte_or_zero(response_str));
            return false;
        }

        if (response.is_object() && response.contains("method") && !response.contains("id")) {
            diag::log_tagged_fmt("mcp_stdio", "recv notification server='%s' method='%s' notif='%s'",
                _cfg.name.c_str(), method.c_str(), response.value("method", std::string()).c_str());
            process_notification(response);
            continue;
        }
        if (response.is_object() && response.contains("method") && response.contains("id")) {
            diag::log_tagged_fmt("mcp_stdio", "recv inbound_request server='%s' method='%s' inbound='%s'",
                _cfg.name.c_str(), method.c_str(), response.value("method", std::string()).c_str());
            json inbound_response;
            if (dispatch_inbound_request(response, inbound_response))
                send_inbound_response(inbound_response);
            continue;
        }
        if (response.is_object() && response.contains("error")) {
            const auto& err = response["error"];
            diag::log_tagged_fmt("mcp_stdio", "recv rpc_error server='%s' method='%s' error='%s'",
                _cfg.name.c_str(), method.c_str(), rpc_error_summary_for_log(err).c_str());
        } else {
            diag::log_tagged_fmt("mcp_stdio", "recv response server='%s' method='%s' has_result=%d",
                _cfg.name.c_str(), method.c_str(),
                response.is_object() && response.contains("result") ? 1 : 0);
        }
        out = std::move(response);
        return true;
    }
}


manager_t::manager_t()  = default;
manager_t::~manager_t() { disconnect_all(); }

void manager_t::add_server(const server_config_t& cfg)
{
    if (!anti_tamper::mcp_posture::is_runtime_trusted_server(cfg, false)) {
        diag::log_tagged_fmt("mcp",
            "add_server_blocked_mcp_posture name_hash=0x%016llX name_len=%zu enabled=%d transport=%d",
            static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
            cfg.name.size(),
            static_cast<int>(cfg.enabled),
            static_cast<int>(cfg.transport));
        return;
    }

    diag::log_tagged_fmt("mcp", "add_server name_hash=0x%016llX name_len=%zu url_hash=0x%016llX enabled=%d auto_connect=%d",
        static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
        cfg.name.size(),
        static_cast<unsigned long long>(mcp_log_hash(cfg.url)),
        static_cast<int>(cfg.enabled),
        static_cast<int>(cfg.auto_connect));
    std::lock_guard<std::mutex> lk(_mtx);


    for (auto& ep : _entries) {
        if (ep->cfg.name == cfg.name) {
            ep->cfg = cfg;
            diag::log_tagged_fmt("mcp", "add_server updated_existing name_hash=0x%016llX name_len=%zu",
                static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
                cfg.name.size());
            return;
        }
    }

    auto ep = std::make_shared<entry_t>();
    ep->cfg = cfg;
    _entries.push_back(std::move(ep));
    diag::log_tagged_fmt("mcp", "add_server added_new name_hash=0x%016llX name_len=%zu total_servers=%zu",
        static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
        cfg.name.size(),
        _entries.size());
}

void manager_t::remove_server(const std::string& name)
{
    diag::log_tagged_fmt("mcp", "remove_server name='%s'", name.c_str());
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);

        auto it = std::find_if(_entries.begin(), _entries.end(),
            [&](const std::shared_ptr<entry_t>& ep) { return ep && ep->cfg.name == name; });

        if (it == _entries.end()) {
            diag::log_tagged_fmt("mcp", "remove_server NOT_FOUND name='%s'", name.c_str());
            return;
        }
        target = *it;
        _entries.erase(it);
    }

    if (target) {
        target->client.disconnect();
        diag::log_tagged_fmt("mcp", "remove_server disconnected name='%s'", name.c_str());
    }
}

void manager_t::connect_all()
{
    diag::log_tagged("mcp", "connect_all enter");
    std::vector<std::string> to_connect;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        to_connect.reserve(_entries.size());
        for (auto& ep : _entries) {
            auto& e = *ep;
            if (e.cfg.enabled && e.cfg.auto_connect &&
                e.client.state() != connection_state_t::connected)
            {
                bool already = false;
                for (const auto& n : _in_flight_connects) {
                    if (n == e.cfg.name) { already = true; break; }
                }
                if (already) continue;
                to_connect.push_back(e.cfg.name);
                _in_flight_connects.push_back(e.cfg.name);
            }
        }
    }

    for (const auto& name : to_connect) {
        server_config_t cfg;
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(_mtx);
            for (auto& ep : _entries) {
                if (ep->cfg.name == name) {
                    cfg = ep->cfg;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            std::lock_guard<std::mutex> lk(_mtx);
            _in_flight_connects.erase(
                std::remove(_in_flight_connects.begin(), _in_flight_connects.end(), name),
                _in_flight_connects.end());
            continue;
        }

        client_t tmp_client;
        bool ok = tmp_client.connect(cfg);
        if (ok) {
            tmp_client.list_tools();
            ok = tmp_client.state() == connection_state_t::connected;
        }

        std::lock_guard<std::mutex> lk(_mtx);
        _in_flight_connects.erase(
            std::remove(_in_flight_connects.begin(), _in_flight_connects.end(), name),
            _in_flight_connects.end());
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                ep->client = std::move(tmp_client);
                break;
            }
        }
    }
}

void manager_t::disconnect_all()
{
    diag::log_tagged("mcp", "disconnect_all enter");
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }
    for (auto& ep : snapshot)
        ep->client.disconnect();
    diag::log_tagged_fmt("mcp", "disconnect_all done disconnected=%zu", snapshot.size());
}

bool manager_t::connect_server(const std::string& name)
{
    server_config_t cfg;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                cfg = ep->cfg;
                found = true;
                break;
            }
        }
        if (!found) return false;
        for (const auto& n : _in_flight_connects) {
            if (n == name) return true;
        }
        _in_flight_connects.push_back(name);
    }

    client_t tmp_client;
    bool ok = tmp_client.connect(cfg);
    if (ok) {
        tmp_client.list_tools();
        ok = tmp_client.state() == connection_state_t::connected;
    }

    std::lock_guard<std::mutex> lk(_mtx);
    _in_flight_connects.erase(
        std::remove(_in_flight_connects.begin(), _in_flight_connects.end(), name),
        _in_flight_connects.end());
    for (auto& ep : _entries) {
        if (ep->cfg.name == name) {
            ep->client = std::move(tmp_client);
            return ok;
        }
    }
    return false;
}

void manager_t::disconnect_server(const std::string& name)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                target = ep;
                break;
            }
        }
    }
    if (target) target->client.disconnect();
}

std::vector<remote_tool_t> manager_t::get_all_tools()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<remote_tool_t> all;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (e.client.is_connected()) {
            const auto& tools = e.client.cached_tools();
            all.insert(all.end(), tools.begin(), tools.end());
        }
    }
    return all;
}

call_result_t manager_t::call_tool(const std::string& qualified_name, const json& arguments)
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    size_t legacy_sep = qualified_name.find("::");
    if (legacy_sep != std::string::npos) {
        std::string server = qualified_name.substr(0, legacy_sep);
        std::string tool   = qualified_name.substr(legacy_sep + 2);

        std::shared_ptr<entry_t> target;
        for (auto& ep : snapshot) {
            if (ep->cfg.name == server && ep->client.is_connected()) {
                target = ep;
                break;
            }
        }
        if (target) return target->client.call_tool(tool, arguments);
        return call_result_t::error("MCP server '" + server + "' not found or not connected");
    }

    std::shared_ptr<entry_t> target;
    std::string resolved_tool;
    for (auto& ep : snapshot) {
        if (!ep->client.is_connected()) continue;
        for (const auto& t : ep->client.cached_tools()) {
            if (t.name == qualified_name) {
                target = ep;
                resolved_tool = t.original_name.empty() ? t.name : t.original_name;
                break;
            }
        }
        if (target) break;
    }
    if (target) return target->client.call_tool(resolved_tool, arguments);

    for (auto& ep : snapshot) {
        if (!ep->client.is_connected()) continue;
        for (const auto& t : ep->client.cached_tools()) {
            if (t.original_name == qualified_name) {
                target = ep;
                resolved_tool = t.original_name;
                break;
            }
        }
        if (target) break;
    }
    if (target) return target->client.call_tool(resolved_tool, arguments);

    return call_result_t::error("MCP tool '" + qualified_name + "' not found on any connected server");
}

size_t manager_t::tool_count() const
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    size_t count = 0;
    for (const auto& ep : snapshot) {
        const auto& e = *ep;
        if (e.client.is_connected())
            count += e.client.cached_tools().size();
    }
    return count;
}

std::vector<remote_resource_t> manager_t::get_all_resources()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<remote_resource_t> all;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (e.client.is_connected()) {
            auto res = e.client.list_resources();
            all.insert(all.end(), res.begin(), res.end());
        }
    }
    return all;
}

std::string manager_t::read_resource(const std::string& server_name, const std::string& uri)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == server_name && ep->client.is_connected()) {
                target = ep;
                break;
            }
        }
    }
    if (target) return target->client.read_resource(uri);
    return {};
}

std::vector<remote_prompt_t> manager_t::get_all_prompts()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<remote_prompt_t> all;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (e.client.is_connected()) {
            auto pr = e.client.list_prompts();
            all.insert(all.end(), pr.begin(), pr.end());
        }
    }
    return all;
}

std::string manager_t::get_prompt(const std::string& server_name,
                                  const std::string& prompt_name,
                                  const std::map<std::string, std::string>& arguments)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == server_name && ep->client.is_connected()) {
                target = ep;
                break;
            }
        }
    }
    if (target) return target->client.get_prompt(prompt_name, arguments);
    return {};
}

std::vector<manager_t::server_status_t> manager_t::get_status() const
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<server_status_t> result;
    result.reserve(snapshot.size());

    for (const auto& ep : snapshot) {
        const auto& e = *ep;
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
    std::vector<std::shared_ptr<entry_t>> snapshot;
    std::vector<std::string> in_flight_snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
        in_flight_snapshot = _in_flight_connects;
    }

    std::vector<std::string> needs_reconnect;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (!e.cfg.enabled || !e.cfg.auto_connect)
            continue;
        auto st = e.client.state();
        if (st == connection_state_t::error || st == connection_state_t::disconnected) {
            if (e.client.oauth_status() == oauth_status_t::needs_auth
                || e.client.oauth_status() == oauth_status_t::needs_client_registration)
                continue;
            bool already = false;
            for (const auto& n : in_flight_snapshot) {
                if (n == e.cfg.name) { already = true; break; }
            }
            if (already) continue;
            needs_reconnect.push_back(e.cfg.name);
            continue;
        }
        if (e.client.is_connected())
            e.client.poll_notifications();
    }

    for (const auto& name : needs_reconnect) {
        work_queue::post([this, name]() { this->connect_server(name); });
    }
}

bool manager_t::refresh_tools(const std::string& name)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                target = ep;
                break;
            }
        }
    }
    if (!target) return false;
    if (!target->client.is_connected()) return false;
    auto tools = target->client.list_tools();
    if (!target->client.is_connected()) return false;
    aida::events::mcp_tools_changed_t payload;
    payload.server_name = name;
    payload.tool_count = static_cast<int>(tools.size());
    aida::events::publish(aida::events::event_mcp_tools_changed, payload);
    return true;
}

bool manager_t::find_config(const std::string& name, server_config_t& out) const
{
    std::lock_guard<std::mutex> lk(_mtx);
    for (const auto& ep : _entries) {
        if (ep->cfg.name == name) {
            out = ep->cfg;
            return true;
        }
    }
    return false;
}

json manager_t::mcp_tool_list_json()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    json arr = json::array();
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (!e.client.is_connected()) continue;
        for (const auto& t : e.client.cached_tools()) {
            json entry;
            entry["name"]        = t.name;
            entry["description"] = t.description;
            if (!t.input_schema.is_null() && !t.input_schema.empty())
                entry["input_schema"] = t.input_schema;
            else
                entry["input_schema"] = json{{"type", "object"}, {"properties", json::object()}};
            entry["server_name"]   = t.server_name;
            entry["original_name"] = t.original_name;
            arr.push_back(std::move(entry));
        }
    }
    return arr;
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
            "[mcp.oauth] Camoufox open failed; non-Camoufox browser fallback is disabled");
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

    work_queue::post([state, on_complete, server_name]() {
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
    return true;
}

}
