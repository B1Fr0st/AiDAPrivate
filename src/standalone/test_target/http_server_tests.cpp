#include "http_server_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

namespace test_target {
namespace http_server {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[HTTP] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static HANDLE s_server_thread = nullptr;
static HANDLE s_udp_beacon_thread = nullptr;
static HANDLE s_outbound_probe_thread = nullptr;
static std::atomic<bool>* s_running_ptr = nullptr;
static uint16_t s_port = 18080;
static ULONGLONG s_start_time = 0;


struct http_request_t {
    char method[16];
    char path[512];
    char query[512];
    char headers[4096];
    char body[8192];
    int  body_length;
    char host[128];
    char content_type[128];
    char cookie[512];
    char connection[32];
    int  content_length;
};

static void parse_http_request(const char* raw, int raw_len, http_request_t* req) {
    memset(req, 0, sizeof(*req));


    const char* line_end = strstr(raw, "\r\n");
    if (!line_end) return;


    const char* p = raw;
    int i = 0;
    while (p < line_end && *p != ' ' && i < 15) { req->method[i++] = *p++; }
    req->method[i] = '\0';
    if (*p == ' ') p++;


    i = 0;
    char full_path[1024] = {0};
    while (p < line_end && *p != ' ' && i < 1023) { full_path[i++] = *p++; }
    full_path[i] = '\0';


    char* qmark = strchr(full_path, '?');
    if (qmark) {
        *qmark = '\0';
        strncpy_s(req->path, sizeof(req->path), full_path, _TRUNCATE);
        strncpy_s(req->query, sizeof(req->query), qmark + 1, _TRUNCATE);
    } else {
        strncpy_s(req->path, sizeof(req->path), full_path, _TRUNCATE);
    }


    const char* header_start = line_end + 2;
    const char* header_end = strstr(header_start, "\r\n\r\n");
    if (header_end) {
        int hdr_len = (int)(header_end - header_start);
        if (hdr_len > 0 && hdr_len < (int)sizeof(req->headers) - 1) {
            memcpy(req->headers, header_start, hdr_len);
            req->headers[hdr_len] = '\0';
        }


        const char* body_start = header_end + 4;
        int body_avail = raw_len - (int)(body_start - raw);
        if (body_avail > 0 && body_avail < (int)sizeof(req->body) - 1) {
            memcpy(req->body, body_start, body_avail);
            req->body[body_avail] = '\0';
            req->body_length = body_avail;
        }
    }


    auto extract_header = [&](const char* name, char* dest, int dest_size) {
        const char* h = header_start;
        int name_len = (int)strlen(name);
        while (h && h < (header_end ? header_end : raw + raw_len)) {
            if (_strnicmp(h, name, name_len) == 0) {
                const char* val = h + name_len;
                while (*val == ' ') val++;
                const char* ve = strstr(val, "\r\n");
                if (ve) {
                    int vlen = (int)(ve - val);
                    if (vlen < dest_size) {
                        memcpy(dest, val, vlen);
                        dest[vlen] = '\0';
                    }
                }
                return;
            }
            h = strstr(h, "\r\n");
            if (h) h += 2;
        }
    };

    extract_header("Host:", req->host, sizeof(req->host));
    extract_header("Content-Type:", req->content_type, sizeof(req->content_type));
    extract_header("Cookie:", req->cookie, sizeof(req->cookie));
    extract_header("Connection:", req->connection, sizeof(req->connection));

    const char* cl_str = nullptr;
    const char* h = header_start;
    while (h && h < (header_end ? header_end : raw + raw_len)) {
        if (_strnicmp(h, "Content-Length:", 15) == 0) {
            cl_str = h + 15;
            while (*cl_str == ' ') cl_str++;
            req->content_length = atoi(cl_str);
            break;
        }
        h = strstr(h, "\r\n");
        if (h) h += 2;
    }
}


static void send_response(SOCKET client, int status, const char* status_text,
                          const char* content_type, const char* body, int body_len,
                          const char* extra_headers = nullptr) {
    char header_buf[2048];
    int hlen = sprintf_s(header_buf, sizeof(header_buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Server: AiDA-TestTarget/1.0\r\n"
        "%s"
        "\r\n",
        status, status_text, content_type, body_len,
        extra_headers ? extra_headers : "");

    send(client, header_buf, hlen, 0);
    if (body && body_len > 0) {
        send(client, body, body_len, 0);
    }
}

static void send_text(SOCKET client, int status, const char* status_text, const char* body) {
    send_response(client, status, status_text, "text/plain", body, (int)strlen(body));
}

static void send_json(SOCKET client, int status, const char* body) {
    send_response(client, status, "OK", "application/json", body, (int)strlen(body));
}

static void send_html(SOCKET client, int status, const char* body) {
    send_response(client, status, "OK", "text/html", body, (int)strlen(body));
}


static bool get_query_param(const char* query, const char* name, char* out, int out_max) {
    if (!query || !name) return false;
    int name_len = (int)strlen(name);
    const char* p = query;
    while (*p) {
        if (strncmp(p, name, name_len) == 0 && p[name_len] == '=') {
            const char* val = p + name_len + 1;
            int i = 0;
            while (val[i] && val[i] != '&' && i < out_max - 1) {
                out[i] = val[i];
                i++;
            }
            out[i] = '\0';
            return true;
        }
        p = strchr(p, '&');
        if (!p) break;
        p++;
    }
    return false;
}


static void handle_index(SOCKET client, const http_request_t* req) {
    const char* html =
        "<!DOCTYPE html><html><head><title>AiDA Test Target</title></head><body>"
        "<h1>AiDA Test Target HTTP Server</h1>"
        "<ul>"
        "<li><a href='/api/status'>GET /api/status</a> - Server status</li>"
        "<li><a href='/api/headers'>GET /api/headers</a> - Echo headers</li>"
        "<li><a href='/api/cookies'>GET /api/cookies</a> - Show cookies</li>"
        "<li><a href='/api/redirect'>GET /api/redirect</a> - 302 redirect</li>"
        "<li><a href='/api/slow'>GET /api/slow</a> - Slow response (3s)</li>"
        "<li><a href='/api/large'>GET /api/large</a> - Large response (64KB)</li>"
        "<li><a href='/api/xml'>GET /api/xml</a> - XML response</li>"
        "<li><a href='/api/form'>GET /api/form</a> - HTML form</li>"
        "<li><a href='/api/jwt'>GET /api/jwt</a> - Sample JWT</li>"
        "<li><a href='/api/xss?input=test'>GET /api/xss</a> - XSS surface</li>"
        "<li><a href='/api/sqli?id=1'>GET /api/sqli</a> - SQLi surface</li>"
        "<li><a href='/api/csp'>GET /api/csp</a> - CSP header</li>"
        "<li><a href='/api/cors'>GET /api/cors</a> - CORS header</li>"
        "<li><a href='/api/set-cookie'>GET /api/set-cookie</a> - Set cookies</li>"
        "<li><a href='/api/websocket-upgrade'>GET /api/websocket-upgrade</a> - WebSocket mock</li>"
        "<li><a href='/api/h2c-upgrade'>GET /api/h2c-upgrade</a> - H2C mock</li>"
        "<li>POST /api/echo - Echo body</li>"
        "<li>POST /api/login - Login surface</li>"
        "</ul></body></html>";
    send_html(client, 200, html);
}

static void handle_status(SOCKET client, const http_request_t* req) {
    ULONGLONG uptime = (GetTickCount64() - s_start_time) / 1000;
    char body[256];
    sprintf_s(body, sizeof(body),
        "{\"status\":\"ok\",\"pid\":%lu,\"uptime\":%llu,\"port\":%u}",
        GetCurrentProcessId(), uptime, s_port);
    send_json(client, 200, body);
}

static void handle_echo(SOCKET client, const http_request_t* req) {
    char body[8192 + 128];
    sprintf_s(body, sizeof(body),
        "{\"method\":\"%s\",\"path\":\"%s\",\"body_length\":%d,\"body\":\"%.*s\"}",
        req->method, req->path, req->body_length,
        req->body_length < 4096 ? req->body_length : 4096, req->body);
    send_json(client, 200, body);
}

static void handle_headers(SOCKET client, const http_request_t* req) {

    std::string json = "{\"headers\":{";
    const char* p = req->headers;
    bool first = true;
    while (p && *p) {
        const char* colon = strchr(p, ':');
        const char* eol = strstr(p, "\r\n");
        if (!colon || !eol || colon > eol) break;

        if (!first) json += ",";
        first = false;

        std::string name(p, colon);
        const char* val = colon + 1;
        while (*val == ' ') val++;
        std::string value(val, eol);

        json += "\"" + name + "\":\"" + value + "\"";
        p = eol + 2;
    }
    json += "}}";
    send_json(client, 200, json.c_str());
}

static void handle_cookies(SOCKET client, const http_request_t* req) {
    char body[1024];
    if (req->cookie[0]) {
        sprintf_s(body, sizeof(body), "{\"cookies\":\"%s\"}", req->cookie);
    } else {
        sprintf_s(body, sizeof(body), "{\"cookies\":null}");
    }
    send_json(client, 200, body);
}

static void handle_redirect(SOCKET client, const http_request_t* req) {
    const char* body = "Redirecting to /api/status";
    send_response(client, 302, "Found", "text/plain", body, (int)strlen(body),
                  "Location: /api/status\r\n");
}

static void handle_slow(SOCKET client, const http_request_t* req) {
    Sleep(3000);
    send_json(client, 200, "{\"delayed\":true,\"seconds\":3}");
}

static void handle_large(SOCKET client, const http_request_t* req) {

    int total = 65536;
    char* buf = (char*)malloc(total + 1);
    if (!buf) {
        send_text(client, 500, "Internal Server Error", "Out of memory");
        return;
    }
    for (int i = 0; i < total; ++i)
        buf[i] = 'A' + (i % 26);
    buf[total] = '\0';
    send_response(client, 200, "OK", "text/plain", buf, total);
    free(buf);
}

static void handle_xml(SOCKET client, const http_request_t* req) {
    const char* xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
        "<response>\r\n"
        "  <status>ok</status>\r\n"
        "  <server>AiDA-TestTarget</server>\r\n"
        "  <version>1.0</version>\r\n"
        "  <items>\r\n"
        "    <item id=\"1\">Alpha</item>\r\n"
        "    <item id=\"2\">Beta</item>\r\n"
        "    <item id=\"3\">Gamma</item>\r\n"
        "  </items>\r\n"
        "</response>\r\n";
    send_response(client, 200, "OK", "application/xml", xml, (int)strlen(xml));
}

static void handle_form(SOCKET client, const http_request_t* req) {
    char html[1024];
    sprintf_s(html, sizeof(html),
        "<!DOCTYPE html><html><body>"
        "<h2>AiDA Test Form</h2>"
        "<form method='POST' action='/api/echo'>"
        "<label>Username: <input type='text' name='username' value='testuser'></label><br>"
        "<label>Password: <input type='password' name='password' value='testpass'></label><br>"
        "<label>Message: <textarea name='message'>Hello AiDA</textarea></label><br>"
        "<input type='hidden' name='csrf_token' value='aida_test_csrf_token_12345'>"
        "<button type='submit'>Submit</button>"
        "</form></body></html>");
    send_html(client, 200, html);
}

static void handle_jwt(SOCKET client, const http_request_t* req) {
    ULONGLONG now = (ULONGLONG)time(nullptr);
    char body[512];
    sprintf_s(body, sizeof(body),
        "{\"token\":\"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJzdWIiOiJ0ZXN0IiwibmFtZSI6IkFpREFfVGVzdFRhcmdldCIsImFkbWluIjpmYWxzZX0.\","
        "\"algorithm\":\"none\","
        "\"issued_at\":%llu}",
        now);
    send_json(client, 200, body);
}

static void handle_login(SOCKET client, const http_request_t* req) {

    bool auth = false;
    if (strstr(req->body, "admin") && strstr(req->body, "password123")) {
        auth = true;
    }
    if (strstr(req->body, "testuser") && strstr(req->body, "testpass")) {
        auth = true;
    }

    if (auth) {
        send_json(client, 200,
            "{\"status\":\"authenticated\",\"user\":\"testuser\",\"session\":\"aida_session_abc123\"}");
    } else {
        send_json(client, 401,
            "{\"status\":\"denied\",\"error\":\"Invalid credentials\"}");
    }
}

static void handle_xss(SOCKET client, const http_request_t* req) {
    char input[256] = {0};
    get_query_param(req->query, "input", input, sizeof(input));


    char html[2048];
    sprintf_s(html, sizeof(html),
        "<!DOCTYPE html><html><body>"
        "<h2>XSS Test Surface</h2>"
        "<p>You searched for: %s</p>"
        "<form method='GET' action='/api/xss'>"
        "<input type='text' name='input' value='%s'>"
        "<button>Search</button>"
        "</form></body></html>",
        input, input);
    send_html(client, 200, html);
}

static void handle_sqli(SOCKET client, const http_request_t* req) {
    char id[128] = {0};
    get_query_param(req->query, "id", id, sizeof(id));


    if (strchr(id, '\'') || strstr(id, "OR") || strstr(id, "or") ||
        strstr(id, "UNION") || strstr(id, "union") || strstr(id, "--")) {
        char body[1024];
        sprintf_s(body, sizeof(body),
            "{\"error\":\"SQL Error: You have an error in your SQL syntax near '%s' at line 1\","
            "\"query\":\"SELECT * FROM users WHERE id = '%s'\","
            "\"database\":\"aida_test_db\"}",
            id, id);
        send_json(client, 500, body);
    } else {
        char body[512];
        sprintf_s(body, sizeof(body),
            "{\"id\":\"%s\",\"name\":\"Test User\",\"email\":\"test@aida.local\"}",
            id);
        send_json(client, 200, body);
    }
}

static void handle_csp(SOCKET client, const http_request_t* req) {
    const char* body = "{\"csp\":\"enabled\"}";
    send_response(client, 200, "OK", "application/json", body, (int)strlen(body),
        "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-aida123'; style-src 'self' 'unsafe-inline'; img-src *; connect-src 'self' https://api.aida.local\r\n");
}

static void handle_cors(SOCKET client, const http_request_t* req) {
    const char* body = "{\"cors\":\"open\"}";
    send_response(client, 200, "OK", "application/json", body, (int)strlen(body),
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: *\r\n"
        "Access-Control-Allow-Credentials: true\r\n");
}

static void handle_set_cookie(SOCKET client, const http_request_t* req) {
    const char* body = "{\"cookies_set\":3}";
    send_response(client, 200, "OK", "application/json", body, (int)strlen(body),
        "Set-Cookie: aida_session=abc123def456; Path=/; HttpOnly\r\n"
        "Set-Cookie: aida_pref=theme=dark; Path=/; Max-Age=86400\r\n"
        "Set-Cookie: aida_tracking=xyz789; Path=/; SameSite=None; Secure\r\n");
}

static void handle_websocket_upgrade(SOCKET client, const http_request_t* req) {

    const char* resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Protocol: aida-test\r\n"
        "\r\n";
    send(client, resp, (int)strlen(resp), 0);
}

static void handle_h2c_upgrade(SOCKET client, const http_request_t* req) {

    const char* resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: h2c\r\n"
        "\r\n";
    send(client, resp, (int)strlen(resp), 0);
}


static void route_request(SOCKET client, const http_request_t* req) {
    log("Request: %s %s%s%s", req->method, req->path,
        req->query[0] ? "?" : "", req->query);

    if (strcmp(req->path, "/") == 0 && strcmp(req->method, "GET") == 0) {
        handle_index(client, req);
    } else if (strcmp(req->path, "/api/status") == 0 && strcmp(req->method, "GET") == 0) {
        handle_status(client, req);
    } else if (strcmp(req->path, "/api/echo") == 0 && strcmp(req->method, "POST") == 0) {
        handle_echo(client, req);
    } else if (strcmp(req->path, "/api/headers") == 0 && strcmp(req->method, "GET") == 0) {
        handle_headers(client, req);
    } else if (strcmp(req->path, "/api/cookies") == 0 && strcmp(req->method, "GET") == 0) {
        handle_cookies(client, req);
    } else if (strcmp(req->path, "/api/redirect") == 0 && strcmp(req->method, "GET") == 0) {
        handle_redirect(client, req);
    } else if (strcmp(req->path, "/api/slow") == 0 && strcmp(req->method, "GET") == 0) {
        handle_slow(client, req);
    } else if (strcmp(req->path, "/api/large") == 0 && strcmp(req->method, "GET") == 0) {
        handle_large(client, req);
    } else if (strcmp(req->path, "/api/xml") == 0 && strcmp(req->method, "GET") == 0) {
        handle_xml(client, req);
    } else if (strcmp(req->path, "/api/form") == 0 && strcmp(req->method, "GET") == 0) {
        handle_form(client, req);
    } else if (strcmp(req->path, "/api/jwt") == 0 && strcmp(req->method, "GET") == 0) {
        handle_jwt(client, req);
    } else if (strcmp(req->path, "/api/login") == 0 && strcmp(req->method, "POST") == 0) {
        handle_login(client, req);
    } else if (strcmp(req->path, "/api/xss") == 0 && strcmp(req->method, "GET") == 0) {
        handle_xss(client, req);
    } else if (strcmp(req->path, "/api/sqli") == 0 && strcmp(req->method, "GET") == 0) {
        handle_sqli(client, req);
    } else if (strcmp(req->path, "/api/csp") == 0 && strcmp(req->method, "GET") == 0) {
        handle_csp(client, req);
    } else if (strcmp(req->path, "/api/cors") == 0 && strcmp(req->method, "GET") == 0) {
        handle_cors(client, req);
    } else if (strcmp(req->path, "/api/set-cookie") == 0 && strcmp(req->method, "GET") == 0) {
        handle_set_cookie(client, req);
    } else if (strcmp(req->path, "/api/websocket-upgrade") == 0 && strcmp(req->method, "GET") == 0) {
        handle_websocket_upgrade(client, req);
    } else if (strcmp(req->path, "/api/h2c-upgrade") == 0 && strcmp(req->method, "GET") == 0) {
        handle_h2c_upgrade(client, req);
    } else {
        send_text(client, 404, "Not Found", "404 - Not Found");
    }
}


static void handle_client(SOCKET client) {
    char buf[16384] = {0};
    int total_recv = 0;


    DWORD timeout = 5000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));


    while (total_recv < (int)sizeof(buf) - 1) {
        int n = recv(client, buf + total_recv, (int)sizeof(buf) - 1 - total_recv, 0);
        if (n <= 0) break;
        total_recv += n;


        if (strstr(buf, "\r\n\r\n")) {

            const char* cl = strstr(buf, "Content-Length:");
            if (!cl) cl = strstr(buf, "content-length:");
            if (cl) {
                int content_len = atoi(cl + 15);
                const char* body_start = strstr(buf, "\r\n\r\n") + 4;
                int body_recv = total_recv - (int)(body_start - buf);
                if (body_recv >= content_len) break;
                continue;
            }
            break;
        }
    }

    if (total_recv > 0) {
        http_request_t req;
        parse_http_request(buf, total_recv, &req);
        route_request(client, &req);
    }
}


static DWORD WINAPI server_thread_func(LPVOID param) {
    log("Server thread starting on port %u...", s_port);

    WSADATA wsa{};
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        log("WSAStartup failed: %d", rc);
        return 1;
    }

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        log("Socket creation failed: %d", WSAGetLastError());
        return 1;
    }

    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(s_port);

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log("Bind failed on port %u: %d", s_port, WSAGetLastError());
        closesocket(listener);
        return 1;
    }

    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        log("Listen failed: %d", WSAGetLastError());
        closesocket(listener);
        return 1;
    }

    log("HTTP server listening on 0.0.0.0:%u", s_port);

    u_long nonblocking = 1;
    ioctlsocket(listener, FIONBIO, &nonblocking);

    while (s_running_ptr && s_running_ptr->load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(0, &readfds, nullptr, nullptr, &tv);
        if (sel > 0 && FD_ISSET(listener, &readfds)) {
            struct sockaddr_in client_addr{};
            int client_len = sizeof(client_addr);
            SOCKET client = accept(listener, (struct sockaddr*)&client_addr, &client_len);
            if (client != INVALID_SOCKET) {
                char client_ip[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                log("Accepted connection from %s:%u", client_ip, ntohs(client_addr.sin_port));

                handle_client(client);
                closesocket(client);
            }
        }
    }

    closesocket(listener);
    log("HTTP server stopped");
    return 0;
}


static DWORD WINAPI udp_beacon_thread_func(LPVOID param) {
    log("UDP beacon thread starting (target port 19999)...");

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        log("UDP beacon socket failed: %d", WSAGetLastError());
        return 1;
    }

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(19999);
    inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

    uint32_t seq = 0;
    while (s_running_ptr && s_running_ptr->load()) {
        char beacon[64];
        int len = sprintf_s(beacon, sizeof(beacon), "AIDA_BEACON seq=%u pid=%lu", seq++, GetCurrentProcessId());
        sendto(udp, beacon, len, 0, (struct sockaddr*)&dest, sizeof(dest));
        Sleep(2000);
    }

    closesocket(udp);
    log("UDP beacon thread stopped (sent %u beacons)", seq);
    return 0;
}


static DWORD WINAPI outbound_probe_thread_func(LPVOID param) {
    log("Outbound probe thread starting (target port 18081)...");

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    uint32_t attempt = 0;
    while (s_running_ptr && s_running_ptr->load()) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            struct sockaddr_in dest{};
            dest.sin_family = AF_INET;
            dest.sin_port = htons(18081);
            inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);


            u_long nonblocking = 1;
            ioctlsocket(s, FIONBIO, &nonblocking);

            connect(s, (struct sockaddr*)&dest, sizeof(dest));


            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(s, &writefds);
            struct timeval tv = { 0, 500000 };
            int sel = select(0, nullptr, &writefds, nullptr, &tv);
            if (sel > 0) {
                const char* probe = "AIDA_PROBE\r\n";
                send(s, probe, (int)strlen(probe), 0);
            }

            closesocket(s);
        }

        attempt++;
        Sleep(5000);
    }

    log("Outbound probe thread stopped (%u attempts)", attempt);
    return 0;
}


void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== HTTP server tests starting ===");

    s_port = cfg.port;
    s_running_ptr = &running;
    s_start_time = GetTickCount64();

    log("Starting HTTP server on port %u", s_port);
    log("Starting UDP beacon (port 19999)");
    log("Starting outbound probe (port 18081)");

    s_server_thread = CreateThread(nullptr, 0, server_thread_func, nullptr, 0, nullptr);
    s_udp_beacon_thread = CreateThread(nullptr, 0, udp_beacon_thread_func, nullptr, 0, nullptr);
    s_outbound_probe_thread = CreateThread(nullptr, 0, outbound_probe_thread_func, nullptr, 0, nullptr);

    if (s_server_thread) log("Server thread started");
    if (s_udp_beacon_thread) log("UDP beacon thread started");
    if (s_outbound_probe_thread) log("Outbound probe thread started");

    log("=== HTTP server tests initialized (running in background) ===");
}

void shutdown_all() {
    log("Shutting down HTTP server threads...");

    HANDLE threads[3] = { s_server_thread, s_udp_beacon_thread, s_outbound_probe_thread };
    int valid = 0;
    HANDLE wait_handles[3];
    for (int i = 0; i < 3; ++i) {
        if (threads[i]) wait_handles[valid++] = threads[i];
    }

    if (valid > 0) {
        WaitForMultipleObjects(valid, wait_handles, TRUE, 5000);
    }

    for (int i = 0; i < 3; ++i) {
        if (threads[i]) CloseHandle(threads[i]);
    }
    s_server_thread = nullptr;
    s_udp_beacon_thread = nullptr;
    s_outbound_probe_thread = nullptr;

    log("HTTP server threads shut down");
}

}
}
