#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>

#include "collaborator.hpp"
#include "../../infra/work_queue.hpp"
#include "helpers/diag_log.hpp"

#include "httplib.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <unordered_map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace aida {
namespace burp {
namespace collaborator {

namespace {

struct wsa_guard_t
{
    WSADATA data{};
    bool    ok = false;
    wsa_guard_t() { ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0); }
    ~wsa_guard_t() { if (ok) WSACleanup(); }
};

static wsa_guard_t s_wsa_guard;

struct state_t
{
    std::mutex                                              mtx;
    std::atomic<bool>                                       running{false};
    std::atomic<bool>                                       http_alive{false};
    std::atomic<bool>                                       dns_alive{false};
    std::atomic<bool>                                       smtp_alive{false};
    std::atomic<bool>                                       stop_request{false};

    collaborator_config_t                                   config;
    uint64_t                                                started_ms = 0;

    std::deque<interaction_t>                               interactions;
    std::atomic<uint64_t>                                   next_id{1};

    std::unordered_map<std::string, token_info_t>           tokens;

    std::unique_ptr<httplib::Server>                        http_server;
    std::thread                                             http_thread;
    std::atomic<bool>                                       http_thread_alive{false};

    SOCKET                                                  dns_socket = INVALID_SOCKET;
    std::thread                                             dns_thread;
    std::atomic<bool>                                       dns_thread_alive{false};

    SOCKET                                                  smtp_socket = INVALID_SOCKET;
    std::thread                                             smtp_thread;
    std::atomic<bool>                                       smtp_thread_alive{false};

    std::mutex                                              err_mtx;
    std::string                                             last_err;
};

static state_t g_state;

static void set_last_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_state.err_mtx);
    g_state.last_err = msg;
}

static uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

static std::string lower_ascii(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
    return out;
}

static std::string trim_ascii(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

static bool is_lower_alpha(char c) { return c >= 'a' && c <= 'z'; }

static std::string strip_port_from_host(const std::string& host)
{
    if (host.empty()) return host;
    if (host[0] == '[') {
        size_t end = host.find(']');
        if (end != std::string::npos) return host.substr(1, end - 1);
        return host;
    }
    size_t colon = host.find(':');
    if (colon == std::string::npos) return host;
    return host.substr(0, colon);
}

static std::string extract_token_from_label(const std::string& label)
{
    std::string lower = lower_ascii(label);
    if (lower.size() < 8 || lower.size() > 64) return {};
    for (char c : lower) {
        if (!is_lower_alpha(c)) return {};
    }
    return lower;
}

static std::string extract_token_from_host(const std::string& host, const std::string& public_host)
{
    std::string h = lower_ascii(strip_port_from_host(host));
    std::string p = lower_ascii(public_host);
    if (!p.empty()) {
        if (h.size() > p.size() + 1) {
            size_t pos = h.size() - p.size();
            if (h.compare(pos, p.size(), p) == 0 && h[pos - 1] == '.') {
                std::string sub = h.substr(0, pos - 1);
                size_t dot = sub.rfind('.');
                std::string leaf = (dot == std::string::npos) ? sub : sub.substr(dot + 1);
                return extract_token_from_label(leaf);
            }
        }
    }
    size_t first_dot = h.find('.');
    std::string leaf = (first_dot == std::string::npos) ? h : h.substr(0, first_dot);
    return extract_token_from_label(leaf);
}

static std::string extract_token_from_qname(const std::string& qname, const std::string& public_host)
{
    return extract_token_from_host(qname, public_host);
}

static std::string extract_token_from_path(const std::string& path)
{
    size_t start = 0;
    if (!path.empty() && path[0] == '/') start = 1;
    size_t end = path.find('/', start);
    if (end == std::string::npos) end = path.find('?', start);
    if (end == std::string::npos) end = path.size();
    if (end <= start) return {};
    std::string seg = path.substr(start, end - start);
    return extract_token_from_label(seg);
}

static void append_interaction(interaction_t&& it)
{
    std::lock_guard<std::mutex> lk(g_state.mtx);
    if (it.id == 0) it.id = g_state.next_id.fetch_add(1);
    if (it.timestamp_ms == 0) it.timestamp_ms = now_ms();

    if (!it.payload_token.empty()) {
        auto found = g_state.tokens.find(it.payload_token);
        if (found != g_state.tokens.end()) {
            found->second.interaction_count++;
            found->second.last_seen_ms = it.timestamp_ms;
        }
    }

    g_state.interactions.push_back(std::move(it));
    while (g_state.interactions.size() > g_state.config.max_interactions) {
        g_state.interactions.pop_front();
    }
}

static std::string client_ip_to_string(uint32_t ip_be)
{
    char buf[INET_ADDRSTRLEN] = {};
    in_addr a{};
    a.s_addr = ip_be;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

static std::string make_raw_http(const httplib::Request& req)
{
    std::string raw;
    raw.reserve(512 + req.body.size());
    raw += req.method;
    raw += ' ';
    raw += req.path;
    if (!req.params.empty()) {
        raw += '?';
        bool first = true;
        for (const auto& kv : req.params) {
            if (!first) raw += '&';
            raw += kv.first;
            raw += '=';
            raw += kv.second;
            first = false;
        }
    }
    raw += ' ';
    raw += "HTTP/1.1\r\n";
    for (const auto& kv : req.headers) {
        raw += kv.first;
        raw += ": ";
        raw += kv.second;
        raw += "\r\n";
    }
    raw += "\r\n";
    raw += req.body;
    return raw;
}

static void on_http_request(const httplib::Request& req, httplib::Response& res)
{
    collaborator_config_t cfg_snapshot;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        cfg_snapshot = g_state.config;
    }

    interaction_t it;
    it.kind = "http";
    it.client_ip = req.remote_addr;
    it.client_port = (req.remote_port < 0 || req.remote_port > 65535) ? 0 : static_cast<uint16_t>(req.remote_port);
    it.timestamp_ms = now_ms();

    std::string host_hdr;
    auto host_it = req.headers.find("Host");
    if (host_it != req.headers.end()) host_hdr = host_it->second;
    it.subdomain = strip_port_from_host(host_hdr);

    std::string token = extract_token_from_host(host_hdr, cfg_snapshot.public_host);
    if (token.empty()) token = extract_token_from_path(req.path);
    it.payload_token = token;

    it.raw = make_raw_http(req);

    it.details["method"]   = req.method;
    it.details["path"]     = req.path;
    it.details["body"]     = req.body;
    it.details["host"]     = host_hdr;
    if (!req.params.empty()) {
        std::string q;
        bool first = true;
        for (const auto& kv : req.params) {
            if (!first) q += '&';
            q += kv.first; q += '='; q += kv.second;
            first = false;
        }
        it.details["query"] = q;
    }
    auto ua_it = req.headers.find("User-Agent");
    if (ua_it != req.headers.end()) it.details["user_agent"] = ua_it->second;
    auto ref_it = req.headers.find("Referer");
    if (ref_it != req.headers.end()) it.details["referer"] = ref_it->second;
    auto auth_it = req.headers.find("Authorization");
    if (auth_it != req.headers.end()) it.details["authorization"] = auth_it->second;

    ::diag::log_tagged_fmt("collaborator",
        "http_interaction client=%s:%u host='%s' method='%s' path='%s' token='%s' body_size=%zu",
        it.client_ip.c_str(), it.client_port,
        host_hdr.c_str(), req.method.c_str(), req.path.c_str(),
        it.payload_token.c_str(), req.body.size());

    append_interaction(std::move(it));

    if (!cfg_snapshot.canned_body.empty()) {
        res.set_content(cfg_snapshot.canned_body, cfg_snapshot.canned_content_type);
    } else {
        res.status = 200;
        res.set_content("", "text/plain");
    }
    res.set_header("Server", "AiDA-Collaborator/1.0");
}

static void http_thread_main(std::string bind_ip, uint16_t port)
{
    g_state.http_thread_alive.store(true);
    g_state.http_alive.store(true);

    bool ok = false;
    try {
        ok = g_state.http_server->listen(bind_ip.c_str(), static_cast<int>(port));
    } catch (...) {
        ok = false;
    }
    (void)ok;

    g_state.http_alive.store(false);
    g_state.http_thread_alive.store(false);
    ::diag::log_tagged("collaborator", "http_thread_exit");
}

struct dns_parse_result_t
{
    bool        valid = false;
    uint16_t    transaction_id = 0;
    uint16_t    flags = 0;
    uint16_t    qd_count = 0;
    std::string qname;
    uint16_t    qtype = 0;
    uint16_t    qclass = 0;
    size_t      header_end = 12;
    size_t      question_end = 0;
};

static dns_parse_result_t parse_dns_question(const uint8_t* buf, size_t len)
{
    dns_parse_result_t r;
    if (len < 12) return r;
    r.transaction_id = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
    r.flags          = static_cast<uint16_t>((buf[2] << 8) | buf[3]);
    r.qd_count       = static_cast<uint16_t>((buf[4] << 8) | buf[5]);
    if (r.qd_count == 0) return r;

    size_t pos = 12;
    std::string name;
    int label_loops = 0;
    while (pos < len) {
        if (label_loops++ > 64) return r;
        uint8_t lab_len = buf[pos];
        if (lab_len == 0) {
            pos += 1;
            break;
        }
        if ((lab_len & 0xC0) != 0) {
            return r;
        }
        if (pos + 1 + lab_len > len) return r;
        if (!name.empty()) name.push_back('.');
        for (size_t i = 0; i < lab_len; ++i) {
            uint8_t c = buf[pos + 1 + i];
            name.push_back(static_cast<char>(c));
        }
        pos += 1 + lab_len;
        if (name.size() > 255) return r;
    }
    if (pos + 4 > len) return r;
    r.qname  = name;
    r.qtype  = static_cast<uint16_t>((buf[pos] << 8) | buf[pos + 1]);
    r.qclass = static_cast<uint16_t>((buf[pos + 2] << 8) | buf[pos + 3]);
    r.question_end = pos + 4;
    r.valid = true;
    return r;
}

static const char* dns_qtype_name(uint16_t qt)
{
    switch (qt) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 41: return "OPT";
        case 257: return "CAA";
        default:  return "OTHER";
    }
}

static std::vector<uint8_t> build_dns_answer(const dns_parse_result_t& q, const std::vector<uint8_t>& query_raw, uint32_t answer_ip_be)
{
    std::vector<uint8_t> out;
    out.reserve(query_raw.size() + 32);
    out.assign(query_raw.begin(), query_raw.begin() + static_cast<ptrdiff_t>(std::min(query_raw.size(), q.question_end)));
    out[2] = 0x84;
    out[3] = 0x00;
    out[4] = 0x00; out[5] = 0x01;
    out[6] = 0x00; out[7] = (q.qtype == 1) ? 0x01 : 0x00;
    out[8] = 0x00; out[9] = 0x00;
    out[10] = 0x00; out[11] = 0x00;

    if (q.qtype != 1) {
        return out;
    }

    out.push_back(0xC0);
    out.push_back(0x0C);
    out.push_back(0x00); out.push_back(0x01);
    out.push_back(0x00); out.push_back(0x01);
    out.push_back(0x00); out.push_back(0x00); out.push_back(0x00); out.push_back(0x3C);
    out.push_back(0x00); out.push_back(0x04);
    out.push_back(static_cast<uint8_t>(answer_ip_be & 0xFF));
    out.push_back(static_cast<uint8_t>((answer_ip_be >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((answer_ip_be >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((answer_ip_be >> 24) & 0xFF));
    return out;
}

static void dns_thread_main(std::string bind_ip, uint16_t port, std::string public_host, std::string public_ip)
{
    g_state.dns_thread_alive.store(true);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        ::diag::log_tagged_fmt("collaborator", "dns_socket_create_failed err=%d", WSAGetLastError());
        g_state.dns_thread_alive.store(false);
        return;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) != 1) {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        ::diag::log_tagged_fmt("collaborator", "dns_bind_failed addr=%s:%u err=%d", bind_ip.c_str(), port, err);
        closesocket(sock);
        g_state.dns_thread_alive.store(false);
        return;
    }

    DWORD recv_timeout = 500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recv_timeout), sizeof(recv_timeout));

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.dns_socket = sock;
    }
    g_state.dns_alive.store(true);

    uint32_t answer_ip_be = 0;
    in_addr aip{};
    if (inet_pton(AF_INET, public_ip.c_str(), &aip) == 1) {
        answer_ip_be = aip.s_addr;
    } else {
        answer_ip_be = htonl(INADDR_LOOPBACK);
    }

    ::diag::log_tagged_fmt("collaborator", "dns_listener_ready bind=%s:%u public_host='%s' public_ip='%s'",
        bind_ip.c_str(), port, public_host.c_str(), public_ip.c_str());

    while (!g_state.stop_request.load(std::memory_order_acquire)) {
        uint8_t buf[1500];
        sockaddr_in from{};
        int from_len = sizeof(from);
        int n = recvfrom(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                         reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) continue;
            if (g_state.stop_request.load(std::memory_order_acquire)) break;
            continue;
        }
        if (n < 12) continue;

        std::vector<uint8_t> raw_q(buf, buf + n);
        dns_parse_result_t parsed = parse_dns_question(buf, static_cast<size_t>(n));
        if (!parsed.valid) continue;

        std::string client = client_ip_to_string(from.sin_addr.s_addr);
        uint16_t client_port = ntohs(from.sin_port);
        std::string token = extract_token_from_qname(parsed.qname, public_host);

        std::string raw_dump;
        raw_dump.reserve(static_cast<size_t>(n) * 3);
        for (int i = 0; i < n; ++i) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02x ", buf[i]);
            raw_dump += hex;
        }

        interaction_t it;
        it.kind = "dns";
        it.client_ip = client;
        it.client_port = client_port;
        it.subdomain = parsed.qname;
        it.payload_token = token;
        it.raw = raw_dump;
        it.details["qname"]  = parsed.qname;
        it.details["qtype"]  = dns_qtype_name(parsed.qtype);
        char tid[16];
        snprintf(tid, sizeof(tid), "0x%04x", parsed.transaction_id);
        it.details["txn_id"] = tid;

        ::diag::log_tagged_fmt("collaborator",
            "dns_interaction client=%s:%u qname='%s' qtype=%s token='%s'",
            client.c_str(), client_port, parsed.qname.c_str(),
            dns_qtype_name(parsed.qtype), token.c_str());

        append_interaction(std::move(it));

        std::vector<uint8_t> answer = build_dns_answer(parsed, raw_q, answer_ip_be);
        if (!answer.empty()) {
            sendto(sock, reinterpret_cast<const char*>(answer.data()),
                   static_cast<int>(answer.size()), 0,
                   reinterpret_cast<sockaddr*>(&from), from_len);
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.dns_socket = INVALID_SOCKET;
    }
    closesocket(sock);
    g_state.dns_alive.store(false);
    g_state.dns_thread_alive.store(false);
    ::diag::log_tagged("collaborator", "dns_thread_exit");
}

static bool smtp_send_line(SOCKET s, const char* text)
{
    size_t len = std::strlen(text);
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, text + sent, static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static int smtp_recv_line(SOCKET s, std::string& out_line, int timeout_ms, size_t max_len = 4096)
{
    DWORD t = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
    out_line.clear();
    while (out_line.size() < max_len) {
        char c = 0;
        int n = recv(s, &c, 1, 0);
        if (n <= 0) return -1;
        out_line.push_back(c);
        if (out_line.size() >= 2 &&
            out_line[out_line.size() - 2] == '\r' &&
            out_line[out_line.size() - 1] == '\n') {
            out_line.resize(out_line.size() - 2);
            return static_cast<int>(out_line.size());
        }
    }
    return static_cast<int>(out_line.size());
}

static void smtp_session(SOCKET client_sock, std::string client_ip, uint16_t client_port,
                          std::string public_host, int max_message)
{
    smtp_send_line(client_sock, "220 collaborator.aida ESMTP\r\n");

    std::string mail_from;
    std::vector<std::string> rcpts;
    std::string envelope_log;
    bool quit = false;

    while (!quit && !g_state.stop_request.load(std::memory_order_acquire)) {
        std::string line;
        int rcv = smtp_recv_line(client_sock, line, 30000);
        if (rcv < 0) break;
        envelope_log += line;
        envelope_log += "\r\n";

        std::string upper = lower_ascii(line);
        if (upper.rfind("ehlo ", 0) == 0 || upper.rfind("ehlo\t", 0) == 0 || upper == "ehlo") {
            std::string banner = "250-collaborator.aida\r\n250 SIZE " + std::to_string(max_message) + "\r\n";
            if (!smtp_send_line(client_sock, banner.c_str())) break;
        } else if (upper.rfind("helo", 0) == 0) {
            if (!smtp_send_line(client_sock, "250 collaborator.aida\r\n")) break;
        } else if (upper.rfind("mail from:", 0) == 0) {
            mail_from = trim_ascii(line.substr(10));
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper.rfind("rcpt to:", 0) == 0) {
            rcpts.push_back(trim_ascii(line.substr(8)));
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper == "data") {
            if (!smtp_send_line(client_sock, "354 End data with <CR><LF>.<CR><LF>\r\n")) break;
            std::string body;
            body.reserve(2048);
            while (!g_state.stop_request.load(std::memory_order_acquire)) {
                std::string dline;
                int dr = smtp_recv_line(client_sock, dline, 60000,
                                        static_cast<size_t>(max_message) > 0 ? static_cast<size_t>(max_message) : 65536);
                if (dr < 0) { quit = true; break; }
                if (dline == ".") break;
                if (!dline.empty() && dline[0] == '.') body += dline.substr(1);
                else body += dline;
                body += "\r\n";
                if (static_cast<int>(body.size()) > max_message) break;
            }
            envelope_log += body;
            if (quit) break;

            std::string token;
            for (const auto& r : rcpts) {
                std::string lower_r = lower_ascii(r);
                size_t at = lower_r.find('@');
                if (at == std::string::npos) continue;
                std::string domain = lower_r.substr(at + 1);
                if (!domain.empty() && domain.back() == '>') domain.pop_back();
                token = extract_token_from_host(domain, public_host);
                if (!token.empty()) break;
            }
            if (token.empty()) {
                std::string lower_mf = lower_ascii(mail_from);
                size_t at = lower_mf.find('@');
                if (at != std::string::npos) {
                    std::string domain = lower_mf.substr(at + 1);
                    if (!domain.empty() && domain.back() == '>') domain.pop_back();
                    token = extract_token_from_host(domain, public_host);
                }
            }

            interaction_t it;
            it.kind = "smtp";
            it.client_ip = client_ip;
            it.client_port = client_port;
            it.subdomain = mail_from;
            it.payload_token = token;
            it.raw = envelope_log;
            it.details["mail_from"] = mail_from;
            std::string rcpt_joined;
            for (size_t i = 0; i < rcpts.size(); ++i) {
                if (i) rcpt_joined += ", ";
                rcpt_joined += rcpts[i];
            }
            it.details["rcpt_to"] = rcpt_joined;
            it.details["body"] = body;

            ::diag::log_tagged_fmt("collaborator",
                "smtp_interaction client=%s:%u mail_from='%s' rcpt_count=%zu token='%s' body_size=%zu",
                client_ip.c_str(), client_port,
                mail_from.c_str(), rcpts.size(), token.c_str(), body.size());

            append_interaction(std::move(it));
            mail_from.clear();
            rcpts.clear();
            envelope_log.clear();

            if (!smtp_send_line(client_sock, "250 2.0.0 Ok: queued\r\n")) break;
        } else if (upper == "rset") {
            mail_from.clear();
            rcpts.clear();
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper == "noop") {
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper == "quit") {
            smtp_send_line(client_sock, "221 Bye\r\n");
            quit = true;
        } else if (upper.empty()) {
            continue;
        } else {
            if (!smtp_send_line(client_sock, "502 Command not implemented\r\n")) break;
        }
    }

    shutdown(client_sock, SD_BOTH);
    closesocket(client_sock);
}

static void smtp_thread_main(std::string bind_ip, uint16_t port, std::string public_host, int max_message)
{
    g_state.smtp_thread_alive.store(true);

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        ::diag::log_tagged_fmt("collaborator", "smtp_socket_create_failed err=%d", WSAGetLastError());
        g_state.smtp_thread_alive.store(false);
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) != 1) {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        ::diag::log_tagged_fmt("collaborator", "smtp_bind_failed addr=%s:%u err=%d", bind_ip.c_str(), port, err);
        closesocket(listen_sock);
        g_state.smtp_thread_alive.store(false);
        return;
    }

    if (listen(listen_sock, 16) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        ::diag::log_tagged_fmt("collaborator", "smtp_listen_failed err=%d", err);
        closesocket(listen_sock);
        g_state.smtp_thread_alive.store(false);
        return;
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.smtp_socket = listen_sock;
    }
    g_state.smtp_alive.store(true);

    ::diag::log_tagged_fmt("collaborator", "smtp_listener_ready bind=%s:%u", bind_ip.c_str(), port);

    while (!g_state.stop_request.load(std::memory_order_acquire)) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listen_sock, &fds);
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_sock == INVALID_SOCKET) continue;

        std::string client_ip = client_ip_to_string(client_addr.sin_addr.s_addr);
        uint16_t client_port = ntohs(client_addr.sin_port);

        std::string pub_host_copy = public_host;
        int max_msg = max_message;
        work_queue::post([client_sock, client_ip, client_port, pub_host_copy, max_msg]() {
            smtp_session(client_sock, client_ip, client_port, pub_host_copy, max_msg);
        });
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.smtp_socket = INVALID_SOCKET;
    }
    closesocket(listen_sock);
    g_state.smtp_alive.store(false);
    g_state.smtp_thread_alive.store(false);
    ::diag::log_tagged("collaborator", "smtp_thread_exit");
}

static std::string generate_token_internal()
{
    uint8_t raw[12];
    NTSTATUS s = BCryptGenRandom(nullptr, raw, sizeof(raw), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (s != 0) {
        for (size_t i = 0; i < sizeof(raw); ++i) {
            raw[i] = static_cast<uint8_t>((now_ms() >> (i % 8)) ^ (i * 37));
        }
    }
    std::string out;
    out.resize(16);
    for (size_t i = 0; i < 16; ++i) {
        uint8_t b = raw[i % sizeof(raw)] ^ static_cast<uint8_t>((i * 11) & 0xFF);
        out[i] = static_cast<char>('a' + (b % 26));
    }
    return out;
}

}

bool start(const collaborator_config_t& cfg)
{
    diag::log_tagged_fmt("collaborator", "start entry http=%d dns=%d smtp=%d bind=%s http_port=%u dns_port=%u smtp_port=%u",
        static_cast<int>(cfg.enable_http), static_cast<int>(cfg.enable_dns), static_cast<int>(cfg.enable_smtp),
        cfg.bind_ip.c_str(), static_cast<unsigned>(cfg.http_port),
        static_cast<unsigned>(cfg.dns_port), static_cast<unsigned>(cfg.smtp_port));
    if (!s_wsa_guard.ok) {
        diag::log_tagged_fmt("collaborator", "start winsock_not_initialized");
        set_last_error("winsock_init_failed");
        return false;
    }

    if (g_state.running.exchange(true)) {
        diag::log_tagged_fmt("collaborator", "start already_running");
        set_last_error("already_running");
        return false;
    }

    g_state.stop_request.store(false);

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.config = cfg;
        if (g_state.config.max_interactions == 0) g_state.config.max_interactions = 4096;
        if (g_state.config.smtp_max_message <= 0) g_state.config.smtp_max_message = 1024 * 1024;
        g_state.started_ms = now_ms();
    }

    if (cfg.enable_http) {
        g_state.http_server = std::make_unique<httplib::Server>();
        auto handler = [](const httplib::Request& req, httplib::Response& res) {
            on_http_request(req, res);
        };
        g_state.http_server->Get(".*", handler);
        g_state.http_server->Post(".*", handler);
        g_state.http_server->Put(".*", handler);
        g_state.http_server->Patch(".*", handler);
        g_state.http_server->Delete(".*", handler);
        g_state.http_server->Options(".*", handler);
        g_state.http_server->set_payload_max_length(64 * 1024 * 1024);

        std::string bind_ip = cfg.bind_ip;
        uint16_t port = cfg.http_port;
        g_state.http_thread = std::thread([bind_ip, port]() {
            http_thread_main(bind_ip, port);
        });
        DWORD wait_iter = 0;
        while (!g_state.http_alive.load() && wait_iter < 60 && g_state.http_thread_alive.load()) {
            Sleep(50);
            ++wait_iter;
        }
        ::diag::log_tagged_fmt("collaborator", "http_started bind=%s:%u alive=%d",
            bind_ip.c_str(), port, g_state.http_alive.load() ? 1 : 0);
    }

    if (cfg.enable_dns) {
        std::string bind_ip = cfg.bind_ip;
        uint16_t port = cfg.dns_port;
        std::string public_host = cfg.public_host;
        std::string public_ip = cfg.public_ip;
        g_state.dns_thread = std::thread([bind_ip, port, public_host, public_ip]() {
            dns_thread_main(bind_ip, port, public_host, public_ip);
        });
        DWORD wait_iter = 0;
        while (!g_state.dns_alive.load() && wait_iter < 60 && g_state.dns_thread_alive.load()) {
            Sleep(50);
            ++wait_iter;
        }
        ::diag::log_tagged_fmt("collaborator", "dns_started bind=%s:%u alive=%d",
            bind_ip.c_str(), port, g_state.dns_alive.load() ? 1 : 0);
    }

    if (cfg.enable_smtp) {
        std::string bind_ip = cfg.bind_ip;
        uint16_t port = cfg.smtp_port;
        std::string public_host = cfg.public_host;
        int max_msg = cfg.smtp_max_message;
        g_state.smtp_thread = std::thread([bind_ip, port, public_host, max_msg]() {
            smtp_thread_main(bind_ip, port, public_host, max_msg);
        });
        DWORD wait_iter = 0;
        while (!g_state.smtp_alive.load() && wait_iter < 60 && g_state.smtp_thread_alive.load()) {
            Sleep(50);
            ++wait_iter;
        }
        ::diag::log_tagged_fmt("collaborator", "smtp_started bind=%s:%u alive=%d",
            bind_ip.c_str(), port, g_state.smtp_alive.load() ? 1 : 0);
    }

    set_last_error("");
    diag::log_tagged_fmt("collaborator", "start done http_alive=%d dns_alive=%d smtp_alive=%d",
        g_state.http_alive.load() ? 1 : 0,
        g_state.dns_alive.load() ? 1 : 0,
        g_state.smtp_alive.load() ? 1 : 0);
    return true;
}

void stop()
{
    diag::log_tagged_fmt("collaborator", "stop entry");
    if (!g_state.running.exchange(false)) {
        diag::log_tagged_fmt("collaborator", "stop not_running");
        return;
    }

    g_state.stop_request.store(true);

    if (g_state.http_server) {
        g_state.http_server->stop();
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        if (g_state.dns_socket != INVALID_SOCKET) {
            closesocket(g_state.dns_socket);
            g_state.dns_socket = INVALID_SOCKET;
        }
        if (g_state.smtp_socket != INVALID_SOCKET) {
            closesocket(g_state.smtp_socket);
            g_state.smtp_socket = INVALID_SOCKET;
        }
    }

    if (g_state.http_thread.joinable()) g_state.http_thread.join();
    if (g_state.dns_thread.joinable())  g_state.dns_thread.join();
    if (g_state.smtp_thread.joinable()) g_state.smtp_thread.join();

    g_state.http_server.reset();

    g_state.http_alive.store(false);
    g_state.dns_alive.store(false);
    g_state.smtp_alive.store(false);

    ::diag::log_tagged("collaborator", "stopped");
}

bool is_running()
{
    bool r = g_state.running.load();
    ::diag::log_tagged_fmt("collaborator", "is_running result=%d", static_cast<int>(r));
    return r;
}

status_t status()
{
    status_t s;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    s.running = g_state.running.load();
    s.http_alive = g_state.http_alive.load();
    s.dns_alive  = g_state.dns_alive.load();
    s.smtp_alive = g_state.smtp_alive.load();
    s.bind_ip   = g_state.config.bind_ip;
    s.http_port = g_state.config.http_port;
    s.dns_port  = g_state.config.dns_port;
    s.smtp_port = g_state.config.smtp_port;
    s.public_host = g_state.config.public_host;
    s.public_ip   = g_state.config.public_ip;
    s.interaction_count = g_state.interactions.size();
    s.token_count = g_state.tokens.size();
    s.started_ms = g_state.started_ms;
    ::diag::log_tagged_fmt("collaborator", "status running=%d http=%d dns=%d smtp=%d interactions=%zu tokens=%zu",
        static_cast<int>(s.running), static_cast<int>(s.http_alive),
        static_cast<int>(s.dns_alive), static_cast<int>(s.smtp_alive),
        s.interaction_count, s.token_count);
    return s;
}

collaborator_config_t current_config()
{
    ::diag::log_tagged_fmt("collaborator", "current_config entry");
    std::lock_guard<std::mutex> lk(g_state.mtx);
    return g_state.config;
}

std::string generate_token()
{
    std::string tok;
    std::string full;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        int attempts = 0;
        do {
            tok = generate_token_internal();
            ++attempts;
        } while (g_state.tokens.find(tok) != g_state.tokens.end() && attempts < 16);

        token_info_t info;
        info.token = tok;
        info.full_domain = tok + "." + g_state.config.public_host;
        info.issued_ms = now_ms();
        full = info.full_domain;
        g_state.tokens[tok] = info;
    }
    ::diag::log_tagged_fmt("collaborator", "token_generated token='%s' full='%s'",
        tok.c_str(), full.c_str());
    return tok;
}

std::vector<token_info_t> list_tokens()
{
    ::diag::log_tagged_fmt("collaborator", "list_tokens entry");
    std::vector<token_info_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    out.reserve(g_state.tokens.size());
    for (const auto& kv : g_state.tokens) out.push_back(kv.second);
    ::diag::log_tagged_fmt("collaborator", "list_tokens result=%zu", out.size());
    return out;
}

bool forget_token(const std::string& token)
{
    ::diag::log_tagged_fmt("collaborator", "forget_token entry token=%s", token.c_str());
    std::string norm = lower_ascii(token);
    std::lock_guard<std::mutex> lk(g_state.mtx);
    auto it = g_state.tokens.find(norm);
    if (it == g_state.tokens.end()) {
        ::diag::log_tagged_fmt("collaborator", "forget_token not_found token=%s", token.c_str());
        return false;
    }
    g_state.tokens.erase(it);
    ::diag::log_tagged_fmt("collaborator", "forget_token ok token=%s", token.c_str());
    return true;
}

std::vector<interaction_t> poll_since(uint64_t timestamp_ms_inclusive)
{
    ::diag::log_tagged_fmt("collaborator", "poll_since entry ts=%llu", static_cast<unsigned long long>(timestamp_ms_inclusive));
    std::vector<interaction_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    out.reserve(g_state.interactions.size());
    for (const auto& it : g_state.interactions) {
        if (it.timestamp_ms >= timestamp_ms_inclusive) out.push_back(it);
    }
    ::diag::log_tagged_fmt("collaborator", "poll_since result=%zu", out.size());
    return out;
}

std::vector<interaction_t> poll_by_token(const std::string& token)
{
    ::diag::log_tagged_fmt("collaborator", "poll_by_token entry token=%s", token.c_str());
    std::string norm = lower_ascii(token);
    std::vector<interaction_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    for (const auto& it : g_state.interactions) {
        if (it.payload_token == norm) out.push_back(it);
    }
    ::diag::log_tagged_fmt("collaborator", "poll_by_token result=%zu token=%s", out.size(), token.c_str());
    return out;
}

std::vector<interaction_t> snapshot_all(size_t max_entries)
{
    ::diag::log_tagged_fmt("collaborator", "snapshot_all entry max=%zu", max_entries);
    std::vector<interaction_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    size_t total = g_state.interactions.size();
    size_t skip = (max_entries == 0 || max_entries >= total) ? 0 : (total - max_entries);
    size_t i = 0;
    for (const auto& it : g_state.interactions) {
        if (i++ < skip) continue;
        out.push_back(it);
    }
    ::diag::log_tagged_fmt("collaborator", "snapshot_all result=%zu total=%zu", out.size(), total);
    return out;
}

bool get_interaction(uint64_t id, interaction_t& out)
{
    ::diag::log_tagged_fmt("collaborator", "get_interaction entry id=%llu", static_cast<unsigned long long>(id));
    std::lock_guard<std::mutex> lk(g_state.mtx);
    for (const auto& it : g_state.interactions) {
        if (it.id == id) {
            ::diag::log_tagged_fmt("collaborator", "get_interaction found id=%llu kind=%s", static_cast<unsigned long long>(id), it.kind.c_str());
            out = it;
            return true;
        }
    }
    ::diag::log_tagged_fmt("collaborator", "get_interaction not_found id=%llu", static_cast<unsigned long long>(id));
    return false;
}

void clear()
{
    ::diag::log_tagged_fmt("collaborator", "clear entry");
    std::lock_guard<std::mutex> lk(g_state.mtx);
    size_t n = g_state.interactions.size();
    g_state.interactions.clear();
    for (auto& kv : g_state.tokens) {
        kv.second.interaction_count = 0;
        kv.second.last_seen_ms = 0;
    }
    g_state.next_id.store(1);
    ::diag::log_tagged_fmt("collaborator", "clear done cleared_interactions=%zu tokens_reset=%zu", n, g_state.tokens.size());
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(g_state.err_mtx);
    std::string e = g_state.last_err;
    ::diag::log_tagged_fmt("collaborator", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
