/*
 * mcp_standalone_tools.cpp
 * Complete MCP tool implementations for standalone mode.
 * Ports ALL non-IDA-specific tools from agent_tools.cpp to work without the IDA SDK.
 */

#ifndef __NT__
#define __NT__
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <optional>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <functional>
#include <set>
#include <map>
#include <mutex>
#include <atomic>
#include <numeric>

#include "mcp_standalone.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "sandbox.hpp"

// Driver communication
#include "../../../../driver/comm.h"

// Emulation engine (standalone-safe, no IDA deps in hpp)
#include "../../../../src/emulation_engine.hpp"

// Network security module
#include "../../../../src/net_security.hpp"

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
using tool_param_t  = mcp_standalone::tool_param_t;

// =============================================================================
//  HELPER FUNCTIONS
// =============================================================================
namespace {

// ---- Address formatting / parsing ----
std::string faddr(uint64_t a) {
    char b[24]; snprintf(b, sizeof(b), "0x%llX", (unsigned long long)a);
    return b;
}

bool parse_addr(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    std::string t = s;
    // trim whitespace
    while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(0, 1);
    while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();
    if (t.empty()) return false;
    try {
        if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
            out = std::stoull(t.substr(2), nullptr, 16);
        else if (t.front() >= 'A' && t.front() <= 'F')
            out = std::stoull(t, nullptr, 16);
        else if (t.front() >= 'a' && t.front() <= 'f')
            out = std::stoull(t, nullptr, 16);
        else
            out = std::stoull(t, nullptr, 0);
        return true;
    } catch (...) { return false; }
}

std::optional<uint64_t> parse_addr_opt(const std::string& s) {
    uint64_t v;
    if (parse_addr(s, v)) return v;
    return std::nullopt;
}

// ---- String helpers ----
std::string to_lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 32;
    return s;
}

std::string trim_str(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    return s.substr(b, s.find_last_not_of(" \t\r\n") - b + 1);
}

// ---- Process helpers ----
bool is_process_alive(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD code = 0;
    GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return code == STILL_ACTIVE;
}

// ---- Driver checks ----
tool_result_t require_connected() {
    if (!device || !device->is_connected())
        return tool_result_t::error("Driver not connected. Call driver_connect first.");
    return tool_result_t::ok(std::string());
}

tool_result_t require_attached() {
    if (!device || !device->is_connected())
        return tool_result_t::error("Driver not connected. Call driver_connect first.");
    if (device->get_process_id() == 0)
        return tool_result_t::error("Not attached to a process. Call driver_attach first.");
    return tool_result_t::ok(std::string());
}

bool is_kernel_addr(uint64_t a) { return a >= 0xFFFF800000000000ULL; }

// ---- Byte parsing ----
bool parse_byte_seq(const std::string& input, std::vector<uint8_t>& out) {
    out.clear();
    std::string s = trim_str(input);
    if (s.empty()) return false;

    // Check for JSON array: [0x41, 0x42, ...]
    if (s.front() == '[') {
        s.erase(0, 1);
        if (!s.empty() && s.back() == ']') s.pop_back();
        std::istringstream iss(s);
        std::string tok;
        while (std::getline(iss, tok, ',')) {
            tok = trim_str(tok);
            if (tok.empty()) continue;
            try {
                unsigned long v = std::stoul(tok, nullptr, 0);
                if (v > 255) return false;
                out.push_back(static_cast<uint8_t>(v));
            } catch (...) { return false; }
        }
        return !out.empty();
    }

    // Check for hex string with spaces: "41 42 43" or "41:42:43"
    bool has_sep = false;
    for (char c : s) {
        if (c == ' ' || c == ':' || c == '-') { has_sep = true; break; }
    }
    if (has_sep || (s.size() >= 4 && s.size() % 2 == 0)) {
        std::string clean;
        for (char c : s) {
            if (c != ' ' && c != ':' && c != '-' && c != '\t') clean += c;
        }
        // Try as packed hex
        if (clean.size() % 2 == 0) {
            bool valid = true;
            for (size_t i = 0; i + 1 < clean.size(); i += 2) {
                auto nib = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                    return -1;
                };
                int h = nib(clean[i]), l = nib(clean[i+1]);
                if (h < 0 || l < 0) { valid = false; break; }
                out.push_back(static_cast<uint8_t>((h << 4) | l));
            }
            if (valid && !out.empty()) return true;
            out.clear();
        }
    }

    // Try as a plain hex string without separators
    if (s.size() >= 2 && s.size() % 2 == 0) {
        bool all_hex = true;
        for (char c : s) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            { all_hex = false; break; }
        }
        if (all_hex) {
            for (size_t i = 0; i + 1 < s.size(); i += 2) {
                auto nib = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                    return -1;
                };
                out.push_back(static_cast<uint8_t>((nib(s[i]) << 4) | nib(s[i+1])));
            }
            return !out.empty();
        }
    }

    // Treat as raw ASCII bytes
    out.assign(s.begin(), s.end());
    return !out.empty();
}

// ---- IP / Network helpers ----
std::string format_ip(const uint8_t* addr, uint32_t af) {
    char buf[64];
    if (af == 23) {
        snprintf(buf, sizeof(buf),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0],addr[1],addr[2],addr[3],addr[4],addr[5],addr[6],addr[7],
            addr[8],addr[9],addr[10],addr[11],addr[12],addr[13],addr[14],addr[15]);
    } else {
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
    return buf;
}

bool parse_ipv4(const std::string& s, uint8_t* out) {
    unsigned a, b, c, d;
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b; out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return true;
}

const char* protocol_name(uint32_t p) {
    switch (p) { case 6: return "TCP"; case 17: return "UDP"; case 1: return "ICMP"; default: return "OTHER"; }
}

const char* tcp_state_name(uint32_t s) {
    switch (s) {
        case 1: return "CLOSED"; case 2: return "LISTEN"; case 3: return "SYN_SENT";
        case 4: return "SYN_RCVD"; case 5: return "ESTABLISHED"; case 6: return "FIN_WAIT1";
        case 7: return "FIN_WAIT2"; case 8: return "CLOSE_WAIT"; case 9: return "CLOSING";
        case 10: return "LAST_ACK"; case 11: return "TIME_WAIT"; default: return "UNKNOWN";
    }
}

const char* direction_name(uint32_t d) { return d == 0 ? "inbound" : "outbound"; }

// ---- Hex dump helpers ----
std::string hex_dump_fmt(const uint8_t* data, size_t len, size_t max_bytes = 512) {
    std::string r;
    size_t show = std::min(len, max_bytes);
    for (size_t i = 0; i < show; i += 16) {
        char ab[16]; snprintf(ab, sizeof(ab), "%04X: ", (unsigned)i); r += ab;
        for (size_t j = 0; j < 16; j++) {
            if (i + j < show) { char hx[4]; snprintf(hx, 4, "%02X ", data[i + j]); r += hx; }
            else r += "   ";
        }
        r += " | ";
        for (size_t j = 0; j < 16 && i + j < show; j++) {
            uint8_t c = data[i + j];
            r += (c >= 32 && c < 127) ? (char)c : '.';
        }
        r += "\n";
    }
    if (show < len) r += "... (" + std::to_string(len - show) + " more bytes)\n";
    return r;
}

std::string extract_ascii(const uint8_t* data, size_t len, size_t max_chars = 256) {
    std::string r;
    for (size_t i = 0; i < std::min(len, max_chars); i++) {
        uint8_t c = data[i];
        r += (c >= 32 && c < 127) ? (char)c : '.';
    }
    if (len > max_chars) r += "...(" + std::to_string(len - max_chars) + " more)";
    return r;
}

std::string bytes_to_hex(const uint8_t* data, size_t len, size_t max_bytes = 512) {
    std::string r;
    size_t show = std::min(len, max_bytes);
    for (size_t i = 0; i < show; i++) { char h[4]; snprintf(h, 4, "%02X", data[i]); r += h; }
    if (show < len) r += "...(" + std::to_string(len - show) + " more)";
    return r;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    std::string clean;
    for (char c : hex) if (c != ' ' && c != ':' && c != '-') clean += c;
    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        int h = nib(clean[i]), l = nib(clean[i + 1]);
        if (h >= 0 && l >= 0) out.push_back((uint8_t)((h << 4) | l));
    }
    return out;
}

// ---- File system helpers ----
std::string get_downloads_folder() {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) return std::string(buf, len) + "\\Downloads\\";
    return ".\\";
}

void ensure_parent_dir(const std::string& path) {
    auto sep = path.find_last_of("\\/");
    if (sep != std::string::npos) {
        std::string dir = path.substr(0, sep);
        CreateDirectoryA(dir.c_str(), nullptr);
    }
}

std::string format_mac(const uint8_t* mac) {
    char buf[20]; snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string format_ipv4_bytes(const uint8_t* ip) {
    char buf[20]; snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

// ---- Memory protection string ----
std::string prot_str(uint32_t p) {
    switch (p) {
        case PAGE_NOACCESS:          return "---";
        case PAGE_READONLY:          return "R--";
        case PAGE_READWRITE:         return "RW-";
        case PAGE_WRITECOPY:         return "RWC";
        case PAGE_EXECUTE:           return "--X";
        case PAGE_EXECUTE_READ:      return "R-X";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "RWXC";
        default: {
            char buf[16]; snprintf(buf, sizeof(buf), "0x%X", p);
            return buf;
        }
    }
}

// ---- Memory state string ----
std::string mem_state_str(uint32_t s) {
    switch (s) {
        case MEM_COMMIT:  return "COMMIT";
        case MEM_RESERVE: return "RESERVE";
        case MEM_FREE:    return "FREE";
        default: return "UNKNOWN";
    }
}

// ---- Memory type string ----
std::string mem_type_str(uint32_t t) {
    switch (t) {
        case MEM_IMAGE:   return "IMAGE";
        case MEM_MAPPED:  return "MAPPED";
        case MEM_PRIVATE: return "PRIVATE";
        default: return "UNKNOWN";
    }
}

// ---- Read remote unicode string ----
std::string read_remote_unicode(uint64_t addr, size_t max_chars = 260) {
    if (!addr || !device || !device->is_connected()) return {};
    std::vector<wchar_t> buf(max_chars + 1, 0);
    size_t rd = device->read_raw(addr, buf.data(), max_chars * 2);
    if (rd == 0) return {};
    buf[max_chars] = 0;
    // Find null terminator
    size_t len = 0;
    for (; len < max_chars && buf[len]; len++) {}
    // Convert to ASCII (lossy)
    std::string result;
    for (size_t i = 0; i < len; i++) {
        wchar_t wc = buf[i];
        result += (wc >= 32 && wc < 127) ? (char)wc : '?';
    }
    return result;
}

// ---- HTTP parsing ----
struct parsed_http_msg_t {
    bool is_request = false;
    bool is_response = false;
    std::string method, uri, http_version, reason_phrase;
    int status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool body_truncated = false;
};

bool try_parse_http(const uint8_t* data, size_t len, parsed_http_msg_t& out) {
    if (len < 10) return false;
    size_t parse_len = std::min(len, (size_t)16384);
    std::string text(reinterpret_cast<const char*>(data), parse_len);
    auto crlf = text.find("\r\n");
    if (crlf == std::string::npos) return false;
    std::string first = text.substr(0, crlf);
    static const char* methods[] = {"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT","TRACE"};
    for (const char* m : methods) {
        size_t ml = strlen(m);
        if (first.size() > ml + 1 && first.compare(0, ml, m) == 0 && first[ml] == ' ') {
            out.is_request = true; out.method = m;
            auto sp = first.rfind(' ');
            if (sp != std::string::npos && sp > ml + 1)
                { out.uri = first.substr(ml+1, sp-ml-1); out.http_version = first.substr(sp+1); }
            else out.uri = first.substr(ml+1);
            break;
        }
    }
    if (!out.is_request && first.size() > 12 && first.compare(0, 5, "HTTP/") == 0) {
        out.is_response = true;
        auto sp1 = first.find(' ');
        if (sp1 != std::string::npos) {
            out.http_version = first.substr(0, sp1);
            auto sp2 = first.find(' ', sp1+1);
            out.status_code = std::atoi(first.substr(sp1+1).c_str());
            if (sp2 != std::string::npos) out.reason_phrase = first.substr(sp2+1);
        }
    }
    if (!out.is_request && !out.is_response) return false;
    size_t pos = crlf + 2;
    while (pos < text.size()) {
        auto nx = text.find("\r\n", pos);
        if (nx == std::string::npos) break;
        if (nx == pos) { pos += 2; break; }
        std::string line = text.substr(pos, nx - pos);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string val = line.substr(colon + 1);
            while (!val.empty() && (val[0] == ' ' || val[0] == '\t')) val.erase(0, 1);
            out.headers.emplace_back(line.substr(0, colon), val);
        }
        pos = nx + 2;
    }
    if (pos < parse_len) {
        size_t body_max = 4096;
        size_t avail = parse_len - pos;
        out.body = text.substr(pos, std::min(avail, body_max));
        out.body_truncated = (avail > body_max);
    }
    return true;
}

// ---- TLS parsing helpers ----
std::string tls_version_str(uint16_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0"; case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1"; case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: { char b[12]; snprintf(b, 12, "0x%04X", ver); return b; }
    }
}
std::string tls_content_type_str(uint8_t ct) {
    switch (ct) { case 20: return "ChangeCipherSpec"; case 21: return "Alert";
        case 22: return "Handshake"; case 23: return "ApplicationData"; default: return std::to_string(ct); }
}
std::string tls_handshake_type_str(uint8_t ht) {
    switch (ht) { case 1: return "ClientHello"; case 2: return "ServerHello";
        case 11: return "Certificate"; case 12: return "ServerKeyExchange";
        case 14: return "ServerHelloDone"; case 16: return "ClientKeyExchange";
        case 20: return "Finished"; default: return "Type " + std::to_string(ht); }
}
std::string tls_cipher_name(uint16_t cs) {
    switch (cs) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        default: { char b[12]; snprintf(b, 12, "0x%04X", cs); return b; }
    }
}

struct parsed_tls_info_t {
    uint8_t content_type = 0;
    uint16_t record_version = 0;
    uint8_t handshake_type = 0;
    uint16_t client_version = 0;
    std::string sni;
    std::vector<std::string> alpn_protocols;
    std::vector<uint16_t> cipher_suites;
    uint16_t selected_cipher = 0;
    bool is_http2 = false;
};

bool try_parse_tls(const uint8_t* data, size_t len, parsed_tls_info_t& out) {
    if (len < 5) return false;
    out.content_type = data[0];
    out.record_version = ((uint16_t)data[1] << 8) | data[2];
    if (out.content_type < 20 || out.content_type > 23 || data[1] != 0x03) return false;
    if (out.content_type != 22 || len < 9) return true;
    size_t off = 5;
    out.handshake_type = data[off];
    if (out.handshake_type != 1 && out.handshake_type != 2) return true;
    if (off + 6 >= len) return true;
    out.client_version = ((uint16_t)data[off+4] << 8) | data[off+5];
    size_t pos = off + 4 + 2 + 32;
    if (pos >= len) return true;
    uint8_t sid_len = data[pos++]; pos += sid_len;
    if (pos >= len) return true;
    if (out.handshake_type == 1) {
        if (pos + 2 > len) return true;
        uint16_t cs_len = ((uint16_t)data[pos] << 8) | data[pos+1]; pos += 2;
        for (uint16_t i = 0; i + 1 < cs_len && pos + 1 < len; i += 2) {
            out.cipher_suites.push_back(((uint16_t)data[pos] << 8) | data[pos+1]); pos += 2;
        }
        if (pos >= len) return true;
        uint8_t comp_len = data[pos++]; pos += comp_len;
    } else {
        if (pos + 2 > len) return true;
        out.selected_cipher = ((uint16_t)data[pos] << 8) | data[pos+1]; pos += 3;
    }
    if (pos + 2 > len) return true;
    uint16_t ext_total = ((uint16_t)data[pos] << 8) | data[pos+1]; pos += 2;
    size_t ext_end = std::min(pos + (size_t)ext_total, len);
    while (pos + 4 <= ext_end) {
        uint16_t et = ((uint16_t)data[pos] << 8) | data[pos+1];
        uint16_t el = ((uint16_t)data[pos+2] << 8) | data[pos+3]; pos += 4;
        if (pos + el > ext_end) break;
        if (et == 0 && el >= 5) { // SNI
            size_t sp = pos + 2;
            if (sp < pos + el && data[sp] == 0) {
                sp++;
                if (sp + 2 <= pos + el) {
                    uint16_t nlen = ((uint16_t)data[sp] << 8) | data[sp+1]; sp += 2;
                    if (sp + nlen <= pos + el)
                        out.sni.assign((const char*)&data[sp], nlen);
                }
            }
        }
        if (et == 16 && el >= 2) { // ALPN
            size_t ap = pos + 2;
            while (ap < pos + el) {
                uint8_t plen = data[ap++];
                if (ap + plen > pos + el) break;
                std::string proto((const char*)&data[ap], plen);
                out.alpn_protocols.push_back(proto);
                if (proto == "h2") out.is_http2 = true;
                ap += plen;
            }
        }
        pos += el;
    }
    return true;
}

const char* http_method_name(uint32_t m) {
    switch (m) { case 1: return "GET"; case 2: return "POST"; case 3: return "PUT";
        case 4: return "DELETE"; case 5: return "HEAD"; case 6: return "OPTIONS";
        case 7: return "PATCH"; case 8: return "CONNECT"; case 9: return "TRACE"; default: return "UNKNOWN"; }
}

// ---- NtQuerySystemInformation for kernel module enumeration ----
#pragma pack(push, 1)
struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};
struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};
#pragma pack(pop)

typedef LONG(WINAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
const ULONG SystemModuleInformation = 11;

struct kernel_module_t {
    std::string name;
    std::string full_path;
    uint64_t    base;
    uint32_t    size;
};

std::vector<kernel_module_t> query_kernel_modules() {
    std::vector<kernel_module_t> result;
    auto NtQSI = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return result;
    ULONG needed = 0;
    NtQSI(SystemModuleInformation, nullptr, 0, &needed);
    if (needed == 0) return result;
    std::vector<uint8_t> buf(needed + 4096);
    if (NtQSI(SystemModuleInformation, buf.data(), (ULONG)buf.size(), &needed) != 0) return result;
    auto* mods = (RTL_PROCESS_MODULES*)buf.data();
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        auto& m = mods->Modules[i];
        kernel_module_t km;
        km.base = (uint64_t)m.ImageBase;
        km.size = m.ImageSize;
        km.full_path = (const char*)m.FullPathName;
        km.name = (const char*)&m.FullPathName[m.OffsetToFileName];
        result.push_back(std::move(km));
    }
    return result;
}

// Resolve NT path like \SystemRoot\... to Win32 path
std::string resolve_nt_path(const std::string& nt_path) {
    if (nt_path.empty()) return nt_path;
    std::string p = nt_path;
    if (p.compare(0, 12, "\\SystemRoot\\") == 0) {
        char windir[MAX_PATH] = {};
        GetWindowsDirectoryA(windir, MAX_PATH);
        p = std::string(windir) + "\\" + p.substr(12);
    } else if (p.compare(0, 4, "\\??\\") == 0) {
        p = p.substr(4);
    }
    return p;
}

} // anonymous namespace

// =============================================================================
//  TOOL HANDLER IMPLEMENTATIONS
// =============================================================================
namespace {

// ===== DRIVER CORE TOOLS =====

tool_result_t handle_driver_status(const json&) {
    json r;
    r["connected"] = device && device->is_connected();
    if (device && device->is_connected()) {
        r["process_id"] = device->get_process_id();
        r["base_address"] = faddr(device->get_base_address());
        r["dtb"] = faddr(device->get_dtb());
        r["kernel_dtb"] = faddr(device->get_kernel_dtb());
        r["has_process"] = device->get_process_id() != 0;
        bool heartbeat = device->send_heartbeat();
        r["heartbeat"] = heartbeat;
    }
    return tool_result_t::ok(
        (device && device->is_connected()) ? "Driver is connected" : "Driver is NOT connected", r);
}

tool_result_t handle_driver_connect(const json&) {
    if (device->is_connected()) {
        device->solve_kernel_dtb();
        json r;
        r["status"] = "already_connected";
        r["kernel_dtb"] = faddr(device->get_kernel_dtb());
        return tool_result_t::ok("Already connected to driver", r);
    }
    if (!device->connect())
        return tool_result_t::error("Failed to connect to driver. Is it loaded?");
    device->solve_kernel_dtb();
    json r;
    r["status"] = "connected";
    r["kernel_dtb"] = faddr(device->get_kernel_dtb());
    return tool_result_t::ok("Connected to kernel driver", r);
}

tool_result_t handle_driver_attach(const json& params) {
    auto chk = require_connected();
    if (!chk.success) return chk;

    uint32_t pid = 0;
    std::string process_name;

    if (params.contains("pid") && params["pid"].is_number())
        pid = params["pid"].get<uint32_t>();
    if (params.contains("name") && params["name"].is_string())
        process_name = params["name"].get<std::string>();

    if (pid == 0 && process_name.empty())
        return tool_result_t::error("Provide 'name' (process name) or 'pid' (process ID).");

    if (pid == 0 && !process_name.empty()) {
        pid = device->find_process(process_name.c_str());
        if (pid == 0)
            return tool_result_t::error("Process not found: " + process_name);
    }

    if (!is_process_alive(pid))
        return tool_result_t::error("Process " + std::to_string(pid) + " is not alive.");

    device->set_process_id(pid);
    uint64_t base = device->find_image();
    device->set_base_address(base);
    device->solve_dtb();

    json r;
    r["pid"] = pid;
    r["base_address"] = faddr(base);
    r["dtb"] = faddr(device->get_dtb());
    if (!process_name.empty()) r["name"] = process_name;
    return tool_result_t::ok("Attached to process " + std::to_string(pid), r);
}

tool_result_t handle_driver_detach(const json&) {
    if (!device || !device->is_connected())
        return tool_result_t::error("Driver not connected.");
    device->clear_process_context();
    return tool_result_t::ok("Detached from process. Driver connection preserved.");
}

tool_result_t handle_list_processes(const json&) {
    auto procs = driver_bridge::enumerate_processes();
    json arr = json::array();
    for (const auto& p : procs) {
        json entry;
        entry["pid"] = p.pid;
        entry["name"] = p.name;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(procs.size()) + " processes found", arr);
}

// ===== DRIVER MEMORY TOOLS =====

tool_result_t handle_read_memory(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t addr = 0;
    if (params.contains("address") && params["address"].is_string()) {
        if (!parse_addr(params["address"].get<std::string>(), addr))
            return tool_result_t::error("Invalid address.");
    } else return tool_result_t::error("Missing required parameter: address");

    uint32_t size = params.value("size", 256u);
    if (size > 1048576) size = 1048576;

    std::vector<uint8_t> buf(size, 0);
    size_t rd = device->read_raw(addr, buf.data(), size);
    if (rd == 0)
        return tool_result_t::error("Failed to read memory at " + faddr(addr));

    json r;
    r["address"] = faddr(addr);
    r["bytes_read"] = rd;
    r["hex"] = bytes_to_hex(buf.data(), rd, 4096);
    r["hex_dump"] = hex_dump_fmt(buf.data(), rd, 1024);
    r["ascii"] = extract_ascii(buf.data(), rd, 512);
    return tool_result_t::ok(std::to_string(rd) + " bytes read from " + faddr(addr), r);
}

tool_result_t handle_write_memory(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t addr = 0;
    if (params.contains("address") && params["address"].is_string()) {
        if (!parse_addr(params["address"].get<std::string>(), addr))
            return tool_result_t::error("Invalid address.");
    } else return tool_result_t::error("Missing required parameter: address");

    std::vector<uint8_t> data;
    if (params.contains("bytes") && params["bytes"].is_string()) {
        if (!parse_byte_seq(params["bytes"].get<std::string>(), data) || data.empty())
            return tool_result_t::error("Invalid byte data. Provide hex like 'AA BB CC' or '41424344'.");
    } else if (params.contains("hex") && params["hex"].is_string()) {
        data = hex_to_bytes(params["hex"].get<std::string>());
    } else return tool_result_t::error("Missing parameter: bytes or hex");

    if (data.empty()) return tool_result_t::error("No data to write.");

    size_t written = device->write_raw(addr, data.data(), data.size());
    json r;
    r["address"] = faddr(addr);
    r["bytes_written"] = written;
    r["size"] = data.size();
    return tool_result_t::ok(std::to_string(written) + " bytes written to " + faddr(addr), r);
}

tool_result_t handle_read_string(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");

    uint32_t max_len = params.value("max_length", 512u);
    if (max_len > 65536) max_len = 65536;
    std::string encoding = params.value("encoding", "auto");

    std::vector<uint8_t> buf(max_len + 2, 0);
    size_t rd = device->read_raw(addr, buf.data(), max_len);
    if (rd == 0)
        return tool_result_t::error("Failed to read memory at " + faddr(addr));

    // Try wide string first if encoding is auto or wide
    if (encoding == "wide" || encoding == "auto") {
        std::string wide_str;
        const wchar_t* wbuf = (const wchar_t*)buf.data();
        size_t wchars = rd / 2;
        for (size_t i = 0; i < wchars && wbuf[i]; i++)
            wide_str += (wbuf[i] >= 32 && wbuf[i] < 127) ? (char)wbuf[i] : '?';
        if (encoding == "wide" || (encoding == "auto" && wide_str.size() > 2)) {
            json r;
            r["address"] = faddr(addr);
            r["string"] = wide_str;
            r["encoding"] = "wide";
            r["length"] = wide_str.size();
            return tool_result_t::ok(wide_str, r);
        }
    }

    // ASCII
    std::string ascii_str;
    for (size_t i = 0; i < rd && buf[i]; i++)
        ascii_str += (buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.';

    json r;
    r["address"] = faddr(addr);
    r["string"] = ascii_str;
    r["encoding"] = "ascii";
    r["length"] = ascii_str.size();
    return tool_result_t::ok(ascii_str, r);
}

tool_result_t handle_read_pointer_chain(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t base = 0;
    if (!params.contains("base") || !params["base"].is_string() ||
        !parse_addr(params["base"].get<std::string>(), base))
        return tool_result_t::error("Invalid or missing base address.");

    if (!params.contains("offsets") || !params["offsets"].is_array() || params["offsets"].empty())
        return tool_result_t::error("Missing or empty offsets array.");

    json chain = json::array();
    uint64_t current = base;

    for (size_t i = 0; i < params["offsets"].size(); i++) {
        int64_t offset = 0;
        const auto& off_val = params["offsets"][i];
        if (off_val.is_number()) offset = off_val.get<int64_t>();
        else if (off_val.is_string()) {
            try { offset = std::stoll(off_val.get<std::string>(), nullptr, 0); } catch (...) {}
        }

        // Dereference pointer
        uint64_t ptr_val = 0;
        size_t rd = device->read_raw(current, &ptr_val, 8);
        if (rd != 8) {
            json r; r["chain"] = chain; r["error_at_step"] = i;
            r["failed_address"] = faddr(current);
            return tool_result_t::error("Failed to read pointer at step " + std::to_string(i) +
                " address " + faddr(current));
        }

        json step;
        step["step"] = i;
        step["read_from"] = faddr(current);
        step["value"] = faddr(ptr_val);
        step["offset"] = offset;
        current = ptr_val + offset;
        step["next"] = faddr(current);
        chain.push_back(step);
    }

    json r;
    r["base"] = faddr(base);
    r["final_address"] = faddr(current);
    r["chain"] = chain;

    // Read final value
    uint64_t final_val = 0;
    device->read_raw(current, &final_val, 8);
    r["final_value"] = faddr(final_val);

    return tool_result_t::ok("Pointer chain resolved to " + faddr(current), r);
}

tool_result_t handle_allocate_memory(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint32_t size = params.value("size", 4096u);
    if (size > 1048576 * 16) size = 1048576 * 16;

    uint64_t addr = device->allocate_memory(size);
    if (!addr) return tool_result_t::error("Memory allocation failed.");

    json r;
    r["address"] = faddr(addr);
    r["size"] = size;
    return tool_result_t::ok("Allocated " + std::to_string(size) + " bytes at " + faddr(addr), r);
}

tool_result_t handle_free_memory(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");

    if (!device->free_memory(addr))
        return tool_result_t::error("Failed to free memory at " + faddr(addr));
    return tool_result_t::ok("Memory freed at " + faddr(addr));
}

tool_result_t handle_query_memory(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");

    voyager::device_t::memory_region_info info{};
    if (!device->query_memory(addr, info))
        return tool_result_t::error("Failed to query memory at " + faddr(addr));

    json r;
    r["base"] = faddr(info.base);
    r["size"] = info.size;
    r["state"] = mem_state_str(info.state);
    r["protect"] = prot_str(info.protect);
    r["type"] = mem_type_str(info.type);
    r["allocation_base"] = faddr(info.allocation_base);
    r["allocation_protect"] = prot_str(info.allocation_protect);
    return tool_result_t::ok("Memory region at " + faddr(info.base) + " size " + std::to_string(info.size), r);
}

tool_result_t handle_protect_memory(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");

    uint64_t size = params.value("size", 4096u);
    uint32_t new_prot = PAGE_EXECUTE_READWRITE;
    if (params.contains("protection") && params["protection"].is_string()) {
        std::string p = to_lower(params["protection"].get<std::string>());
        if (p == "rwx" || p == "execute_readwrite") new_prot = PAGE_EXECUTE_READWRITE;
        else if (p == "rw" || p == "readwrite") new_prot = PAGE_READWRITE;
        else if (p == "rx" || p == "execute_read") new_prot = PAGE_EXECUTE_READ;
        else if (p == "r" || p == "readonly") new_prot = PAGE_READONLY;
        else if (p == "x" || p == "execute") new_prot = PAGE_EXECUTE;
        else if (p == "noaccess") new_prot = PAGE_NOACCESS;
    } else if (params.contains("protection") && params["protection"].is_number()) {
        new_prot = params["protection"].get<uint32_t>();
    }

    uint32_t old_prot = 0;
    if (!device->protect_memory(addr, size, new_prot, &old_prot))
        return tool_result_t::error("Failed to change memory protection.");

    json r;
    r["address"] = faddr(addr);
    r["size"] = size;
    r["old_protection"] = prot_str(old_prot);
    r["new_protection"] = prot_str(new_prot);
    return tool_result_t::ok("Protection changed at " + faddr(addr), r);
}

tool_result_t handle_enumerate_memory_regions(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint64_t start = 0, end = 0;
    if (params.contains("start") && params["start"].is_string())
        parse_addr(params["start"].get<std::string>(), start);
    if (params.contains("end") && params["end"].is_string())
        parse_addr(params["end"].get<std::string>(), end);

    auto regions = device->enumerate_memory_regions(start, end);
    json arr = json::array();
    for (const auto& r : regions) {
        json entry;
        entry["base"] = faddr(r.base);
        entry["size"] = r.size;
        entry["state"] = mem_state_str(r.state);
        entry["protect"] = prot_str(r.protect);
        entry["type"] = mem_type_str(r.type);
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(regions.size()) + " memory regions", arr);
}

// ===== DRIVER MODULE TOOLS =====

tool_result_t handle_enumerate_modules(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    // Read PEB -> Ldr -> InLoadOrderModuleList
    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || !peb.ldr_address)
        return tool_result_t::error("Failed to read PEB or LDR.");

    // LDR_DATA_TABLE_ENTRY offsets (InLoadOrderLinks at offset 0)
    uint64_t ldr = peb.ldr_address;
    uint64_t list_head = ldr + 0x10; // InLoadOrderModuleList
    uint64_t flink = 0;
    device->read_raw(list_head, &flink, 8);
    if (!flink || flink == list_head)
        return tool_result_t::ok("No modules found", json::array());

    json arr = json::array();
    uint64_t current = flink;
    int count = 0;
    while (current && current != list_head && count < 1024) {
        // LDR_DATA_TABLE_ENTRY: DllBase at +0x30, SizeOfImage at +0x40, BaseDllName at +0x58
        uint64_t dll_base = 0, entry_point = 0;
        uint32_t size_of_image = 0;
        device->read_raw(current + 0x30, &dll_base, 8);
        device->read_raw(current + 0x38, &entry_point, 8);
        device->read_raw(current + 0x40, &size_of_image, 4);

        // BaseDllName is UNICODE_STRING at +0x58: Length(2), MaxLength(2), pad(4), Buffer(8)
        uint16_t name_len = 0;
        uint64_t name_buf = 0;
        device->read_raw(current + 0x58, &name_len, 2);
        device->read_raw(current + 0x60, &name_buf, 8);

        std::string name = read_remote_unicode(name_buf, name_len / 2);

        // FullDllName at +0x48
        uint16_t full_len = 0;
        uint64_t full_buf = 0;
        device->read_raw(current + 0x48, &full_len, 2);
        device->read_raw(current + 0x50, &full_buf, 8);
        std::string full_name = read_remote_unicode(full_buf, full_len / 2);

        json entry;
        entry["name"] = name;
        entry["full_path"] = full_name;
        entry["base"] = faddr(dll_base);
        entry["size"] = size_of_image;
        entry["entry_point"] = faddr(entry_point);
        arr.push_back(entry);

        uint64_t next = 0;
        device->read_raw(current, &next, 8);
        if (next == current) break;
        current = next;
        count++;
    }
    return tool_result_t::ok(std::to_string(arr.size()) + " modules enumerated", arr);
}

tool_result_t handle_enumerate_kernel_modules(const json&) {
    auto chk = require_connected();
    if (!chk.success) return chk;

    auto modules = query_kernel_modules();
    json arr = json::array();
    for (const auto& m : modules) {
        json entry;
        entry["name"] = m.name;
        entry["full_path"] = resolve_nt_path(m.full_path);
        entry["base"] = faddr(m.base);
        entry["size"] = m.size;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(modules.size()) + " kernel modules", arr);
}

tool_result_t handle_resolve_export(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    if (!params.contains("export_name") || !params["export_name"].is_string())
        return tool_result_t::error("Missing required parameter: export_name");

    std::string export_name = params["export_name"].get<std::string>();
    uint64_t module_base = 0;

    if (params.contains("module_base") && params["module_base"].is_string())
        parse_addr(params["module_base"].get<std::string>(), module_base);
    else if (params.contains("module_name") && params["module_name"].is_string()) {
        // Find module by name
        std::string mod_name = to_lower(params["module_name"].get<std::string>());
        voyager::device_t::peb_info peb{};
        if (device->read_peb(peb) && peb.ldr_address) {
            uint64_t list_head = peb.ldr_address + 0x10;
            uint64_t flink = 0;
            device->read_raw(list_head, &flink, 8);
            uint64_t cur = flink;
            int cnt = 0;
            while (cur && cur != list_head && cnt < 512) {
                uint64_t dll_base = 0;
                device->read_raw(cur + 0x30, &dll_base, 8);
                uint16_t nlen = 0; uint64_t nbuf = 0;
                device->read_raw(cur + 0x58, &nlen, 2);
                device->read_raw(cur + 0x60, &nbuf, 8);
                std::string name = to_lower(read_remote_unicode(nbuf, nlen / 2));
                if (name == mod_name || name.find(mod_name) != std::string::npos) {
                    module_base = dll_base;
                    break;
                }
                uint64_t next = 0;
                device->read_raw(cur, &next, 8);
                if (next == cur) break;
                cur = next; cnt++;
            }
        }
        if (!module_base)
            return tool_result_t::error("Module not found: " + params["module_name"].get<std::string>());
    } else {
        module_base = device->get_base_address();
    }

    uint64_t addr = device->resolve_export(module_base, export_name.c_str());
    if (!addr)
        return tool_result_t::error("Export not found: " + export_name);

    json r;
    r["export_name"] = export_name;
    r["address"] = faddr(addr);
    r["module_base"] = faddr(module_base);
    return tool_result_t::ok(export_name + " = " + faddr(addr), r);
}

// ===== DRIVER THREAD TOOLS =====

tool_result_t handle_enumerate_threads(const json&) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    auto threads = device->enumerate_threads();
    json arr = json::array();
    for (const auto& t : threads) {
        json entry;
        entry["tid"] = t.tid;
        entry["state"] = t.state;
        entry["rip"] = faddr(t.rip);
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(threads.size()) + " threads", arr);
}

tool_result_t handle_get_thread_context(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint32_t tid = 0;
    if (params.contains("tid") && params["tid"].is_number())
        tid = params["tid"].get<uint32_t>();
    if (tid == 0) {
        auto threads = device->enumerate_threads();
        if (threads.empty()) return tool_result_t::error("No threads found.");
        tid = threads[0].tid;
    }

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
        return tool_result_t::error("Failed to get thread context for TID " + std::to_string(tid));

    json r;
    r["tid"] = tid;
    r["rax"] = faddr(ctx.rax); r["rbx"] = faddr(ctx.rbx);
    r["rcx"] = faddr(ctx.rcx); r["rdx"] = faddr(ctx.rdx);
    r["rsi"] = faddr(ctx.rsi); r["rdi"] = faddr(ctx.rdi);
    r["rbp"] = faddr(ctx.rbp); r["rsp"] = faddr(ctx.rsp);
    r["r8"]  = faddr(ctx.r8);  r["r9"]  = faddr(ctx.r9);
    r["r10"] = faddr(ctx.r10); r["r11"] = faddr(ctx.r11);
    r["r12"] = faddr(ctx.r12); r["r13"] = faddr(ctx.r13);
    r["r14"] = faddr(ctx.r14); r["r15"] = faddr(ctx.r15);
    r["rip"] = faddr(ctx.rip); r["rflags"] = faddr(ctx.rflags);
    r["dr0"] = faddr(ctx.dr0); r["dr1"] = faddr(ctx.dr1);
    r["dr2"] = faddr(ctx.dr2); r["dr3"] = faddr(ctx.dr3);
    r["dr6"] = faddr(ctx.dr6); r["dr7"] = faddr(ctx.dr7);
    return tool_result_t::ok("Thread context for TID " + std::to_string(tid), r);
}

tool_result_t handle_set_thread_context(const json& params) {
    auto chk = require_attached();
    if (!chk.success) return chk;

    uint32_t tid = 0;
    if (params.contains("tid") && params["tid"].is_number())
        tid = params["tid"].get<uint32_t>();
    if (tid == 0) return tool_result_t::error("Missing required parameter: tid");

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
        return tool_result_t::error("Failed to get current context.");

    uint64_t mask = 0;
    auto set_reg = [&](const char* name, uint64_t& reg, uint64_t bit) {
        if (params.contains(name)) {
            uint64_t v = 0;
            if (params[name].is_number()) v = params[name].get<uint64_t>();
            else if (params[name].is_string()) { if (!parse_addr(params[name].get<std::string>(), v)) return; }
            reg = v; mask |= bit;
        }
    };
    set_reg("rax", ctx.rax, 1ULL<<0); set_reg("rbx", ctx.rbx, 1ULL<<1);
    set_reg("rcx", ctx.rcx, 1ULL<<2); set_reg("rdx", ctx.rdx, 1ULL<<3);
    set_reg("rsi", ctx.rsi, 1ULL<<4); set_reg("rdi", ctx.rdi, 1ULL<<5);
    set_reg("rbp", ctx.rbp, 1ULL<<6); set_reg("rsp", ctx.rsp, 1ULL<<7);
    set_reg("r8",  ctx.r8,  1ULL<<8); set_reg("r9",  ctx.r9,  1ULL<<9);
    set_reg("r10", ctx.r10, 1ULL<<10); set_reg("r11", ctx.r11, 1ULL<<11);
    set_reg("r12", ctx.r12, 1ULL<<12); set_reg("r13", ctx.r13, 1ULL<<13);
    set_reg("r14", ctx.r14, 1ULL<<14); set_reg("r15", ctx.r15, 1ULL<<15);
    set_reg("rip", ctx.rip, 1ULL<<16); set_reg("rflags", ctx.rflags, 1ULL<<17);

    if (mask == 0) return tool_result_t::error("No registers specified to set.");

    if (!device->set_thread_context(tid, ctx, mask))
        return tool_result_t::error("Failed to set thread context.");

    json r; r["tid"] = tid; r["registers_set"] = static_cast<int>(__popcnt64(mask));
    return tool_result_t::ok("Thread context updated", r);
}

tool_result_t handle_suspend_thread(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t tid = params.value("tid", 0u);
    if (tid == 0) return tool_result_t::error("Missing required parameter: tid");
    uint32_t prev = 0;
    if (!device->suspend_thread(tid, &prev))
        return tool_result_t::error("Failed to suspend thread " + std::to_string(tid));
    json r; r["tid"] = tid; r["previous_suspend_count"] = prev;
    return tool_result_t::ok("Thread " + std::to_string(tid) + " suspended", r);
}

tool_result_t handle_resume_thread(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t tid = params.value("tid", 0u);
    if (tid == 0) return tool_result_t::error("Missing required parameter: tid");
    uint32_t prev = 0;
    if (!device->resume_thread(tid, &prev))
        return tool_result_t::error("Failed to resume thread " + std::to_string(tid));
    json r; r["tid"] = tid; r["previous_suspend_count"] = prev;
    return tool_result_t::ok("Thread " + std::to_string(tid) + " resumed", r);
}

// ===== DRIVER KERNEL TOOLS =====

tool_result_t handle_read_kernel_memory(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");
    if (!is_kernel_addr(addr))
        return tool_result_t::error("Address does not appear to be a kernel address.");
    uint32_t size = params.value("size", 256u);
    if (size > 1048576) size = 1048576;
    std::vector<uint8_t> buf(size, 0);
    size_t rd = device->read_kernel_raw(addr, buf.data(), size);
    if (rd == 0) return tool_result_t::error("Failed to read kernel memory at " + faddr(addr));
    json r;
    r["address"] = faddr(addr);
    r["bytes_read"] = rd;
    r["hex"] = bytes_to_hex(buf.data(), rd, 4096);
    r["hex_dump"] = hex_dump_fmt(buf.data(), rd, 1024);
    return tool_result_t::ok(std::to_string(rd) + " kernel bytes read", r);
}

tool_result_t handle_write_kernel_memory(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");
    if (!is_kernel_addr(addr))
        return tool_result_t::error("Address does not appear to be a kernel address.");
    std::vector<uint8_t> data;
    if (params.contains("bytes") && params["bytes"].is_string())
        parse_byte_seq(params["bytes"].get<std::string>(), data);
    else if (params.contains("hex") && params["hex"].is_string())
        data = hex_to_bytes(params["hex"].get<std::string>());
    if (data.empty()) return tool_result_t::error("No data to write.");
    size_t written = device->write_kernel_raw(addr, data.data(), data.size());
    json r; r["address"] = faddr(addr); r["bytes_written"] = written;
    return tool_result_t::ok(std::to_string(written) + " bytes written to kernel", r);
}

tool_result_t handle_read_peb(const json&) {
    auto chk = require_attached(); if (!chk.success) return chk;
    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb))
        return tool_result_t::error("Failed to read PEB.");
    json r;
    r["peb_address"] = faddr(peb.peb_address);
    r["image_base"] = faddr(peb.image_base);
    r["being_debugged"] = peb.being_debugged;
    r["nt_global_flag"] = peb.nt_global_flag;
    r["ldr_address"] = faddr(peb.ldr_address);
    r["process_heap"] = faddr(peb.process_heap);
    r["number_of_heaps"] = peb.number_of_heaps;
    return tool_result_t::ok("PEB at " + faddr(peb.peb_address), r);
}

tool_result_t handle_spoof_debug_flags(const json&) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t flags = 0;
    if (!device->spoof_debug_flags(&flags))
        return tool_result_t::error("Failed to spoof debug flags.");
    json r; r["cleared_flags"] = flags;
    r["note"] = "Cleared BeingDebugged, NtGlobalFlag, and DebugPort in PEB.";
    return tool_result_t::ok("Debug flags spoofed successfully", r);
}

// ===== DRIVER HW BREAKPOINT TOOLS =====

tool_result_t handle_set_hw_breakpoint(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t tid = params.value("tid", 0u);
    if (tid == 0) return tool_result_t::error("Missing required parameter: tid");
    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");
    int index = params.value("index", 0);
    if (index < 0 || index > 3) return tool_result_t::error("Index must be 0-3.");
    int type = params.value("type", 0); // 0=exec, 1=write, 3=rw
    int size = params.value("size", 0); // 0=1byte, 1=2byte, 3=8byte, 2=4byte
    if (!device->set_hardware_breakpoint(tid, index, addr, type, size))
        return tool_result_t::error("Failed to set hardware breakpoint.");
    json r; r["tid"] = tid; r["index"] = index; r["address"] = faddr(addr);
    return tool_result_t::ok("Hardware breakpoint set at " + faddr(addr), r);
}

tool_result_t handle_clear_hw_breakpoint(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t tid = params.value("tid", 0u);
    if (tid == 0) return tool_result_t::error("Missing required parameter: tid");
    int index = params.value("index", 0);
    if (!device->clear_hardware_breakpoint(tid, index))
        return tool_result_t::error("Failed to clear hardware breakpoint.");
    json r; r["tid"] = tid; r["index"] = index;
    return tool_result_t::ok("Hardware breakpoint cleared", r);
}

// ===== DRIVER MISC TOOLS =====

tool_result_t handle_call_function(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing function address.");

    uint64_t a1 = 0, a2 = 0, a3 = 0, a4 = 0;
    if (params.contains("arg1")) { if (params["arg1"].is_number()) a1 = params["arg1"].get<uint64_t>();
        else if (params["arg1"].is_string()) parse_addr(params["arg1"].get<std::string>(), a1); }
    if (params.contains("arg2")) { if (params["arg2"].is_number()) a2 = params["arg2"].get<uint64_t>();
        else if (params["arg2"].is_string()) parse_addr(params["arg2"].get<std::string>(), a2); }
    if (params.contains("arg3")) { if (params["arg3"].is_number()) a3 = params["arg3"].get<uint64_t>();
        else if (params["arg3"].is_string()) parse_addr(params["arg3"].get<std::string>(), a3); }
    if (params.contains("arg4")) { if (params["arg4"].is_number()) a4 = params["arg4"].get<uint64_t>();
        else if (params["arg4"].is_string()) parse_addr(params["arg4"].get<std::string>(), a4); }

    uint64_t ret = device->call_function(addr, a1, a2, a3, a4);
    json r;
    r["address"] = faddr(addr);
    r["return_value"] = faddr(ret);
    r["return_decimal"] = ret;
    return tool_result_t::ok("Function returned " + faddr(ret), r);
}

tool_result_t handle_virtual_to_physical(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");
    uint64_t phys = device->virtual_to_physical(addr);
    if (!phys) return tool_result_t::error("Translation failed for " + faddr(addr));
    json r; r["virtual"] = faddr(addr); r["physical"] = faddr(phys);
    return tool_result_t::ok(faddr(addr) + " -> " + faddr(phys), r);
}

tool_result_t handle_scan_pattern(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;

    if (!params.contains("pattern") || !params["pattern"].is_string())
        return tool_result_t::error("Missing required parameter: pattern (e.g. '48 8B 05 ?? ?? ?? ??')");

    std::string pattern_str = params["pattern"].get<std::string>();
    uint64_t start = 0, end_addr = 0;
    if (params.contains("start") && params["start"].is_string())
        parse_addr(params["start"].get<std::string>(), start);
    if (params.contains("end") && params["end"].is_string())
        parse_addr(params["end"].get<std::string>(), end_addr);

    if (start == 0) start = device->get_base_address();
    uint32_t scan_size = params.value("size", 0x100000u);
    if (end_addr == 0) end_addr = start + scan_size;

    // Parse pattern bytes and mask
    std::vector<uint8_t> pattern_bytes;
    std::vector<bool> mask;
    std::istringstream iss(pattern_str);
    std::string tok;
    while (iss >> tok) {
        if (tok == "?" || tok == "??" || tok == "xx") {
            pattern_bytes.push_back(0);
            mask.push_back(false);
        } else {
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                return -1;
            };
            if (tok.size() == 2) {
                int h = nib(tok[0]), l = nib(tok[1]);
                if (h >= 0 && l >= 0) {
                    pattern_bytes.push_back((uint8_t)((h << 4) | l));
                    mask.push_back(true);
                    continue;
                }
            }
            return tool_result_t::error("Invalid pattern byte: " + tok);
        }
    }
    if (pattern_bytes.empty()) return tool_result_t::error("Empty pattern.");

    uint32_t max_results = params.value("max_results", 32u);
    json arr = json::array();
    uint64_t addr = start;
    const uint32_t chunk_size = 65536;
    std::vector<uint8_t> buf(chunk_size + pattern_bytes.size());

    while (addr < end_addr && arr.size() < max_results) {
        uint32_t read_size = (uint32_t)std::min((uint64_t)(chunk_size + pattern_bytes.size()), end_addr - addr);
        size_t rd = device->read_raw(addr, buf.data(), read_size);
        if (rd < pattern_bytes.size()) break;

        for (size_t i = 0; i + pattern_bytes.size() <= rd; i++) {
            bool match = true;
            for (size_t j = 0; j < pattern_bytes.size(); j++) {
                if (mask[j] && buf[i + j] != pattern_bytes[j]) { match = false; break; }
            }
            if (match) {
                arr.push_back(faddr(addr + i));
                if (arr.size() >= max_results) break;
            }
        }
        addr += chunk_size;
    }

    json r;
    r["pattern"] = pattern_str;
    r["matches"] = arr;
    r["count"] = arr.size();
    return tool_result_t::ok(std::to_string(arr.size()) + " pattern matches found", r);
}

// ===== DRIVER WFP / SOCKET TOOLS =====

tool_result_t handle_enumerate_wfp_callouts(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    std::string filter;
    if (params.contains("module") && params["module"].is_string())
        filter = params["module"].get<std::string>();
    auto callouts = device->enumerate_wfp_callouts(filter);
    json arr = json::array();
    for (const auto& c : callouts) {
        json e;
        e["callout_id"] = c.callout_id; e["layer_id"] = c.layer_id;
        e["owning_module"] = c.owning_module; e["callout_key"] = c.callout_key_str;
        e["classify_fn"] = faddr(c.classify_fn); e["module_base"] = faddr(c.owning_module_base);
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(callouts.size()) + " WFP callouts", arr);
}

tool_result_t handle_get_socket_handles(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t pid = params.value("pid", 0u);
    auto socks = device->get_socket_handles(pid);
    json arr = json::array();
    for (const auto& s : socks) {
        json e;
        e["handle"] = faddr(s.handle_value); e["pid"] = s.pid;
        e["protocol"] = protocol_name(s.protocol);
        e["state"] = (s.protocol == 6) ? tcp_state_name(s.state) : "N/A";
        e["local"] = format_ip(s.local_addr, s.address_family) + ":" + std::to_string(s.local_port);
        e["remote"] = format_ip(s.remote_addr, s.address_family) + ":" + std::to_string(s.remote_port);
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(socks.size()) + " socket handles", arr);
}

tool_result_t handle_dump_tcpip(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t pid = 0, proto = 0;
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = to_lower(params["protocol"].get<std::string>());
        if (p == "tcp") proto = 6; else if (p == "udp") proto = 17;
    }
    auto conns = device->dump_tcpip_connections(pid, proto);
    json arr = json::array();
    for (const auto& c : conns) {
        json e;
        e["pid"] = c.pid; e["protocol"] = protocol_name(c.protocol);
        e["state"] = (c.protocol == 6) ? tcp_state_name(c.state) : "N/A";
        e["local"] = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        e["remote"] = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);
        e["bytes_in"] = c.bytes_in; e["bytes_out"] = c.bytes_out;
        e["tcb_address"] = faddr(c.tcb_address);
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(conns.size()) + " TCPIP connections", arr);
}

// ===== NETWORK TOOLS =====

tool_result_t handle_network_enumerate_connections(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t pid = 0, proto = 0;
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        auto p = to_lower(params["protocol"].get<std::string>());
        if (p == "tcp") proto = 6; else if (p == "udp") proto = 17;
    }
    auto conns = device->enumerate_connections(pid, proto);
    json arr = json::array();
    for (const auto& c : conns) {
        json e;
        e["pid"] = c.pid; e["protocol"] = protocol_name(c.protocol);
        e["state"] = (c.protocol == 6) ? tcp_state_name(c.state) : "N/A";
        e["local"] = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        e["remote"] = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);
        e["address_family"] = (c.address_family == 23) ? "IPv6" : "IPv4";
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(conns.size()) + " connections", arr);
}

tool_result_t handle_network_start_capture(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t filter_pid = params.value("pid", 0u);
    uint32_t filter_port = params.value("port", 0u);
    uint32_t filter_proto = params.value("protocol", 0u);
    uint32_t max_payload = params.value("max_payload", 1500u);
    if (!device->start_capture(filter_pid, filter_port, filter_proto, nullptr, max_payload))
        return tool_result_t::error("Failed to start network capture.");
    json r; r["filter_pid"] = filter_pid; r["filter_port"] = filter_port;
    r["filter_protocol"] = filter_proto; r["max_payload"] = max_payload;
    return tool_result_t::ok("Network capture started", r);
}

tool_result_t handle_network_stop_capture(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!device->stop_capture())
        return tool_result_t::error("Failed to stop capture.");
    return tool_result_t::ok("Network capture stopped");
}

tool_result_t handle_network_get_packets(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t count = params.value("count", 50u);
    if (count > 200) count = 200;
    auto packets = device->get_captured_packets(count);
    json arr = json::array();
    uint32_t idx = 0;
    for (const auto& p : packets) {
        json e;
        e["index"] = idx++; e["timestamp"] = p.timestamp;
        e["protocol"] = protocol_name(p.protocol); e["direction"] = direction_name(p.direction);
        e["src"] = format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
        e["dst"] = format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
        e["length"] = p.payload_size; e["pid"] = p.pid;
        if (!p.payload.empty())
            e["data_preview"] = bytes_to_hex(p.payload.data(), std::min(p.payload.size(), (size_t)64));
        arr.push_back(e);
    }
    json r; r["packets"] = arr; r["count"] = (uint32_t)packets.size();
    return tool_result_t::ok(std::to_string(packets.size()) + " packets", r);
}

tool_result_t handle_network_analyze_packet(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t idx = params.value("index", 0u);
    auto packets = device->get_captured_packets(idx + 1);
    if (packets.empty() || idx >= packets.size())
        return tool_result_t::error("Packet not found at index " + std::to_string(idx));
    const auto& p = packets[idx];
    json r;
    r["index"] = idx; r["timestamp"] = p.timestamp;
    r["protocol"] = protocol_name(p.protocol); r["direction"] = direction_name(p.direction);
    r["src"] = format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
    r["dst"] = format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
    r["length"] = p.payload_size; r["pid"] = p.pid;
    if (!p.payload.empty()) {
        size_t dlen = std::min(p.payload.size(), (size_t)1500);
        r["hex_dump"] = hex_dump_fmt(p.payload.data(), dlen, 512);
        r["ascii"] = extract_ascii(p.payload.data(), dlen);
        parsed_http_msg_t http;
        if (try_parse_http(p.payload.data(), dlen, http)) {
            json hj;
            if (http.is_request) { hj["type"] = "request"; hj["method"] = http.method; hj["uri"] = http.uri; }
            else if (http.is_response) { hj["type"] = "response"; hj["status"] = http.status_code; hj["reason"] = http.reason_phrase; }
            json hdrs = json::array();
            for (const auto& h : http.headers) hdrs.push_back({{h.first, h.second}});
            hj["headers"] = hdrs;
            if (!http.body.empty()) hj["body_preview"] = http.body.substr(0, 512);
            r["http"] = hj;
        }
        parsed_tls_info_t tls;
        if (try_parse_tls(p.payload.data(), dlen, tls)) {
            json tj;
            tj["content_type"] = tls_content_type_str(tls.content_type);
            tj["version"] = tls_version_str(tls.record_version);
            if (tls.handshake_type) tj["handshake_type"] = tls_handshake_type_str(tls.handshake_type);
            if (!tls.sni.empty()) tj["sni"] = tls.sni;
            if (!tls.cipher_suites.empty()) {
                json cs = json::array();
                for (auto c : tls.cipher_suites) cs.push_back(tls_cipher_name(c));
                tj["cipher_suites"] = cs;
            }
            if (tls.selected_cipher) tj["selected_cipher"] = tls_cipher_name(tls.selected_cipher);
            r["tls"] = tj;
        }
    }
    return tool_result_t::ok("Packet " + std::to_string(idx) + " analyzed", r);
}

tool_result_t handle_network_dns_log(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t filter_pid = params.value("filter_pid", 0u);
    auto entries = device->get_dns_queries(filter_pid);
    json arr = json::array();
    for (const auto& e : entries) {
        json j;
        j["domain"] = e.domain; j["resolved_ip"] = format_ip(e.resolved_addr, 2 /*AF_INET*/);
        j["query_type"] = e.query_type; j["timestamp"] = e.timestamp; j["ttl"] = e.ttl;
        arr.push_back(j);
    }
    return tool_result_t::ok(std::to_string(entries.size()) + " DNS entries", arr);
}

tool_result_t handle_network_add_filter(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t action    = params.value("action", 1u);     // 1=block, 0=allow
    uint32_t direction = params.value("direction", 0u);   // 0=both
    uint32_t protocol  = params.value("protocol", 0u);
    uint32_t pid       = params.value("pid", 0u);
    uint32_t port      = params.value("port", 0u);
    uint32_t rule_id = 0;
    if (!device->add_filter_rule(action, direction, protocol, pid, port, nullptr, nullptr, &rule_id))
        return tool_result_t::error("Failed to add filter rule.");
    json r; r["rule_id"] = rule_id;
    return tool_result_t::ok("Filter rule added", r);
}

tool_result_t handle_network_remove_filter(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t rule_id = params.value("rule_id", 0u);
    if (rule_id == 0) return tool_result_t::error("Missing required parameter: rule_id");
    if (!device->remove_filter_rule(rule_id))
        return tool_result_t::error("Failed to remove filter rule.");
    return tool_result_t::ok("Filter rule removed");
}

tool_result_t handle_network_clear_filters(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!device->clear_filter_rules())
        return tool_result_t::error("Failed to clear filter rules.");
    return tool_result_t::ok("All filter rules cleared");
}

tool_result_t handle_network_stats(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    voyager::device_t::network_stats stats{};
    if (!device->get_network_stats(stats))
        return tool_result_t::error("Failed to retrieve network statistics.");
    json r;
    r["bytes_sent"] = stats.bytes_sent;
    r["bytes_received"] = stats.bytes_received;
    r["packets_sent"] = stats.packets_sent;
    r["packets_received"] = stats.packets_received;
    r["active_connections"] = stats.active_connections;
    r["capture_active"] = stats.capture_active;
    r["total_captured"] = stats.total_captured;
    r["total_dropped"] = stats.total_dropped;
    r["active_filter_rules"] = stats.active_filter_rules;
    return tool_result_t::ok("Network statistics", r);
}

tool_result_t handle_network_capture_status(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    voyager::device_t::network_stats stats{};
    device->get_network_stats(stats);
    json r;
    r["active"] = (bool)stats.capture_active;
    r["packets"] = stats.total_captured;
    r["dropped"] = stats.total_dropped;
    r["filters"] = stats.active_filter_rules;
    return tool_result_t::ok(stats.capture_active ? "Capture is active" : "Capture is inactive", r);
}

tool_result_t handle_network_block_ip(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!params.contains("ip") || !params["ip"].is_string())
        return tool_result_t::error("Missing required parameter: ip");
    std::string ip = params["ip"].get<std::string>();
    uint8_t addr[16] = {};
    uint32_t af = 2; // AF_INET
    if (ip.find(':') != std::string::npos) af = 23; // AF_INET6
    // Parse simple IPv4
    if (af == 2) {
        unsigned a, b, c, d;
        if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            addr[0] = (uint8_t)a; addr[1] = (uint8_t)b; addr[2] = (uint8_t)c; addr[3] = (uint8_t)d;
        }
    }
    uint32_t rule_id = 0;
    if (!device->add_filter_rule(1 /*block*/, 0 /*both*/, 0, 0, 0, addr, nullptr, &rule_id))
        return tool_result_t::error("Failed to block IP.");
    json r; r["rule_id"] = rule_id;
    return tool_result_t::ok("IP blocked: " + ip, r);
}

tool_result_t handle_network_block_port(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t port = params.value("port", 0u);
    if (port == 0 || port > 65535) return tool_result_t::error("Invalid port number.");
    uint32_t rule_id = 0;
    if (!device->add_filter_rule(1 /*block*/, 0 /*both*/, 0, 0, port, nullptr, nullptr, &rule_id))
        return tool_result_t::error("Failed to block port.");
    json r; r["rule_id"] = rule_id;
    return tool_result_t::ok("Port " + std::to_string(port) + " blocked", r);
}

tool_result_t handle_network_block_process(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t pid = params.value("pid", 0u);
    if (pid == 0) return tool_result_t::error("Missing required parameter: pid");
    uint32_t rule_id = 0;
    if (!device->add_filter_rule(1 /*block*/, 0 /*both*/, 0, pid, 0, nullptr, nullptr, &rule_id))
        return tool_result_t::error("Failed to block process.");
    json r; r["rule_id"] = rule_id;
    return tool_result_t::ok("Process " + std::to_string(pid) + " blocked", r);
}

tool_result_t handle_network_deep_inspect(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t filter_pid = params.value("pid", 0u);
    uint32_t filter_proto = params.value("protocol", 0u);
    auto results = device->get_dpi_results(filter_pid, filter_proto);
    json arr = json::array();
    for (const auto& d : results) {
        json e;
        e["timestamp"] = d.timestamp;
        e["protocol"] = protocol_name(d.protocol);
        e["direction"] = direction_name(d.direction);
        e["src"] = format_ip(d.src_addr, d.af) + ":" + std::to_string(d.src_port);
        e["dst"] = format_ip(d.dst_addr, d.af) + ":" + std::to_string(d.dst_port);
        e["pid"] = d.pid; e["payload_size"] = d.payload_size;
        if (d.is_http) { e["http_host"] = d.http_host; e["http_path"] = d.http_path; }
        if (d.is_tls) { e["tls_sni"] = d.tls_sni; e["tls_version"] = d.tls_version; }
        if (d.is_dns) e["is_dns"] = true;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(results.size()) + " DPI results", arr);
}

tool_result_t handle_network_follow_tcp_stream(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!params.contains("src") || !params.contains("dst"))
        return tool_result_t::error("Missing src and dst parameters ('ip:port' format).");
    std::string src = params["src"].get<std::string>();
    std::string dst = params["dst"].get<std::string>();
    uint8_t src_addr[16] = {}, dst_addr[16] = {};
    uint32_t src_port = 0, dst_port = 0;
    auto colon1 = src.rfind(':');
    if (colon1 != std::string::npos) {
        parse_ipv4(src.substr(0, colon1), src_addr);
        src_port = (uint32_t)std::atoi(src.substr(colon1 + 1).c_str());
    }
    auto colon2 = dst.rfind(':');
    if (colon2 != std::string::npos) {
        parse_ipv4(dst.substr(0, colon2), dst_addr);
        dst_port = (uint32_t)std::atoi(dst.substr(colon2 + 1).c_str());
    }
    uint32_t pid = params.value("pid", 0u);
    std::vector<uint8_t> out_data;
    uint32_t out_packets = 0, out_truncated = 0;
    if (!device->stream_reassemble_op(0 /*start*/, src_port, dst_port, pid, src_addr, dst_addr,
                                       &out_data, &out_packets, &out_truncated))
        return tool_result_t::error("Failed to reassemble TCP stream.");
    json r;
    r["bytes_reassembled"] = (uint32_t)out_data.size();
    r["packets"] = out_packets; r["truncated"] = out_truncated;
    if (!out_data.empty()) {
        r["hex_dump"] = hex_dump_fmt(out_data.data(), std::min(out_data.size(), (size_t)4096));
        r["ascii"] = extract_ascii(out_data.data(), std::min(out_data.size(), (size_t)2048));
    }
    return tool_result_t::ok("Stream reassembled: " + std::to_string(out_data.size()) + " bytes", r);
}

tool_result_t handle_network_parse_http(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t idx = params.value("index", 0u);
    auto packets = device->get_captured_packets(idx + 1);
    if (packets.empty() || idx >= packets.size()) return tool_result_t::error("Packet not found.");
    const auto& p = packets[idx];
    if (p.payload.empty()) return tool_result_t::error("No payload data in packet.");
    parsed_http_msg_t http;
    if (!try_parse_http(p.payload.data(), p.payload.size(), http))
        return tool_result_t::error("Packet does not contain HTTP data.");
    json r;
    if (http.is_request) { r["type"] = "request"; r["method"] = http.method; r["uri"] = http.uri; r["version"] = http.http_version; }
    else { r["type"] = "response"; r["status"] = http.status_code; r["reason"] = http.reason_phrase; r["version"] = http.http_version; }
    json hdrs = json::object();
    for (const auto& h : http.headers) hdrs[h.first] = h.second;
    r["headers"] = hdrs;
    if (!http.body.empty()) { r["body"] = http.body; r["body_truncated"] = http.body_truncated; }
    return tool_result_t::ok("HTTP parsed", r);
}

tool_result_t handle_network_parse_tls(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t idx = params.value("index", 0u);
    auto packets = device->get_captured_packets(idx + 1);
    if (packets.empty() || idx >= packets.size()) return tool_result_t::error("Packet not found.");
    const auto& p = packets[idx];
    if (p.payload.empty()) return tool_result_t::error("No payload data.");
    parsed_tls_info_t tls;
    if (!try_parse_tls(p.payload.data(), p.payload.size(), tls))
        return tool_result_t::error("Packet does not contain TLS data.");
    json r;
    r["content_type"] = tls_content_type_str(tls.content_type);
    r["version"] = tls_version_str(tls.record_version);
    if (tls.handshake_type) r["handshake_type"] = tls_handshake_type_str(tls.handshake_type);
    if (tls.client_version) r["client_version"] = tls_version_str(tls.client_version);
    if (!tls.sni.empty()) r["sni"] = tls.sni;
    if (!tls.alpn_protocols.empty()) r["alpn"] = tls.alpn_protocols;
    if (tls.is_http2) r["is_http2"] = true;
    if (!tls.cipher_suites.empty()) {
        json cs = json::array();
        for (auto c : tls.cipher_suites) cs.push_back(tls_cipher_name(c));
        r["cipher_suites"] = cs;
    }
    if (tls.selected_cipher) r["selected_cipher"] = tls_cipher_name(tls.selected_cipher);
    return tool_result_t::ok("TLS record parsed", r);
}

tool_result_t handle_network_enumerate_interfaces(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    auto ifaces = device->enumerate_interfaces();
    json arr = json::array();
    for (const auto& i : ifaces) {
        json e;
        e["index"] = i.if_index; e["name"] = i.name; e["description"] = i.description;
        e["mac"] = format_mac(i.mac_addr);
        e["ipv4"] = format_ipv4_bytes(i.ipv4_addr);
        e["mtu"] = i.mtu; e["speed"] = i.speed;
        e["oper_status"] = i.oper_status;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(ifaces.size()) + " interfaces", arr);
}

tool_result_t handle_network_inject_packet(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!params.contains("data") || !params["data"].is_string())
        return tool_result_t::error("Missing required parameter: data (hex bytes)");
    auto payload = hex_to_bytes(params["data"].get<std::string>());
    if (payload.empty()) return tool_result_t::error("Invalid packet data.");
    uint32_t direction = params.value("direction", 0u);
    uint32_t protocol = params.value("protocol", 6u);
    uint32_t af = params.value("af", 2u);
    uint32_t src_port = params.value("src_port", 0u);
    uint32_t dst_port = params.value("dst_port", 0u);
    uint8_t src_addr[16] = {}, dst_addr[16] = {};
    if (params.contains("src_ip") && params["src_ip"].is_string())
        parse_ipv4(params["src_ip"].get<std::string>(), src_addr);
    if (params.contains("dst_ip") && params["dst_ip"].is_string())
        parse_ipv4(params["dst_ip"].get<std::string>(), dst_addr);
    if (!device->inject_packet(direction, protocol, af, src_port, dst_port,
                                src_addr, dst_addr, payload.data(), (uint32_t)payload.size()))
        return tool_result_t::error("Failed to inject packet.");
    json r; r["bytes_injected"] = payload.size();
    return tool_result_t::ok("Packet injected (" + std::to_string(payload.size()) + " bytes)", r);
}

tool_result_t handle_network_modify_packet_rule(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t operation = params.value("action", 0u); // 0=add, 1=remove
    uint32_t rule_id = params.value("rule_id", 0u);
    uint32_t direction = params.value("direction", 2u);
    uint32_t protocol = params.value("protocol", 0u);
    uint32_t port = params.value("port", 0u);
    uint32_t pid = params.value("pid", 0u);
    std::vector<uint8_t> pattern, replacement;
    if (params.contains("match_pattern") && params["match_pattern"].is_string())
        pattern = hex_to_bytes(params["match_pattern"].get<std::string>());
    if (params.contains("replace_pattern") && params["replace_pattern"].is_string())
        replacement = hex_to_bytes(params["replace_pattern"].get<std::string>());
    uint32_t out_rule_id = 0;
    if (!device->packet_mod_rule_op(operation, rule_id, direction, protocol, port, pid,
                                     pattern.empty() ? nullptr : pattern.data(), (uint32_t)pattern.size(),
                                     replacement.empty() ? nullptr : replacement.data(), (uint32_t)replacement.size(),
                                     &out_rule_id))
        return tool_result_t::error("Failed to apply packet modification rule.");
    json r; r["rule_id"] = out_rule_id;
    return tool_result_t::ok("Packet modification rule applied", r);
}

tool_result_t handle_network_list_mod_rules(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    auto rules = device->list_packet_mod_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json e;
        e["id"] = r.rule_id; e["direction"] = r.direction;
        e["protocol"] = r.protocol; e["port"] = r.port;
        e["pid"] = r.pid; e["match_count"] = r.match_count;
        e["active"] = r.active;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + " modification rules", arr);
}

tool_result_t handle_network_redirect_traffic(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t operation = params.value("action", 0u); // 0=add, 1=remove
    uint32_t rule_id = params.value("rule_id", 0u);
    uint32_t protocol = params.value("protocol", 6u);
    uint32_t match_port = params.value("match_port", 0u);
    uint32_t redirect_port = params.value("redirect_port", 0u);
    uint32_t af = params.value("af", 2u);
    uint8_t match_addr[16] = {}, redirect_addr[16] = {};
    if (params.contains("match_ip") && params["match_ip"].is_string())
        parse_ipv4(params["match_ip"].get<std::string>(), match_addr);
    if (params.contains("redirect_ip") && params["redirect_ip"].is_string())
        parse_ipv4(params["redirect_ip"].get<std::string>(), redirect_addr);
    uint32_t out_rule_id = 0;
    if (!device->traffic_redirect_op(operation, rule_id, protocol, match_port, match_addr,
                                      redirect_port, redirect_addr, af, &out_rule_id))
        return tool_result_t::error("Failed to apply traffic redirect rule.");
    json r; r["rule_id"] = out_rule_id;
    return tool_result_t::ok("Traffic redirect rule applied", r);
}

tool_result_t handle_network_list_redirect_rules(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    auto rules = device->list_redirect_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json e;
        e["id"] = r.rule_id; e["protocol"] = r.protocol;
        e["match_port"] = r.match_port; e["redirect_port"] = r.redirect_port;
        e["af"] = r.af; e["match_count"] = r.match_count; e["active"] = r.active;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + " redirect rules", arr);
}

tool_result_t handle_network_intercept(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t operation = params.value("action", 0u); // 0=start, 1=stop
    uint32_t filter_pid = params.value("pid", 0u);
    uint32_t filter_port = params.value("port", 0u);
    uint32_t filter_protocol = params.value("protocol_num", 0u);
    uint32_t held_count = 0; bool active = false;
    if (!device->intercept_op(operation, filter_pid, filter_port, filter_protocol,
                               0, nullptr, 0, &held_count, &active))
        return tool_result_t::error("Failed to apply intercept operation.");
    json r; r["active"] = active; r["held_count"] = held_count;
    return tool_result_t::ok(operation == 0 ? "Intercept started" : "Intercept stopped", r);
}

tool_result_t handle_network_get_held_packets(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    auto held = device->get_held_packets();
    json arr = json::array();
    for (const auto& h : held) {
        json e;
        e["packet_id"] = h.hold_id;
        e["direction"] = direction_name(h.direction);
        e["src"] = format_ip(h.src_addr, h.af) + ":" + std::to_string(h.src_port);
        e["dst"] = format_ip(h.dst_addr, h.af) + ":" + std::to_string(h.dst_port);
        e["length"] = h.payload_size;
        if (!h.payload.empty())
            e["data_preview"] = bytes_to_hex(h.payload.data(), std::min(h.payload.size(), (size_t)64));
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(held.size()) + " held packets", arr);
}

tool_result_t handle_network_release_packet(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint64_t hold_id = params.value("packet_id", (uint64_t)0);
    bool drop = params.value("drop", false);
    bool modified = params.value("modified", false);
    std::vector<uint8_t> new_data;
    if (modified && params.contains("data") && params["data"].is_string())
        new_data = hex_to_bytes(params["data"].get<std::string>());
    // operation: 2=release, 3=drop
    uint32_t op = drop ? 3u : 2u;
    if (!device->intercept_op(op, 0, 0, 0, hold_id,
                               modified ? new_data.data() : nullptr,
                               modified ? (uint32_t)new_data.size() : 0,
                               nullptr, nullptr))
        return tool_result_t::error("Failed to release packet.");
    return tool_result_t::ok(drop ? "Packet dropped" : "Packet released");
}

tool_result_t handle_network_kill_connection(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!params.contains("src") || !params.contains("dst"))
        return tool_result_t::error("Missing src/dst parameters ('ip:port').");
    uint8_t src_addr[16] = {}, dst_addr[16] = {};
    uint32_t src_port = 0, dst_port = 0;
    auto s = params["src"].get<std::string>(), d = params["dst"].get<std::string>();
    auto c1 = s.rfind(':'), c2 = d.rfind(':');
    if (c1 != std::string::npos) { parse_ipv4(s.substr(0, c1), src_addr); src_port = (uint32_t)std::atoi(s.substr(c1+1).c_str()); }
    if (c2 != std::string::npos) { parse_ipv4(d.substr(0, c2), dst_addr); dst_port = (uint32_t)std::atoi(d.substr(c2+1).c_str()); }
    uint32_t protocol = params.value("protocol", 6u);
    uint32_t af = params.value("af", 2u);
    uint32_t pid = params.value("pid", 0u);
    if (!device->kill_connection(protocol, af, src_port, dst_port, src_addr, dst_addr, pid))
        return tool_result_t::error("Failed to kill connection.");
    return tool_result_t::ok("Connection killed: " + s + " -> " + d);
}

tool_result_t handle_network_spoof_dns(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t operation = params.value("action", 0u); // 0=add, 1=remove
    uint32_t rule_id = params.value("rule_id", 0u);
    std::string domain_str;
    if (params.contains("domain") && params["domain"].is_string())
        domain_str = params["domain"].get<std::string>();
    uint8_t spoof_addr[16] = {};
    if (params.contains("redirect_ip") && params["redirect_ip"].is_string())
        parse_ipv4(params["redirect_ip"].get<std::string>(), spoof_addr);
    uint32_t af = params.value("af", 2u);
    uint32_t ttl = params.value("ttl", 300u);
    uint32_t out_rule_id = 0;
    if (!device->dns_spoof_op(operation, rule_id, domain_str.empty() ? nullptr : domain_str.c_str(),
                               spoof_addr, af, ttl, &out_rule_id))
        return tool_result_t::error("Failed to apply DNS spoof rule.");
    json r; r["rule_id"] = out_rule_id;
    return tool_result_t::ok("DNS spoof rule applied", r);
}

tool_result_t handle_network_list_dns_spoof_rules(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    auto rules = device->list_dns_spoof_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json e;
        e["id"] = r.rule_id; e["domain"] = r.domain;
        e["af"] = r.af; e["ttl"] = r.ttl;
        e["match_count"] = r.match_count; e["active"] = r.active;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + " DNS spoof rules", arr);
}

tool_result_t handle_network_bandwidth_monitor(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t operation = params.value("action", 0u); // 0=start, 1=stop, 2=query
    uint32_t filter_pid = params.value("pid", 0u);
    voyager::device_t::bw_stats stats{};
    if (!device->bw_monitor_op(operation, filter_pid, &stats))
        return tool_result_t::error("Failed bandwidth monitor operation.");
    json r;
    r["bytes_sent"] = stats.total_bytes_sent; r["bytes_recv"] = stats.total_bytes_recv;
    r["packets_sent"] = stats.total_packets_sent; r["packets_recv"] = stats.total_packets_recv;
    r["bps_in"] = stats.bps_in; r["bps_out"] = stats.bps_out;
    r["active"] = stats.active;
    return tool_result_t::ok("Bandwidth stats", r);
}

tool_result_t handle_network_bandwidth_per_process(const json&) {
    auto chk = require_connected(); if (!chk.success) return chk;
    auto procs = device->get_bw_per_process();
    json arr = json::array();
    for (const auto& p : procs) {
        json e;
        e["pid"] = p.pid;
        e["bytes_sent"] = p.bytes_sent; e["bytes_recv"] = p.bytes_recv;
        e["packets_sent"] = p.packets_sent; e["packets_recv"] = p.packets_recv;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(procs.size()) + " processes", arr);
}

tool_result_t handle_network_os_fingerprint(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t operation = params.value("action", 0u); // 0=start, 1=stop, 2=query
    if (!device->fingerprint_op(operation))
        return tool_result_t::error("Failed to perform fingerprint operation.");
    auto fps = device->get_fingerprints();
    json arr = json::array();
    for (const auto& f : fps) {
        json e;
        e["ip"] = format_ip(f.remote_addr, f.af);
        e["os_guess"] = f.os_guess;
        e["ttl"] = f.ttl; e["window_size"] = f.window_size;
        e["mss"] = f.mss; e["df_flag"] = f.df_flag;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(fps.size()) + " fingerprint results", arr);
}

tool_result_t handle_network_export_pcap(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t filter_pid = params.value("pid", 0u);
    uint32_t filter_proto = params.value("protocol", 0u);
    uint32_t max_packets = params.value("max_packets", 64u);
    voyager::device_t::pcap_export_result pcap_result{};
    if (!device->export_pcap(filter_pid, filter_proto, max_packets, &pcap_result))
        return tool_result_t::error("Failed to export PCAP data.");
    // Write to file
    std::string path;
    if (params.contains("path") && params["path"].is_string())
        path = params["path"].get<std::string>();
    else
        path = get_downloads_folder() + "capture_" +
            std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".pcap";
    ensure_parent_dir(path);
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return tool_result_t::error("Cannot open output file: " + path);
    ofs.write(reinterpret_cast<const char*>(&pcap_result.header), sizeof(pcap_result.header));
    for (const auto& pkt : pcap_result.packets) {
        uint32_t incl_len = (uint32_t)pkt.data.size();
        uint32_t orig_len = incl_len;
        ofs.write(reinterpret_cast<const char*>(&pkt.ts_sec), 4);
        ofs.write(reinterpret_cast<const char*>(&pkt.ts_usec), 4);
        ofs.write(reinterpret_cast<const char*>(&incl_len), 4);
        ofs.write(reinterpret_cast<const char*>(&orig_len), 4);
        if (!pkt.data.empty()) ofs.write(reinterpret_cast<const char*>(pkt.data.data()), pkt.data.size());
    }
    ofs.close();
    json r; r["path"] = path; r["packets_exported"] = (uint32_t)pcap_result.packets.size();
    return tool_result_t::ok("PCAP exported: " + path, r);
}

tool_result_t handle_network_sniff_buffers(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t address = 0;
    if (params.contains("buffer_address") && params["buffer_address"].is_string())
        parse_addr(params["buffer_address"].get<std::string>(), address);
    uint32_t buf_reg = params.value("buf_reg", 0u);
    uint32_t size_reg = params.value("size_reg", 1u);
    uint32_t max_captures = params.value("max_captures", 1u);
    if (address != 0) {
        if (!device->sniff_net_buffers_start(address, buf_reg, size_reg, max_captures))
            return tool_result_t::error("Failed to start buffer sniffing.");
    }
    bool active = false;
    auto results = device->sniff_net_buffers_get(active);
    json arr = json::array();
    for (const auto& r : results) {
        json e;
        e["timestamp"] = r.timestamp; e["thread_id"] = r.thread_id;
        if (!r.buffer.empty()) {
            e["data_hex"] = bytes_to_hex(r.buffer.data(), std::min(r.buffer.size(), (size_t)4096));
            e["hex_dump"] = hex_dump_fmt(r.buffer.data(), std::min(r.buffer.size(), (size_t)2048));
        }
        arr.push_back(e);
    }
    json res; res["active"] = active; res["buffers"] = arr;
    return tool_result_t::ok(std::to_string(results.size()) + " buffers sniffed", res);
}

// ===== NET SECURITY TOOLS =====

tool_result_t handle_tls_extract_keys(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    net_security::tls_key_scan_config_t config;
    config.pid = params.value("pid", device->get_process_id());
    auto keys = net_security::TlsKeyExtractor::instance().extract_keys(config);
    json arr = json::array();
    for (const auto& k : keys) {
        json e;
        e["label"] = k.label;
        e["client_random"] = bytes_to_hex(k.client_random.data(), k.client_random.size());
        e["secret"] = bytes_to_hex(k.secret.data(), k.secret.size());
        arr.push_back(e);
    }
    json r; r["keys"] = arr; r["count"] = arr.size(); r["pid"] = config.pid;
    return tool_result_t::ok(std::to_string(arr.size()) + " TLS keys extracted", r);
}

tool_result_t handle_tls_start_keylog(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    net_security::keylog_config_t config;
    if (params.contains("path") && params["path"].is_string())
        config.output_file = params["path"].get<std::string>();
    else config.output_file = get_downloads_folder() + "sslkeys.log";
    config.pid = params.value("pid", device->get_process_id());
    if (!net_security::TlsKeyExtractor::instance().start_keylog(config))
        return tool_result_t::error("Failed to start TLS key logging.");
    json r; r["path"] = config.output_file; r["pid"] = config.pid;
    return tool_result_t::ok("TLS keylogging started -> " + config.output_file, r);
}

tool_result_t handle_tls_stop_keylog(const json&) {
    net_security::TlsKeyExtractor::instance().stop_keylog();
    return tool_result_t::ok("TLS keylogging stopped");
}

tool_result_t handle_tls_get_extracted_keys(const json&) {
    const auto& seen = net_security::TlsKeyExtractor::instance().get_seen_keys();
    json arr = json::array();
    for (const auto& [id, k] : seen) {
        json e; e["label"] = k.label;
        e["client_random"] = bytes_to_hex(k.client_random.data(), k.client_random.size());
        e["secret"] = bytes_to_hex(k.secret.data(), k.secret.size());
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(arr.size()) + " cached keys", arr);
}

tool_result_t handle_tls_ensure_keylogfile(const json&) {
    if (!net_security::TlsKeyExtractor::instance().ensure_sslkeylogfile_env())
        return tool_result_t::error("Failed to set SSLKEYLOGFILE environment variable.");
    return tool_result_t::ok("SSLKEYLOGFILE environment variable configured");
}

tool_result_t handle_network_decrypt_capture(const json& params) {
    if (!params.contains("pcap_path") || !params["pcap_path"].is_string())
        return tool_result_t::error("Missing required parameter: pcap_path");
    std::string pcap = params["pcap_path"].get<std::string>();
    std::string keylog;
    if (params.contains("keylog_path") && params["keylog_path"].is_string())
        keylog = params["keylog_path"].get<std::string>();
    else keylog = get_downloads_folder() + "sslkeys.log";
    std::string display_filter = params.value("display_filter", "http2");
    auto result = net_security::TlsKeyExtractor::instance().decrypt_pcap_with_tshark(pcap, keylog, display_filter);
    json r; r["success"] = result.success;
    if (!result.error_message.empty()) r["error"] = result.error_message;
    r["total_packets"] = result.total_packets;
    r["decrypted_packets"] = result.decrypted_packets;
    if (!result.raw_output.empty()) r["raw_output"] = result.raw_output.substr(0, 4096);
    return result.success ?
        tool_result_t::ok("PCAP decrypted successfully", r) :
        tool_result_t::error("Decryption failed: " + result.error_message);
}

tool_result_t handle_cert_inject(const json& params) {
    if (!params.contains("cert_path") || !params["cert_path"].is_string())
        return tool_result_t::error("Missing required parameter: cert_path");
    net_security::cert_injection_config_t config;
    config.cert_pem = params["cert_path"].get<std::string>();
    config.store_name = params.value("store_name", "ROOT");
    auto result = net_security::CertificateInjector::instance().inject_certificate(config);
    json r; r["success"] = result.success;
    if (!result.thumbprint.empty()) r["thumbprint"] = result.thumbprint;
    if (!result.method.empty()) r["method"] = result.method;
    return result.success ? tool_result_t::ok("Certificate injected", r) :
        tool_result_t::error("Injection failed");
}

tool_result_t handle_cert_remove(const json& params) {
    if (!params.contains("thumbprint") || !params["thumbprint"].is_string())
        return tool_result_t::error("Missing required parameter: thumbprint");
    auto result = net_security::CertificateInjector::instance().remove_certificate(
        params["thumbprint"].get<std::string>(),
        params.value("store_name", "ROOT"));
    return result ? tool_result_t::ok("Certificate removed") :
        tool_result_t::error("Failed to remove certificate.");
}

tool_result_t handle_cert_generate_ca(const json& params) {
    std::string cn = params.value("common_name", "AiDA Proxy CA");
    uint32_t days = params.value("validity_days", 365u);
    std::vector<uint8_t> out_cert, out_key;
    bool ok = net_security::CertificateInjector::instance().generate_ca_certificate(cn, days, out_cert, out_key);
    json r; r["success"] = ok;
    if (ok) { r["cert_size"] = out_cert.size(); r["key_size"] = out_key.size(); }
    return ok ? tool_result_t::ok("CA certificate generated", r) :
        tool_result_t::error("CA generation failed");
}

tool_result_t handle_cert_list(const json& params) {
    std::string store = params.value("store_name", "ROOT");
    auto certs = net_security::CertificateInjector::instance().list_certificates(store);
    json arr = json::array();
    for (const auto& c : certs) {
        json e; e["subject"] = c.subject; e["issuer"] = c.issuer;
        e["thumbprint"] = c.thumbprint; e["not_before"] = c.not_before;
        e["not_after"] = c.not_after; e["is_ca"] = c.is_ca;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(certs.size()) + " certificates in " + store, arr);
}

tool_result_t handle_pin_bypass(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    net_security::pin_bypass_config_t config;
    config.pid = params.value("pid", device->get_process_id());
    auto result = net_security::CertPinBypasser::instance().bypass_pins(config);
    json r; r["success"] = result.success; r["pid"] = config.pid;
    r["patches_applied"] = result.patches_applied;
    r["patches_failed"] = result.patches_failed;
    return result.success ? tool_result_t::ok("Certificate pinning bypassed", r) :
        tool_result_t::error("Bypass failed");
}

tool_result_t handle_pin_bypass_revert(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t pid = params.value("pid", device->get_process_id());
    auto result = net_security::CertPinBypasser::instance().revert_bypass(pid);
    return result ? tool_result_t::ok("Pinning bypass reverted") :
        tool_result_t::error("Failed to revert bypass.");
}

tool_result_t handle_pin_bypass_status(const json& params) {
    uint32_t pid = params.value("pid", device ? device->get_process_id() : 0u);
    bool active = net_security::CertPinBypasser::instance().is_bypass_active(pid);
    json r; r["pid"] = pid; r["bypass_active"] = active;
    return tool_result_t::ok(active ? "Bypass is ACTIVE" : "Bypass is NOT active", r);
}

tool_result_t handle_quic_detect(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t pid = params.value("pid", 0u);
    auto conns = net_security::QuicAnalyzer::instance().detect_quic_connections(pid);
    json arr = json::array();
    for (const auto& c : conns) {
        json e;
        e["dcid"] = bytes_to_hex(c.dcid.data(), c.dcid.size());
        e["src"] = format_ip(c.src_addr, c.address_family) + ":" + std::to_string(c.src_port);
        e["dst"] = format_ip(c.dst_addr, c.address_family) + ":" + std::to_string(c.dst_port);
        e["version"] = bytes_to_hex(c.version, 4); e["alpn"] = c.alpn;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(conns.size()) + " QUIC connections detected", arr);
}

tool_result_t handle_quic_decrypt_initial(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!params.contains("packet_data") || !params["packet_data"].is_string())
        return tool_result_t::error("Missing required parameter: packet_data (hex)");
    auto pkt = hex_to_bytes(params["packet_data"].get<std::string>());
    if (pkt.empty()) return tool_result_t::error("Invalid packet data.");
    auto result = net_security::QuicAnalyzer::instance().decrypt_initial_packet(pkt.data(), pkt.size());
    json r; r["success"] = result.success;
    if (result.success) {
        r["quic_version"] = result.quic_version;
        r["packet_type"] = result.packet_type;
        r["packet_number"] = result.packet_number;
        if (!result.crypto_frame_hex.empty()) r["crypto_frame"] = result.crypto_frame_hex;
    }
    return result.success ? tool_result_t::ok("Initial packet decrypted", r) :
        tool_result_t::error("Decryption failed");
}

tool_result_t handle_quic_extract_keys(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t pid = params.value("pid", device->get_process_id());
    auto keys = net_security::QuicAnalyzer::instance().extract_quic_traffic_keys(pid);
    json arr = json::array();
    for (const auto& k : keys) {
        json e; e["label"] = k.label;
        e["client_random"] = bytes_to_hex(k.client_random.data(), k.client_random.size());
        e["secret"] = bytes_to_hex(k.secret.data(), k.secret.size());
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(keys.size()) + " QUIC keys extracted", arr);
}

tool_result_t handle_dtls_detect(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    uint32_t pid = params.value("pid", 0u);
    auto sessions = net_security::DtlsAnalyzer::instance().detect_dtls_sessions(pid);
    json arr = json::array();
    for (const auto& s : sessions) {
        json e;
        e["src"] = format_ip(s.src_addr, s.address_family) + ":" + std::to_string(s.src_port);
        e["dst"] = format_ip(s.dst_addr, s.address_family) + ":" + std::to_string(s.dst_port);
        e["dtls_version"] = s.dtls_version;
        e["state"] = s.state;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(sessions.size()) + " DTLS sessions", arr);
}

tool_result_t handle_dtls_extract_keys(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint32_t pid = params.value("pid", device->get_process_id());
    auto keys = net_security::DtlsAnalyzer::instance().extract_dtls_keys(pid);
    json arr = json::array();
    for (const auto& k : keys) {
        json e; e["dtls_version"] = k.dtls_version;
        e["client_random"] = bytes_to_hex(k.client_random.data(), k.client_random.size());
        e["master_secret"] = bytes_to_hex(k.master_secret.data(), k.master_secret.size());
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(keys.size()) + " DTLS keys extracted", arr);
}

tool_result_t handle_autoresponder_add_rule(const json& params) {
    if (!params.contains("match_pattern") || !params["match_pattern"].is_string())
        return tool_result_t::error("Missing required parameter: match_pattern");
    net_security::autoresponder_rule_t rule;
    rule.match_pattern = params["match_pattern"].get<std::string>();
    if (params.contains("status_code")) rule.status_code = params.value("status_code", 200u);
    if (params.contains("response_body") && params["response_body"].is_string())
        rule.response_body = params["response_body"].get<std::string>();
    if (params.contains("response_file_path") && params["response_file_path"].is_string())
        rule.response_file_path = params["response_file_path"].get<std::string>();
    if (params.contains("match_method") && params["match_method"].is_string())
        rule.match_method = params["match_method"].get<std::string>();
    rule.drop_request = params.value("drop_request", false);
    rule.passthrough = params.value("passthrough", false);
    rule.latency_ms = params.value("latency_ms", 0u);
    rule.priority = params.value("priority", 0);
    auto result = net_security::AutoResponder::instance().add_rule(rule);
    json r; r["rule_id"] = result;
    return tool_result_t::ok("Rule added with ID " + std::to_string(result), r);
}

tool_result_t handle_autoresponder_remove_rule(const json& params) {
    int id = params.value("rule_id", -1);
    if (id < 0) return tool_result_t::error("Missing required parameter: rule_id");
    auto result = net_security::AutoResponder::instance().remove_rule(id);
    return result ? tool_result_t::ok("Rule removed") : tool_result_t::error("Failed to remove rule.");
}

tool_result_t handle_autoresponder_list_rules(const json&) {
    auto rules = net_security::AutoResponder::instance().list_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json e; e["rule_id"] = r.rule_id; e["match_pattern"] = r.match_pattern;
        e["status_code"] = r.status_code; e["enabled"] = r.enabled;
        e["match_count"] = r.match_count; e["priority"] = r.priority;
        e["drop_request"] = r.drop_request; e["passthrough"] = r.passthrough;
        arr.push_back(e);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + " autoresponder rules", arr);
}

tool_result_t handle_autoresponder_start(const json&) {
    auto result = net_security::AutoResponder::instance().start();
    return result ? tool_result_t::ok("AutoResponder started") :
        tool_result_t::error("Failed to start AutoResponder.");
}

tool_result_t handle_autoresponder_stop(const json&) {
    auto result = net_security::AutoResponder::instance().stop();
    return result ? tool_result_t::ok("AutoResponder stopped") :
        tool_result_t::error("Failed to stop AutoResponder.");
}

tool_result_t handle_autoresponder_import(const json& params) {
    if (!params.contains("json_data") || !params["json_data"].is_string())
        return tool_result_t::error("Missing required parameter: json_data");
    auto result = net_security::AutoResponder::instance().import_rules(params["json_data"].get<std::string>());
    return result ? tool_result_t::ok("Rules imported successfully") :
        tool_result_t::error("Failed to import rules.");
}

tool_result_t handle_autoresponder_export(const json&) {
    auto result = net_security::AutoResponder::instance().export_rules();
    if (result.empty()) return tool_result_t::error("Failed to export rules or no rules.");
    json r; r["json_data"] = result;
    return tool_result_t::ok("Rules exported", r);
}

// ===== EMULATION TOOLS =====

tool_result_t handle_disassemble_zydis(const json& params) {
    // Disassemble bytes using Zydis â€” works both from memory and from raw hex
    if (params.contains("hex") && params["hex"].is_string()) {
        auto bytes = hex_to_bytes(params["hex"].get<std::string>());
        if (bytes.empty()) return tool_result_t::error("Invalid hex data.");
        uint64_t va = 0;
        if (params.contains("address") && params["address"].is_string())
            parse_addr(params["address"].get<std::string>(), va);
        json arr = json::array();
        size_t off = 0;
        uint32_t max_insn = params.value("max_instructions", 64u);
        while (off < bytes.size() && arr.size() < max_insn) {
            auto insn = zydis_decode_one(bytes.data() + off, bytes.size() - off, va + off);
            if (insn.len == 0) break;
            json e;
            e["address"] = faddr(va + off);
            e["mnemonic"] = insn.mnem;
            e["operands"] = insn.ops;
            e["length"] = insn.len;
            e["hex"] = bytes_to_hex(insn.raw, insn.len);
            e["is_call"] = insn.is_call; e["is_branch"] = insn.is_branch;
            e["is_ret"] = insn.is_ret;
            arr.push_back(e);
            off += insn.len;
        }
        json r; r["instructions"] = arr; r["count"] = arr.size();
        return tool_result_t::ok(std::to_string(arr.size()) + " instructions disassembled", r);
    }

    // Disassemble from process memory
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), addr))
        return tool_result_t::error("Invalid or missing address.");
    uint32_t count = params.value("count", 32u);
    uint32_t max_bytes = count * 15;
    if (max_bytes > 65536) max_bytes = 65536;
    std::vector<uint8_t> buf(max_bytes);
    size_t rd = device->read_raw(addr, buf.data(), max_bytes);
    if (rd == 0) return tool_result_t::error("Failed to read memory at " + faddr(addr));
    json arr = json::array();
    size_t off = 0;
    while (off < rd && arr.size() < count) {
        auto insn = zydis_decode_one(buf.data() + off, rd - off, addr + off);
        if (insn.len == 0) break;
        json e;
        e["address"] = faddr(addr + off);
        e["mnemonic"] = insn.mnem;
        e["operands"] = insn.ops;
        e["length"] = insn.len;
        e["hex"] = bytes_to_hex(insn.raw, insn.len);
        e["is_call"] = insn.is_call; e["is_branch"] = insn.is_branch;
        e["is_ret"] = insn.is_ret;
        arr.push_back(e);
        off += insn.len;
    }
    json r; r["instructions"] = arr; r["count"] = arr.size(); r["start_address"] = faddr(addr);
    return tool_result_t::ok(std::to_string(arr.size()) + " instructions at " + faddr(addr), r);
}

tool_result_t handle_driver_snapshot_and_emulate(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t start_addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), start_addr))
        return tool_result_t::error("Invalid or missing address.");
    uint32_t max_steps = params.value("max_steps", 1000u);
    uint64_t stop_addr = 0;
    if (params.contains("stop_address") && params["stop_address"].is_string())
        parse_addr(params["stop_address"].get<std::string>(), stop_addr);
    uint32_t tid = params.value("tid", 0u);
    // Take snapshot
    auto snapshot = emulation::driver_snapshot(device->get_process_id(), tid, start_addr);
    if (snapshot.regions.empty())
        return tool_result_t::error("Failed to take process snapshot.");
    // Configure emulation
    emulation::emulation_config_t cfg;
    cfg.start_address = start_addr;
    cfg.max_instructions = max_steps;
    if (stop_addr) cfg.stop_address = stop_addr;
    cfg.record_mem_writes = params.value("trace_memory", true);
    cfg.record_registers = params.value("trace_registers", false);
    auto result = emulation::emulate_from_snapshot(snapshot, cfg);
    json r;
    r["total_instructions"] = result.total_instructions;
    r["success"] = result.success;
    r["end_address"] = faddr(result.end_address);
    if (!result.error.empty()) r["error"] = result.error;
    if (!result.trace.empty()) {
        json trace_arr = json::array();
        size_t max_trace = (std::min)(result.trace.size(), (size_t)200);
        for (size_t i = 0; i < max_trace; i++) {
            const auto& t = result.trace[i];
            json te;
            te["address"] = faddr(t.address);
            te["disasm"] = t.disasm;
            trace_arr.push_back(te);
        }
        r["trace"] = trace_arr;
        if (result.trace.size() > 200) r["trace_truncated"] = true;
    }
    if (!result.mem_writes.empty()) {
        json writes = json::array();
        for (const auto& w : result.mem_writes) {
            json we; we["address"] = faddr(w.address); we["size"] = w.size;
            we["value_hex"] = bytes_to_hex(w.data.data(), (std::min)(w.data.size(), (size_t)32));
            writes.push_back(we);
        }
        r["memory_writes"] = writes;
    }
    return tool_result_t::ok("Emulation: " + std::to_string(result.total_instructions) + " insns, success=" + std::string(result.success ? "true" : "false"), r);
}

tool_result_t handle_trace_execution_unicorn(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t start_addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), start_addr))
        return tool_result_t::error("Invalid or missing address.");
    uint32_t max_steps = params.value("max_steps", 5000u);
    auto snapshot = emulation::driver_snapshot(device->get_process_id(), 0, start_addr);
    if (snapshot.regions.empty())
        return tool_result_t::error("Failed to take snapshot.");
    emulation::emulation_config_t cfg;
    cfg.start_address = start_addr;
    cfg.max_instructions = max_steps;
    cfg.record_mem_writes = true;
    cfg.record_registers = params.value("trace_registers", true);
    if (params.contains("stop_addresses") && params["stop_addresses"].is_array()) {
        for (const auto& sa : params["stop_addresses"]) {
            uint64_t a = 0;
            if (sa.is_string()) parse_addr(sa.get<std::string>(), a);
            if (a) cfg.breakpoint_addresses.insert(a);
        }
    }
    auto result = emulation::emulate_from_snapshot(snapshot, cfg);
    json r;
    r["total_instructions"] = result.total_instructions;
    r["success"] = result.success;
    r["end_address"] = faddr(result.end_address);
    // Execution summary
    std::map<std::string, int> mnem_freq;
    std::set<uint64_t> unique_addrs;
    for (const auto& t : result.trace) {
        // Extract mnemonic from disasm string (first word)
        auto sp = t.disasm.find(' ');
        std::string mnem = (sp != std::string::npos) ? t.disasm.substr(0, sp) : t.disasm;
        mnem_freq[mnem]++;
        unique_addrs.insert(t.address);
    }
    r["unique_addresses"] = unique_addrs.size();
    json freq = json::object();
    for (const auto& [m, c] : mnem_freq) freq[m] = c;
    r["mnemonic_frequency"] = freq;
    // Trace (limited)
    json trace_arr = json::array();
    size_t show = (std::min)(result.trace.size(), (size_t)500);
    for (size_t i = 0; i < show; i++) {
        const auto& t = result.trace[i];
        json te; te["address"] = faddr(t.address); te["disasm"] = t.disasm;
        trace_arr.push_back(te);
    }
    r["trace"] = trace_arr;
    return tool_result_t::ok(std::to_string(result.total_instructions) + " instructions traced", r);
}

tool_result_t handle_analyze_vm_handler(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t handler_addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), handler_addr))
        return tool_result_t::error("Invalid or missing handler address.");
    uint64_t dispatcher = 0;
    if (params.contains("dispatcher") && params["dispatcher"].is_string())
        parse_addr(params["dispatcher"].get<std::string>(), dispatcher);
    auto snapshot = emulation::driver_snapshot(device->get_process_id(), 0, handler_addr);
    if (snapshot.regions.empty()) return tool_result_t::error("Snapshot failed.");
    emulation::emulation_config_t cfg;
    cfg.start_address = handler_addr;
    cfg.max_instructions = params.value("max_steps", 2000u);
    cfg.record_mem_writes = true; cfg.record_registers = true;
    auto emu_result = emulation::emulate_from_snapshot(snapshot, cfg);
    auto analysis = emulation::analyze_vm_trace(emu_result);
    json r;
    r["handler_address"] = faddr(handler_addr);
    r["semantic_summary"] = analysis.summary;
    r["total_instructions"] = analysis.total_instructions;
    r["junk_instructions"] = analysis.junk_instructions;
    r["effective_instructions"] = analysis.effective_instructions;
    if (!analysis.effective_ops.empty()) {
        json ops = json::array();
        for (const auto& op : analysis.effective_ops) ops.push_back(op);
        r["effective_ops"] = ops;
    }
    if (!analysis.net_reg_changes.empty()) {
        json regs = json::array();
        for (const auto& rd : analysis.net_reg_changes) {
            json re; re["name"] = rd.name; re["before"] = faddr(rd.before); re["after"] = faddr(rd.after);
            regs.push_back(re);
        }
        r["register_effects"] = regs;
    }
    if (!analysis.net_mem_writes.empty()) {
        json mw = json::array();
        for (const auto& w : analysis.net_mem_writes) {
            json we; we["address"] = faddr(w.address); we["size"] = w.size;
            mw.push_back(we);
        }
        r["memory_writes"] = mw;
    }
    return tool_result_t::ok("VM handler analysis: " + analysis.summary, r);
}

tool_result_t handle_emulate_multi_trace(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    if (!params.contains("addresses") || !params["addresses"].is_array() || params["addresses"].empty())
        return tool_result_t::error("Missing required parameter: addresses (array of hex addr)");
    uint32_t max_steps = params.value("max_steps", 1000u);
    json results = json::array();
    for (const auto& addr_val : params["addresses"]) {
        uint64_t addr = 0;
        if (addr_val.is_string()) parse_addr(addr_val.get<std::string>(), addr);
        if (!addr) continue;
        auto snapshot = emulation::driver_snapshot(device->get_process_id(), 0, addr);
        if (snapshot.regions.empty()) {
            json e; e["address"] = faddr(addr); e["error"] = "Snapshot failed";
            results.push_back(e); continue;
        }
        emulation::emulation_config_t cfg;
        cfg.start_address = addr; cfg.max_instructions = max_steps;
        cfg.record_mem_writes = true;
        auto emu = emulation::emulate_from_snapshot(snapshot, cfg);
        json e;
        e["address"] = faddr(addr);
        e["total_instructions"] = emu.total_instructions;
        e["success"] = emu.success;
        e["end_address"] = faddr(emu.end_address);
        if (!emu.error.empty()) e["error"] = emu.error;
        e["memory_writes"] = emu.mem_writes.size();
        results.push_back(e);
    }
    json r; r["traces"] = results; r["count"] = results.size();
    return tool_result_t::ok(std::to_string(results.size()) + " addresses traced", r);
}

tool_result_t handle_emulate_function(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t func_addr = 0;
    if (!params.contains("address") || !params["address"].is_string() ||
        !parse_addr(params["address"].get<std::string>(), func_addr))
        return tool_result_t::error("Invalid or missing function address.");
    auto snapshot = emulation::driver_snapshot(device->get_process_id(), 0, func_addr);
    if (snapshot.regions.empty()) return tool_result_t::error("Snapshot failed.");
    emulation::emulation_config_t cfg;
    cfg.start_address = func_addr;
    cfg.max_instructions = params.value("max_steps", 10000u);
    cfg.record_mem_writes = true; cfg.record_registers = true;
    // Set arguments via initial register state
    if (params.contains("rcx")) { uint64_t v = 0; if (params["rcx"].is_string()) parse_addr(params["rcx"].get<std::string>(), v);
        else if (params["rcx"].is_number()) v = params["rcx"].get<uint64_t>(); snapshot.rcx = v; }
    if (params.contains("rdx")) { uint64_t v = 0; if (params["rdx"].is_string()) parse_addr(params["rdx"].get<std::string>(), v);
        else if (params["rdx"].is_number()) v = params["rdx"].get<uint64_t>(); snapshot.rdx = v; }
    if (params.contains("r8"))  { uint64_t v = 0; if (params["r8"].is_string()) parse_addr(params["r8"].get<std::string>(), v);
        else if (params["r8"].is_number()) v = params["r8"].get<uint64_t>(); snapshot.r8 = v; }
    if (params.contains("r9"))  { uint64_t v = 0; if (params["r9"].is_string()) parse_addr(params["r9"].get<std::string>(), v);
        else if (params["r9"].is_number()) v = params["r9"].get<uint64_t>(); snapshot.r9 = v; }
    auto result = emulation::emulate_from_snapshot(snapshot, cfg);
    json r;
    r["function_address"] = faddr(func_addr);
    r["total_instructions"] = result.total_instructions;
    r["success"] = result.success;
    r["end_address"] = faddr(result.end_address);
    if (!result.error.empty()) r["error"] = result.error;
    r["memory_writes_count"] = result.mem_writes.size();
    r["memory_reads_count"] = result.mem_reads.size();
    // Show first few mem writes
    if (!result.mem_writes.empty()) {
        json writes = json::array();
        for (size_t i = 0; i < (std::min)(result.mem_writes.size(), (size_t)50); i++) {
            const auto& w = result.mem_writes[i];
            json we; we["address"] = faddr(w.address); we["size"] = w.size;
            we["value"] = bytes_to_hex(w.data.data(), (std::min)(w.data.size(), (size_t)32));
            writes.push_back(we);
        }
        r["memory_writes"] = writes;
    }
    return tool_result_t::ok("Function emulated: " + std::to_string(result.total_instructions) + " insns", r);
}

// ===== STANDALONE-SPECIFIC TOOLS =====

tool_result_t handle_disassemble_file(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    std::string path = params["path"].get<std::string>();
    DisasmFile df;
    if (!disasm::load_pe(path, df))
        return tool_result_t::error("Failed to load PE file: " + path);
    json arr = json::array();
    uint32_t max = params.value("max_instructions", 200u);
    uint64_t start_va = 0;
    if (params.contains("address") && params["address"].is_string())
        parse_addr(params["address"].get<std::string>(), start_va);
    size_t shown = 0;
    for (const auto& insn : df.instrs) {
        if (start_va && insn.addr < start_va) continue;
        json e;
        e["address"] = faddr(insn.addr);
        e["mnemonic"] = insn.mnem;
        e["operands"] = insn.ops;
        e["length"] = insn.len;
        e["hex"] = bytes_to_hex(insn.raw, insn.len);
        arr.push_back(e);
        if (++shown >= max) break;
    }
    json r;
    r["file"] = path;
    r["total_instructions"] = df.instrs.size();
    r["shown"] = shown;
    r["instructions"] = arr;
    return tool_result_t::ok(std::to_string(df.instrs.size()) + " instructions in " + path, r);
}

tool_result_t handle_sandbox_execute(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    sandbox::config cfg;
    {
        auto s = params["path"].get<std::string>();
        cfg.exe_path = std::wstring(s.begin(), s.end());
    }
    if (params.contains("arguments") && params["arguments"].is_string()) {
        auto s = params["arguments"].get<std::string>();
        cfg.arguments = std::wstring(s.begin(), s.end());
    }
    cfg.timeout_ms = params.value("timeout_ms", 30000u);
    cfg.max_memory = params.value("max_memory", 256u * 1024 * 1024);
    cfg.capture_stdout = params.value("capture_stdout", true);
    cfg.capture_stderr = params.value("capture_stderr", true);
    cfg.use_appcontainer = params.value("sandbox", true);
    auto result = sandbox::execute(cfg);
    json r;
    r["success"] = result.success;
    r["exit_code"] = result.exit_code;
    r["timed_out"] = result.timed_out;
    r["elapsed_ms"] = result.elapsed_ms;
    if (!result.stdout_data.empty()) r["stdout"] = result.stdout_data.substr(0, 65536);
    if (!result.stderr_data.empty()) r["stderr"] = result.stderr_data.substr(0, 65536);
    return tool_result_t::ok(result.success ? "Execution completed" : "Execution failed", r);
}

tool_result_t handle_convert_number(const json& params) {
    if (!params.contains("value") || !params["value"].is_string())
        return tool_result_t::error("Missing required parameter: value");
    std::string input = params["value"].get<std::string>();
    uint64_t val = 0;
    bool parsed = false;
    // Try hex
    if (input.size() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        try { val = std::stoull(input.substr(2), nullptr, 16); parsed = true; } catch (...) {}
    }
    // Try binary
    if (!parsed && input.size() > 2 && input[0] == '0' && (input[1] == 'b' || input[1] == 'B')) {
        try { val = std::stoull(input.substr(2), nullptr, 2); parsed = true; } catch (...) {}
    }
    // Try octal
    if (!parsed && input.size() > 2 && input[0] == '0' && (input[1] == 'o' || input[1] == 'O')) {
        try { val = std::stoull(input.substr(2), nullptr, 8); parsed = true; } catch (...) {}
    }
    // Try decimal
    if (!parsed) {
        try { val = std::stoull(input, nullptr, 0); parsed = true; } catch (...) {}
    }
    if (!parsed) return tool_result_t::error("Cannot parse value: " + input);

    // Build binary string
    std::string bin_str;
    if (val == 0) bin_str = "0";
    else { uint64_t tmp = val; while (tmp) { bin_str = ((tmp & 1) ? "1" : "0") + bin_str; tmp >>= 1; } }

    json r;
    r["decimal"] = val;
    r["hex"] = faddr(val);
    r["binary"] = "0b" + bin_str;
    char oct_buf[32]; snprintf(oct_buf, sizeof(oct_buf), "0o%llo", (unsigned long long)val);
    r["octal"] = oct_buf;
    r["signed_decimal"] = (int64_t)val;
    // Float interpretation
    if (val <= 0xFFFFFFFF) {
        uint32_t f32bits = (uint32_t)val;
        float f; memcpy(&f, &f32bits, 4);
        if (std::isfinite(f)) r["float32"] = f;
    }
    double d; memcpy(&d, &val, 8);
    if (std::isfinite(d)) r["float64"] = d;
    // Character interpretation
    if (val >= 32 && val < 127) r["ascii_char"] = std::string(1, (char)val);
    // Byte representation
    json bytes = json::array();
    for (int i = 0; i < 8; i++) bytes.push_back((val >> (i * 8)) & 0xFF);
    r["bytes_le"] = bytes;
    return tool_result_t::ok("Conversion of " + input, r);
}

// ===== DRIVER DUMP TOOLS =====

tool_result_t handle_driver_dump_module(const json& params) {
    auto chk = require_attached(); if (!chk.success) return chk;
    uint64_t module_base = 0;
    if (params.contains("base") && params["base"].is_string())
        parse_addr(params["base"].get<std::string>(), module_base);
    if (!module_base) module_base = device->get_base_address();
    if (!module_base) return tool_result_t::error("No module base address specified or available.");
    // Read DOS + PE headers
    uint8_t dos_hdr[0x40] = {};
    size_t rd = device->read_raw(module_base, dos_hdr, sizeof(dos_hdr));
    if (rd < sizeof(dos_hdr) || dos_hdr[0] != 'M' || dos_hdr[1] != 'Z')
        return tool_result_t::error("Invalid PE header at " + faddr(module_base));
    uint32_t pe_offset = *(uint32_t*)(dos_hdr + 0x3C);
    uint8_t pe_hdr[0x200] = {};
    device->read_raw(module_base + pe_offset, pe_hdr, sizeof(pe_hdr));
    if (pe_hdr[0] != 'P' || pe_hdr[1] != 'E')
        return tool_result_t::error("Invalid PE signature.");
    uint16_t num_sections = *(uint16_t*)(pe_hdr + 6);
    uint32_t size_of_image = *(uint32_t*)(pe_hdr + 0x50);
    // Choose output path
    std::string out_path;
    if (params.contains("output") && params["output"].is_string())
        out_path = params["output"].get<std::string>();
    else
        out_path = get_downloads_folder() + "dump_" + faddr(module_base).substr(2) + ".bin";
    ensure_parent_dir(out_path);
    // Dump entire image
    std::vector<uint8_t> dump(size_of_image, 0);
    size_t total = 0;
    const uint32_t chunk = 65536;
    for (uint32_t off = 0; off < size_of_image; off += chunk) {
        uint32_t sz = std::min(chunk, size_of_image - off);
        size_t r = device->read_raw(module_base + off, dump.data() + off, sz);
        total += r;
    }
    FILE* fp = fopen(out_path.c_str(), "wb");
    if (!fp) return tool_result_t::error("Cannot create output file: " + out_path);
    fwrite(dump.data(), 1, size_of_image, fp);
    fclose(fp);
    json r;
    r["base"] = faddr(module_base);
    r["size_of_image"] = size_of_image;
    r["bytes_read"] = total;
    r["sections"] = num_sections;
    r["output_path"] = out_path;
    return tool_result_t::ok("Module dumped to " + out_path, r);
}

tool_result_t handle_driver_dump_kernel_module(const json& params) {
    auto chk = require_connected(); if (!chk.success) return chk;
    if (!params.contains("name") || !params["name"].is_string())
        return tool_result_t::error("Missing required parameter: name (kernel module name)");
    std::string target = to_lower(params["name"].get<std::string>());
    auto kmodules = query_kernel_modules();
    uint64_t kbase = 0; uint32_t ksize = 0; std::string kname;
    for (const auto& m : kmodules) {
        if (to_lower(m.name) == target || to_lower(m.name).find(target) != std::string::npos) {
            kbase = m.base; ksize = m.size; kname = m.name; break;
        }
    }
    if (!kbase) return tool_result_t::error("Kernel module not found: " + target);
    if (ksize > 64 * 1024 * 1024) ksize = 64 * 1024 * 1024;
    std::string out_path;
    if (params.contains("output") && params["output"].is_string())
        out_path = params["output"].get<std::string>();
    else
        out_path = get_downloads_folder() + "kdump_" + kname;
    ensure_parent_dir(out_path);
    std::vector<uint8_t> dump(ksize, 0);
    size_t total = 0;
    const uint32_t chunk = 4096;
    for (uint32_t off = 0; off < ksize; off += chunk) {
        uint32_t sz = std::min(chunk, ksize - off);
        size_t r = device->read_kernel_raw(kbase + off, dump.data() + off, sz);
        total += r;
    }
    FILE* fp = fopen(out_path.c_str(), "wb");
    if (!fp) return tool_result_t::error("Cannot create output file: " + out_path);
    fwrite(dump.data(), 1, ksize, fp);
    fclose(fp);
    json r;
    r["module"] = kname;
    r["base"] = faddr(kbase);
    r["size"] = ksize;
    r["bytes_read"] = total;
    r["output_path"] = out_path;
    return tool_result_t::ok("Kernel module " + kname + " dumped to " + out_path, r);
}

// =============================================================================
//  FILE MANIPULATION TOOLS (for AI agent code editing)
// =============================================================================

tool_result_t handle_read_file(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");

    std::string path = params["path"].get<std::string>();
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "rb");
    if (!f) return tool_result_t::error("Cannot open file: " + path);

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz > 2 * 1024 * 1024) { fclose(f); return tool_result_t::error("File too large (>2MB)"); }

    std::string content(sz, '\0');
    fread(&content[0], 1, sz, f);
    fclose(f);

    // Optional line range
    int start_line = params.contains("start_line") && params["start_line"].is_number() ? params["start_line"].get<int>() : 0;
    int end_line   = params.contains("end_line")   && params["end_line"].is_number()   ? params["end_line"].get<int>()   : 0;

    if (start_line > 0 || end_line > 0) {
        std::vector<std::string> lines;
        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) lines.push_back(line);

        if (start_line < 1) start_line = 1;
        if (end_line < 1 || end_line > (int)lines.size()) end_line = (int)lines.size();
        if (start_line > end_line) return tool_result_t::error("start_line > end_line");

        std::string result;
        for (int i = start_line - 1; i < end_line; i++)
            result += lines[i] + "\n";
        json r;
        r["path"] = path;
        r["start_line"] = start_line;
        r["end_line"] = end_line;
        r["total_lines"] = (int)lines.size();
        r["content"] = result;
        return tool_result_t::ok(result, r);
    }

    json r;
    r["path"] = path;
    r["size"] = sz;
    r["content"] = content;
    return tool_result_t::ok(content, r);
}

tool_result_t handle_write_file(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    if (!params.contains("content") || !params["content"].is_string())
        return tool_result_t::error("Missing required parameter: content");

    std::string path    = params["path"].get<std::string>();
    std::string content = params["content"].get<std::string>();

    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "wb");
    if (!f) return tool_result_t::error("Cannot write file: " + path);
    fwrite(content.data(), 1, content.size(), f);
    fclose(f);

    json r;
    r["path"] = path;
    r["bytes_written"] = content.size();
    return tool_result_t::ok("Wrote " + std::to_string(content.size()) + " bytes to " + path, r);
}

tool_result_t handle_edit_file(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    if (!params.contains("old_text") || !params["old_text"].is_string())
        return tool_result_t::error("Missing required parameter: old_text");
    if (!params.contains("new_text") || !params["new_text"].is_string())
        return tool_result_t::error("Missing required parameter: new_text");

    std::string path     = params["path"].get<std::string>();
    std::string old_text = params["old_text"].get<std::string>();
    std::string new_text = params["new_text"].get<std::string>();

    // Read file
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "rb");
    if (!f) return tool_result_t::error("Cannot open file: " + path);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string content(sz, '\0');
    fread(&content[0], 1, sz, f);
    fclose(f);

    // Find and replace
    size_t pos = content.find(old_text);
    if (pos == std::string::npos)
        return tool_result_t::error("old_text not found in file");

    // Check uniqueness
    size_t pos2 = content.find(old_text, pos + 1);
    if (pos2 != std::string::npos)
        return tool_result_t::error("old_text matches multiple locations. Add more context to make it unique.");

    content.replace(pos, old_text.size(), new_text);

    // Write back
    fopen_s(&f, path.c_str(), "wb");
    if (!f) return tool_result_t::error("Cannot write file: " + path);
    fwrite(content.data(), 1, content.size(), f);
    fclose(f);

    json r;
    r["path"] = path;
    r["replaced_at_offset"] = (int)pos;
    return tool_result_t::ok("Edit applied to " + path, r);
}

tool_result_t handle_delete_file(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");

    std::string path = params["path"].get<std::string>();
    if (!DeleteFileA(path.c_str()))
        return tool_result_t::error("Cannot delete file: " + path + " (error " + std::to_string(GetLastError()) + ")");

    json r;
    r["path"] = path;
    return tool_result_t::ok("Deleted " + path, r);
}

tool_result_t handle_create_directory(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");

    std::string path = params["path"].get<std::string>();

    // Recursive directory creation
    int ret = SHCreateDirectoryExA(nullptr, path.c_str(), nullptr);
    if (ret != ERROR_SUCCESS && ret != ERROR_ALREADY_EXISTS)
        return tool_result_t::error("Cannot create directory: " + path + " (error " + std::to_string(ret) + ")");

    json r;
    r["path"] = path;
    r["already_existed"] = (ret == ERROR_ALREADY_EXISTS);
    return tool_result_t::ok("Directory created: " + path, r);
}

tool_result_t handle_list_directory(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");

    std::string dir = params["path"].get<std::string>();
    bool recursive = params.contains("recursive") && params["recursive"].is_boolean() && params["recursive"].get<bool>();
    int max_depth = params.contains("max_depth") && params["max_depth"].is_number() ? params["max_depth"].get<int>() : 1;
    if (recursive && max_depth <= 1) max_depth = 3;

    json entries = json::array();
    WIN32_FIND_DATAA fd;
    std::string search = dir;
    if (!search.empty() && search.back() != '\\' && search.back() != '/') search += "\\";
    search += "*";

    HANDLE h = FindFirstFileA(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return tool_result_t::error("Cannot list directory: " + dir);

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        json e;
        e["name"] = fd.cFileName;
        e["is_dir"] = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            e["size"] = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        entries.push_back(e);
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    json r;
    r["path"] = dir;
    r["entries"] = entries;
    r["count"] = entries.size();
    return tool_result_t::ok("Listed " + std::to_string(entries.size()) + " entries in " + dir, r);
}

tool_result_t handle_search_files(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    if (!params.contains("pattern") || !params["pattern"].is_string())
        return tool_result_t::error("Missing required parameter: pattern");

    std::string dir = params["path"].get<std::string>();
    std::string pattern = params["pattern"].get<std::string>();
    // Convert pattern to lowercase for case-insensitive search
    std::string pattern_lower = pattern;
    for (auto& c : pattern_lower) c = (char)tolower((unsigned char)c);

    int max_results = params.contains("max_results") && params["max_results"].is_number()
        ? params["max_results"].get<int>() : 50;

    json matches = json::array();

    // Recursive file search
    std::function<void(const std::string&, int)> search_dir;
    search_dir = [&](const std::string& path, int depth) {
        if (depth > 8 || (int)matches.size() >= max_results) return;
        WIN32_FIND_DATAA fd;
        std::string sp = path + "\\*";
        HANDLE h = FindFirstFileA(sp.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            std::string full = path + "\\" + fd.cFileName;
            std::string name_lower = fd.cFileName;
            for (auto& c : name_lower) c = (char)tolower((unsigned char)c);

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (name_lower.find(pattern_lower) != std::string::npos) {
                    json e; e["path"] = full; e["is_dir"] = true;
                    matches.push_back(e);
                }
                search_dir(full, depth + 1);
            } else {
                if (name_lower.find(pattern_lower) != std::string::npos) {
                    json e; e["path"] = full; e["is_dir"] = false;
                    e["size"] = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                    matches.push_back(e);
                }
            }
        } while (FindNextFileA(h, &fd) && (int)matches.size() < max_results);
        FindClose(h);
    };
    search_dir(dir, 0);

    json r;
    r["matches"] = matches;
    r["count"] = matches.size();
    return tool_result_t::ok("Found " + std::to_string(matches.size()) + " matches", r);
}

tool_result_t handle_grep_in_files(const json& params) {
    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    if (!params.contains("query") || !params["query"].is_string())
        return tool_result_t::error("Missing required parameter: query");

    std::string dir   = params["path"].get<std::string>();
    std::string query = params["query"].get<std::string>();
    int max_results = params.contains("max_results") && params["max_results"].is_number()
        ? params["max_results"].get<int>() : 100;

    std::string query_lower = query;
    for (auto& c : query_lower) c = (char)tolower((unsigned char)c);

    json matches = json::array();

    std::function<void(const std::string&, int)> search_dir;
    search_dir = [&](const std::string& path, int depth) {
        if (depth > 6 || (int)matches.size() >= max_results) return;
        WIN32_FIND_DATAA fd;
        std::string sp = path + "\\*";
        HANDLE h = FindFirstFileA(sp.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            std::string full = path + "\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                search_dir(full, depth + 1);
            } else {
                // Only search text-like files
                uint64_t fsz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                if (fsz > 1024 * 1024) continue; // skip >1MB files
                std::string ext;
                const char* dot = strrchr(fd.cFileName, '.');
                if (dot) { ext = dot; for (auto& c : ext) c = (char)tolower((unsigned char)c); }
                static const char* text_exts[] = {
                    ".cpp",".c",".h",".hpp",".py",".js",".ts",".json",".xml",".yaml",".yml",
                    ".md",".txt",".log",".cfg",".ini",".toml",".java",".cs",".rs",".go",".rb",
                    ".html",".css",".lua",".sh",".bat",".ps1",".cmake",".asm",".def",".rules",
                };
                bool is_text = false;
                for (auto& te : text_exts) if (ext == te) { is_text = true; break; }
                if (!is_text) continue;

                FILE* ff = nullptr;
                fopen_s(&ff, full.c_str(), "rb");
                if (!ff) continue;
                std::string content((size_t)fsz, '\0');
                fread(&content[0], 1, fsz, ff);
                fclose(ff);

                std::string content_lower = content;
                for (auto& c : content_lower) c = (char)tolower((unsigned char)c);

                size_t pos = 0;
                int line_num = 1;
                size_t line_start = 0;
                while (pos < content_lower.size() && (int)matches.size() < max_results) {
                    // Track line numbers
                    while (line_start < pos) {
                        if (content[line_start] == '\n') line_num++;
                        line_start++;
                    }
                    size_t found = content_lower.find(query_lower, pos);
                    if (found == std::string::npos) break;
                    // Count lines up to found
                    while (line_start < found) {
                        if (content[line_start] == '\n') line_num++;
                        line_start++;
                    }
                    // Extract the line
                    size_t ls = content.rfind('\n', found);
                    size_t le = content.find('\n', found);
                    if (ls == std::string::npos) ls = 0; else ls++;
                    if (le == std::string::npos) le = content.size();
                    std::string line_text = content.substr(ls, std::min(le - ls, (size_t)200));

                    json m;
                    m["file"] = full;
                    m["line"] = line_num;
                    m["text"] = line_text;
                    matches.push_back(m);
                    pos = found + query.size();
                }
            }
        } while (FindNextFileA(h, &fd) && (int)matches.size() < max_results);
        FindClose(h);
    };
    search_dir(dir, 0);

    json r;
    r["matches"] = matches;
    r["count"] = matches.size();
    return tool_result_t::ok("Found " + std::to_string(matches.size()) + " matches for '" + query + "'", r);
}

} // anonymous namespace

// =============================================================================
//  TOOL REGISTRATION
// =============================================================================
void mcp_standalone::register_standalone_tools(mcp_standalone::server_t& srv)
{
    // ---- Driver Core ----
    srv.register_tool({"driver_status",
        "Check kernel driver connection status, attached process, DTB values, and heartbeat.",
        {}, true, handle_driver_status});

    srv.register_tool({"driver_connect",
        "Connect to the kernel driver. Automatically solves kernel DTB for kernel memory access.",
        {}, false, handle_driver_connect});

    srv.register_tool({"driver_attach",
        "Attach to a target process by name or PID. Solves the process DTB for memory access.",
        {{"name", "string", "Process name (e.g. 'notepad.exe')", false},
         {"pid", "number", "Process ID", false}},
        false, handle_driver_attach});

    srv.register_tool({"driver_detach",
        "Detach from the current process. Driver connection is preserved.",
        {}, false, handle_driver_detach});

    srv.register_tool({"list_processes",
        "List all running processes with PIDs and names.",
        {}, true, handle_list_processes});

    // ---- Driver Memory ----
    srv.register_tool({"read_memory",
        "Read memory from the attached process. Returns hex dump, raw hex, and ASCII.",
        {{"address", "string", "Memory address to read (hex)", true},
         {"size", "number", "Number of bytes to read (default 256, max 1MB)", false}},
        true, handle_read_memory});

    srv.register_tool({"write_memory",
        "Write bytes to the attached process memory. Supports hex strings, byte arrays, and packed hex.",
        {{"address", "string", "Memory address to write to (hex)", true},
         {"bytes", "string", "Byte data: hex 'AA BB CC', packed 'AABBCC', or array '[0x41, 0x42]'", false},
         {"hex", "string", "Alternative: raw hex string to write", false}},
        false, handle_write_memory});

    srv.register_tool({"read_string",
        "Read a null-terminated string from process memory. Auto-detects ASCII vs Wide.",
        {{"address", "string", "Address to read string from", true},
         {"max_length", "number", "Max string length (default 512)", false},
         {"encoding", "string", "Force 'ascii', 'wide', or 'auto' (default auto)", false}},
        true, handle_read_string});

    srv.register_tool({"read_pointer_chain",
        "Follow a chain of pointer dereferences with offsets. Like [[[base]+off0]+off1]+off2.",
        {{"base", "string", "Starting address", true},
         {"offsets", "array", "Array of offsets to apply at each dereference level", true}},
        true, handle_read_pointer_chain});

    srv.register_tool({"driver_allocate_memory",
        "Allocate memory in the attached process (RWX).",
        {{"size", "number", "Size in bytes to allocate (default 4096)", false}},
        false, handle_allocate_memory});

    srv.register_tool({"driver_free_memory",
        "Free previously allocated memory in the attached process.",
        {{"address", "string", "Address to free", true}},
        false, handle_free_memory});

    srv.register_tool({"driver_query_memory",
        "Query memory region information at an address (base, size, state, protection, type).",
        {{"address", "string", "Address to query", true}},
        true, handle_query_memory});

    srv.register_tool({"driver_protect_memory",
        "Change memory protection on a region in the attached process.",
        {{"address", "string", "Address of region", true},
         {"size", "number", "Size of region (default 4096)", false},
         {"protection", "string", "New protection: rwx, rw, rx, r, x, noaccess", false}},
        false, handle_protect_memory});

    srv.register_tool({"driver_enumerate_memory_regions",
        "Enumerate all virtual memory regions in the attached process.",
        {{"start", "string", "Start address (optional)", false},
         {"end", "string", "End address (optional)", false}},
        true, handle_enumerate_memory_regions});

    // ---- Driver Modules ----
    srv.register_tool({"driver_enumerate_modules",
        "Enumerate loaded modules by walking the PEB InLoadOrderModuleList.",
        {}, true, handle_enumerate_modules});

    srv.register_tool({"driver_enumerate_kernel_modules",
        "Enumerate loaded kernel modules via NtQuerySystemInformation.",
        {}, true, handle_enumerate_kernel_modules});

    srv.register_tool({"driver_resolve_export",
        "Resolve an exported function address from a module's export table.",
        {{"export_name", "string", "Name of the export to resolve", true},
         {"module_base", "string", "Module base address (hex). Uses main image if omitted.", false},
         {"module_name", "string", "Module name to find base for (e.g. 'ntdll.dll')", false}},
        true, handle_resolve_export});

    // ---- Driver Threads ----
    srv.register_tool({"driver_enumerate_threads",
        "Enumerate all threads in the attached process with TID, state, and RIP.",
        {}, true, handle_enumerate_threads});

    srv.register_tool({"driver_get_thread_context",
        "Get full register state of a thread (RAX-R15, RIP, RFLAGS, DR0-DR7).",
        {{"tid", "number", "Thread ID (auto-selects first thread if omitted)", false}},
        true, handle_get_thread_context});

    srv.register_tool({"driver_set_thread_context",
        "Set specific registers of a thread. Only specified registers are modified.",
        {{"tid", "number", "Thread ID", true},
         {"rax", "string", "RAX value (hex)", false}, {"rbx", "string", "RBX value (hex)", false},
         {"rcx", "string", "RCX value (hex)", false}, {"rdx", "string", "RDX value (hex)", false},
         {"rsi", "string", "RSI value (hex)", false}, {"rdi", "string", "RDI value (hex)", false},
         {"rbp", "string", "RBP value (hex)", false}, {"rsp", "string", "RSP value (hex)", false},
         {"r8", "string", "R8 value (hex)", false}, {"r9", "string", "R9 value (hex)", false},
         {"r10", "string", "R10 value (hex)", false}, {"r11", "string", "R11 value (hex)", false},
         {"r12", "string", "R12 value (hex)", false}, {"r13", "string", "R13 value (hex)", false},
         {"r14", "string", "R14 value (hex)", false}, {"r15", "string", "R15 value (hex)", false},
         {"rip", "string", "RIP value (hex)", false}, {"rflags", "string", "RFLAGS value (hex)", false}},
        false, handle_set_thread_context});

    srv.register_tool({"driver_suspend_thread",
        "Suspend a thread in the attached process.",
        {{"tid", "number", "Thread ID to suspend", true}},
        false, handle_suspend_thread});

    srv.register_tool({"driver_resume_thread",
        "Resume a suspended thread.",
        {{"tid", "number", "Thread ID to resume", true}},
        false, handle_resume_thread});

    // ---- Driver Kernel ----
    srv.register_tool({"driver_read_kernel_memory",
        "Read kernel-mode memory via physical memory translation.",
        {{"address", "string", "Kernel address to read (must be >= 0xFFFF800000000000)", true},
         {"size", "number", "Bytes to read (default 256)", false}},
        true, handle_read_kernel_memory});

    srv.register_tool({"driver_write_kernel_memory",
        "Write to kernel-mode memory. Extremely dangerous - use with caution.",
        {{"address", "string", "Kernel address to write to", true},
         {"bytes", "string", "Byte data as hex string", false},
         {"hex", "string", "Alternative hex data", false}},
        false, handle_write_kernel_memory});

    srv.register_tool({"driver_read_peb",
        "Read the Process Environment Block (PEB) of the attached process.",
        {}, true, handle_read_peb});

    srv.register_tool({"driver_spoof_debug_flags",
        "Clear debug-related flags in PEB (BeingDebugged, NtGlobalFlag, DebugPort).",
        {}, false, handle_spoof_debug_flags});

    // ---- Driver HW Breakpoints ----
    srv.register_tool({"driver_set_hw_breakpoint",
        "Set a hardware breakpoint (DR0-DR3) on a thread.",
        {{"tid", "number", "Thread ID", true},
         {"address", "string", "Breakpoint address", true},
         {"index", "number", "DR index 0-3 (default 0)", false},
         {"type", "number", "0=execute, 1=write, 3=read/write (default 0)", false},
         {"size", "number", "0=1byte, 1=2byte, 2=4byte, 3=8byte (default 0)", false}},
        false, handle_set_hw_breakpoint});

    srv.register_tool({"driver_clear_hw_breakpoint",
        "Clear a hardware breakpoint (DR0-DR3) on a thread.",
        {{"tid", "number", "Thread ID", true},
         {"index", "number", "DR index 0-3 to clear (default 0)", false}},
        false, handle_clear_hw_breakpoint});

    // ---- Driver Misc ----
    srv.register_tool({"driver_call_function",
        "Call a function in the attached process via thread hijacking. Supports up to 4 arguments.",
        {{"address", "string", "Function address to call", true},
         {"arg1", "string", "First argument (hex)", false},
         {"arg2", "string", "Second argument (hex)", false},
         {"arg3", "string", "Third argument (hex)", false},
         {"arg4", "string", "Fourth argument (hex)", false}},
        false, handle_call_function});

    srv.register_tool({"driver_virtual_to_physical",
        "Translate a virtual address to its physical address.",
        {{"address", "string", "Virtual address to translate", true}},
        true, handle_virtual_to_physical});

    srv.register_tool({"driver_scan_pattern",
        "Scan process memory for a byte pattern with wildcards (e.g. '48 8B 05 ?? ?? ?? ??').",
        {{"pattern", "string", "Byte pattern with ?? wildcards", true},
         {"start", "string", "Start address (default: image base)", false},
         {"end", "string", "End address", false},
         {"size", "number", "Scan size from start (default 0x100000)", false},
         {"max_results", "number", "Maximum matches to return (default 32)", false}},
        true, handle_scan_pattern});

    // ---- Driver WFP/Sockets ----
    srv.register_tool({"driver_enumerate_wfp_callouts",
        "Enumerate WFP (Windows Filtering Platform) callouts registered in the kernel.",
        {{"module", "string", "Filter by owning module name", false}},
        true, handle_enumerate_wfp_callouts});

    srv.register_tool({"driver_get_socket_handles",
        "Enumerate socket handles in a process (or all processes).",
        {{"pid", "number", "Filter by process ID (0 = all)", false}},
        true, handle_get_socket_handles});

    srv.register_tool({"driver_dump_tcpip_connections",
        "Dump TCPIP connections from kernel structures with byte counters and TCB addresses.",
        {{"pid", "number", "Filter by PID", false},
         {"protocol", "string", "'tcp' or 'udp'", false}},
        true, handle_dump_tcpip});

    // ---- Network Capture & Analysis ----
    srv.register_tool({"network_enumerate_connections",
        "Enumerate active network connections (TCP/UDP) across or per-process.",
        {{"pid", "number", "Filter by process ID (0=all)", false},
         {"protocol", "string", "'tcp' or 'udp'", false}},
        true, handle_network_enumerate_connections});

    srv.register_tool({"network_start_capture",
        "Start capturing network packets through the kernel driver.",
        {{"max_packets", "number", "Max packets to buffer (default 10000)", false},
         {"promiscuous", "boolean", "Enable promiscuous mode", false}},
        false, handle_network_start_capture});

    srv.register_tool({"network_stop_capture",
        "Stop the active network packet capture.",
        {}, false, handle_network_stop_capture});

    srv.register_tool({"network_get_packets",
        "Retrieve captured packets with pagination.",
        {{"offset", "number", "Starting packet index (default 0)", false},
         {"count", "number", "Number of packets (default 50, max 200)", false}},
        true, handle_network_get_packets});

    srv.register_tool({"network_analyze_packet",
        "Deep-analyze a single captured packet: headers, HTTP, TLS parsing, hex dump.",
        {{"index", "number", "Packet index to analyze", true}},
        true, handle_network_analyze_packet});

    srv.register_tool({"network_dns_log",
        "Retrieve captured DNS queries and responses.",
        {{"max_entries", "number", "Max entries to return (default 100)", false}},
        true, handle_network_dns_log});

    // ---- Network Filters ----
    srv.register_tool({"network_add_filter",
        "Add a kernel-level network filter rule.",
        {{"rule", "string", "Filter rule string (e.g. 'ip:1.2.3.4', 'port:443')", true},
         {"block", "boolean", "True to block, false to allow (default true)", false}},
        false, handle_network_add_filter});

    srv.register_tool({"network_remove_filter",
        "Remove a network filter rule.",
        {{"rule", "string", "Filter rule to remove", true}},
        false, handle_network_remove_filter});

    srv.register_tool({"network_clear_filters",
        "Remove all active network filter rules.",
        {}, false, handle_network_clear_filters});

    srv.register_tool({"network_stats",
        "Get network capture statistics (packets captured/dropped, bytes, active filters).",
        {}, true, handle_network_stats});

    srv.register_tool({"network_capture_status",
        "Check whether network capture is active and get summary stats.",
        {}, true, handle_network_capture_status});

    srv.register_tool({"network_block_ip",
        "Block all traffic to/from a specific IP address.",
        {{"ip", "string", "IP address to block", true}},
        false, handle_network_block_ip});

    srv.register_tool({"network_block_port",
        "Block all traffic on a specific port.",
        {{"port", "number", "Port number to block", true}},
        false, handle_network_block_port});

    srv.register_tool({"network_block_process",
        "Block all network traffic from a specific process.",
        {{"pid", "number", "Process ID to block", true}},
        false, handle_network_block_process});

    // ---- Network Analysis ----
    srv.register_tool({"network_deep_inspect",
        "Run deep packet inspection to identify application-layer protocols.",
        {{"enable", "boolean", "Enable DPI (default true)", false}},
        true, handle_network_deep_inspect});

    srv.register_tool({"network_follow_tcp_stream",
        "Reassemble a TCP stream between two endpoints.",
        {{"src", "string", "Source (ip:port)", true},
         {"dst", "string", "Destination (ip:port)", true},
         {"max_bytes", "number", "Max bytes to reassemble (default 64KB)", false}},
        true, handle_network_follow_tcp_stream});

    srv.register_tool({"network_parse_http",
        "Parse HTTP request/response from a captured packet.",
        {{"index", "number", "Packet index", true}},
        true, handle_network_parse_http});

    srv.register_tool({"network_parse_tls",
        "Parse TLS record from a captured packet (handshake, SNI, ciphers).",
        {{"index", "number", "Packet index", true}},
        true, handle_network_parse_tls});

    srv.register_tool({"network_enumerate_interfaces",
        "List network interfaces with IPs, MACs, MTU, and speed.",
        {}, true, handle_network_enumerate_interfaces});

    // ---- Network Injection/Modification ----
    srv.register_tool({"network_inject_packet",
        "Inject a raw packet onto the network.",
        {{"data", "string", "Hex-encoded packet bytes", true},
         {"interface_index", "number", "Interface index (default auto)", false}},
        false, handle_network_inject_packet});

    srv.register_tool({"network_modify_packet_rule",
        "Add/remove packet modification rules (match & replace bytes in transit).",
        {{"action", "number", "0=add, 1=remove", false},
         {"match_pattern", "string", "Hex bytes to match", false},
         {"replace_pattern", "string", "Hex bytes to replace with", false},
         {"offset", "number", "Match offset in packet", false},
         {"direction", "number", "0=inbound, 1=outbound, 2=both", false}},
        false, handle_network_modify_packet_rule});

    srv.register_tool({"network_list_mod_rules",
        "List active packet modification rules.",
        {}, true, handle_network_list_mod_rules});

    srv.register_tool({"network_redirect_traffic",
        "Add/remove traffic redirection rules.",
        {{"action", "number", "0=add, 1=remove", false},
         {"src_ip", "string", "Match source IP", false}, {"src_port", "number", "Match source port", false},
         {"dst_ip", "string", "Match destination IP", false}, {"dst_port", "number", "Match dest port", false},
         {"redirect_ip", "string", "Redirect to this IP", false},
         {"redirect_port", "number", "Redirect to this port", false}},
        false, handle_network_redirect_traffic});

    srv.register_tool({"network_list_redirect_rules",
        "List active traffic redirect rules.",
        {}, true, handle_network_list_redirect_rules});

    // ---- Network Intercept ----
    srv.register_tool({"network_intercept",
        "Start/stop intercepting packets (hold, modify, or drop in realtime).",
        {{"action", "number", "0=start, 1=stop", true},
         {"direction", "number", "0=inbound, 1=outbound, 2=both (default)", false},
         {"ip", "string", "Filter by IP", false}, {"port", "number", "Filter by port", false},
         {"protocol_num", "number", "Filter by protocol (6=TCP, 17=UDP)", false}},
        false, handle_network_intercept});

    srv.register_tool({"network_get_held_packets",
        "Get currently intercepted (held) packets waiting for release.",
        {{"max", "number", "Max held packets to return (default 50)", false}},
        true, handle_network_get_held_packets});

    srv.register_tool({"network_release_packet",
        "Release or drop a held intercepted packet.",
        {{"packet_id", "number", "ID of held packet", true},
         {"drop", "boolean", "True to drop, false to release (default false)", false},
         {"modified", "boolean", "True if providing modified data", false},
         {"data", "string", "Modified packet data (hex) if modified=true", false}},
        false, handle_network_release_packet});

    srv.register_tool({"network_kill_connection",
        "Forcibly terminate a TCP connection.",
        {{"src", "string", "Source endpoint (ip:port)", true},
         {"dst", "string", "Destination endpoint (ip:port)", true}},
        false, handle_network_kill_connection});

    // ---- Network DNS/Bandwidth/Fingerprint ----
    srv.register_tool({"network_spoof_dns",
        "Add/remove DNS spoofing rules to redirect domain lookups.",
        {{"action", "number", "0=add, 1=remove", false},
         {"domain", "string", "Domain to spoof (e.g. 'example.com')", true},
         {"redirect_ip", "string", "IP to redirect to", false}},
        false, handle_network_spoof_dns});

    srv.register_tool({"network_list_dns_spoof_rules",
        "List active DNS spoofing rules.",
        {}, true, handle_network_list_dns_spoof_rules});

    srv.register_tool({"network_bandwidth_monitor",
        "Start bandwidth monitoring and get current throughput stats.",
        {{"action", "number", "0=start, 1=stop, 2=get stats", false},
         {"interval_ms", "number", "Sampling interval (default 1000)", false}},
        true, handle_network_bandwidth_monitor});

    srv.register_tool({"network_bandwidth_per_process",
        "Get per-process bandwidth usage.",
        {}, true, handle_network_bandwidth_per_process});

    srv.register_tool({"network_os_fingerprint",
        "Perform passive or active OS fingerprinting on network hosts.",
        {{"passive", "boolean", "Passive mode (default true)", false},
         {"target_ip", "string", "Target IP for active fingerprinting", false}},
        true, handle_network_os_fingerprint});

    srv.register_tool({"network_export_pcap",
        "Export captured packets to a PCAP file.",
        {{"path", "string", "Output file path (default: Downloads/capture_*.pcap)", false}},
        false, handle_network_export_pcap});

    srv.register_tool({"driver_sniff_network_buffers",
        "Sniff raw network buffers in process memory (pre-encryption).",
        {{"buffer_address", "string", "Start address to sniff (optional)", false},
         {"max_size", "number", "Max bytes to scan (default 4096)", false}},
        true, handle_network_sniff_buffers});

    // ---- TLS / Key Extraction ----
    srv.register_tool({"tls_extract_keys",
        "Extract TLS session keys from a process for traffic decryption.",
        {{"pid", "number", "Process ID (default: attached process)", false}},
        true, handle_tls_extract_keys});

    srv.register_tool({"tls_start_keylog",
        "Start continuous TLS key logging to an SSLKEYLOGFILE.",
        {{"path", "string", "Output path (default: Downloads/sslkeys.log)", false},
         {"pid", "number", "Process ID (default: attached)", false}},
        false, handle_tls_start_keylog});

    srv.register_tool({"tls_stop_keylog",
        "Stop TLS key logging.",
        {}, false, handle_tls_stop_keylog});

    srv.register_tool({"tls_get_extracted_keys",
        "Get previously extracted TLS keys from cache.",
        {}, true, handle_tls_get_extracted_keys});

    srv.register_tool({"tls_ensure_keylogfile",
        "Set the SSLKEYLOGFILE environment variable for compatible apps.",
        {}, false, handle_tls_ensure_keylogfile});

    srv.register_tool({"network_decrypt_capture",
        "Decrypt a PCAP file using TLS keys and tshark.",
        {{"pcap_path", "string", "Path to PCAP file", true},
         {"keylog_path", "string", "Path to SSLKEYLOGFILE (default: Downloads/sslkeys.log)", false},
         {"output_path", "string", "Output path for decrypted capture", false}},
        false, handle_network_decrypt_capture});

    // ---- Certificate Management ----
    srv.register_tool({"cert_inject",
        "Inject a certificate into the Windows certificate store.",
        {{"cert_path", "string", "Path to certificate file", true},
         {"store_name", "string", "Store name (default ROOT)", false}},
        false, handle_cert_inject});

    srv.register_tool({"cert_remove",
        "Remove a certificate from the Windows certificate store.",
        {{"thumbprint", "string", "Certificate thumbprint to remove", true},
         {"store_name", "string", "Store name (default ROOT)", false}},
        false, handle_cert_remove});

    srv.register_tool({"cert_generate_ca",
        "Generate a self-signed CA certificate for MITM proxying.",
        {{"common_name", "string", "CA common name (default 'AiDA Proxy CA')", false},
         {"validity_days", "number", "Validity in days (default 365)", false}},
        false, handle_cert_generate_ca});

    srv.register_tool({"cert_list",
        "List certificates in a Windows certificate store.",
        {{"store_name", "string", "Store name (default ROOT)", false}},
        true, handle_cert_list});

    // ---- Certificate Pinning Bypass ----
    srv.register_tool({"pin_bypass",
        "Bypass certificate pinning in the attached process.",
        {{"pid", "number", "Process ID (default: attached)", false}},
        false, handle_pin_bypass});

    srv.register_tool({"pin_bypass_revert",
        "Revert certificate pinning bypass patches.",
        {{"pid", "number", "Process ID (default: attached)", false}},
        false, handle_pin_bypass_revert});

    srv.register_tool({"pin_bypass_status",
        "Check whether certificate pinning bypass is active.",
        {{"pid", "number", "Process ID (default: attached)", false}},
        true, handle_pin_bypass_status});

    // ---- QUIC / DTLS ----
    srv.register_tool({"quic_detect_connections",
        "Detect active QUIC connections.",
        {{"pid", "number", "Process ID filter", false}},
        true, handle_quic_detect});

    srv.register_tool({"quic_decrypt_initial",
        "Decrypt a QUIC initial packet using connection ID derivation.",
        {{"packet_index", "number", "Captured packet index", true}},
        true, handle_quic_decrypt_initial});

    srv.register_tool({"quic_extract_keys",
        "Extract QUIC traffic keys from a process.",
        {{"pid", "number", "Process ID (default: attached)", false}},
        true, handle_quic_extract_keys});

    srv.register_tool({"dtls_detect_sessions",
        "Detect DTLS sessions.",
        {{"pid", "number", "Process ID filter", false}},
        true, handle_dtls_detect});

    srv.register_tool({"dtls_extract_keys",
        "Extract DTLS session keys from a process.",
        {{"pid", "number", "Process ID (default: attached)", false}},
        true, handle_dtls_extract_keys});

    // ---- AutoResponder ----
    srv.register_tool({"autoresponder_add_rule",
        "Add an auto-response rule matching URL patterns.",
        {{"match", "string", "URL/path pattern to match", true},
         {"response", "string", "Response action (file path or inline content)", true},
         {"is_regex", "boolean", "Treat match as regex (default false)", false}},
        false, handle_autoresponder_add_rule});

    srv.register_tool({"autoresponder_remove_rule",
        "Remove an auto-response rule.",
        {{"rule_id", "number", "Rule ID to remove", true}},
        false, handle_autoresponder_remove_rule});

    srv.register_tool({"autoresponder_list_rules",
        "List all auto-response rules.",
        {}, true, handle_autoresponder_list_rules});

    srv.register_tool({"autoresponder_start",
        "Start the AutoResponder proxy.",
        {}, false, handle_autoresponder_start});

    srv.register_tool({"autoresponder_stop",
        "Stop the AutoResponder proxy.",
        {}, false, handle_autoresponder_stop});

    srv.register_tool({"autoresponder_import_rules",
        "Import AutoResponder rules from a file.",
        {{"path", "string", "Path to rules file", true}},
        false, handle_autoresponder_import});

    srv.register_tool({"autoresponder_export_rules",
        "Export AutoResponder rules to a file.",
        {{"path", "string", "Output path for rules", true}},
        false, handle_autoresponder_export});

    // ---- Emulation ----
    srv.register_tool({"disassemble_zydis",
        "Disassemble x86-64 code using Zydis. Accepts hex bytes or reads from memory.",
        {{"hex", "string", "Hex-encoded machine code to disassemble", false},
         {"address", "string", "Memory address to disassemble from (or base VA for hex mode)", false},
         {"count", "number", "Max instructions to decode (default 32)", false},
         {"max_instructions", "number", "Max instructions for hex mode (default 64)", false}},
        true, handle_disassemble_zydis});

    srv.register_tool({"driver_snapshot_and_emulate",
        "Take a process memory snapshot and emulate code via Unicorn engine.",
        {{"address", "string", "Start address to emulate from", true},
         {"max_steps", "number", "Max instructions (default 1000)", false},
         {"stop_address", "string", "Stop emulation at this address", false},
         {"tid", "number", "Thread ID for initial register context", false},
         {"trace_memory", "boolean", "Log memory writes (default true)", false},
         {"trace_registers", "boolean", "Log register changes (default false)", false}},
        true, handle_driver_snapshot_and_emulate});

    srv.register_tool({"trace_execution_unicorn",
        "Trace execution path via Unicorn emulation with detailed mnemonic/address trace.",
        {{"address", "string", "Start address", true},
         {"max_steps", "number", "Max instructions (default 5000)", false},
         {"trace_registers", "boolean", "Include register trace (default true)", false},
         {"stop_addresses", "array", "Array of stop addresses", false}},
        true, handle_trace_execution_unicorn});

    srv.register_tool({"analyze_vm_handler",
        "Analyze a virtualized (VM) handler using emulation traces.",
        {{"address", "string", "Handler entry address", true},
         {"dispatcher", "string", "Dispatcher (switch-table) address", false},
         {"max_steps", "number", "Max emulation steps (default 2000)", false}},
        true, handle_analyze_vm_handler});

    srv.register_tool({"emulate_multi_trace",
        "Emulate multiple addresses and compare results.",
        {{"addresses", "array", "Array of addresses to emulate", true},
         {"max_steps", "number", "Max instructions per trace (default 1000)", false}},
        true, handle_emulate_multi_trace});

    srv.register_tool({"emulate_function",
        "Emulate a function call with arguments (x64 calling convention).",
        {{"address", "string", "Function address", true},
         {"max_steps", "number", "Max instructions (default 10000)", false},
         {"rcx", "string", "First arg (RCX)", false}, {"rdx", "string", "Second arg (RDX)", false},
         {"r8", "string", "Third arg (R8)", false}, {"r9", "string", "Fourth arg (R9)", false}},
        true, handle_emulate_function});

    // ---- Standalone-Specific ----
    srv.register_tool({"disassemble_file",
        "Load a PE file from disk and disassemble it using Zydis.",
        {{"path", "string", "Path to PE file", true},
         {"address", "string", "Only show instructions from this VA onward", false},
         {"max_instructions", "number", "Max instructions to show (default 200)", false}},
        true, handle_disassemble_file});

    srv.register_tool({"sandbox_execute",
        "Execute a program in a sandboxed AppContainer with captured I/O.",
        {{"path", "string", "Executable path", true},
         {"arguments", "string", "Command-line arguments", false},
         {"timeout_ms", "number", "Timeout in ms (default 30000)", false},
         {"max_memory", "number", "Max memory in bytes", false},
         {"capture_stdout", "boolean", "Capture stdout (default true)", false},
         {"capture_stderr", "boolean", "Capture stderr (default true)", false},
         {"sandbox", "boolean", "Enable AppContainer sandbox (default true)", false}},
        false, handle_sandbox_execute});

    srv.register_tool({"convert_number",
        "Convert a number between decimal, hex, binary, octal, float, and ASCII.",
        {{"value", "string", "Number to convert (e.g. '0xFF', '255', '0b11111111')", true}},
        true, handle_convert_number});

    // ---- Module Dump ----
    srv.register_tool({"driver_dump_module",
        "Dump a usermode module's PE image from process memory to disk.",
        {{"base", "string", "Module base address (default: main image)", false},
         {"output", "string", "Output file path (default: Downloads/dump_*.bin)", false}},
        false, handle_driver_dump_module});

    srv.register_tool({"driver_dump_kernel_module",
        "Dump a kernel module from kernel memory to disk.",
        {{"name", "string", "Kernel module name (e.g. 'ntoskrnl.exe')", true},
         {"output", "string", "Output file path", false}},
        false, handle_driver_dump_kernel_module});

    // ---- File Manipulation Tools (IDE) ----
    srv.register_tool({"read_file",
        "Read a file from disk. Optionally specify line range.",
        {{"path", "string", "Absolute file path to read", true},
         {"start_line", "number", "Start line (1-based)", false},
         {"end_line", "number", "End line (inclusive)", false}},
        true, handle_read_file});

    srv.register_tool({"write_file",
        "Write content to a file (creates or overwrites).",
        {{"path", "string", "Absolute file path to write", true},
         {"content", "string", "Full file content to write", true}},
        false, handle_write_file});

    srv.register_tool({"edit_file",
        "Edit a file by replacing exact text. old_text must match exactly once in the file.",
        {{"path", "string", "Absolute file path to edit", true},
         {"old_text", "string", "Exact text to find and replace (must be unique)", true},
         {"new_text", "string", "Replacement text", true}},
        false, handle_edit_file});

    srv.register_tool({"delete_file",
        "Delete a file from disk.",
        {{"path", "string", "Absolute file path to delete", true}},
        false, handle_delete_file});

    srv.register_tool({"create_directory",
        "Create a directory (recursive, creates parent dirs as needed).",
        {{"path", "string", "Absolute directory path to create", true}},
        false, handle_create_directory});

    srv.register_tool({"list_directory",
        "List files and subdirectories in a directory.",
        {{"path", "string", "Absolute directory path to list", true},
         {"recursive", "boolean", "List recursively", false},
         {"max_depth", "number", "Max recursion depth (default 1)", false}},
        true, handle_list_directory});

    srv.register_tool({"search_files",
        "Search for files by name pattern in a directory tree.",
        {{"path", "string", "Root directory to search", true},
         {"pattern", "string", "File name pattern to search for (case-insensitive substring)", true},
         {"max_results", "number", "Max results (default 50)", false}},
        true, handle_search_files});

    srv.register_tool({"grep_in_files",
        "Search for text content across files in a directory (case-insensitive).",
        {{"path", "string", "Root directory to search", true},
         {"query", "string", "Text to search for in file contents", true},
         {"max_results", "number", "Max results (default 100)", false}},
        true, handle_grep_in_files});
}
