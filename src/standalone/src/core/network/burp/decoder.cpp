#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "decoder.hpp"

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <zlib.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <map>
#include <sstream>

namespace aida {
namespace burp {
namespace decoder {

using json = nlohmann::json;

namespace {

const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode_impl(const uint8_t* data, size_t len, bool url_safe)
{
    static const char url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char* tbl = url_safe ? url_table : b64_table;
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3)
    {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(tbl[(n >> 18) & 0x3F]);
        out.push_back(tbl[(n >> 12) & 0x3F]);
        if (i + 1 < len) out.push_back(tbl[(n >> 6) & 0x3F]); else out.push_back('=');
        if (i + 2 < len) out.push_back(tbl[n & 0x3F]); else out.push_back('=');
    }
    return out;
}

int b64_char_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

std::vector<uint8_t> base64_decode_impl(const std::string& s)
{
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t accum = 0;
    int bits = 0;
    for (char c : s)
    {
        if (c == '=' || c == '\0') continue;
        int v = b64_char_val(c);
        if (v < 0) continue;
        accum = (accum << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
        }
    }
    return out;
}

std::string to_hex_string(const uint8_t* data, size_t len, bool upper)
{
    static const char lo[] = "0123456789abcdef";
    static const char up[] = "0123456789ABCDEF";
    const char* h = upper ? up : lo;
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
        out.push_back(h[(data[i] >> 4) & 0xF]);
        out.push_back(h[data[i] & 0xF]);
    }
    return out;
}

bool is_printable_ascii(const std::vector<uint8_t>& data)
{
    for (uint8_t b : data)
    {
        if (b < 0x20 && b != '\n' && b != '\r' && b != '\t') return false;
        if (b > 0x7E) return false;
    }
    return true;
}

std::string bytes_to_string(const std::vector<uint8_t>& data)
{
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::vector<uint8_t> string_to_bytes(const std::string& s)
{
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::string url_encode_impl(const std::string& s)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s)
    {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
            out.push_back(static_cast<char>(c));
        else
        {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

std::string url_decode_impl(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '%' && i + 2 < s.size())
        {
            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            int hi = hex_val(s[i + 1]);
            int lo = hex_val(s[i + 2]);
            if (hi >= 0 && lo >= 0)
            {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
            }
            else
                out.push_back(s[i]);
        }
        else if (s[i] == '+')
            out.push_back(' ');
        else
            out.push_back(s[i]);
    }
    return out;
}

bool has_url_encoding(const std::string& s)
{
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '%' && i + 2 < s.size())
        {
            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            if (hex_val(s[i + 1]) >= 0 && hex_val(s[i + 2]) >= 0)
                return true;
        }
    }
    return false;
}

std::string html_encode_impl(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 6);
    for (char c : s)
    {
        switch (c)
        {
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '&': out += "&amp;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out.push_back(c); break;
        }
    }
    return out;
}

std::string html_entity_encode_impl(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 6);
    for (unsigned char c : s)
    {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ')
            out.push_back(static_cast<char>(c));
        else
        {
            out += "&#";
            out += std::to_string(static_cast<unsigned int>(c));
            out += ";";
        }
    }
    return out;
}

std::string html_decode_impl(const std::string& s)
{
    static const std::map<std::string, std::string> named = {
        {"lt", "<"}, {"gt", ">"}, {"amp", "&"}, {"quot", "\""},
        {"apos", "'"}, {"nbsp", "\xC2\xA0"}, {"copy", "\xC2\xA9"},
        {"reg", "\xC2\xAE"}, {"trade", "\xE2\x84\xA2"}, {"euro", "\xE2\x82\xAC"},
        {"pound", "\xC2\xA3"}, {"yen", "\xC2\xA5"}, {"cent", "\xC2\xA2"},
        {"mdash", "\xE2\x80\x94"}, {"ndash", "\xE2\x80\x93"},
        {"ldquo", "\xE2\x80\x9C"}, {"rdquo", "\xE2\x80\x9D"},
        {"lsquo", "\xE2\x80\x98"}, {"rsquo", "\xE2\x80\x99"},
        {"hellip", "\xE2\x80\xA6"}, {"bull", "\xE2\x80\xA2"},
        {"deg", "\xC2\xB0"}, {"plusmn", "\xC2\xB1"}, {"times", "\xC3\x97"},
        {"divide", "\xC3\xB7"}, {"frac12", "\xC2\xBD"}, {"frac14", "\xC2\xBC"},
        {"frac34", "\xC2\xBE"}, {"sup2", "\xC2\xB2"}, {"sup3", "\xC2\xB3"},
        {"micro", "\xC2\xB5"}, {"para", "\xC2\xB6"}, {"middot", "\xC2\xB7"},
        {"laquo", "\xC2\xAB"}, {"raquo", "\xC2\xBB"}, {"iexcl", "\xC2\xA1"},
        {"iquest", "\xC2\xBF"},
    };

    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] != '&') { out.push_back(s[i]); continue; }
        size_t semi = s.find(';', i + 1);
        if (semi == std::string::npos || semi - i > 12) { out.push_back('&'); continue; }
        std::string ent = s.substr(i + 1, semi - i - 1);
        if (ent.empty()) { out.push_back('&'); continue; }
        if (ent[0] == '#')
        {
            uint32_t code = 0;
            if (ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X'))
                code = static_cast<uint32_t>(std::stoul(ent.substr(2), nullptr, 16));
            else
                code = static_cast<uint32_t>(std::stoul(ent.substr(1)));
            if (code < 0x80)
                out.push_back(static_cast<char>(code));
            else if (code < 0x800)
            {
                out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
            else if (code < 0x10000)
            {
                out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
            else
            {
                out.push_back(static_cast<char>(0xF0 | (code >> 18)));
                out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
        }
        else
        {
            auto it = named.find(ent);
            if (it != named.end())
                out += it->second;
            else
            {
                out.push_back('&');
                out += ent;
                out.push_back(';');
            }
        }
        i = semi;
    }
    return out;
}

bool has_html_entities(const std::string& s)
{
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '&')
        {
            size_t semi = s.find(';', i + 1);
            if (semi != std::string::npos && semi - i <= 12)
                return true;
        }
    }
    return false;
}

std::vector<uint8_t> hex_decode_impl(const std::string& input)
{
    std::string s;
    s.reserve(input.size());
    for (char c : input)
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            s.push_back(c);
    if (s.size() % 2 != 0) return {};
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return 0;
    };
    for (size_t i = 0; i < s.size(); i += 2)
        out.push_back(static_cast<uint8_t>((hex_val(s[i]) << 4) | hex_val(s[i + 1])));
    return out;
}

std::string ascii_to_hex_impl(const std::string& s)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (size_t i = 0; i < s.size(); ++i)
    {
        unsigned char c = static_cast<unsigned char>(s[i]);
        out.push_back(hex[(c >> 4) & 0xF]);
        out.push_back(hex[c & 0xF]);
        if (i + 1 < s.size()) out.push_back(' ');
    }
    return out;
}

std::vector<uint8_t> gzip_compress_impl(const uint8_t* data, size_t len)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};
    zs.next_in = const_cast<Bytef*>(data);
    zs.avail_in = static_cast<uInt>(len);
    std::vector<uint8_t> out;
    out.resize(4096);
    int ret = Z_OK;
    do
    {
        if (zs.total_out >= out.size())
            out.resize(out.size() * 2);
        zs.next_out = reinterpret_cast<Bytef*>(out.data() + zs.total_out);
        zs.avail_out = static_cast<uInt>(out.size() - zs.total_out);
        ret = deflate(&zs, Z_FINISH);
    } while (ret == Z_OK);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    if (ret != Z_STREAM_END) return {};
    return out;
}

std::vector<uint8_t> gzip_decompress_impl(const uint8_t* data, size_t len)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 15 + 32) != Z_OK)
        return {};
    zs.next_in = const_cast<Bytef*>(data);
    zs.avail_in = static_cast<uInt>(len);
    std::vector<uint8_t> out;
    out.resize(4096);
    int ret = Z_OK;
    do
    {
        if (zs.total_out >= out.size())
            out.resize(out.size() * 2);
        zs.next_out = reinterpret_cast<Bytef*>(out.data() + zs.total_out);
        zs.avail_out = static_cast<uInt>(out.size() - zs.total_out);
        ret = inflate(&zs, Z_NO_FLUSH);
    } while (ret == Z_OK);
    out.resize(zs.total_out);
    inflateEnd(&zs);
    if (ret != Z_STREAM_END) return {};
    return out;
}

std::vector<uint8_t> bcrypt_hash(const uint8_t* data, size_t len, LPCWSTR alg_id)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    DWORD hash_len = 0;
    DWORD cb = 0;
    std::vector<uint8_t> result;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, alg_id, nullptr, 0);
    if (!BCRYPT_SUCCESS(st)) goto bh_cleanup;

    st = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len),
        sizeof(hash_len), &cb, 0);
    if (!BCRYPT_SUCCESS(st) || hash_len == 0) goto bh_cleanup;

    st = BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(st)) goto bh_cleanup;

    st = BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
    if (!BCRYPT_SUCCESS(st)) goto bh_cleanup;

    result.assign(hash_len, 0);
    st = BCryptFinishHash(h, reinterpret_cast<PUCHAR>(result.data()), hash_len, 0);
    if (!BCRYPT_SUCCESS(st))
        result.clear();

bh_cleanup:
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

uint32_t crc32_table[256];
bool crc32_table_init = false;

void init_crc32_table()
{
    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_init = true;
}

uint32_t crc32_impl(const uint8_t* data, size_t len)
{
    if (!crc32_table_init) init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i)
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

std::string json_pretty_impl(const std::string& s)
{
    json j = json::parse(s, nullptr, false);
    if (j.is_discarded()) return {};
    return j.dump(2);
}

std::string json_minify_impl(const std::string& s)
{
    json j = json::parse(s, nullptr, false);
    if (j.is_discarded()) return {};
    return j.dump();
}

std::string xml_pretty_impl(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 2);
    int depth = 0;
    bool in_tag = false;
    bool in_text = false;
    bool tag_closing = false;
    static auto push_indent = [&out](int d) {
        for (int i = 0; i < d; ++i) out += "  ";
    };
    for (size_t i = 0; i < s.size(); ++i)
    {
        char c = s[i];
        if (in_tag)
        {
            if (c == '>')
            {
                in_tag = false;
                if (tag_closing)
                    --depth;
                out += ">\n";
                in_text = true;
            }
            else
                out.push_back(c);
            continue;
        }
        if (c == '<')
        {
            in_text = false;
            if (i + 1 < s.size() && s[i + 1] == '/')
            {
                push_indent(depth - 1);
                out += "</";
                in_tag = true;
                tag_closing = true;
                ++i;
            }
            else if (i + 1 < s.size() && (s[i + 1] == '?' || s[i + 1] == '!'))
            {
                size_t end = s.find('>', i);
                if (end == std::string::npos) { out += s.substr(i); break; }
                push_indent(depth);
                out += s.substr(i, end - i + 1);
                out += "\n";
                i = end;
            }
            else
            {
                push_indent(depth);
                out += "<";
                in_tag = true;
                tag_closing = false;
                bool self_closing = false;
                size_t gt = s.find('>', i);
                if (gt != std::string::npos && gt > 0 && s[gt - 1] == '/') self_closing = true;
                if (!self_closing) ++depth;
            }
        }
        else if (in_text)
        {
            if (!std::isspace(static_cast<unsigned char>(c)))
            {
                push_indent(depth);
                in_text = false;
                out.push_back(c);
            }
        }
        else if (!std::isspace(static_cast<unsigned char>(c)))
        {
            out.push_back(c);
        }
    }
    return out;
}

std::string unicode_escape_impl(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 6);
    for (size_t i = 0; i < s.size();)
    {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80)
        {
            out.push_back(static_cast<char>(c));
            ++i;
        }
        else
        {
            uint32_t cp = 0;
            int extra = 0;
            if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; extra = 1; }
            else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; extra = 2; }
            else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; extra = 3; }
            else { out.push_back(static_cast<char>(c)); ++i; continue; }
            bool valid = true;
            for (int j = 0; j < extra; ++j)
            {
                if (i + 1 + j >= s.size()) { valid = false; break; }
                unsigned char cc = static_cast<unsigned char>(s[i + 1 + j]);
                if ((cc & 0xC0) != 0x80) { valid = false; break; }
                cp = (cp << 6) | (cc & 0x3F);
            }
            if (!valid) { out.push_back(static_cast<char>(c)); ++i; continue; }
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04X", cp);
            out += buf;
            i += 1 + extra;
        }
    }
    return out;
}

std::string unicode_unescape_impl(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '\\' && i + 1 < s.size() && (s[i + 1] == 'u' || s[i + 1] == 'U'))
        {
            bool upper = (s[i + 1] == 'U');
            int hex_len = upper ? 8 : 4;
            if (i + 2 + hex_len <= s.size())
            {
                std::string hexs = s.substr(i + 2, hex_len);
                uint32_t cp = static_cast<uint32_t>(std::stoul(hexs, nullptr, 16));
                if (cp < 0x80)
                    out.push_back(static_cast<char>(cp));
                else if (cp < 0x800)
                {
                    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                else if (cp < 0x10000)
                {
                    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                else
                {
                    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                i += 1 + hex_len;
            }
            else
                out.push_back(s[i]);
        }
        else
            out.push_back(s[i]);
    }
    return out;
}

std::string jwt_decode_impl(const std::string& s)
{
    size_t first_dot = s.find('.');
    if (first_dot == std::string::npos) return {};
    size_t second_dot = s.find('.', first_dot + 1);
    if (second_dot == std::string::npos) return {};

    std::string header_b64 = s.substr(0, first_dot);
    std::string payload_b64 = s.substr(first_dot + 1, second_dot - first_dot - 1);

    auto header_bytes = base64_decode_impl(header_b64);
    auto payload_bytes = base64_decode_impl(payload_b64);

    json out;
    std::string header_str(header_bytes.begin(), header_bytes.end());
    std::string payload_str(payload_bytes.begin(), payload_bytes.end());

    out["header_raw"] = header_str;
    out["payload_raw"] = payload_str;

    json header_json = json::parse(header_str, nullptr, false);
    json payload_json = json::parse(payload_str, nullptr, false);

    if (!header_json.is_discarded()) out["header"] = header_json;
    else out["header"] = header_str;

    if (!payload_json.is_discarded()) out["payload"] = payload_json;
    else out["payload"] = payload_str;

    if (second_dot + 1 < s.size())
    {
        std::string sig_b64 = s.substr(second_dot + 1);
        out["signature_b64"] = sig_b64;
        auto sig_bytes = base64_decode_impl(sig_b64);
        out["signature_hex"] = to_hex_string(sig_bytes.data(), sig_bytes.size(), false);
    }
    else
        out["signature_b64"] = "";

    return out.dump(2);
}

std::string detect_format(const std::vector<uint8_t>& input)
{
    if (input.empty()) return "empty";
    std::string s(input.begin(), input.end());

    if (!s.empty())
    {
        char first = s[0];
        if (first == '{' || first == '[')
        {
            json j = json::parse(s, nullptr, false);
            if (!j.is_discarded()) return "json";
        }
        if (first == '<')
        {
            size_t gt = s.find('>');
            if (gt != std::string::npos && s.find('<', 1) != std::string::npos)
                return "xml";
        }
    }

    size_t dot1 = s.find('.');
    if (dot1 != std::string::npos)
    {
        size_t dot2 = s.find('.', dot1 + 1);
        if (dot2 != std::string::npos)
        {
            auto h = base64_decode_impl(s.substr(0, dot1));
            auto p = base64_decode_impl(s.substr(dot1 + 1, dot2 - dot1 - 1));
            if (!h.empty() && !p.empty())
            {
                json hj = json::parse(std::string(h.begin(), h.end()), nullptr, false);
                if (!hj.is_discarded() && hj.contains("typ"))
                    return "jwt";
            }
        }
    }

    if (has_html_entities(s)) return "html";
    if (has_url_encoding(s)) return "url";

    bool all_b64 = true;
    bool has_b64_char = false;
    int pad_count = 0;
    for (char c : s)
    {
        if (c == '=') { ++pad_count; continue; }
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (b64_char_val(c) >= 0) has_b64_char = true;
        else { all_b64 = false; break; }
    }
    if (all_b64 && has_b64_char && s.size() >= 4 && pad_count <= 2)
    {
        size_t non_ws = 0;
        for (char c : s) if (c != '\n' && c != '\r' && c != ' ' && c != '\t') ++non_ws;
        if (non_ws % 4 == 0) return "base64";
    }

    bool all_hex = true;
    bool has_hex = false;
    for (char c : s)
    {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            has_hex = true;
        else if (c != ' ' && c != '\n' && c != '\r' && c != '\t')
        {
            all_hex = false;
            break;
        }
    }
    if (all_hex && has_hex)
    {
        size_t hex_count = 0;
        for (char c : s)
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                ++hex_count;
        if (hex_count % 2 == 0 && hex_count >= 2) return "hex";
    }

    if (s.find("\\u") != std::string::npos) return "unicode_escape";

    return "text";
}

transform_result_t make_result_bytes(std::vector<uint8_t> bytes, const std::string& format_name = "")
{
    transform_result_t r;
    r.success = true;
    r.output_bytes = std::move(bytes);
    if (is_printable_ascii(r.output_bytes))
        r.output = bytes_to_string(r.output_bytes);
    else
        r.output = to_hex_string(r.output_bytes.data(), r.output_bytes.size(), false);
    r.detected_format = format_name;
    return r;
}

transform_result_t make_result_string(std::string str, const std::string& format_name = "")
{
    transform_result_t r;
    r.success = true;
    r.output = std::move(str);
    r.output_bytes = string_to_bytes(r.output);
    r.detected_format = format_name;
    return r;
}

transform_result_t make_error(const std::string& err)
{
    transform_result_t r;
    r.success = false;
    r.error = err;
    return r;
}

transform_result_t make_hash_result(std::vector<uint8_t> hash_bytes)
{
    transform_result_t r;
    r.success = true;
    r.output_bytes = std::move(hash_bytes);
    r.output = to_hex_string(r.output_bytes.data(), r.output_bytes.size(), false);
    return r;
}

}

std::vector<std::string> available_transforms()
{
    return {
        "base64_encode", "base64_decode", "base64url_encode", "base64url_decode",
        "url_encode", "url_decode", "url_decode_all",
        "html_encode", "html_decode", "html_entity_encode", "html_entity_decode",
        "hex_encode", "hex_decode", "ascii_to_hex",
        "gzip_compress", "gzip_decompress",
        "md5_hash", "sha1_hash", "sha256_hash", "sha512_hash", "crc32",
        "json_pretty", "json_minify", "xml_pretty",
        "jwt_decode", "unicode_escape", "unicode_unescape",
        "detect"
    };
}

transform_result_t apply_transform(const std::string& name, const std::vector<uint8_t>& input)
{
    if (name == "base64_encode")
        return make_result_string(base64_encode_impl(input.data(), input.size(), false), "base64");

    if (name == "base64url_encode")
        return make_result_string(base64_encode_impl(input.data(), input.size(), true), "base64url");

    if (name == "base64_decode")
    {
        std::string s(input.begin(), input.end());
        auto decoded = base64_decode_impl(s);
        if (decoded.empty() && !input.empty())
            return make_error("base64_decode: invalid input");
        return make_result_bytes(std::move(decoded));
    }

    if (name == "base64url_decode")
    {
        std::string s(input.begin(), input.end());
        auto decoded = base64_decode_impl(s);
        if (decoded.empty() && !input.empty())
            return make_error("base64url_decode: invalid input");
        return make_result_bytes(std::move(decoded));
    }

    if (name == "url_encode")
        return make_result_string(url_encode_impl(bytes_to_string(input)), "url");

    if (name == "url_decode")
        return make_result_string(url_decode_impl(bytes_to_string(input)));

    if (name == "url_decode_all")
    {
        std::string s = bytes_to_string(input);
        for (int i = 0; i < 10 && has_url_encoding(s); ++i)
            s = url_decode_impl(s);
        return make_result_string(std::move(s));
    }

    if (name == "html_encode")
        return make_result_string(html_encode_impl(bytes_to_string(input)), "html");

    if (name == "html_decode")
        return make_result_string(html_decode_impl(bytes_to_string(input)));

    if (name == "html_entity_encode")
        return make_result_string(html_entity_encode_impl(bytes_to_string(input)), "html_entity");

    if (name == "html_entity_decode")
        return make_result_string(html_decode_impl(bytes_to_string(input)));

    if (name == "hex_encode")
        return make_result_string(to_hex_string(input.data(), input.size(), false), "hex");

    if (name == "hex_decode")
    {
        std::string s(input.begin(), input.end());
        auto decoded = hex_decode_impl(s);
        if (decoded.empty() && !input.empty())
            return make_error("hex_decode: invalid input");
        return make_result_bytes(std::move(decoded));
    }

    if (name == "ascii_to_hex")
        return make_result_string(ascii_to_hex_impl(bytes_to_string(input)), "ascii_hex");

    if (name == "gzip_compress")
    {
        auto compressed = gzip_compress_impl(input.data(), input.size());
        if (compressed.empty() && !input.empty())
            return make_error("gzip_compress: compression failed");
        return make_result_bytes(std::move(compressed));
    }

    if (name == "gzip_decompress")
    {
        auto decompressed = gzip_decompress_impl(input.data(), input.size());
        if (decompressed.empty() && !input.empty())
            return make_error("gzip_decompress: decompression failed");
        return make_result_bytes(std::move(decompressed));
    }
    if (name == "md5_hash")
    {
        auto h = bcrypt_hash(input.data(), input.size(), BCRYPT_MD5_ALGORITHM);
        if (h.empty()) return make_error("md5_hash: BCrypt failed");
        return make_hash_result(std::move(h));
    }

    if (name == "sha1_hash")
    {
        auto h = bcrypt_hash(input.data(), input.size(), BCRYPT_SHA1_ALGORITHM);
        if (h.empty()) return make_error("sha1_hash: BCrypt failed");
        return make_hash_result(std::move(h));
    }

    if (name == "sha256_hash")
    {
        auto h = bcrypt_hash(input.data(), input.size(), BCRYPT_SHA256_ALGORITHM);
        if (h.empty()) return make_error("sha256_hash: BCrypt failed");
        return make_hash_result(std::move(h));
    }

    if (name == "sha512_hash")
    {
        auto h = bcrypt_hash(input.data(), input.size(), BCRYPT_SHA512_ALGORITHM);
        if (h.empty()) return make_error("sha512_hash: BCrypt failed");
        return make_hash_result(std::move(h));
    }

    if (name == "crc32")
    {
        uint32_t val = crc32_impl(input.data(), input.size());
        uint8_t buf[4] = {
            static_cast<uint8_t>((val >> 24) & 0xFF),
            static_cast<uint8_t>((val >> 16) & 0xFF),
            static_cast<uint8_t>((val >> 8) & 0xFF),
            static_cast<uint8_t>(val & 0xFF)
        };
        return make_hash_result(std::vector<uint8_t>(buf, buf + 4));
    }

    if (name == "json_pretty")
    {
        std::string s(input.begin(), input.end());
        std::string result = json_pretty_impl(s);
        if (result.empty()) return make_error("json_pretty: invalid JSON");
        return make_result_string(std::move(result));
    }

    if (name == "json_minify")
    {
        std::string s(input.begin(), input.end());
        std::string result = json_minify_impl(s);
        if (result.empty()) return make_error("json_minify: invalid JSON");
        return make_result_string(std::move(result));
    }

    if (name == "xml_pretty")
    {
        std::string s(input.begin(), input.end());
        std::string result = xml_pretty_impl(s);
        if (result.empty()) return make_error("xml_pretty: invalid XML");
        return make_result_string(std::move(result));
    }

    if (name == "jwt_decode")
    {
        std::string s(input.begin(), input.end());
        std::string result = jwt_decode_impl(s);
        if (result.empty()) return make_error("jwt_decode: invalid JWT format");
        return make_result_string(std::move(result));
    }

    if (name == "unicode_escape")
        return make_result_string(unicode_escape_impl(bytes_to_string(input)));

    if (name == "unicode_unescape")
        return make_result_string(unicode_unescape_impl(bytes_to_string(input)));

    if (name == "detect")
    {
        std::string fmt = detect_format(input);
        transform_result_t r;
        r.success = true;
        r.detected_format = fmt;
        r.output = fmt;
        r.output_bytes = input;
        return r;
    }

    return make_error("unknown transform: " + name);
}

transform_result_t apply_pipeline(const std::vector<std::string>& transforms, const std::vector<uint8_t>& input)
{
    std::vector<uint8_t> current = input;
    for (const auto& name : transforms)
    {
        transform_result_t r = apply_transform(name, current);
        if (!r.success)
        {
            r.error = "pipeline step '" + name + "' failed: " + r.error;
            return r;
        }
        current = r.output_bytes;
    }
    transform_result_t result;
    result.success = true;
    result.output_bytes = std::move(current);
    if (is_printable_ascii(result.output_bytes))
        result.output = bytes_to_string(result.output_bytes);
    else
        result.output = to_hex_string(result.output_bytes.data(), result.output_bytes.size(), false);
    return result;
}

transform_result_t smart_detect(const std::vector<uint8_t>& input)
{
    std::string fmt = detect_format(input);
    transform_result_t result;

    if (fmt == "base64")
    {
        result = apply_transform("base64_decode", input);
        result.detected_format = "base64";
    }
    else if (fmt == "hex")
    {
        result = apply_transform("hex_decode", input);
        result.detected_format = "hex";
    }
    else if (fmt == "url")
    {
        result = apply_transform("url_decode_all", input);
        result.detected_format = "url";
    }
    else if (fmt == "html")
    {
        result = apply_transform("html_decode", input);
        result.detected_format = "html";
    }
    else if (fmt == "jwt")
    {
        result = apply_transform("jwt_decode", input);
        result.detected_format = "jwt";
    }
    else if (fmt == "json")
    {
        result = apply_transform("json_pretty", input);
        result.detected_format = "json";
    }
    else if (fmt == "unicode_escape")
    {
        result = apply_transform("unicode_unescape", input);
        result.detected_format = "unicode_escape";
    }
    else
    {
        result.success = true;
        result.detected_format = fmt;
        result.output = fmt;
        result.output_bytes = input;
    }

    return result;
}

}
}
}