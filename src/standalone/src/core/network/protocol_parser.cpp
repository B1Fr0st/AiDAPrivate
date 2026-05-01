#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "protocol_parser.hpp"

#include <zlib.h>
#include <brotli/decode.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

namespace protocol_parser {


static std::string to_lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

static bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

static size_t find_crlf(const uint8_t* data, size_t len, size_t start = 0) {
    for (size_t i = start; i + 1 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') return i;
    }
    return std::string::npos;
}

static std::string make_string(const uint8_t* data, size_t len) {
    return std::string(reinterpret_cast<const char*>(data), len);
}


static bool parse_headers(const uint8_t* data, size_t len, size_t& pos,
                           std::vector<http_header>& headers) {
    while (pos + 1 < len) {
        if (data[pos] == '\r' && data[pos + 1] == '\n') {
            pos += 2;
            return true;
        }
        size_t eol = find_crlf(data, len, pos);
        if (eol == std::string::npos) return false;

        std::string line = make_string(data + pos, eol - pos);
        pos = eol + 2;

        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        http_header hdr;
        hdr.name = line.substr(0, colon);
        size_t val_start = colon + 1;
        while (val_start < line.size() && line[val_start] == ' ') val_start++;
        hdr.value = line.substr(val_start);
        headers.push_back(std::move(hdr));
    }
    return false;
}

static std::vector<uint8_t> decode_chunked(const uint8_t* data, size_t len) {
    std::vector<uint8_t> result;
    size_t pos = 0;
    while (pos < len) {
        size_t eol = find_crlf(data, len, pos);
        if (eol == std::string::npos) break;

        std::string chunk_sz_str = make_string(data + pos, eol - pos);
        unsigned long chunk_sz = 0;
        try { chunk_sz = std::stoul(chunk_sz_str, nullptr, 16); }
        catch (...) { break; }

        pos = eol + 2;
        if (chunk_sz == 0) break;
        if (pos + chunk_sz > len) break;

        result.insert(result.end(), data + pos, data + pos + chunk_sz);
        pos += chunk_sz;
        if (pos + 1 < len && data[pos] == '\r' && data[pos + 1] == '\n')
            pos += 2;
    }
    return result;
}

http_request parse_http_request(const uint8_t* data, size_t len) {
    http_request req;
    if (len < 16) return req;

    size_t first_eol = find_crlf(data, len);
    if (first_eol == std::string::npos) return req;

    std::string request_line = make_string(data, first_eol);
    size_t sp1 = request_line.find(' ');
    size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return req;

    req.method = request_line.substr(0, sp1);
    req.uri = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = request_line.substr(sp2 + 1);

    static const char* methods[] = { "GET", "POST", "PUT", "DELETE", "PATCH",
                                      "HEAD", "OPTIONS", "CONNECT", "TRACE" };
    bool method_ok = false;
    for (auto m : methods) {
        if (req.method == m) { method_ok = true; break; }
    }
    if (!method_ok) return req;

    req.valid = true;
    size_t pos = first_eol + 2;

    if (!parse_headers(data, len, pos, req.headers)) {
        req.complete = false;
        req.total_consumed = len;
        return req;
    }

    std::string cl_str = find_header(req.headers, "Content-Length");
    std::string te = to_lower(find_header(req.headers, "Transfer-Encoding"));

    if (te.find("chunked") != std::string::npos) {
        size_t body_start = pos;
        req.body = decode_chunked(data + body_start, len - body_start);
        req.complete = true;
        req.total_consumed = len;
    } else if (!cl_str.empty()) {
        size_t cl = 0;
        try { cl = std::stoul(cl_str); } catch (...) { cl = 0; }
        if (pos + cl <= len) {
            req.body.assign(data + pos, data + pos + cl);
            req.complete = true;
            req.total_consumed = pos + cl;
        } else {
            req.body.assign(data + pos, data + len);
            req.complete = false;
            req.total_consumed = len;
        }
    } else {
        req.complete = true;
        req.total_consumed = pos;
    }
    return req;
}

http_response parse_http_response(const uint8_t* data, size_t len) {
    http_response resp;
    if (len < 12) return resp;

    size_t first_eol = find_crlf(data, len);
    if (first_eol == std::string::npos) return resp;

    std::string status_line = make_string(data, first_eol);
    if (status_line.size() < 12 || status_line.substr(0, 5) != "HTTP/") return resp;

    size_t sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) return resp;
    size_t sp2 = status_line.find(' ', sp1 + 1);

    resp.version = status_line.substr(0, sp1);
    std::string code_str = (sp2 != std::string::npos)
        ? status_line.substr(sp1 + 1, sp2 - sp1 - 1)
        : status_line.substr(sp1 + 1);

    try { resp.status_code = std::stoi(code_str); } catch (...) { return resp; }
    if (sp2 != std::string::npos) resp.reason = status_line.substr(sp2 + 1);

    resp.valid = true;
    size_t pos = first_eol + 2;

    if (!parse_headers(data, len, pos, resp.headers)) {
        resp.complete = false;
        resp.total_consumed = len;
        return resp;
    }

    std::string cl_str = find_header(resp.headers, "Content-Length");
    std::string te = to_lower(find_header(resp.headers, "Transfer-Encoding"));

    if (te.find("chunked") != std::string::npos) {
        resp.body = decode_chunked(data + pos, len - pos);
        resp.complete = true;
        resp.total_consumed = len;
    } else if (!cl_str.empty()) {
        size_t cl = 0;
        try { cl = std::stoul(cl_str); } catch (...) { cl = 0; }
        if (pos + cl <= len) {
            resp.body.assign(data + pos, data + pos + cl);
            resp.complete = true;
            resp.total_consumed = pos + cl;
        } else {
            resp.body.assign(data + pos, data + len);
            resp.complete = false;
            resp.total_consumed = len;
        }
    } else {
        resp.body.assign(data + pos, data + len);
        resp.complete = (len == pos);
        resp.total_consumed = len;
    }
    return resp;
}

std::string find_header(const std::vector<http_header>& headers, const std::string& name) {
    for (auto& h : headers) {
        if (iequals(h.name, name)) return h.value;
    }
    return {};
}

std::vector<uint8_t> decompress_body(const std::vector<uint8_t>& body, const std::string& encoding) {
    std::string enc = to_lower(encoding);

    if (enc == "gzip" || enc == "deflate" || enc == "x-gzip") {
        if (body.empty()) return body;

        z_stream strm = {};
        strm.next_in = const_cast<Bytef*>(body.data());
        strm.avail_in = static_cast<uInt>(body.size());


        int window_bits = 15 + 32;
        if (inflateInit2(&strm, window_bits) != Z_OK)
            return body;

        std::vector<uint8_t> result;
        result.reserve(body.size() * 4);

        uint8_t out_buf[16384];
        int ret;
        do {
            strm.next_out = out_buf;
            strm.avail_out = sizeof(out_buf);
            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                inflateEnd(&strm);
                return body;
            }
            size_t have = sizeof(out_buf) - strm.avail_out;
            result.insert(result.end(), out_buf, out_buf + have);
        } while (ret != Z_STREAM_END);

        inflateEnd(&strm);
        return result;
    }

    if (enc == "br") {
        size_t decoded_size = body.size() * 4;
        std::vector<uint8_t> result;
        result.resize(decoded_size);

        BrotliDecoderState* bs = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        if (!bs) return body;

        const uint8_t* next_in = body.data();
        size_t avail_in = body.size();
        uint8_t* next_out = result.data();
        size_t avail_out = decoded_size;
        size_t total_out = 0;

        BrotliDecoderResult br_res = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;
        while (br_res == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            br_res = BrotliDecoderDecompressStream(bs, &avail_in, &next_in, &avail_out, &next_out, &total_out);
            if (br_res == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
                size_t off = next_out - result.data();
                result.resize(result.size() * 2);
                next_out = result.data() + off;
                avail_out = result.size() - off;
            }
        }

        BrotliDecoderDestroyInstance(bs);

        if (br_res == BROTLI_DECODER_RESULT_SUCCESS) {
            result.resize(total_out);
            return result;
        }
        return body;
    }

    return body;
}

content_type_t detect_content_type(const std::vector<http_header>& headers) {
    std::string ct = to_lower(find_header(headers, "Content-Type"));
    if (ct.empty()) return content_type_t::unknown;
    if (ct.find("application/json") != std::string::npos) return content_type_t::json;
    if (ct.find("text/xml") != std::string::npos || ct.find("application/xml") != std::string::npos)
        return content_type_t::xml;
    if (ct.find("text/html") != std::string::npos) return content_type_t::html;
    if (ct.find("text/") != std::string::npos) return content_type_t::text;
    if (ct.find("application/x-www-form-urlencoded") != std::string::npos)
        return content_type_t::form_urlencoded;
    if (ct.find("multipart/") != std::string::npos) return content_type_t::multipart;
    return content_type_t::binary;
}

std::string content_type_name(content_type_t ct) {
    switch (ct) {
        case content_type_t::json: return "JSON";
        case content_type_t::xml: return "XML";
        case content_type_t::html: return "HTML";
        case content_type_t::text: return "Text";
        case content_type_t::form_urlencoded: return "Form";
        case content_type_t::multipart: return "Multipart";
        case content_type_t::binary: return "Binary";
        default: return "Unknown";
    }
}


static uint32_t read_u24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
            static_cast<uint32_t>(p[2]);
}

static uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
            static_cast<uint32_t>(p[3]);
}

static uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

std::vector<h2_frame> parse_h2_frames(const uint8_t* data, size_t len) {
    std::vector<h2_frame> frames;


    static const char h2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t preface_len = 24;
    size_t offset = 0;
    if (len >= preface_len && memcmp(data, h2_preface, preface_len) == 0) {
        offset = preface_len;
    }

    while (offset + 9 <= len) {
        h2_frame f;
        f.length = read_u24(data + offset);
        f.type = static_cast<h2_frame_type>(data[offset + 3]);
        f.flags = data[offset + 4];
        f.stream_id = read_u32(data + offset + 5) & 0x7FFFFFFF;
        offset += 9;

        if (f.length > 16384 * 4) break;
        if (offset + f.length > len) break;

        f.payload.assign(data + offset, data + offset + f.length);
        offset += f.length;
        frames.push_back(std::move(f));
    }
    return frames;
}

std::string h2_frame_type_name(h2_frame_type t) {
    switch (t) {
        case h2_frame_type::DATA:          return "DATA";
        case h2_frame_type::HEADERS:       return "HEADERS";
        case h2_frame_type::PRIORITY:      return "PRIORITY";
        case h2_frame_type::RST_STREAM:    return "RST_STREAM";
        case h2_frame_type::SETTINGS:      return "SETTINGS";
        case h2_frame_type::PUSH_PROMISE:  return "PUSH_PROMISE";
        case h2_frame_type::PING:          return "PING";
        case h2_frame_type::GOAWAY:        return "GOAWAY";
        case h2_frame_type::WINDOW_UPDATE: return "WINDOW_UPDATE";
        case h2_frame_type::CONTINUATION:  return "CONTINUATION";
        default: return "UNKNOWN(" + std::to_string(static_cast<int>(t)) + ")";
    }
}


static const h2_header_field hpack_static_table[] = {
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" }
};
static const size_t HPACK_STATIC_TABLE_SIZE = sizeof(hpack_static_table) / sizeof(hpack_static_table[0]);

static uint32_t hpack_decode_integer(const uint8_t* data, size_t len, size_t& pos, uint8_t prefix_bits) {
    if (pos >= len) return 0;
    uint32_t max_first = (1u << prefix_bits) - 1;
    uint32_t value = data[pos] & max_first;
    pos++;
    if (value < max_first) return value;

    uint32_t m = 0;
    while (pos < len) {
        uint8_t b = data[pos];
        pos++;
        value += static_cast<uint32_t>(b & 0x7F) << m;
        m += 7;
        if ((b & 0x80) == 0) break;
        if (m > 28) break;
    }
    return value;
}

static std::string hpack_decode_string(const uint8_t* data, size_t len, size_t& pos) {
    if (pos >= len) return {};
    bool huffman = (data[pos] & 0x80) != 0;
    uint32_t slen = hpack_decode_integer(data, len, pos, 7);
    if (pos + slen > len) { pos = len; return {}; }

    if (!huffman) {
        std::string s(reinterpret_cast<const char*>(data + pos), slen);
        pos += slen;
        return s;
    }


    struct huff_entry { uint32_t code; uint8_t bits; uint16_t sym; };
    static const huff_entry huff_table[] = {
        {0x1ff8, 13, 0}, {0x7fffd8, 23, 1}, {0xfffffe2, 28, 2}, {0xfffffe3, 28, 3},
        {0xfffffe4, 28, 4}, {0xfffffe5, 28, 5}, {0xfffffe6, 28, 6}, {0xfffffe7, 28, 7},
        {0xfffffe8, 28, 8}, {0xffffea, 24, 9}, {0x3ffffffc, 30, 10}, {0xfffffe9, 28, 11},
        {0xfffffea, 28, 12}, {0x3ffffffd, 30, 13}, {0xfffffeb, 28, 14}, {0xfffffec, 28, 15},
        {0xfffffed, 28, 16}, {0xfffffee, 28, 17}, {0xfffffef, 28, 18}, {0xffffff0, 28, 19},
        {0xffffff1, 28, 20}, {0xffffff2, 28, 21}, {0x3ffffffe, 30, 22}, {0xffffff3, 28, 23},
        {0xffffff4, 28, 24}, {0xffffff5, 28, 25}, {0xffffff6, 28, 26}, {0xffffff7, 28, 27},
        {0xffffff8, 28, 28}, {0xffffff9, 28, 29}, {0xffffffa, 28, 30}, {0xffffffb, 28, 31},
        {0x14, 6, 32}, {0x3f8, 10, 33}, {0x3f9, 10, 34}, {0xffa, 12, 35},
        {0x1ff9, 13, 36}, {0x15, 6, 37}, {0xf8, 8, 38}, {0x7fa, 11, 39},
        {0x3fa, 10, 40}, {0x3fb, 10, 41}, {0xf9, 8, 42}, {0x7fb, 11, 43},
        {0xfa, 8, 44}, {0x16, 6, 45}, {0x17, 6, 46}, {0x18, 6, 47},
        {0x0, 5, 48}, {0x1, 5, 49}, {0x2, 5, 50}, {0x19, 6, 51},
        {0x1a, 6, 52}, {0x1b, 6, 53}, {0x1c, 6, 54}, {0x1d, 6, 55},
        {0x1e, 6, 56}, {0x1f, 6, 57}, {0x5c, 7, 58}, {0xfb, 8, 59},
        {0x7ffc, 15, 60}, {0x20, 6, 61}, {0xffb, 12, 62}, {0x3fc, 10, 63},
        {0x1ffa, 13, 64}, {0x21, 6, 65}, {0x5d, 7, 66}, {0x5e, 7, 67},
        {0x5f, 7, 68}, {0x60, 7, 69}, {0x61, 7, 70}, {0x62, 7, 71},
        {0x63, 7, 72}, {0x64, 7, 73}, {0x65, 7, 74}, {0x66, 7, 75},
        {0x67, 7, 76}, {0x68, 7, 77}, {0x69, 7, 78}, {0x6a, 7, 79},
        {0x6b, 7, 80}, {0x6c, 7, 81}, {0x6d, 7, 82}, {0x6e, 7, 83},
        {0x6f, 7, 84}, {0x70, 7, 85}, {0x71, 7, 86}, {0x72, 7, 87},
        {0xfc, 8, 88}, {0x73, 7, 89}, {0xfd, 8, 90}, {0x1ffb, 13, 91},
        {0x7fff0, 19, 92}, {0x1ffc, 13, 93}, {0x3ffc, 14, 94}, {0x22, 6, 95},
        {0x7ffd, 15, 96}, {0x3, 5, 97}, {0x23, 6, 98}, {0x4, 5, 99},
        {0x24, 6, 100}, {0x5, 5, 101}, {0x25, 6, 102}, {0x26, 6, 103},
        {0x27, 6, 104}, {0x6, 5, 105}, {0x74, 7, 106}, {0x75, 7, 107},
        {0x28, 6, 108}, {0x29, 6, 109}, {0x2a, 6, 110}, {0x7, 5, 111},
        {0x2b, 6, 112}, {0x76, 7, 113}, {0x2c, 6, 114}, {0x8, 5, 115},
        {0x9, 5, 116}, {0x2d, 6, 117}, {0x77, 7, 118}, {0x78, 7, 119},
        {0x79, 7, 120}, {0x7a, 7, 121}, {0x7b, 7, 122}, {0x7ffe, 15, 123},
        {0x7fc, 11, 124}, {0x3ffd, 14, 125}, {0x1ffd, 13, 126}, {0xffffffc, 28, 127},
        {0xfffe6, 20, 128}, {0x3fffd2, 22, 129}, {0xfffe7, 20, 130}, {0xfffe8, 20, 131},
        {0x3fffd3, 22, 132}, {0x3fffd4, 22, 133}, {0x3fffd5, 22, 134}, {0x7fffd9, 23, 135},
        {0x3fffd6, 22, 136}, {0x7fffda, 23, 137}, {0x7fffdb, 23, 138}, {0x7fffdc, 23, 139},
        {0x7fffdd, 23, 140}, {0x7fffde, 23, 141}, {0xffffeb, 24, 142}, {0x7fffdf, 23, 143},
        {0xffffec, 24, 144}, {0xffffed, 24, 145}, {0x3fffd7, 22, 146}, {0x7fffe0, 23, 147},
        {0xffffee, 24, 148}, {0x7fffe1, 23, 149}, {0x7fffe2, 23, 150}, {0x7fffe3, 23, 151},
        {0x7fffe4, 23, 152}, {0x1fffdc, 21, 153}, {0x3fffd8, 22, 154}, {0x7fffe5, 23, 155},
        {0x3fffd9, 22, 156}, {0x7fffe6, 23, 157}, {0x7fffe7, 23, 158}, {0xffffef, 24, 159},
        {0x3fffda, 22, 160}, {0x1fffdd, 21, 161}, {0xfffe9, 20, 162}, {0x3fffdb, 22, 163},
        {0x3fffdc, 22, 164}, {0x7fffe8, 23, 165}, {0x7fffe9, 23, 166}, {0x1fffde, 21, 167},
        {0x7fffea, 23, 168}, {0x3fffdd, 22, 169}, {0x3fffde, 22, 170}, {0xfffff0, 24, 171},
        {0x1fffdf, 21, 172}, {0x3fffdf, 22, 173}, {0x7fffeb, 23, 174}, {0x7fffec, 23, 175},
        {0x1fffe0, 21, 176}, {0x1fffe1, 21, 177}, {0x3fffe0, 22, 178}, {0x1fffe2, 21, 179},
        {0x7fffed, 23, 180}, {0x3fffe1, 22, 181}, {0x7fffee, 23, 182}, {0x7fffef, 23, 183},
        {0xfffea, 20, 184}, {0x3fffe2, 22, 185}, {0x3fffe3, 22, 186}, {0x3fffe4, 22, 187},
        {0x7ffff0, 23, 188}, {0x3fffe5, 22, 189}, {0x3fffe6, 22, 190}, {0x7ffff1, 23, 191},
        {0x3ffffe0, 26, 192}, {0x3ffffe1, 26, 193}, {0xfffeb, 20, 194}, {0x7fff1, 19, 195},
        {0x3fffe7, 22, 196}, {0x7ffff2, 23, 197}, {0x3fffe8, 22, 198}, {0x1ffffec, 25, 199},
        {0x3ffffe2, 26, 200}, {0x3ffffe3, 26, 201}, {0x3ffffe4, 26, 202}, {0x7ffffde, 27, 203},
        {0x7ffffdf, 27, 204}, {0x3ffffe5, 26, 205}, {0xfffff1, 24, 206}, {0x1ffffed, 25, 207},
        {0x7fff2, 19, 208}, {0x1fffe3, 21, 209}, {0x3ffffe6, 26, 210}, {0x7ffffe0, 27, 211},
        {0x7ffffe1, 27, 212}, {0x3ffffe7, 26, 213}, {0x7ffffe2, 27, 214}, {0xfffff2, 24, 215},
        {0x1fffe4, 21, 216}, {0x1fffe5, 21, 217}, {0x3ffffe8, 26, 218}, {0x3ffffe9, 26, 219},
        {0xffffffd, 28, 220}, {0x7ffffe3, 27, 221}, {0x7ffffe4, 27, 222}, {0x7ffffe5, 27, 223},
        {0xfffec, 20, 224}, {0xfffff3, 24, 225}, {0xfffed, 20, 226}, {0x1fffe6, 21, 227},
        {0x3fffe9, 22, 228}, {0x1fffe7, 21, 229}, {0x1fffe8, 21, 230}, {0x7ffff3, 23, 231},
        {0x3fffea, 22, 232}, {0x3fffeb, 22, 233}, {0x1ffffee, 25, 234}, {0x1ffffef, 25, 235},
        {0xfffff4, 24, 236}, {0xfffff5, 24, 237}, {0x3ffffea, 26, 238}, {0x7ffff4, 23, 239},
        {0x3ffffeb, 26, 240}, {0x7ffffe6, 27, 241}, {0x3ffffec, 26, 242}, {0x3ffffed, 26, 243},
        {0x7ffffe7, 27, 244}, {0x7ffffe8, 27, 245}, {0x7ffffe9, 27, 246}, {0x7ffffea, 27, 247},
        {0x7ffffeb, 27, 248}, {0xffffffe, 28, 249}, {0x7ffffec, 27, 250}, {0x7ffffed, 27, 251},
        {0x7ffffee, 27, 252}, {0x7ffffef, 27, 253}, {0x7fffff0, 27, 254}, {0x3ffffee, 26, 255},
        {0x3fffffff, 30, 256}
    };
    static const size_t HUFF_TABLE_SIZE = sizeof(huff_table) / sizeof(huff_table[0]);


    std::string result;
    uint64_t accum = 0;
    uint32_t bits = 0;
    const uint8_t* hdata = data + pos;

    for (uint32_t i = 0; i < slen; i++) {
        accum = (accum << 8) | hdata[i];
        bits += 8;

        while (bits >= 5) {
            bool found = false;
            for (size_t t = 0; t < HUFF_TABLE_SIZE - 1; t++) {
                if (huff_table[t].bits <= bits) {
                    uint32_t mask = (1u << huff_table[t].bits) - 1;
                    uint32_t candidate = static_cast<uint32_t>(accum >> (bits - huff_table[t].bits)) & mask;
                    if (candidate == huff_table[t].code) {
                        result += static_cast<char>(huff_table[t].sym);
                        bits -= huff_table[t].bits;
                        accum &= (static_cast<uint64_t>(1) << bits) - 1;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) break;
        }
    }

    pos += slen;
    return result;
}

static h2_header_field hpack_get_indexed(size_t index, const hpack_context& ctx) {
    if (index == 0) return {};
    if (index <= HPACK_STATIC_TABLE_SIZE) {
        return hpack_static_table[index - 1];
    }
    size_t dyn_idx = index - HPACK_STATIC_TABLE_SIZE - 1;
    if (dyn_idx < ctx.dynamic_table.size()) {
        return ctx.dynamic_table[dyn_idx];
    }
    return {};
}

static void hpack_add_to_dynamic(hpack_context& ctx, const h2_header_field& field) {
    size_t entry_size = field.name.size() + field.value.size() + 32;
    ctx.dynamic_table.insert(ctx.dynamic_table.begin(), field);
    ctx.dynamic_table_size += entry_size;

    while (ctx.dynamic_table_size > ctx.max_dynamic_table_size && !ctx.dynamic_table.empty()) {
        auto& last = ctx.dynamic_table.back();
        ctx.dynamic_table_size -= (last.name.size() + last.value.size() + 32);
        ctx.dynamic_table.pop_back();
    }
}

h2_parsed_headers decode_hpack(const uint8_t* data, size_t len, hpack_context& ctx) {
    h2_parsed_headers result;
    size_t pos = 0;

    while (pos < len) {
        uint8_t b = data[pos];

        if (b & 0x80) {

            uint32_t index = hpack_decode_integer(data, len, pos, 7);
            auto field = hpack_get_indexed(index, ctx);
            if (!field.name.empty()) result.fields.push_back(field);
        }
        else if (b & 0x40) {

            uint32_t index = hpack_decode_integer(data, len, pos, 6);
            h2_header_field field;
            if (index > 0) {
                field = hpack_get_indexed(index, ctx);
                field.value = hpack_decode_string(data, len, pos);
            } else {
                field.name = hpack_decode_string(data, len, pos);
                field.value = hpack_decode_string(data, len, pos);
            }
            hpack_add_to_dynamic(ctx, field);
            result.fields.push_back(field);
        }
        else if (b & 0x20) {

            uint32_t new_size = hpack_decode_integer(data, len, pos, 5);
            ctx.max_dynamic_table_size = new_size;
            while (ctx.dynamic_table_size > ctx.max_dynamic_table_size && !ctx.dynamic_table.empty()) {
                auto& last = ctx.dynamic_table.back();
                ctx.dynamic_table_size -= (last.name.size() + last.value.size() + 32);
                ctx.dynamic_table.pop_back();
            }
        }
        else {

            bool never_index = (b & 0x10) != 0;
            (void)never_index;
            uint32_t index = hpack_decode_integer(data, len, pos, 4);
            h2_header_field field;
            if (index > 0) {
                field = hpack_get_indexed(index, ctx);
                field.value = hpack_decode_string(data, len, pos);
            } else {
                field.name = hpack_decode_string(data, len, pos);
                field.value = hpack_decode_string(data, len, pos);
            }
            result.fields.push_back(field);
        }
    }
    result.valid = true;
    return result;
}


bool is_websocket_upgrade(const http_request& req) {
    if (!req.valid) return false;
    std::string upgrade = to_lower(find_header(req.headers, "Upgrade"));
    std::string conn = to_lower(find_header(req.headers, "Connection"));
    return upgrade.find("websocket") != std::string::npos &&
           conn.find("upgrade") != std::string::npos;
}

bool is_websocket_accept(const http_response& resp) {
    if (!resp.valid) return false;
    if (resp.status_code != 101) return false;
    std::string upgrade = to_lower(find_header(resp.headers, "Upgrade"));
    return upgrade.find("websocket") != std::string::npos;
}

ws_frame parse_ws_frame(const uint8_t* data, size_t len) {
    ws_frame f;
    if (len < 2) return f;

    f.fin = (data[0] & 0x80) != 0;
    f.opcode = static_cast<ws_opcode>(data[0] & 0x0F);
    f.masked = (data[1] & 0x80) != 0;

    uint64_t plen = data[1] & 0x7F;
    size_t hdr_size = 2;

    if (plen == 126) {
        if (len < 4) return f;
        plen = read_u16(data + 2);
        hdr_size = 4;
    } else if (plen == 127) {
        if (len < 10) return f;
        plen = 0;
        for (int i = 0; i < 8; i++)
            plen = (plen << 8) | data[2 + i];
        hdr_size = 10;
    }

    if (f.masked) {
        if (len < hdr_size + 4) return f;
        memcpy(f.masking_key, data + hdr_size, 4);
        hdr_size += 4;
    }

    f.payload_length = plen;
    if (hdr_size + plen > len) return f;

    f.payload.assign(data + hdr_size, data + hdr_size + plen);
    f.valid = true;
    f.total_consumed = hdr_size + static_cast<size_t>(plen);
    return f;
}

std::vector<uint8_t> unmask_payload(const ws_frame& frame) {
    if (!frame.masked || frame.payload.empty()) return frame.payload;
    std::vector<uint8_t> result = frame.payload;
    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= frame.masking_key[i % 4];
    }
    return result;
}

std::string ws_opcode_name(ws_opcode op) {
    switch (op) {
        case ws_opcode::continuation: return "Continuation";
        case ws_opcode::text: return "Text";
        case ws_opcode::binary: return "Binary";
        case ws_opcode::close: return "Close";
        case ws_opcode::ping: return "Ping";
        case ws_opcode::pong: return "Pong";
        default: return "Unknown";
    }
}


bool is_quic_packet(const uint8_t* data, size_t len, uint16_t dst_port) {
    if (len < 5) return false;


    if ((data[0] & 0x80) != 0) {

        if (len < 5) return false;
        uint32_t ver = read_u32(data + 1);

        if (ver == 0x00000001 || ver == 0x6b3343cf || ver == 0xff000000 ||
            (ver & 0xffffff00) == 0xff000000 || ver == 0) {
            return true;
        }
    }


    if (dst_port == 443 && (data[0] & 0x40) != 0) return true;
    return false;
}

quic_header parse_quic_header(const uint8_t* data, size_t len) {
    quic_header h;
    if (len < 5) return h;

    h.first_byte = data[0];
    h.is_long_header = (data[0] & 0x80) != 0;

    if (h.is_long_header) {
        h.version = read_u32(data + 1);
        h.version_name = quic_version_name(h.version);

        if (len < 6) return h;
        uint8_t dcid_len = data[5];
        if (len < 6u + dcid_len + 1u) return h;
        h.dcid.assign(data + 6, data + 6 + dcid_len);

        size_t scid_off = 6 + dcid_len;
        uint8_t scid_len = data[scid_off];
        if (len < scid_off + 1 + scid_len) return h;
        h.scid.assign(data + scid_off + 1, data + scid_off + 1 + scid_len);

        size_t pos = scid_off + 1 + scid_len;

        if (h.version == 0) {
            h.is_version_negotiation = true;
            h.packet_type = "Version Negotiation";
            while (pos + 4 <= len) {
                h.supported_versions.push_back(read_u32(data + pos));
                pos += 4;
            }
            h.payload_offset = pos;
            h.valid = true;
        } else {
            uint8_t ptype = (data[0] & 0x30) >> 4;
            switch (ptype) {
                case 0: {
                    h.packet_type = "Initial";
                    if (pos < len) {
                        uint64_t token_len = 0;
                        size_t varint_bytes = 0;
                        uint8_t first = data[pos];
                        uint8_t prefix = first >> 6;
                        if (prefix == 0) {
                            token_len = first & 0x3F;
                            varint_bytes = 1;
                        } else if (prefix == 1 && pos + 2 <= len) {
                            token_len = (static_cast<uint64_t>(first & 0x3F) << 8)
                                      | data[pos + 1];
                            varint_bytes = 2;
                        } else if (prefix == 2 && pos + 4 <= len) {
                            token_len = (static_cast<uint64_t>(first & 0x3F) << 24)
                                      | (static_cast<uint64_t>(data[pos + 1]) << 16)
                                      | (static_cast<uint64_t>(data[pos + 2]) << 8)
                                      | data[pos + 3];
                            varint_bytes = 4;
                        }
                        pos += varint_bytes;
                        if (token_len > 0 && pos + token_len <= len) {
                            h.token.assign(data + pos, data + pos + token_len);
                            pos += static_cast<size_t>(token_len);
                        }
                    }
                    h.payload_offset = pos;
                    break;
                }
                case 1: h.packet_type = "0-RTT"; h.payload_offset = pos; break;
                case 2: h.packet_type = "Handshake"; h.payload_offset = pos; break;
                case 3: {
                    h.packet_type = "Retry";
                    if (pos < len) {
                        size_t integrity_tag_size = 16;
                        size_t token_end = (len >= integrity_tag_size) ? len - integrity_tag_size : len;
                        if (pos < token_end) {
                            h.token.assign(data + pos, data + token_end);
                        }
                        h.payload_offset = len;
                    }
                    break;
                }
            }
            h.valid = true;
        }
    } else {
        h.packet_type = "1-RTT (Short)";
        if (len > 1) {
            constexpr size_t kQuicDcidLenHeuristic = 20;
            size_t dcid_len = (std::min)(kQuicDcidLenHeuristic, len - 1);
            h.dcid.assign(data + 1, data + 1 + dcid_len);
        }
        h.payload_offset = 1 + h.dcid.size();
        h.valid = true;
    }
    return h;
}

std::string quic_version_name(uint32_t version) {
    switch (version) {
        case 0x00000001: return "QUIC v1 (RFC 9000)";
        case 0x6b3343cf: return "QUIC v2 (RFC 9369)";
        case 0x00000000: return "Version Negotiation";
        default:
            if ((version & 0x0f0f0f0f) == 0x0a0a0a0a)
                return "QUIC Greasing";
            if ((version & 0xff000000) == 0xff000000)
                return "QUIC Draft-" + std::to_string(version & 0xFF);
            char buf[32];
            snprintf(buf, sizeof(buf), "Unknown (0x%08X)", version);
            return buf;
    }
}


tls_record parse_tls_record(const uint8_t* data, size_t len) {
    tls_record rec;
    if (len < 5) return rec;

    rec.content_type = data[0];
    rec.version = read_u16(data + 1);
    rec.length = read_u16(data + 3);


    if (rec.content_type < 20 || (rec.content_type > 25 && rec.content_type != 255))
        return rec;

    if ((rec.version & 0xFF00) != 0x0300) return rec;

    if (rec.length > 16384 + 2048) return rec;

    if (5 + rec.length <= len) {
        rec.fragment.assign(data + 5, data + 5 + rec.length);
    }
    rec.valid = true;
    return rec;
}

tls_client_hello parse_client_hello(const uint8_t* data, size_t len) {
    tls_client_hello hello;


    auto rec = parse_tls_record(data, len);
    if (!rec.valid || rec.content_type != 22) return hello;

    const uint8_t* hs = rec.fragment.data();
    size_t hs_len = rec.fragment.size();
    if (hs_len < 4) return hello;

    uint8_t hs_type = hs[0];
    if (hs_type != 1) return hello;

    uint32_t hs_length = read_u24(hs + 1);
    if (hs_length + 4 > hs_len) return hello;

    const uint8_t* ch = hs + 4;
    size_t ch_len = hs_length;
    size_t pos = 0;

    if (ch_len < 2 + 32) return hello;
    hello.version = read_u16(ch);
    pos = 2 + 32;


    if (pos >= ch_len) return hello;
    uint8_t sid_len = ch[pos]; pos++;
    pos += sid_len;


    if (pos + 2 > ch_len) return hello;
    uint16_t cs_len = read_u16(ch + pos); pos += 2;
    if (pos + cs_len > ch_len) return hello;
    for (uint16_t i = 0; i < cs_len; i += 2) {
        hello.cipher_suites.push_back(read_u16(ch + pos + i));
    }
    pos += cs_len;


    if (pos >= ch_len) return hello;
    uint8_t cm_len = ch[pos]; pos++;
    pos += cm_len;


    if (pos + 2 > ch_len) { hello.valid = true; return hello; }
    uint16_t ext_len = read_u16(ch + pos); pos += 2;
    size_t ext_end = pos + ext_len;
    if (ext_end > ch_len) ext_end = ch_len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = read_u16(ch + pos);
        uint16_t ext_data_len = read_u16(ch + pos + 2);
        pos += 4;
        if (pos + ext_data_len > ext_end) break;

        if (ext_type == 0x0000 && ext_data_len >= 2) {

            uint16_t sni_list_len = read_u16(ch + pos);
            size_t sni_pos = pos + 2;
            size_t sni_end = pos + sni_list_len + 2;
            if (sni_end > pos + ext_data_len) sni_end = pos + ext_data_len;

            while (sni_pos + 3 < sni_end) {
                uint8_t name_type = ch[sni_pos]; sni_pos++;
                uint16_t name_len = read_u16(ch + sni_pos); sni_pos += 2;
                if (name_type == 0 && sni_pos + name_len <= sni_end) {
                    hello.sni = std::string(reinterpret_cast<const char*>(ch + sni_pos), name_len);
                }
                sni_pos += name_len;
            }
        }
        else if (ext_type == 0x0010 && ext_data_len >= 2) {

            uint16_t alpn_list_len = read_u16(ch + pos);
            size_t alpn_pos = pos + 2;
            size_t alpn_end = pos + 2 + alpn_list_len;
            if (alpn_end > pos + ext_data_len) alpn_end = pos + ext_data_len;

            while (alpn_pos < alpn_end) {
                uint8_t proto_len = ch[alpn_pos]; alpn_pos++;
                if (alpn_pos + proto_len > alpn_end) break;
                hello.alpn_protocols.push_back(
                    std::string(reinterpret_cast<const char*>(ch + alpn_pos), proto_len));
                alpn_pos += proto_len;
            }
        }

        pos += ext_data_len;
    }

    hello.valid = true;
    return hello;
}

std::string tls_content_type_name(uint8_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "ApplicationData";
        default: return "Unknown(" + std::to_string(ct) + ")";
    }
}

std::string tls_version_name(uint16_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%04X", ver);
            return buf;
        }
    }
}


detection_result detect_protocol(const uint8_t* data, size_t len,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint32_t ip_protocol) {
    detection_result r;
    if (!data || len == 0) return r;


    if (ip_protocol == 17 && (src_port == 53 || dst_port == 53) && len >= 12) {
        r.protocol = detected_protocol_t::dns;
        r.label = "DNS";
        r.summary = (src_port == 53) ? "DNS Response" : "DNS Query";
        return r;
    }


    if (ip_protocol == 17 && is_quic_packet(data, len, dst_port)) {
        auto qh = parse_quic_header(data, len);
        r.protocol = detected_protocol_t::quic;
        r.label = "QUIC";
        if (qh.valid) {
            r.summary = qh.packet_type;
            if (!qh.version_name.empty()) r.summary += " " + qh.version_name;
            if (!qh.dcid.empty()) r.summary += " DCID=" + qh.dcid_hex();
            if (qh.is_version_negotiation && !qh.supported_versions.empty()) {
                r.summary += " (supports:";
                for (auto v : qh.supported_versions) {
                    r.summary += " " + quic_version_name(v);
                }
                r.summary += ")";
            }
            if (!qh.token.empty()) {
                r.summary += " token=" + std::to_string(qh.token.size()) + "B";
            }
            if (!qh.is_long_header) {
                r.summary += " (encrypted)";
            }
        } else {
            r.summary = "QUIC (encrypted)";
        }
        return r;
    }


    if (len >= 5 && data[0] >= 20 && data[0] <= 25 &&
        data[1] == 0x03 && data[2] <= 0x04) {
        auto rec = parse_tls_record(data, len);
        if (rec.valid) {
            r.protocol = detected_protocol_t::tls;
            r.label = "TLS";
            r.summary = tls_content_type_name(rec.content_type) + " " + tls_version_name(rec.version);
            if (rec.content_type == 22 && !rec.fragment.empty() && rec.fragment[0] == 1) {
                auto hello = parse_client_hello(data, len);
                if (hello.valid && !hello.sni.empty())
                    r.summary += " SNI=" + hello.sni;
            }
            return r;
        }
    }


    if (len >= 24 && memcmp(data, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
        r.protocol = detected_protocol_t::http2;
        r.label = "HTTP/2";
        r.summary = "Connection Preface";
        return r;
    }


    static const char* http_methods[] = { "GET ", "POST ", "PUT ", "DELETE ",
                                           "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE " };
    for (auto m : http_methods) {
        size_t mlen = strlen(m);
        if (len >= mlen && memcmp(data, m, mlen) == 0) {
            auto req = parse_http_request(data, len);
            if (req.valid) {
                r.protocol = detected_protocol_t::http_request;
                r.label = "HTTP";
                r.summary = req.method + " " + req.uri;
                return r;
            }
        }
    }


    if (len >= 12 && memcmp(data, "HTTP/", 5) == 0) {
        auto resp = parse_http_response(data, len);
        if (resp.valid) {
            r.protocol = detected_protocol_t::http_response;
            r.label = "HTTP";
            r.summary = std::to_string(resp.status_code) + " " + resp.reason;
            return r;
        }
    }

    r.protocol = detected_protocol_t::unknown;
    r.label = (ip_protocol == 6) ? "TCP" : ((ip_protocol == 17) ? "UDP" : "");
    return r;
}

}
