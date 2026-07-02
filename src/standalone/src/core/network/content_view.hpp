#pragma once

#include "protocol_parser.hpp"
#include "protobuf_codec.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

namespace network_content_view {

enum class view_kind_t {
    raw,
    json,
    xml,
    hex,
    form,
    protobuf,
    image
};

struct view_t {
    view_kind_t kind = view_kind_t::raw;
    std::string title;
    std::string meta;
    std::string text;
};

inline std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

inline std::string header_value(const std::vector<protocol_parser::http_header>& headers, const std::string& name)
{
    const std::string wanted = lower_copy(name);
    for (const auto& h : headers) {
        if (lower_copy(h.name) == wanted)
            return h.value;
    }
    return {};
}

inline bool is_image_content_type(const std::vector<protocol_parser::http_header>& headers)
{
    const std::string ct = lower_copy(header_value(headers, "Content-Type"));
    return ct.find("image/png") != std::string::npos ||
           ct.find("image/jpeg") != std::string::npos ||
           ct.find("image/jpg") != std::string::npos ||
           ct.find("image/bmp") != std::string::npos ||
           ct.find("image/gif") != std::string::npos ||
           ct.find("image/webp") != std::string::npos ||
           ct.find("image/tga") != std::string::npos;
}

inline std::vector<uint8_t> decoded_body(const std::vector<protocol_parser::http_header>& headers,
                                         const std::vector<uint8_t>& body)
{
    if (body.size() > 2ull * 1024ull * 1024ull)
        return body;
    const std::string enc = header_value(headers, "Content-Encoding");
    if (enc.empty())
        return body;
    return protocol_parser::decompress_body(body, enc);
}

inline std::string bytes_to_text(const std::vector<uint8_t>& bytes, size_t cap = 524288)
{
    const size_t n = std::min(bytes.size(), cap);
    std::string out;
    out.reserve(n + 64);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = bytes[i];
        out.push_back((c >= 0x20 || c == '\n' || c == '\r' || c == '\t') ? static_cast<char>(c) : '.');
    }
    if (bytes.size() > n) {
        out += "\n\n[truncated ";
        out += std::to_string(bytes.size() - n);
        out += " bytes]";
    }
    return out;
}

inline std::string hex_dump(const std::vector<uint8_t>& bytes, size_t cap = 262144)
{
    const size_t n = std::min(bytes.size(), cap);
    std::string out;
    out.reserve(n * 4);
    char line[128];
    for (size_t off = 0; off < n; off += 16) {
        int pos = std::snprintf(line, sizeof(line), "%08zx  ", off);
        for (size_t j = 0; j < 16; ++j) {
            if (off + j < n)
                pos += std::snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02X ", bytes[off + j]);
            else
                pos += std::snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
        }
        pos += std::snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
        for (size_t j = 0; j < 16 && off + j < n; ++j) {
            const unsigned char c = bytes[off + j];
            line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
        }
        line[pos++] = '\n';
        line[pos] = '\0';
        out += line;
    }
    if (bytes.size() > n) {
        out += "\n[truncated ";
        out += std::to_string(bytes.size() - n);
        out += " bytes]";
    }
    return out;
}

inline int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline std::string url_decode(std::string value)
{
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '+' ) {
            out.push_back(' ');
        } else if (value[i] == '%' && i + 2 < value.size()) {
            const int a = hex_value(value[i + 1]);
            const int b = hex_value(value[i + 2]);
            if (a >= 0 && b >= 0) {
                out.push_back(static_cast<char>((a << 4) | b));
                i += 2;
            } else {
                out.push_back(value[i]);
            }
        } else {
            out.push_back(value[i]);
        }
    }
    return out;
}

inline std::string format_form(const std::vector<uint8_t>& bytes)
{
    const std::string raw(bytes.begin(), bytes.end());
    std::ostringstream out;
    size_t start = 0;
    while (start <= raw.size()) {
        size_t amp = raw.find('&', start);
        if (amp == std::string::npos) amp = raw.size();
        const std::string part = raw.substr(start, amp - start);
        const size_t eq = part.find('=');
        if (eq == std::string::npos)
            out << url_decode(part) << "\n";
        else
            out << url_decode(part.substr(0, eq)) << " = " << url_decode(part.substr(eq + 1)) << "\n";
        if (amp == raw.size()) break;
        start = amp + 1;
    }
    return out.str();
}

inline std::string format_json(const std::vector<uint8_t>& bytes)
{
    const std::string text(bytes.begin(), bytes.end());
    const auto parsed = nlohmann::json::parse(text, nullptr, false);
    if (parsed.is_discarded())
        return {};
    return parsed.dump(2);
}

inline std::string format_xml(const std::vector<uint8_t>& bytes)
{
    const std::string input(bytes.begin(), bytes.end());
    std::string out;
    int indent = 0;
    bool in_tag = false;
    bool last_was_tag = false;
    for (size_t i = 0; i < input.size(); ++i) {
        const char c = input[i];
        if (c == '<') {
            const bool closing = i + 1 < input.size() && input[i + 1] == '/';
            const bool declaration = i + 1 < input.size() && (input[i + 1] == '?' || input[i + 1] == '!');
            if (closing && indent > 0)
                --indent;
            if (!out.empty() && out.back() != '\n')
                out.push_back('\n');
            out.append(static_cast<size_t>(std::max(0, indent)) * 2, ' ');
            in_tag = true;
            last_was_tag = true;
            out.push_back(c);
            if (!closing && !declaration) {
                const size_t close = input.find('>', i + 1);
                if (close != std::string::npos && close > i && input[close - 1] != '/')
                    ++indent;
            }
        } else if (c == '>') {
            out.push_back(c);
            in_tag = false;
            if (last_was_tag)
                out.push_back('\n');
        } else {
            if (!in_tag && std::isspace(static_cast<unsigned char>(c)) && (out.empty() || out.back() == '\n'))
                continue;
            out.push_back(c);
            if (!std::isspace(static_cast<unsigned char>(c)))
                last_was_tag = false;
        }
    }
    return out.empty() ? bytes_to_text(bytes) : out;
}

inline void append_protobuf_field(std::ostringstream& out, const protobuf_codec::field_t& field)
{
    out << std::string(static_cast<size_t>(field.depth) * 2, ' ')
        << field.field_number << " ";
    switch (field.wire_type) {
        case protobuf_codec::wire_type_t::varint: out << "varint"; break;
        case protobuf_codec::wire_type_t::fixed64: out << "fixed64"; break;
        case protobuf_codec::wire_type_t::length_delimited: out << "len"; break;
        case protobuf_codec::wire_type_t::fixed32: out << "fixed32"; break;
    }
    out << " = " << protobuf_codec::format_field_value(field) << "\n";
    for (const auto& nested : field.nested_fields)
        append_protobuf_field(out, nested);
}

inline std::string format_protobuf(const std::vector<uint8_t>& bytes)
{
    if (bytes.empty())
        return {};
    auto fields = protobuf_codec::decode(bytes.data(), bytes.size());
    if (fields.empty())
        return {};
    protobuf_codec::auto_detect_types(fields);
    std::ostringstream out;
    for (const auto& field : fields)
        append_protobuf_field(out, field);
    return out.str();
}

inline std::string format_grpc_protobuf(const std::vector<uint8_t>& bytes)
{
    auto frames = protobuf_codec::parse_grpc_frames(bytes.data(), bytes.size());
    if (frames.empty())
        return {};
    std::ostringstream out;
    for (size_t i = 0; i < frames.size(); ++i) {
        out << "frame " << i << " compressed=" << static_cast<int>(frames[i].compressed)
            << " length=" << frames[i].length << "\n";
        auto fields = protobuf_codec::decode(frames[i].data.data(), frames[i].data.size());
        if (fields.empty()) {
            out << network_content_view::hex_dump(frames[i].data, 4096);
        } else {
            protobuf_codec::auto_detect_types(fields);
            for (const auto& field : fields)
                append_protobuf_field(out, field);
        }
        out << "\n";
    }
    return out.str();
}

inline std::vector<view_t> build_views(const std::vector<protocol_parser::http_header>& headers,
                                       const std::vector<uint8_t>& body)
{
    std::vector<view_t> views;
    const auto decoded = decoded_body(headers, body);
    const std::string ct_header = lower_copy(header_value(headers, "Content-Type"));
    protocol_parser::content_type_t ct = protocol_parser::content_type_t::binary;
    if (ct_header.empty()) ct = protocol_parser::content_type_t::unknown;
    else if (ct_header.find("json") != std::string::npos) ct = protocol_parser::content_type_t::json;
    else if (ct_header.find("xml") != std::string::npos) ct = protocol_parser::content_type_t::xml;
    else if (ct_header.find("text/html") != std::string::npos) ct = protocol_parser::content_type_t::html;
    else if (ct_header.find("text/") != std::string::npos) ct = protocol_parser::content_type_t::text;
    else if (ct_header.find("application/x-www-form-urlencoded") != std::string::npos) ct = protocol_parser::content_type_t::form_urlencoded;
    else if (ct_header.find("multipart/") != std::string::npos) ct = protocol_parser::content_type_t::multipart;

    views.push_back({view_kind_t::raw, "Raw", std::to_string(decoded.size()) + " bytes", bytes_to_text(decoded)});

    const std::string pretty_json = decoded.size() <= 1024ull * 1024ull ? format_json(decoded) : std::string();
    if (!pretty_json.empty() || ct == protocol_parser::content_type_t::json) {
        const bool too_large = decoded.size() > 1024ull * 1024ull;
        views.push_back({view_kind_t::json, "JSON", too_large ? "too large for pretty view" : (pretty_json.empty() ? "invalid JSON" : "pretty"),
                         too_large ? bytes_to_text(decoded) : (pretty_json.empty() ? bytes_to_text(decoded) : pretty_json)});
    }

    if (ct == protocol_parser::content_type_t::xml || ct_header.find("+xml") != std::string::npos)
        views.push_back({view_kind_t::xml, "XML", decoded.size() <= 1024ull * 1024ull ? "formatted" : "too large for formatted view",
                         decoded.size() <= 1024ull * 1024ull ? format_xml(decoded) : bytes_to_text(decoded)});

    if (ct == protocol_parser::content_type_t::form_urlencoded)
        views.push_back({view_kind_t::form, "Form", decoded.size() <= 1024ull * 1024ull ? "urlencoded" : "too large for parsed view",
                         decoded.size() <= 1024ull * 1024ull ? format_form(decoded) : bytes_to_text(decoded)});

    const bool protobuf_hint = ct_header.find("protobuf") != std::string::npos ||
                               ct_header.find("grpc") != std::string::npos ||
                               ct_header.find("x-protobuf") != std::string::npos;
    std::string protobuf_text;
    if (protobuf_hint && decoded.size() <= 262144ull)
        protobuf_text = ct_header.find("grpc") != std::string::npos ? format_grpc_protobuf(decoded) : format_protobuf(decoded);
    if (!protobuf_text.empty())
        views.push_back({view_kind_t::protobuf, "Protobuf", "wire fields", protobuf_text});

    if (is_image_content_type(headers))
        views.push_back({view_kind_t::image, "Image", header_value(headers, "Content-Type"), {}});

    views.push_back({view_kind_t::hex, "Hex", std::to_string(decoded.size()) + " bytes", hex_dump(decoded)});
    return views;
}

}
