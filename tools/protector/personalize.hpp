#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <functional>

#include "pe_file.hpp"
#include "transforms.hpp"

namespace protector {
namespace personalize {

constexpr uint32_t kKeySlotMagicWbAes   = 0xCAFE0000u;
constexpr uint32_t kKeySlotMagicArc    = 0xCAFE0001u;
constexpr uint32_t kKeySlotMagicDriver = 0xCAFE0002u;
constexpr uint32_t kTemplateMagicMarker = 0xDEAD0001u;
constexpr uint32_t kPersonalizeTimeoutMs = 60000u;
constexpr uint32_t kMinWatermarkSites = 5000u;
constexpr uint32_t kWbaesTableSize = 188448u;
constexpr uint32_t kArcPageKeySize = 8192u;
constexpr uint32_t kDriverKeySlotSize = 64u;
constexpr uint32_t kArcPageCount = 256u;
constexpr uint32_t kArcKeyLen = 32u;
constexpr uint32_t kDriverKeyCount = 2u;
constexpr uint32_t kDriverKeyLen = 32u;

inline void hex_string_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            clean.push_back(c);
        }
    }
    if (clean.size() % 2 != 0) return;
    out.reserve(clean.size() / 2);
    auto hexv = [](char c, int& v) -> bool {
        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
        return false;
    };
    for (size_t i = 0; i < clean.size(); i += 2) {
        int hi = 0, lo = 0;
        if (!hexv(clean[i], hi) || !hexv(clean[i + 1], lo)) return;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
}

inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xF]);
        out.push_back(kHex[data[i] & 0xF]);
    }
    return out;
}

inline std::string bytes_to_hex_spaced(const uint8_t* data, size_t len) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 3);
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) out.push_back(' ');
        out.push_back(kHex[(data[i] >> 4) & 0xF]);
        out.push_back(kHex[data[i] & 0xF]);
    }
    return out;
}

inline uint32_t parse_hex_u32(const std::string& s) {
    if (s.empty()) return 0;
    uint32_t v = 0;
    const char* p = s.c_str();
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    while (*p) {
        char c = *p;
        uint32_t digit = 0;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        v = (v << 4) | digit;
        ++p;
    }
    return v;
}

inline uint64_t parse_hex_u64(const std::string& s) {
    if (s.empty()) return 0;
    uint64_t v = 0;
    const char* p = s.c_str();
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    while (*p) {
        char c = *p;
        uint64_t digit = 0;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        v = (v << 4) | digit;
        ++p;
    }
    return v;
}

struct json_value_t {
    enum class kind_t { null, boolean, number, string_val, array, object } kind = kind_t::null;
    bool boolean = false;
    double number = 0.0;
    std::string str;
    std::vector<json_value_t> arr;
    std::vector<std::pair<std::string, json_value_t>> obj;

    const json_value_t* find(const std::string& key) const {
        if (kind != kind_t::object) return nullptr;
        for (const auto& kv : obj) {
            if (kv.first == key) return &kv.second;
        }
        return nullptr;
    }

    std::string as_string() const {
        if (kind == kind_t::string_val) return str;
        if (kind == kind_t::number) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%g", number);
            return buf;
        }
        return {};
    }

    double as_number() const {
        if (kind == kind_t::number) return number;
        if (kind == kind_t::string_val) {
            if (!str.empty() && (str[0] == '0' && str.size() > 1 && (str[1] == 'x' || str[1] == 'X'))) {
                return static_cast<double>(parse_hex_u64(str));
            }
            try { return std::stod(str); } catch (...) { return 0.0; }
        }
        return 0.0;
    }

    uint32_t as_u32() const {
        return static_cast<uint32_t>(as_number());
    }

    uint64_t as_u64() const {
        return static_cast<uint64_t>(as_number());
    }

    bool as_bool() const {
        if (kind == kind_t::boolean) return boolean;
        return false;
    }
};

class json_parser_t {
    const char* p_;
    const char* end_;

    void skip_ws() {
        while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) ++p_;
    }

    char peek() { return p_ < end_ ? *p_ : '\0'; }
    char next() { return p_ < end_ ? *p_++ : '\0'; }

    void expect(char c) {
        skip_ws();
        if (peek() != c) throw std::runtime_error(std::string("JSON parse: expected '") + c + "'");
        ++p_;
    }

    json_value_t parse_string_val() {
        json_value_t v;
        v.kind = json_value_t::kind_t::string_val;
        expect('"');
        std::string s;
        while (p_ < end_ && *p_ != '"') {
            if (*p_ == '\\') {
                ++p_;
                if (p_ >= end_) break;
                char esc = *p_++;
                switch (esc) {
                    case 'n': s.push_back('\n'); break;
                    case 't': s.push_back('\t'); break;
                    case 'r': s.push_back('\r'); break;
                    case '"': s.push_back('"'); break;
                    case '\\': s.push_back('\\'); break;
                    case '/': s.push_back('/'); break;
                    case 'u': {
                        if (p_ + 4 > end_) break;
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            cp <<= 4;
                            char c = *p_++;
                            if (c >= '0' && c <= '9') cp |= c - '0';
                            else if (c >= 'a' && c <= 'f') cp |= c - 'a' + 10;
                            else if (c >= 'A' && c <= 'F') cp |= c - 'A' + 10;
                        }
                        if (cp < 0x80) s.push_back(static_cast<char>(cp));
                        else if (cp < 0x800) {
                            s.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        } else {
                            s.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                            s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: s.push_back(esc); break;
                }
            } else {
                s.push_back(*p_++);
            }
        }
        if (p_ < end_) ++p_;
        v.str = std::move(s);
        return v;
    }

    json_value_t parse_number_val() {
        json_value_t v;
        v.kind = json_value_t::kind_t::number;
        const char* start = p_;
        if (peek() == '-') ++p_;
        while (p_ < end_ && ((*p_ >= '0' && *p_ <= '9') || *p_ == '.' || *p_ == 'e' || *p_ == 'E' || *p_ == '+' || *p_ == '-')) ++p_;
        std::string num(start, p_ - start);
        try { v.number = std::stod(num); } catch (...) { v.number = 0.0; }
        return v;
    }

    json_value_t parse_value() {
        skip_ws();
        char c = peek();
        if (c == '{') return parse_object_val();
        if (c == '[') return parse_array_val();
        if (c == '"') return parse_string_val();
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number_val();
        if (p_ + 4 <= end_ && std::strncmp(p_, "true", 4) == 0) { p_ += 4; json_value_t v; v.kind = json_value_t::kind_t::boolean; v.boolean = true; return v; }
        if (p_ + 5 <= end_ && std::strncmp(p_, "false", 5) == 0) { p_ += 5; json_value_t v; v.kind = json_value_t::kind_t::boolean; v.boolean = false; return v; }
        if (p_ + 4 <= end_ && std::strncmp(p_, "null", 4) == 0) { p_ += 4; json_value_t v; v.kind = json_value_t::kind_t::null; return v; }
        throw std::runtime_error("JSON parse: unexpected character");
    }

    json_value_t parse_object_val() {
        json_value_t v;
        v.kind = json_value_t::kind_t::object;
        expect('{');
        skip_ws();
        if (peek() == '}') { ++p_; return v; }
        for (;;) {
            skip_ws();
            json_value_t key = parse_string_val();
            skip_ws();
            expect(':');
            json_value_t val = parse_value();
            v.obj.emplace_back(key.str, std::move(val));
            skip_ws();
            char c = next();
            if (c == '}') break;
            if (c != ',') throw std::runtime_error("JSON parse: expected ',' or '}'");
        }
        return v;
    }

    json_value_t parse_array_val() {
        json_value_t v;
        v.kind = json_value_t::kind_t::array;
        expect('[');
        skip_ws();
        if (peek() == ']') { ++p_; return v; }
        for (;;) {
            v.arr.push_back(parse_value());
            skip_ws();
            char c = next();
            if (c == ']') break;
            if (c != ',') throw std::runtime_error("JSON parse: expected ',' or ']'");
        }
        return v;
    }

public:
    json_parser_t(const char* data, size_t len) : p_(data), end_(data + len) {}

    json_value_t parse() {
        skip_ws();
        json_value_t v = parse_value();
        return v;
    }
};

struct watermark_site_meta_t {
    uint32_t offset;
    uint32_t rva;
    uint32_t type;
    uint32_t bit_index;
    std::vector<uint8_t> encoding_a;
    std::vector<uint8_t> encoding_b;
    uint32_t slot_magic;
};

struct key_slot_meta_t {
    uint32_t offset;
    uint32_t size;
    uint32_t magic;
};

struct key_slots_meta_t {
    key_slot_meta_t wb_aes_tables;
    key_slot_meta_t arc_page_keys;
    key_slot_meta_t driver_keys;
};

struct pe_info_meta_t {
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t entry_point;
    uint32_t file_alignment;
    uint32_t section_alignment;
};

struct pe_section_info_t {
    char name[9];
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t characteristics;
};

struct packed_header_meta_t {
    uint32_t magic;
    uint32_t version;
    uint32_t packed_section_rva;
    uint32_t packed_offset_in_section;
    uint32_t section_count;
    uint32_t import_count;
    uint32_t aux_offset;
    uint32_t aux_size;
    uint32_t master_key_offset;
    uint32_t stub_code_offset;
};

struct master_key_consistency_t {
    std::string test_uuid_hex;
    std::string expected_customer_seed;
    std::string info_string;
};

struct template_metadata_t {
    std::string template_version;
    std::string build_hash_hex;
    std::string template_hash_hex;
    std::string metadata_self_hash;
    pe_info_meta_t pe_info;
    std::vector<pe_section_info_t> pe_sections;
    std::vector<watermark_site_meta_t> watermark_sites;
    key_slots_meta_t key_slots;
    packed_header_meta_t packed_header;
    uint32_t watermark_total_sites;
    uint32_t watermark_uuid_bits;
    uint32_t watermark_redundancy;
    master_key_consistency_t master_key_consistency;
};

inline std::string read_file_to_string(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) throw std::runtime_error("Failed to open: " + path);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return content;
}

inline std::vector<uint8_t> read_file_to_bytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) throw std::runtime_error("Failed to open: " + path);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return data;
}

inline void compute_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    sha256_detail::sha256(data, len, out);
}

inline std::string compute_file_sha256_hex(const std::string& path) {
    std::vector<uint8_t> data = read_file_to_bytes(path);
    uint8_t hash[32];
    compute_sha256(data.data(), data.size(), hash);
    return bytes_to_hex(hash, 32);
}

inline std::string json_escape_string(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

inline std::string serialize_metadata_canonical(const template_metadata_t& meta, bool include_self_hash) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(0);

    ss << "{";

    ss << "\"build_hash_hex\":\"" << json_escape_string(meta.build_hash_hex) << "\"";
    ss << ",\"key_slots\":{";
    ss << "\"arc_page_keys\":{\"magic\":\"0x" << std::hex << meta.key_slots.arc_page_keys.magic << std::dec << "\",\"offset\":\"0x" << std::hex << meta.key_slots.arc_page_keys.offset << std::dec << "\",\"size\":" << meta.key_slots.arc_page_keys.size << "}";
    ss << ",\"driver_keys\":{\"magic\":\"0x" << std::hex << meta.key_slots.driver_keys.magic << std::dec << "\",\"offset\":\"0x" << std::hex << meta.key_slots.driver_keys.offset << std::dec << "\",\"size\":" << meta.key_slots.driver_keys.size << "}";
    ss << ",\"wb_aes_tables\":{\"magic\":\"0x" << std::hex << meta.key_slots.wb_aes_tables.magic << std::dec << "\",\"offset\":\"0x" << std::hex << meta.key_slots.wb_aes_tables.offset << std::dec << "\",\"size\":" << meta.key_slots.wb_aes_tables.size << "}";
    ss << "}";

    ss << ",\"master_key_consistency_check\":{";
    ss << "\"expected_customer_seed\":\"" << json_escape_string(meta.master_key_consistency.expected_customer_seed) << "\"";
    ss << ",\"info_string\":\"" << json_escape_string(meta.master_key_consistency.info_string) << "\"";
    ss << ",\"test_uuid\":\"" << json_escape_string(meta.master_key_consistency.test_uuid_hex) << "\"";
    ss << "}";

    if (include_self_hash) {
        ss << ",\"metadata_self_hash\":\"" << json_escape_string(meta.metadata_self_hash) << "\"";
    }

    ss << ",\"packed_header\":{";
    ss << "\"aux_offset\":\"0x" << std::hex << meta.packed_header.aux_offset << std::dec << "\"";
    ss << ",\"aux_size\":" << meta.packed_header.aux_size;
    ss << ",\"import_count\":" << meta.packed_header.import_count;
    ss << ",\"magic\":\"0x" << std::hex << meta.packed_header.magic << std::dec << "\"";
    ss << ",\"master_key_offset\":\"0x" << std::hex << meta.packed_header.master_key_offset << std::dec << "\"";
    ss << ",\"packed_offset_in_section\":\"0x" << std::hex << meta.packed_header.packed_offset_in_section << std::dec << "\"";
    ss << ",\"packed_section_rva\":\"0x" << std::hex << meta.packed_header.packed_section_rva << std::dec << "\"";
    ss << ",\"section_count\":" << meta.packed_header.section_count;
    ss << ",\"stub_code_offset\":\"0x" << std::hex << meta.packed_header.stub_code_offset << std::dec << "\"";
    ss << ",\"version\":\"0x" << std::hex << meta.packed_header.version << std::dec << "\"";
    ss << "}";

    ss << ",\"pe_info\":{";
    ss << "\"entry_point\":\"0x" << std::hex << meta.pe_info.entry_point << std::dec << "\"";
    ss << ",\"file_alignment\":" << meta.pe_info.file_alignment;
    ss << ",\"image_base\":\"0x" << std::hex << meta.pe_info.image_base << std::dec << "\"";
    ss << ",\"section_alignment\":" << meta.pe_info.section_alignment;
    ss << ",\"size_of_image\":\"0x" << std::hex << meta.pe_info.size_of_image << std::dec << "\"";
    ss << "}";

    ss << ",\"pe_sections\":[";
    for (size_t i = 0; i < meta.pe_sections.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "{\"characteristics\":\"0x" << std::hex << meta.pe_sections[i].characteristics << std::dec << "\"";
        ss << ",\"name\":\"" << json_escape_string(meta.pe_sections[i].name) << "\"";
        ss << ",\"raw_offset\":\"0x" << std::hex << meta.pe_sections[i].raw_offset << std::dec << "\"";
        ss << ",\"raw_size\":\"0x" << std::hex << meta.pe_sections[i].raw_size << std::dec << "\"";
        ss << ",\"virtual_address\":\"0x" << std::hex << meta.pe_sections[i].virtual_address << std::dec << "\"";
        ss << ",\"virtual_size\":\"0x" << std::hex << meta.pe_sections[i].virtual_size << std::dec << "\"";
        ss << "}";
    }
    ss << "]";

    ss << ",\"template_hash\":\"" << json_escape_string(meta.template_hash_hex) << "\"";
    ss << ",\"template_version\":\"" << json_escape_string(meta.template_version) << "\"";

    ss << ",\"watermark_redundancy\":{";
    ss << "\"redundancy_factor\":" << meta.watermark_redundancy;
    ss << ",\"total_sites\":" << meta.watermark_total_sites;
    ss << ",\"uuid_bits\":" << meta.watermark_uuid_bits;
    ss << "}";

    ss << ",\"watermark_sites\":[";
    for (size_t i = 0; i < meta.watermark_sites.size(); ++i) {
        if (i > 0) ss << ",";
        const auto& s = meta.watermark_sites[i];
        ss << "{\"bit_index\":" << s.bit_index;
        ss << ",\"encoding_a_hex\":\"" << bytes_to_hex_spaced(s.encoding_a.data(), s.encoding_a.size()) << "\"";
        ss << ",\"encoding_b_hex\":\"" << bytes_to_hex_spaced(s.encoding_b.data(), s.encoding_b.size()) << "\"";
        ss << ",\"offset\":\"0x" << std::hex << s.offset << std::dec << "\"";
        ss << ",\"rva\":\"0x" << std::hex << s.rva << std::dec << "\"";
        ss << ",\"slot_magic\":\"0x" << std::hex << s.slot_magic << std::dec << "\"";
        ss << ",\"type\":\"";
        switch (s.type) {
            case 0: ss << "branch"; break;
            case 1: ss << "nop"; break;
            case 2: ss << "reg_alloc"; break;
            case 3: ss << "bb_order"; break;
            default: ss << "unknown"; break;
        }
        ss << "\"}";
    }
    ss << "]";

    ss << "}";
    return ss.str();
}

inline std::string compute_metadata_self_hash(const template_metadata_t& meta) {
    std::string canonical = serialize_metadata_canonical(meta, false);
    uint8_t hash[32];
    compute_sha256(reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size(), hash);
    return bytes_to_hex(hash, 32);
}

inline bool verify_metadata_self_hash(const template_metadata_t& meta) {
    std::string computed = compute_metadata_self_hash(meta);
    return computed == meta.metadata_self_hash;
}

inline template_metadata_t parse_template_metadata(const std::string& json_text) {
    template_metadata_t meta{};
    json_parser_t parser(json_text.data(), json_text.size());
    json_value_t root = parser.parse();

    if (root.kind != json_value_t::kind_t::object) {
        throw std::runtime_error("metadata root is not an object");
    }

    const json_value_t* v;

    v = root.find("template_version");
    if (v) meta.template_version = v->as_string();

    v = root.find("build_hash");
    if (v) meta.build_hash_hex = v->as_string();
    v = root.find("build_hash_hex");
    if (v) meta.build_hash_hex = v->as_string();

    v = root.find("template_hash");
    if (v) meta.template_hash_hex = v->as_string();

    v = root.find("metadata_self_hash");
    if (v) meta.metadata_self_hash = v->as_string();

    v = root.find("pe_info");
    if (v && v->kind == json_value_t::kind_t::object) {
        const json_value_t* pi;
        pi = v->find("image_base");
        if (pi) meta.pe_info.image_base = parse_hex_u64(pi->as_string());
        pi = v->find("size_of_image");
        if (pi) meta.pe_info.size_of_image = parse_hex_u32(pi->as_string());
        pi = v->find("entry_point");
        if (pi) meta.pe_info.entry_point = parse_hex_u32(pi->as_string());
        pi = v->find("file_alignment");
        if (pi) meta.pe_info.file_alignment = static_cast<uint32_t>(pi->as_number());
        pi = v->find("section_alignment");
        if (pi) meta.pe_info.section_alignment = static_cast<uint32_t>(pi->as_number());
    }

    v = root.find("pe_sections");
    if (v && v->kind == json_value_t::kind_t::array) {
        for (const auto& sec : v->arr) {
            pe_section_info_t si{};
            std::memset(si.name, 0, sizeof(si.name));
            const json_value_t* sv;
            sv = sec.find("name");
            if (sv) {
                std::string nm = sv->as_string();
                size_t cl = nm.size() < 8 ? nm.size() : 8;
                std::memcpy(si.name, nm.data(), cl);
                si.name[cl] = '\0';
            }
            sv = sec.find("virtual_address");
            if (sv) si.virtual_address = parse_hex_u32(sv->as_string());
            sv = sec.find("virtual_size");
            if (sv) si.virtual_size = parse_hex_u32(sv->as_string());
            sv = sec.find("raw_size");
            if (sv) si.raw_size = parse_hex_u32(sv->as_string());
            sv = sec.find("raw_offset");
            if (sv) si.raw_offset = parse_hex_u32(sv->as_string());
            sv = sec.find("characteristics");
            if (sv) si.characteristics = parse_hex_u32(sv->as_string());
            meta.pe_sections.push_back(si);
        }
    }

    v = root.find("watermark_sites");
    if (v && v->kind == json_value_t::kind_t::array) {
        for (const auto& site : v->arr) {
            watermark_site_meta_t ws{};
            const json_value_t* sv;
            sv = site.find("offset");
            if (sv) ws.offset = parse_hex_u32(sv->as_string());
            sv = site.find("rva");
            if (sv) ws.rva = parse_hex_u32(sv->as_string());
            sv = site.find("type");
            if (sv) {
                std::string t = sv->as_string();
                if (t == "branch") ws.type = 0;
                else if (t == "nop") ws.type = 1;
                else if (t == "reg_alloc") ws.type = 2;
                else if (t == "bb_order") ws.type = 3;
                else ws.type = static_cast<uint32_t>(sv->as_number());
            }
            sv = site.find("bit_index");
            if (sv) ws.bit_index = static_cast<uint32_t>(sv->as_number());
            sv = site.find("encoding_a_hex");
            if (sv) hex_string_to_bytes(sv->as_string(), ws.encoding_a);
            sv = site.find("encoding_b_hex");
            if (sv) hex_string_to_bytes(sv->as_string(), ws.encoding_b);
            sv = site.find("slot_magic");
            if (sv) ws.slot_magic = parse_hex_u32(sv->as_string());
            meta.watermark_sites.push_back(std::move(ws));
        }
    }

    v = root.find("key_slots");
    if (v && v->kind == json_value_t::kind_t::object) {
        const json_value_t* ks;
        ks = v->find("wb_aes_tables");
        if (ks) {
            const json_value_t* sv;
            sv = ks->find("offset");
            if (sv) meta.key_slots.wb_aes_tables.offset = parse_hex_u32(sv->as_string());
            sv = ks->find("size");
            if (sv) meta.key_slots.wb_aes_tables.size = static_cast<uint32_t>(sv->as_number());
            sv = ks->find("magic");
            if (sv) meta.key_slots.wb_aes_tables.magic = parse_hex_u32(sv->as_string());
        }
        ks = v->find("arc_page_keys");
        if (ks) {
            const json_value_t* sv;
            sv = ks->find("offset");
            if (sv) meta.key_slots.arc_page_keys.offset = parse_hex_u32(sv->as_string());
            sv = ks->find("size");
            if (sv) meta.key_slots.arc_page_keys.size = static_cast<uint32_t>(sv->as_number());
            sv = ks->find("magic");
            if (sv) meta.key_slots.arc_page_keys.magic = parse_hex_u32(sv->as_string());
        }
        ks = v->find("driver_keys");
        if (ks) {
            const json_value_t* sv;
            sv = ks->find("offset");
            if (sv) meta.key_slots.driver_keys.offset = parse_hex_u32(sv->as_string());
            sv = ks->find("size");
            if (sv) meta.key_slots.driver_keys.size = static_cast<uint32_t>(sv->as_number());
            sv = ks->find("magic");
            if (sv) meta.key_slots.driver_keys.magic = parse_hex_u32(sv->as_string());
        }
    }

    v = root.find("packed_header");
    if (v && v->kind == json_value_t::kind_t::object) {
        const json_value_t* sv;
        sv = v->find("magic");
        if (sv) meta.packed_header.magic = parse_hex_u32(sv->as_string());
        sv = v->find("version");
        if (sv) meta.packed_header.version = parse_hex_u32(sv->as_string());
        sv = v->find("packed_section_rva");
        if (sv) meta.packed_header.packed_section_rva = parse_hex_u32(sv->as_string());
        sv = v->find("packed_offset_in_section");
        if (sv) meta.packed_header.packed_offset_in_section = parse_hex_u32(sv->as_string());
        sv = v->find("section_count");
        if (sv) meta.packed_header.section_count = static_cast<uint32_t>(sv->as_number());
        sv = v->find("import_count");
        if (sv) meta.packed_header.import_count = static_cast<uint32_t>(sv->as_number());
        sv = v->find("aux_offset");
        if (sv) meta.packed_header.aux_offset = parse_hex_u32(sv->as_string());
        sv = v->find("aux_size");
        if (sv) meta.packed_header.aux_size = static_cast<uint32_t>(sv->as_number());
        sv = v->find("master_key_offset");
        if (sv) meta.packed_header.master_key_offset = parse_hex_u32(sv->as_string());
        sv = v->find("stub_code_offset");
        if (sv) meta.packed_header.stub_code_offset = parse_hex_u32(sv->as_string());
    }

    v = root.find("watermark_redundancy");
    if (v && v->kind == json_value_t::kind_t::object) {
        const json_value_t* sv;
        sv = v->find("total_sites");
        if (sv) meta.watermark_total_sites = static_cast<uint32_t>(sv->as_number());
        sv = v->find("uuid_bits");
        if (sv) meta.watermark_uuid_bits = static_cast<uint32_t>(sv->as_number());
        sv = v->find("redundancy_factor");
        if (sv) meta.watermark_redundancy = static_cast<uint32_t>(sv->as_number());
    }

    v = root.find("master_key_consistency_check");
    if (v && v->kind == json_value_t::kind_t::object) {
        const json_value_t* sv;
        sv = v->find("test_uuid");
        if (sv) meta.master_key_consistency.test_uuid_hex = sv->as_string();
        sv = v->find("expected_customer_seed");
        if (sv) meta.master_key_consistency.expected_customer_seed = sv->as_string();
        sv = v->find("info_string");
        if (sv) meta.master_key_consistency.info_string = sv->as_string();
    }

    return meta;
}

struct customer_keys_t {
    uint8_t customer_seed[32];
    uint8_t wb_aes_key[32];
    uint8_t arc_seed[32];
    uint8_t driver_keys[2][32];
    uint8_t arc_page_keys[256][32];
    aes_detail::wbaes_table_t* wb_aes_table;
};

inline bool hkdf_self_test_rfc5869() {
    static const uint8_t kIkm[22] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t kSalt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c
    };
    static const uint8_t kInfo[10] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    static const uint8_t kExpectedPrk[32] = {
        0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,
        0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
        0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,
        0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5
    };
    static const uint8_t kExpectedOkm[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
        0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
        0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
        0x58,0x65
    };

    uint8_t prk[32];
    sha256_detail::hkdf_extract(kSalt, sizeof(kSalt), kIkm, sizeof(kIkm), prk);
    if (std::memcmp(prk, kExpectedPrk, 32) != 0) return false;

    uint8_t okm[42];
    sha256_detail::hkdf_expand(prk, kInfo, sizeof(kInfo), okm, sizeof(okm));
    if (std::memcmp(okm, kExpectedOkm, 42) != 0) return false;

    return true;
}

inline bool verify_master_key_consistency(
    const uint8_t master_key[32],
    const template_metadata_t& meta) {

    uint8_t test_uuid[16] = {0};
    std::vector<uint8_t> tmp;
    hex_string_to_bytes(meta.master_key_consistency.test_uuid_hex, tmp);
    if (tmp.size() == 16) {
        std::memcpy(test_uuid, tmp.data(), 16);
    }

    std::string info_str = meta.master_key_consistency.info_string;
    std::vector<uint8_t> info_buf;
    info_buf.insert(info_buf.end(), test_uuid, test_uuid + 16);
    info_buf.insert(info_buf.end(), info_str.begin(), info_str.end());

    uint8_t derived_seed[32];
    sha256_detail::hkdf_sha256(
        master_key, 32,
        nullptr, 0,
        info_buf.data(), info_buf.size(),
        derived_seed, 32);

    std::string derived_hex = bytes_to_hex(derived_seed, 32);
    SecureZeroMemory(derived_seed, sizeof(derived_seed));

    return derived_hex == meta.master_key_consistency.expected_customer_seed;
}

inline void extract_master_key_from_template(
    const pe_file::pe_image_t& pe,
    uint8_t out_master_key[32]) {

    const pe_file::section_t* packed_sec = nullptr;
    for (const auto& s : pe.sections) {
        if (section_skip_list::name_equals(s.name, ".packed")) {
            packed_sec = &s;
            break;
        }
    }
    if (!packed_sec) throw std::runtime_error("extract_master_key: .packed section not found");

    packed_header_t hdr{};
    bool found = false;
    uint32_t packed_off = 0;
    for (size_t off = 0; off + sizeof(packed_header_t) <= packed_sec->data.size(); off += 8) {
        std::memcpy(&hdr, packed_sec->data.data() + off, sizeof(hdr));
        if (hdr.magic == kPackedMagic && hdr.version == kPackedVersion) {
            packed_off = static_cast<uint32_t>(off);
            found = true;
            break;
        }
    }
    if (!found) throw std::runtime_error("extract_master_key: packed header not found");

    if (static_cast<size_t>(packed_off) + hdr.master_key_offset + 64 > packed_sec->data.size()) {
        throw std::runtime_error("extract_master_key: master key region exceeds packed data");
    }

    uint8_t obfuscated[32];
    uint8_t mask[32];
    std::memcpy(obfuscated, packed_sec->data.data() + packed_off + hdr.master_key_offset, 32);
    std::memcpy(mask, packed_sec->data.data() + packed_off + hdr.master_key_offset + 32, 32);

    uint8_t pe_mask[32];
    derive_pe_mask(hdr.master_key_pe_timestamp, hdr.master_key_pe_size_of_code, pe_mask);

    for (int i = 0; i < 32; ++i) {
        out_master_key[i] = static_cast<uint8_t>(obfuscated[i] ^ mask[i] ^ pe_mask[i]);
    }

    SecureZeroMemory(obfuscated, sizeof(obfuscated));
    SecureZeroMemory(mask, sizeof(mask));
    SecureZeroMemory(pe_mask, sizeof(pe_mask));
}

inline void derive_customer_keys(
    const uint8_t master_key[32],
    const uint8_t customer_uuid[16],
    const std::string& template_version,
    customer_keys_t& out) {

    std::memset(&out, 0, sizeof(out));

    std::vector<uint8_t> seed_info;
    seed_info.insert(seed_info.end(), customer_uuid, customer_uuid + 16);
    size_t vlen = template_version.size() < 32 ? template_version.size() : 32;
    seed_info.insert(seed_info.end(), template_version.data(), template_version.data() + vlen);

    sha256_detail::hkdf_sha256(
        master_key, 32,
        nullptr, 0,
        seed_info.data(), seed_info.size(),
        out.customer_seed, 32);

    static const uint8_t kWbAesInfo[] = { 'w','b','_','a','e','s' };
    sha256_detail::hkdf_expand(out.customer_seed, kWbAesInfo, sizeof(kWbAesInfo), out.wb_aes_key, 32);

    static const uint8_t kArcInfo[] = { 'a','r','c' };
    sha256_detail::hkdf_expand(out.customer_seed, kArcInfo, sizeof(kArcInfo), out.arc_seed, 32);

    static const uint8_t kDriverInfo[] = { 'd','r','i','v','e','r' };
    uint8_t driver_raw[64];
    sha256_detail::hkdf_expand(out.customer_seed, kDriverInfo, sizeof(kDriverInfo), driver_raw, 64);
    std::memcpy(out.driver_keys[0], driver_raw, 32);
    std::memcpy(out.driver_keys[1], driver_raw + 32, 32);
    SecureZeroMemory(driver_raw, sizeof(driver_raw));

    static const uint8_t kArcPagesInfo[] = { 'a','r','c','-','p','a','g','e','s' };
    uint8_t arc_raw[kArcPageCount * kArcKeyLen];
    sha256_detail::hkdf_expand(out.arc_seed, kArcPagesInfo, sizeof(kArcPagesInfo), arc_raw, sizeof(arc_raw));
    for (uint32_t i = 0; i < kArcPageCount; ++i) {
        std::memcpy(out.arc_page_keys[i], arc_raw + i * kArcKeyLen, kArcKeyLen);
    }
    SecureZeroMemory(arc_raw, sizeof(arc_raw));

    uint8_t wb_aes_key16[16];
    std::memcpy(wb_aes_key16, out.wb_aes_key, 16);
    uint64_t entropy_seed = 0;
    std::memcpy(&entropy_seed, out.wb_aes_key + 16, 8);

    out.wb_aes_table = static_cast<aes_detail::wbaes_table_t*>(
        HeapAlloc(GetProcessHeap(), 0, sizeof(aes_detail::wbaes_table_t)));
    if (!out.wb_aes_table) throw std::runtime_error("derive_customer_keys: HeapAlloc failed for WB-AES table");

    aes_detail::wbaes_generate_tables(wb_aes_key16, entropy_seed, *out.wb_aes_table);

    SecureZeroMemory(wb_aes_key16, sizeof(wb_aes_key16));
    SecureZeroMemory(&entropy_seed, sizeof(entropy_seed));
}

inline void free_customer_keys(customer_keys_t& keys) {
    if (keys.wb_aes_table) {
        SecureZeroMemory(keys.wb_aes_table, sizeof(aes_detail::wbaes_table_t));
        HeapFree(GetProcessHeap(), 0, keys.wb_aes_table);
        keys.wb_aes_table = nullptr;
    }
    SecureZeroMemory(&keys, sizeof(keys));
}

inline pe_file::section_t* find_packed_section(pe_file::pe_image_t& pe) {
    for (auto& s : pe.sections) {
        if (section_skip_list::name_equals(s.name, ".packed")) {
            return &s;
        }
    }
    return nullptr;
}

inline uint32_t find_packed_header_offset(const pe_file::section_t& sec) {
    for (size_t off = 0; off + sizeof(packed_header_t) <= sec.data.size(); off += 8) {
        packed_header_t hdr{};
        std::memcpy(&hdr, sec.data.data() + off, sizeof(hdr));
        if (hdr.magic == kPackedMagic && hdr.version == kPackedVersion) {
            return static_cast<uint32_t>(off);
        }
    }
    return 0xFFFFFFFFu;
}

inline bool verify_key_slot_magics(
    const pe_file::pe_image_t& pe,
    const template_metadata_t& meta) {

    const pe_file::section_t* packed_sec = nullptr;
    for (const auto& s : pe.sections) {
        if (section_skip_list::name_equals(s.name, ".packed")) {
            packed_sec = &s;
            break;
        }
    }
    if (!packed_sec) return false;

    uint32_t packed_off = find_packed_header_offset(*packed_sec);
    if (packed_off == 0xFFFFFFFFu) return false;

    auto check_magic = [&](uint32_t slot_offset, uint32_t expected_magic) -> bool {
        uint32_t abs_off = packed_off + slot_offset;
        if (static_cast<size_t>(abs_off) + 4 > packed_sec->data.size()) return false;
        uint32_t magic = 0;
        std::memcpy(&magic, packed_sec->data.data() + abs_off, 4);
        return magic == expected_magic;
    };

    if (!check_magic(meta.key_slots.wb_aes_tables.offset, kKeySlotMagicWbAes)) return false;
    if (!check_magic(meta.key_slots.arc_page_keys.offset, kKeySlotMagicArc)) return false;
    if (!check_magic(meta.key_slots.driver_keys.offset, kKeySlotMagicDriver)) return false;

    return true;
}

inline bool verify_pe_structure(
    const pe_file::pe_image_t& pe,
    const template_metadata_t& meta,
    std::string& detail_out) {

    if (pe.optional_header.ImageBase != meta.pe_info.image_base) {
        detail_out = "image_base mismatch";
        return false;
    }
    if (pe.optional_header.SizeOfImage != meta.pe_info.size_of_image) {
        detail_out = "size_of_image mismatch";
        return false;
    }
    if (pe.optional_header.AddressOfEntryPoint != meta.pe_info.entry_point) {
        detail_out = "entry_point mismatch";
        return false;
    }
    if (pe.optional_header.FileAlignment != meta.pe_info.file_alignment) {
        detail_out = "file_alignment mismatch";
        return false;
    }
    if (pe.optional_header.SectionAlignment != meta.pe_info.section_alignment) {
        detail_out = "section_alignment mismatch";
        return false;
    }

    if (pe.sections.size() != meta.pe_sections.size()) {
        detail_out = "section count mismatch";
        return false;
    }
    for (size_t i = 0; i < pe.sections.size() && i < meta.pe_sections.size(); ++i) {
        const auto& sec = pe.sections[i];
        const auto& ms = meta.pe_sections[i];
        if (std::memcmp(sec.name, ms.name, 8) != 0) {
            detail_out = "section name mismatch at index " + std::to_string(i);
            return false;
        }
        if (sec.virtual_address != ms.virtual_address) {
            detail_out = "section virtual_address mismatch at index " + std::to_string(i);
            return false;
        }
        if (sec.virtual_size != ms.virtual_size) {
            detail_out = "section virtual_size mismatch at index " + std::to_string(i);
            return false;
        }
        if (sec.raw_size != ms.raw_size) {
            detail_out = "section raw_size mismatch at index " + std::to_string(i);
            return false;
        }
        if (sec.raw_offset != ms.raw_offset) {
            detail_out = "section raw_offset mismatch at index " + std::to_string(i);
            return false;
        }
        if (sec.characteristics != ms.characteristics) {
            detail_out = "section characteristics mismatch at index " + std::to_string(i);
            return false;
        }
    }

    const pe_file::section_t* packed_sec = nullptr;
    for (const auto& s : pe.sections) {
        if (section_skip_list::name_equals(s.name, ".packed")) {
            packed_sec = &s;
            break;
        }
    }
    if (!packed_sec) {
        detail_out = "packed section not found";
        return false;
    }

    uint32_t packed_off = find_packed_header_offset(*packed_sec);
    if (packed_off == 0xFFFFFFFFu) {
        detail_out = "packed header not found";
        return false;
    }

    packed_header_t hdr{};
    std::memcpy(&hdr, packed_sec->data.data() + packed_off, sizeof(hdr));
    if (hdr.magic != meta.packed_header.magic) {
        detail_out = "packed header magic mismatch";
        return false;
    }
    if (hdr.version != meta.packed_header.version) {
        detail_out = "packed header version mismatch";
        return false;
    }

    return true;
}

inline void apply_watermark_bits(
    pe_file::pe_image_t& pe,
    const template_metadata_t& meta,
    const uint8_t uuid[16]) {

    for (const auto& site : meta.watermark_sites) {
        uint32_t byte_idx = (site.bit_index % 128) / 8;
        uint32_t bit_idx = (site.bit_index % 128) % 8;
        bool bit = (uuid[byte_idx] >> bit_idx) & 1u;

        pe_file::section_t* sec = nullptr;
        for (auto& s : pe.sections) {
            if (site.offset >= s.raw_offset &&
                site.offset < s.raw_offset + s.raw_size) {
                sec = &s;
                break;
            }
        }
        if (!sec) continue;

        uint32_t local_off = site.offset - sec->raw_offset;

        const std::vector<uint8_t>& enc = bit ? site.encoding_b : site.encoding_a;

        if (static_cast<size_t>(local_off) + enc.size() > sec->data.size()) continue;

        std::memcpy(sec->data.data() + local_off, enc.data(), enc.size());
    }
}

inline void write_customer_keys(
    pe_file::pe_image_t& pe,
    const template_metadata_t& meta,
    const customer_keys_t& keys) {

    pe_file::section_t* packed_sec = find_packed_section(pe);
    if (!packed_sec) throw std::runtime_error("write_customer_keys: .packed section not found");

    uint32_t packed_off = find_packed_header_offset(*packed_sec);
    if (packed_off == 0xFFFFFFFFu) throw std::runtime_error("write_customer_keys: packed header not found");

    uint32_t wb_abs = packed_off + meta.key_slots.wb_aes_tables.offset;
    if (static_cast<size_t>(wb_abs) + sizeof(aes_detail::wbaes_table_t) > packed_sec->data.size()) {
        throw std::runtime_error("write_customer_keys: WB-AES table slot exceeds packed data");
    }
    std::memcpy(packed_sec->data.data() + wb_abs, keys.wb_aes_table, sizeof(aes_detail::wbaes_table_t));

    uint32_t arc_abs = packed_off + meta.key_slots.arc_page_keys.offset;
    if (static_cast<size_t>(arc_abs) + kArcPageKeySize > packed_sec->data.size()) {
        throw std::runtime_error("write_customer_keys: ARC key slot exceeds packed data");
    }
    for (uint32_t i = 0; i < kArcPageCount; ++i) {
        std::memcpy(packed_sec->data.data() + arc_abs + i * kArcKeyLen,
                    keys.arc_page_keys[i], kArcKeyLen);
    }

    uint32_t drv_abs = packed_off + meta.key_slots.driver_keys.offset;
    if (static_cast<size_t>(drv_abs) + kDriverKeySlotSize > packed_sec->data.size()) {
        throw std::runtime_error("write_customer_keys: driver key slot exceeds packed data");
    }
    std::memcpy(packed_sec->data.data() + drv_abs, keys.driver_keys[0], kDriverKeyLen);
    std::memcpy(packed_sec->data.data() + drv_abs + kDriverKeyLen, keys.driver_keys[1], kDriverKeyLen);
}

inline void update_aux_watermark(
    pe_file::pe_image_t& pe,
    const uint8_t uuid[16]) {

    pe_file::section_t* packed_sec = find_packed_section(pe);
    if (!packed_sec) throw std::runtime_error("update_aux_watermark: .packed section not found");

    uint32_t packed_off = find_packed_header_offset(*packed_sec);
    if (packed_off == 0xFFFFFFFFu) throw std::runtime_error("update_aux_watermark: packed header not found");

    packed_header_t hdr{};
    std::memcpy(&hdr, packed_sec->data.data() + packed_off, sizeof(hdr));

    if (hdr.aux_offset == 0u || hdr.aux_size != sizeof(aux_block_t)) {
        throw std::runtime_error("update_aux_watermark: invalid aux block offset/size");
    }

    size_t aux_abs = static_cast<size_t>(packed_off) + hdr.aux_offset;
    if (aux_abs + sizeof(aux_block_t) > packed_sec->data.size()) {
        throw std::runtime_error("update_aux_watermark: aux block exceeds packed data");
    }

    aux_block_t aux{};
    std::memcpy(&aux, packed_sec->data.data() + aux_abs, sizeof(aux_block_t));

    std::memcpy(aux.watermark, uuid, 16);
    sha256_detail::sha256(uuid, 16, aux.watermark_hash);

    aux.pin_reserved[2] = 0x2u;

    std::memcpy(packed_sec->data.data() + aux_abs, &aux, sizeof(aux_block_t));

    SecureZeroMemory(&aux, sizeof(aux_block_t));
}

inline bool post_write_verification(
    const std::string& output_path,
    const template_metadata_t& meta,
    const uint8_t uuid[16],
    std::string& detail_out) {

    pe_file::pe_image_t pe;
    try {
        pe = pe_file::load(output_path);
    } catch (const std::exception& e) {
        detail_out = std::string("post-write: failed to load output: ") + e.what();
        return false;
    }

    if (pe.dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        detail_out = "post-write: DOS signature invalid";
        return false;
    }
    if (pe.pe_signature != IMAGE_NT_SIGNATURE) {
        detail_out = "post-write: PE signature invalid";
        return false;
    }
    if (pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        detail_out = "post-write: optional header magic invalid";
        return false;
    }

    const pe_file::section_t* packed_sec = nullptr;
    for (const auto& s : pe.sections) {
        if (section_skip_list::name_equals(s.name, ".packed")) {
            packed_sec = &s;
            break;
        }
    }
    if (!packed_sec) {
        detail_out = "post-write: .packed section not found";
        return false;
    }

    uint32_t packed_off = find_packed_header_offset(*packed_sec);
    if (packed_off == 0xFFFFFFFFu) {
        detail_out = "post-write: packed header not found";
        return false;
    }

    packed_header_t hdr{};
    std::memcpy(&hdr, packed_sec->data.data() + packed_off, sizeof(hdr));
    if (hdr.magic != kPackedMagic || hdr.version != kPackedVersion) {
        detail_out = "post-write: packed header magic/version mismatch";
        return false;
    }

    size_t aux_abs = static_cast<size_t>(packed_off) + hdr.aux_offset;
    if (aux_abs + sizeof(aux_block_t) > packed_sec->data.size()) {
        detail_out = "post-write: aux block out of bounds";
        return false;
    }

    aux_block_t aux{};
    std::memcpy(&aux, packed_sec->data.data() + aux_abs, sizeof(aux_block_t));

    if (std::memcmp(aux.watermark, uuid, 16) != 0) {
        detail_out = "post-write: watermark mismatch";
        return false;
    }

    uint8_t expected_wm_hash[32];
    sha256_detail::sha256(uuid, 16, expected_wm_hash);
    if (std::memcmp(aux.watermark_hash, expected_wm_hash, 32) != 0) {
        detail_out = "post-write: watermark hash mismatch";
        return false;
    }

    uint32_t patched = 0;
    for (const auto& site : meta.watermark_sites) {
        uint32_t byte_idx = (site.bit_index % 128) / 8;
        uint32_t bit_idx = (site.bit_index % 128) % 8;
        bool bit = (uuid[byte_idx] >> bit_idx) & 1u;
        const std::vector<uint8_t>& expected = bit ? site.encoding_b : site.encoding_a;

        const pe_file::section_t* sec = nullptr;
        for (const auto& s : pe.sections) {
            if (site.offset >= s.raw_offset &&
                site.offset < s.raw_offset + s.raw_size) {
                sec = &s;
                break;
            }
        }
        if (!sec) continue;

        uint32_t local_off = site.offset - sec->raw_offset;
        if (static_cast<size_t>(local_off) + expected.size() > sec->data.size()) continue;

        if (std::memcmp(sec->data.data() + local_off, expected.data(), expected.size()) == 0) {
            ++patched;
        }
    }

    if (patched < meta.watermark_sites.size()) {
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "post-write: only %u/%zu watermark sites verified",
                      patched, meta.watermark_sites.size());
        detail_out = buf;
        return false;
    }

    uint32_t wb_abs = packed_off + meta.key_slots.wb_aes_tables.offset;
    if (static_cast<size_t>(wb_abs) + sizeof(aes_detail::wbaes_table_t) > packed_sec->data.size()) {
        detail_out = "post-write: WB-AES table slot out of bounds";
        return false;
    }
    if (!bytes_have_nonzero(packed_sec->data.data() + wb_abs, sizeof(aes_detail::wbaes_table_t))) {
        detail_out = "post-write: WB-AES tables are all zero";
        return false;
    }

    uint32_t arc_abs = packed_off + meta.key_slots.arc_page_keys.offset;
    if (static_cast<size_t>(arc_abs) + kArcPageKeySize > packed_sec->data.size()) {
        detail_out = "post-write: ARC key slot out of bounds";
        return false;
    }
    if (!bytes_have_nonzero(packed_sec->data.data() + arc_abs, kArcPageKeySize)) {
        detail_out = "post-write: ARC page keys are all zero";
        return false;
    }

    uint32_t drv_abs = packed_off + meta.key_slots.driver_keys.offset;
    if (static_cast<size_t>(drv_abs) + kDriverKeySlotSize > packed_sec->data.size()) {
        detail_out = "post-write: driver key slot out of bounds";
        return false;
    }
    if (!bytes_have_nonzero(packed_sec->data.data() + drv_abs, kDriverKeySlotSize)) {
        detail_out = "post-write: driver keys are all zero";
        return false;
    }

    SecureZeroMemory(&aux, sizeof(aux_block_t));
    return true;
}

struct personalize_progress_t {
    std::function<void(int, const char*)> report;
};

inline int run_personalize_pipeline(
    const std::string& input_path,
    const std::string& output_path,
    const std::string& metadata_path,
    const std::string& customer_uuid_hex,
    const uint8_t* embedded_master_key,
    personalize_progress_t* progress = nullptr) {

    auto report = [&](int pct, const char* msg) {
        if (progress && progress->report) {
            progress->report(pct, msg);
        }
    };

    auto start_time = std::chrono::steady_clock::now();
    auto check_timeout = [&]() -> bool {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();
        return static_cast<uint64_t>(elapsed) > kPersonalizeTimeoutMs;
    };

    report(0, "starting personalization");

    std::string template_hash = compute_file_sha256_hex(input_path);

    std::string metadata_json = read_file_to_string(metadata_path);
    template_metadata_t meta = parse_template_metadata(metadata_json);

    if (!meta.metadata_self_hash.empty()) {
        if (!verify_metadata_self_hash(meta)) {
            std::fprintf(stderr, "[!] metadata self-hash mismatch\n");
            return 1;
        }
    }

    if (!meta.template_hash_hex.empty()) {
        if (template_hash != meta.template_hash_hex) {
            std::fprintf(stderr, "[!] template hash mismatch: expected %s, got %s\n",
                         meta.template_hash_hex.c_str(), template_hash.c_str());
            return 1;
        }
    }

    report(5, "template loaded, hash verified");

    pe_file::pe_image_t pe;
    try {
        pe = pe_file::load(input_path);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] failed to load template PE: %s\n", e.what());
        return 2;
    }

    if (pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::fprintf(stderr, "[!] template is not a PE32+ image\n");
        return 2;
    }

    {
        std::string pe_detail;
        if (!verify_pe_structure(pe, meta, pe_detail)) {
            std::fprintf(stderr, "[!] metadata PE structure mismatch: %s\n", pe_detail.c_str());
            return 2;
        }
    }

    report(10, "metadata verified, PE structure checked");

    if (!verify_key_slot_magics(pe, meta)) {
        std::fprintf(stderr, "[!] key slot magic mismatch\n");
        return 2;
    }

    if (!hkdf_self_test_rfc5869()) {
        std::fprintf(stderr, "[!] HKDF self-test failed\n");
        return 3;
    }

    report(15, "HKDF self-test passed");

    uint8_t master_key[32];
    if (embedded_master_key != nullptr) {
        std::memcpy(master_key, embedded_master_key, 32);
    } else {
        try {
            extract_master_key_from_template(pe, master_key);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[!] failed to extract master key: %s\n", e.what());
            return 3;
        }
    }

    if (!meta.master_key_consistency.expected_customer_seed.empty()) {
        if (!verify_master_key_consistency(master_key, meta)) {
            std::fprintf(stderr, "[!] master key consistency mismatch: personalizer master_key does not match template master_key\n");
            SecureZeroMemory(master_key, sizeof(master_key));
            return 3;
        }
    }

    report(20, "master key consistency verified");

    if (meta.watermark_sites.size() < kMinWatermarkSites) {
        SecureZeroMemory(master_key, sizeof(master_key));
        std::fprintf(stderr, "[!] insufficient watermark sites: %zu < %u\n",
                     meta.watermark_sites.size(), kMinWatermarkSites);
        return 2;
    }

    if (customer_uuid_hex.size() != 32) {
        SecureZeroMemory(master_key, sizeof(master_key));
        std::fprintf(stderr, "[!] customer UUID must be 32 hex chars\n");
        return 1;
    }

    uint8_t uuid[16] = {0};
    {
        auto hexv = [](char c, int& v) -> bool {
            if (c >= '0' && c <= '9') { v = c - '0'; return true; }
            if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
            if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
            return false;
        };
        for (int i = 0; i < 16; ++i) {
            int hi = 0, lo = 0;
            if (!hexv(customer_uuid_hex[i * 2], hi) || !hexv(customer_uuid_hex[i * 2 + 1], lo)) {
                SecureZeroMemory(master_key, sizeof(master_key));
                std::fprintf(stderr, "[!] invalid hex in customer UUID\n");
                return 1;
            }
            uuid[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
    }

    if (check_timeout()) {
        SecureZeroMemory(master_key, sizeof(master_key));
        std::fprintf(stderr, "[!] personalization timeout\n");
        return 4;
    }

    customer_keys_t keys;
    derive_customer_keys(master_key, uuid, meta.template_version, keys);
    SecureZeroMemory(master_key, sizeof(master_key));

    report(30, "customer keys derived");

    if (check_timeout()) {
        free_customer_keys(keys);
        std::fprintf(stderr, "[!] personalization timeout\n");
        return 4;
    }

    apply_watermark_bits(pe, meta, uuid);
    report(40, "watermark sites patched");

    write_customer_keys(pe, meta, keys);
    report(60, "WB-AES tables and key slots written");

    update_aux_watermark(pe, uuid);
    report(80, "aux block watermark updated");

    free_customer_keys(keys);

    pe_file::recalculate_headers(pe);
    report(90, "PE headers recalculated");

    if (check_timeout()) {
        std::fprintf(stderr, "[!] personalization timeout\n");
        return 4;
    }

    try {
        pe_file::write(pe, output_path);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] failed to write output: %s\n", e.what());
        return 4;
    }

    report(95, "post-write verification starting");

    {
        std::string verify_detail;
        if (!post_write_verification(output_path, meta, uuid, verify_detail)) {
            std::fprintf(stderr, "[!] post-write verification failed: %s\n", verify_detail.c_str());
            return 5;
        }
    }

    report(100, "personalized binary written and verified");
    return 0;
}

}

constexpr uint32_t kTmWatermarkMagic           = 0xDEAD0001u;
constexpr uint32_t kTmKeySlotMagicWbAes        = 0xCAFE0000u;
constexpr uint32_t kTmKeySlotMagicArc          = 0xCAFE0001u;
constexpr uint32_t kTmKeySlotMagicDriver       = 0xCAFE0002u;
constexpr uint32_t kTmWbAesTableSize           = 188448u;
constexpr uint32_t kTmArcPageKeysSize          = 8192u;
constexpr uint32_t kTmDriverKeysSize           = 64u;
constexpr uint32_t kTmKeySlotTotalSize         = 196704u;
constexpr uint32_t kTmWatermarkTargetSites     = 5000u;
constexpr uint32_t kTmWatermarkUuidBits        = 128u;
constexpr uint32_t kTmWatermarkRedundancy      = 39u;
constexpr uint32_t kTmWatermarkErrorCorrection = 19u;

struct tm_watermark_site_t {
    uint32_t file_offset;
    uint32_t rva;
    uint32_t type;
    uint32_t bit_index;
    std::vector<uint8_t> encoding_a;
    std::vector<uint8_t> encoding_b;
    uint32_t slot_magic;
};

struct tm_watermark_site_collection_t {
    std::vector<tm_watermark_site_t> sites;
    uint32_t total_bits;
    uint32_t redundancy;
};

struct tm_key_slot_info_t {
    uint32_t wb_aes_tables_offset;
    uint32_t wb_aes_tables_size;
    uint32_t arc_page_keys_offset;
    uint32_t arc_page_keys_size;
    uint32_t driver_keys_offset;
    uint32_t driver_keys_size;
    uint32_t key_slot_magic;
};

inline std::string tm_hex_bytes_spaced(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 3);
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) out.push_back(' ');
        out.push_back(hex[(data[i] >> 4) & 0xF]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

inline std::string tm_hex_bytes_compact(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[(data[i] >> 4) & 0xF]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

inline std::string tm_u32_hex(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08X", v);
    return std::string(buf);
}

inline std::string tm_u64_hex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

inline bool tm_zero_template_watermark(pe_file::pe_image_t& pe,
                                        uint32_t packed_section_rva,
                                        const packed_section_layout_t& layout) {
    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (!sec) return false;
    if (layout.aux_offset == 0u) return false;
    if (static_cast<size_t>(layout.aux_offset) + sizeof(aux_block_t) > sec->data.size()) return false;
    aux_block_t aux{};
    std::memcpy(&aux, sec->data.data() + layout.aux_offset, sizeof(aux_block_t));
    if (aux.magic != kAuxMagic || aux.version != kAuxVersion) return false;
    std::memset(aux.watermark, 0, 16);
    std::memset(aux.watermark_hash, 0, 32);
    aux.spread_seed = kTmWatermarkMagic;
    std::memcpy(sec->data.data() + layout.aux_offset, &aux, sizeof(aux_block_t));
    return true;
}

inline tm_key_slot_info_t tm_place_key_slots(pe_file::pe_image_t& pe,
                                              uint32_t packed_section_rva,
                                              const packed_section_layout_t& layout) {
    tm_key_slot_info_t info{};
    info.wb_aes_tables_size = kTmWbAesTableSize;
    info.arc_page_keys_size = kTmArcPageKeysSize;
    info.driver_keys_size = kTmDriverKeysSize;
    info.key_slot_magic = kTmKeySlotMagicWbAes;

    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (!sec) return info;

    uint32_t packed_off = packed_section_rva - sec->virtual_address;
    size_t cursor = sec->data.size();
    while ((cursor % 16u) != 0u) { sec->data.push_back(0); ++cursor; }

    info.wb_aes_tables_offset = static_cast<uint32_t>(cursor) - packed_off;
    sec->data.resize(cursor + kTmWbAesTableSize, 0);
    {
        uint8_t zero_key[16] = {0};
        wbaes_table_t* tbl = static_cast<wbaes_table_t*>(
            HeapAlloc(GetProcessHeap(), 0, sizeof(wbaes_table_t)));
        if (tbl) {
            wbaes_generate_tables(zero_key, 0, *tbl);
            std::memcpy(sec->data.data() + cursor, tbl, kTmWbAesTableSize);
            SecureZeroMemory(tbl, sizeof(wbaes_table_t));
            HeapFree(GetProcessHeap(), 0, tbl);
        }
        uint32_t magic = kTmKeySlotMagicWbAes;
        std::memcpy(sec->data.data() + cursor, &magic, sizeof(magic));
        SecureZeroMemory(zero_key, sizeof(zero_key));
    }
    cursor += kTmWbAesTableSize;

    info.arc_page_keys_offset = static_cast<uint32_t>(cursor) - packed_off;
    sec->data.resize(cursor + kTmArcPageKeysSize, 0);
    {
        uint32_t magic = kTmKeySlotMagicArc;
        std::memcpy(sec->data.data() + cursor, &magic, sizeof(magic));
    }
    cursor += kTmArcPageKeysSize;

    info.driver_keys_offset = static_cast<uint32_t>(cursor) - packed_off;
    sec->data.resize(cursor + kTmDriverKeysSize, 0);
    {
        uint32_t magic = kTmKeySlotMagicDriver;
        std::memcpy(sec->data.data() + cursor, &magic, sizeof(magic));
    }
    cursor += kTmDriverKeysSize;

    sec->virtual_size = static_cast<uint32_t>(sec->data.size());
    uint32_t fa = pe.file_alignment();
    sec->raw_size = pe_file::align_up(static_cast<uint32_t>(sec->data.size()), fa);
    if (sec->data.size() < sec->raw_size) {
        sec->data.resize(sec->raw_size, 0);
    }

    (void)patch_aux_pin_reserved(pe, packed_section_rva, layout,
                                  info.wb_aes_tables_offset,
                                  info.arc_page_keys_offset,
                                  info.driver_keys_offset,
                                  kTmKeySlotTotalSize);
    return info;
}

inline tm_watermark_site_collection_t tm_generate_watermark_sites(
    pe_file::pe_image_t& pe,
    uint32_t packed_section_rva,
    const packed_section_layout_t& layout,
    uint64_t seed) {

    tm_watermark_site_collection_t collection;
    collection.total_bits = kTmWatermarkUuidBits;
    collection.redundancy = kTmWatermarkRedundancy;

    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (!sec) return collection;

    uint32_t packed_off = packed_section_rva - sec->virtual_address;
    size_t data_size = sec->data.size();
    if (static_cast<size_t>(packed_off) + sizeof(packed_header_t) > data_size) return collection;

    packed_header_t hdr{};
    std::memcpy(&hdr, sec->data.data() + packed_off, sizeof(hdr));
    if (hdr.magic != kPackedMagic) return collection;

    rng_state_t rng = make_rng(seed ^ 0xDEAD0001ULL);

    uint32_t stub_start = hdr.stub_code_offset;
    uint32_t stub_end = static_cast<uint32_t>(data_size) - packed_off;

    std::vector<uint32_t> occupied;
    uint32_t site_index = 0;

    auto is_occupied = [&](uint32_t off, uint32_t sz) -> bool {
        for (uint32_t o : occupied) {
            if (off < o + sz && o < off + sz) return true;
        }
        return false;
    };

    auto add_site = [&](uint32_t offset_in_packed, uint32_t type,
                        const std::vector<uint8_t>& enc_a,
                        const std::vector<uint8_t>& enc_b) {
        if (collection.sites.size() >= kTmWatermarkTargetSites) return;
        if (is_occupied(offset_in_packed, static_cast<uint32_t>(enc_a.size()))) return;
        tm_watermark_site_t site{};
        site.file_offset = offset_in_packed;
        site.rva = sec->virtual_address + packed_off + offset_in_packed;
        site.type = type;
        site.bit_index = site_index % kTmWatermarkUuidBits;
        site.encoding_a = enc_a;
        site.encoding_b = enc_b;
        site.slot_magic = kTmWatermarkMagic + site_index;
        collection.sites.push_back(std::move(site));
        occupied.push_back(offset_in_packed);
        ++site_index;
    };

    if (stub_end > stub_start + 16) {
        for (uint32_t i = stub_start; i + 2 < stub_end && collection.sites.size() < 1500; ++i) {
            const uint8_t* p = sec->data.data() + packed_off + i;
            if (p[0] == 0x90 && p[1] == 0x90) {
                if (i > 0) {
                    const uint8_t* prev = sec->data.data() + packed_off + i - 1;
                    if (prev[0] == 0xE9 || prev[0] == 0xEB) continue;
                }
                uint32_t off = i - stub_start;
                add_site(hdr.stub_code_offset + off, 1,
                         {0x90, 0x90}, {0x87, 0xC0});
                ++i;
            }
        }
    }

    if (stub_end > stub_start + 12) {
        for (uint32_t i = stub_start; i + 10 < stub_end && collection.sites.size() < 2500; ++i) {
            const uint8_t* p = sec->data.data() + packed_off + i;
            if (p[0] == 0x49 && p[1] == 0xBA) {
                uint32_t off = i - stub_start;
                std::vector<uint8_t> enc_a(p, p + 10);
                std::vector<uint8_t> enc_b = enc_a;
                enc_b[1] = 0xBB;
                add_site(hdr.stub_code_offset + off, 2, enc_a, enc_b);
                i += 9;
            }
        }
    }

    size_t current_end = sec->data.size();
    while ((current_end % 16u) != 0u) { sec->data.push_back(0); ++current_end; }

    uint32_t branch_target = 1500;
    uint32_t nop_target = 1500;
    uint32_t reg_target = 1000;
    uint32_t bb_target = 1000;

    uint32_t branch_count = 0, nop_count = 0, reg_count = 0, bb_count = 0;
    for (const auto& s : collection.sites) {
        switch (s.type) {
            case 0: ++branch_count; break;
            case 1: ++nop_count; break;
            case 2: ++reg_count; break;
            case 3: ++bb_count; break;
        }
    }

    while (branch_count < branch_target) {
        uint32_t rel8 = static_cast<uint8_t>(rng.next_u32_in_range(0, 127));
        sec->data.push_back(0xEBu);
        sec->data.push_back(0x02u);
        uint32_t site_off = static_cast<uint32_t>(sec->data.size()) - packed_off;
        sec->data.push_back(0x75u);
        sec->data.push_back(static_cast<uint8_t>(rel8));
        add_site(site_off, 0, {0x75, static_cast<uint8_t>(rel8)},
                                {0x74, static_cast<uint8_t>(rel8)});
        ++branch_count;
    }

    while (nop_count < nop_target) {
        uint32_t site_off = static_cast<uint32_t>(sec->data.size()) - packed_off;
        sec->data.push_back(0x90u);
        sec->data.push_back(0x90u);
        add_site(site_off, 1, {0x90, 0x90}, {0x87, 0xC0});
        ++nop_count;
    }

    while (reg_count < reg_target) {
        uint32_t site_off = static_cast<uint32_t>(sec->data.size()) - packed_off;
        sec->data.push_back(0x49u);
        sec->data.push_back(0xBAu);
        std::vector<uint8_t> enc_a;
        enc_a.push_back(0x49u);
        enc_a.push_back(0xBAu);
        for (int j = 0; j < 8; ++j) {
            uint8_t b = static_cast<uint8_t>(rng.next_u64() & 0xFF);
            sec->data.push_back(b);
            enc_a.push_back(b);
        }
        std::vector<uint8_t> enc_b = enc_a;
        enc_b[1] = 0xBBu;
        add_site(site_off, 2, enc_a, enc_b);
        ++reg_count;
    }

    while (bb_count < bb_target) {
        uint32_t site_off = static_cast<uint32_t>(sec->data.size()) - packed_off;
        sec->data.push_back(0xE9u);
        sec->data.push_back(0x00u);
        sec->data.push_back(0x00u);
        sec->data.push_back(0x00u);
        sec->data.push_back(0x00u);
        sec->data.push_back(0x90u);
        sec->data.push_back(0x90u);
        add_site(site_off + 1, 3,
                 {0x00, 0x00, 0x00, 0x00},
                 {0x02, 0x00, 0x00, 0x00});
        ++bb_count;
    }

    for (const auto& site : collection.sites) {
        uint32_t abs_off = packed_off + site.file_offset;
        if (abs_off + site.encoding_a.size() <= sec->data.size()) {
            std::memcpy(sec->data.data() + abs_off,
                        site.encoding_a.data(), site.encoding_a.size());
        }
    }

    sec->virtual_size = static_cast<uint32_t>(sec->data.size());
    uint32_t fa = pe.file_alignment();
    sec->raw_size = pe_file::align_up(static_cast<uint32_t>(sec->data.size()), fa);
    if (sec->data.size() < sec->raw_size) {
        sec->data.resize(sec->raw_size, 0);
    }

    return collection;
}

inline void tm_finalize_watermark_offsets(pe_file::pe_image_t& pe,
                                           uint32_t packed_section_rva,
                                           tm_watermark_site_collection_t& collection) {
    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (!sec) return;
    uint32_t packed_off = packed_section_rva - sec->virtual_address;
    for (auto& site : collection.sites) {
        uint32_t offset_in_packed = site.file_offset;
        site.file_offset = sec->raw_offset + packed_off + offset_in_packed;
        site.rva = sec->virtual_address + packed_off + offset_in_packed;
    }
}

inline void tm_recover_master_key(const transform_result_t& result,
                                   uint8_t master[32]) {
    uint8_t pe_mask[32];
    derive_pe_mask(result.master_key_pe_timestamp,
                    result.master_key_pe_size_of_code, pe_mask);
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>(
            result.obfuscated_master_key[i] ^ result.key_obfuscation_mask[i] ^ pe_mask[i]);
    }
    SecureZeroMemory(pe_mask, sizeof(pe_mask));
}

inline std::string tm_serialize_template_metadata(
    const pe_file::pe_image_t& pe,
    const transform_result_t& result,
    const tm_watermark_site_collection_t& sites,
    const std::string& template_version,
    const uint8_t template_hash[32],
    const tm_key_slot_info_t& key_slots) {

    std::string hash_hex = tm_hex_bytes_compact(template_hash, 32);

    std::string json;
    json.reserve(1 << 20);

    json += "{";
    json += "\"key_slots\":{";
    json += "\"arc_page_keys\":{\"key_size\":32,\"magic\":\"" + tm_u32_hex(kTmKeySlotMagicArc) + "\",\"offset\":\"" + tm_u32_hex(key_slots.arc_page_keys_offset) + "\",\"page_count\":256,\"size\":" + std::to_string(kTmArcPageKeysSize) + "},";
    json += "\"driver_keys\":{\"driver_count\":2,\"key_size\":32,\"magic\":\"" + tm_u32_hex(kTmKeySlotMagicDriver) + "\",\"offset\":\"" + tm_u32_hex(key_slots.driver_keys_offset) + "\",\"size\":" + std::to_string(kTmDriverKeysSize) + "},";
    json += "\"wb_aes_tables\":{\"magic\":\"" + tm_u32_hex(kTmKeySlotMagicWbAes) + "\",\"offset\":\"" + tm_u32_hex(key_slots.wb_aes_tables_offset) + "\",\"size\":" + std::to_string(kTmWbAesTableSize) + "}";
    json += "},";

    {
        uint8_t master[32];
        tm_recover_master_key(result, master);
        uint8_t test_uuid[16] = {0};
        const char info_str[] = "template-consistency-check";
        uint8_t info[16 + sizeof(info_str) - 1];
        std::memcpy(info, test_uuid, 16);
        std::memcpy(info + 16, info_str, sizeof(info_str) - 1);
        uint8_t customer_seed[32];
        sha256_detail::hkdf_sha256(master, 32, nullptr, 0,
                                    info, sizeof(info), customer_seed, 32);
        std::string seed_hex = tm_hex_bytes_compact(customer_seed, 32);
        json += "\"master_key_consistency_check\":{";
        json += "\"expected_customer_seed\":\"" + seed_hex + "\",";
        json += "\"info_string\":\"" + std::string(info_str) + "\",";
        json += "\"test_uuid\":\"00000000000000000000000000000000\"";
        json += "},";
        SecureZeroMemory(master, sizeof(master));
        SecureZeroMemory(customer_seed, sizeof(customer_seed));
    }

    json += "\"metadata_self_hash\":\"PLACEHOLDER\",";

    {
        json += "\"packed_header\":{";
        json += "\"aux_offset\":\"" + tm_u32_hex(result.layout.aux_offset) + "\",";
        json += "\"aux_size\":368,";
        json += "\"import_count\":" + std::to_string(result.imports.entry_count) + ",";
        json += "\"magic\":\"" + tm_u32_hex(kPackedMagic) + "\",";
        json += "\"master_key_offset\":\"" + tm_u32_hex(result.layout.master_key_offset) + "\",";
        json += "\"packed_offset_in_section\":\"0x00000000\",";
        json += "\"packed_section_rva\":\"" + tm_u32_hex(result.packed_section_rva) + "\",";
        json += "\"section_count\":" + std::to_string(static_cast<uint32_t>(pe.sections.size())) + ",";
        json += "\"stub_code_offset\":\"" + tm_u32_hex(result.layout.stub_offset) + "\",";
        json += "\"version\":\"" + tm_u32_hex(kPackedVersion) + "\"";
        json += "},";
    }

    json += "\"pe_info\":{";
    json += "\"entry_point\":\"" + tm_u32_hex(pe.optional_header.AddressOfEntryPoint) + "\",";
    json += "\"file_alignment\":" + std::to_string(pe.optional_header.FileAlignment) + ",";
    json += "\"image_base\":\"" + tm_u64_hex(pe.optional_header.ImageBase) + "\",";
    json += "\"section_alignment\":" + std::to_string(pe.optional_header.SectionAlignment) + ",";
    json += "\"size_of_image\":\"" + tm_u32_hex(pe.optional_header.SizeOfImage) + "\"";
    json += "},";

    json += "\"pe_sections\":[";
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const auto& s = pe.sections[i];
        char name_buf[9] = {0};
        std::memcpy(name_buf, s.name, 8);
        json += "{\"characteristics\":\"" + tm_u32_hex(s.characteristics) + "\",";
        json += "\"name\":\"" + std::string(name_buf) + "\",";
        json += "\"raw_offset\":\"" + tm_u32_hex(s.raw_offset) + "\",";
        json += "\"raw_size\":\"" + tm_u32_hex(s.raw_size) + "\",";
        json += "\"virtual_address\":\"" + tm_u32_hex(s.virtual_address) + "\",";
        json += "\"virtual_size\":\"" + tm_u32_hex(s.virtual_size) + "\"}";
        if (i + 1 < pe.sections.size()) json += ",";
    }
    json += "],";

    json += "\"template_hash\":\"sha256:" + hash_hex + "\",";
    json += "\"template_version\":\"" + template_version + "\",";

    json += "\"watermark_redundancy\":{";
    json += "\"error_correction_capacity\":" + std::to_string(kTmWatermarkErrorCorrection) + ",";
    json += "\"redundancy_factor\":" + std::to_string(kTmWatermarkRedundancy) + ",";
    json += "\"total_sites\":" + std::to_string(static_cast<uint32_t>(sites.sites.size())) + ",";
    json += "\"uuid_bits\":" + std::to_string(kTmWatermarkUuidBits);
    json += "},";

    json += "\"watermark_sites\":[";
    for (size_t i = 0; i < sites.sites.size(); ++i) {
        const auto& site = sites.sites[i];
        const char* type_names[] = {"branch", "nop", "reg_alloc", "bb_order"};
        const char* tn = (site.type < 4) ? type_names[site.type] : "unknown";
        json += "{\"bit_index\":" + std::to_string(site.bit_index) + ",";
        json += "\"encoding_a_hex\":\"" + tm_hex_bytes_spaced(site.encoding_a.data(), site.encoding_a.size()) + "\",";
        json += "\"encoding_b_hex\":\"" + tm_hex_bytes_spaced(site.encoding_b.data(), site.encoding_b.size()) + "\",";
        json += "\"offset\":\"" + tm_u32_hex(site.file_offset) + "\",";
        json += "\"rva\":\"" + tm_u32_hex(site.rva) + "\",";
        json += "\"slot_magic\":\"" + tm_u32_hex(site.slot_magic) + "\",";
        json += "\"type\":\"" + std::string(tn) + "\"}";
        if (i + 1 < sites.sites.size()) json += ",";
    }
    json += "]";

    json += "}";

    size_t placeholder_pos = json.find("\"metadata_self_hash\":\"PLACEHOLDER\"");
    if (placeholder_pos != std::string::npos) {
        std::string json_without = json.substr(0, placeholder_pos);
        std::string after = json.substr(placeholder_pos + 34);
        if (!after.empty() && after[0] == ',') {
            after = after.substr(1);
        } else if (!json_without.empty() && json_without.back() == ',') {
            json_without.pop_back();
        }
        std::string canonical = json_without + after;

        uint8_t self_hash[32];
        sha256_detail::sha256(
            reinterpret_cast<const uint8_t*>(canonical.data()),
            canonical.size(), self_hash);
        std::string self_hash_hex = tm_hex_bytes_compact(self_hash, 32);

        json = json_without;
        json += "\"metadata_self_hash\":\"" + self_hash_hex + "\"";
        json += after;

        SecureZeroMemory(self_hash, sizeof(self_hash));
    }

    return json;
}

inline bool tm_verify_template(pe_file::pe_image_t& pe,
                               uint32_t packed_section_rva,
                               const packed_section_layout_t& layout,
                               const tm_watermark_site_collection_t& sites,
                               const tm_key_slot_info_t& key_slots,
                               std::string& detail_out) {
    if (sites.sites.size() < kTmWatermarkTargetSites) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "insufficient watermark sites: %zu < %u",
                      sites.sites.size(), kTmWatermarkTargetSites);
        detail_out = buf;
        return false;
    }

    std::vector<uint32_t> bit_counts(kTmWatermarkUuidBits, 0);
    for (const auto& site : sites.sites) {
        if (site.bit_index < kTmWatermarkUuidBits) {
            ++bit_counts[site.bit_index];
        }
    }
    for (uint32_t i = 0; i < kTmWatermarkUuidBits; ++i) {
        if (bit_counts[i] < 30u) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "watermark bit %u has only %u sites (minimum 30 required)",
                          i, bit_counts[i]);
            detail_out = buf;
            return false;
        }
    }

    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (!sec) { detail_out = "packed section not found"; return false; }
    uint32_t packed_off = packed_section_rva - sec->virtual_address;

    std::vector<uint32_t> site_starts;
    uint32_t type2_rejected = 0;

    for (const auto& site : sites.sites) {
        uint32_t abs_off = packed_off + (site.rva - sec->virtual_address - packed_off);
        uint32_t site_size = static_cast<uint32_t>(site.encoding_a.size());
        if (static_cast<size_t>(abs_off) + site_size > sec->data.size()) {
            detail_out = "watermark site exceeds packed section data";
            return false;
        }
        for (uint32_t s : site_starts) {
            if (abs_off < s + site_size && s < abs_off + site_size) {
                detail_out = "watermark sites overlap";
                return false;
            }
        }
        site_starts.push_back(abs_off);

        bool enc_a_ok = true;
        for (size_t k = 0; k < site.encoding_a.size(); ++k) {
            if (sec->data[abs_off + k] != site.encoding_a[k]) { enc_a_ok = false; break; }
        }
        if (!enc_a_ok) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "site at offset 0x%X type %u encoding_a mismatch", abs_off, site.type);
            detail_out = buf;
            return false;
        }

        if (site.type == 0) {
            if (site.encoding_a.size() < 2 || site.encoding_b.size() < 2) {
                detail_out = "branch watermark site encoding too short";
                return false;
            }
            if (site.encoding_a[0] != 0x75 || site.encoding_b[0] != 0x74) {
                detail_out = "branch watermark site encoding pattern mismatch";
                return false;
            }
        } else if (site.type == 1) {
            if (site.encoding_a.size() < 2 || site.encoding_b.size() < 2) {
                detail_out = "NOP watermark site encoding too short";
                return false;
            }
            if (site.encoding_a[0] != 0x90 || site.encoding_a[1] != 0x90 ||
                site.encoding_b[0] != 0x87 || site.encoding_b[1] != 0xC0) {
                detail_out = "NOP watermark site encoding pattern mismatch";
                return false;
            }
        } else if (site.type == 2) {
            if (site.encoding_a.size() < 2 || site.encoding_b.size() < 2) {
                detail_out = "reg_alloc watermark site encoding too short";
                return false;
            }
            if (site.encoding_a[0] != 0x49 || site.encoding_a[1] != 0xBA ||
                site.encoding_b[0] != 0x49 || site.encoding_b[1] != 0xBB) {
                detail_out = "reg_alloc watermark site encoding pattern mismatch";
                return false;
            }

            constexpr uint32_t kRegRefScanWindow = 32;
            size_t scan_start = static_cast<size_t>(abs_off) + site_size;
            size_t scan_end = (std::min)(scan_start + kRegRefScanWindow, sec->data.size());
            bool r10_conflict = false;
            bool r11_conflict = false;
            for (size_t j = scan_start; j + 1 < scan_end; ++j) {
                uint8_t b = sec->data[j];
                if (b >= 0x40 && b <= 0x4F) {
                    uint8_t next = sec->data[j + 1];
                    bool rex_b = (b & 0x01) != 0;
                    bool rex_r = (b & 0x04) != 0;
                    if (rex_b) {
                        if ((next & 0x07) == 0x02) { r10_conflict = true; }
                        if ((next & 0x07) == 0x03) { r11_conflict = true; }
                        if (next == 0xBA) { r10_conflict = true; }
                        if (next == 0xBB) { r11_conflict = true; }
                    }
                    if (rex_r) {
                        if ((next & 0x38) == 0x10) { r10_conflict = true; }
                        if ((next & 0x38) == 0x18) { r11_conflict = true; }
                    }
                }
            }
            if (r10_conflict || r11_conflict) {
                ++type2_rejected;
            }
        } else if (site.type == 3) {
            if (site.encoding_a.size() < 4 || site.encoding_b.size() < 4) {
                detail_out = "bb_order watermark site encoding too short";
                return false;
            }
            if (site.encoding_a[0] != 0x00 || site.encoding_b[0] != 0x02) {
                detail_out = "bb_order watermark site encoding pattern mismatch";
                return false;
            }
        } else {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "unknown watermark site type %u", site.type);
            detail_out = buf;
            return false;
        }
    }

    if (type2_rejected > 0) {
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "watermark site register conflict: %u type 2 sites rejected",
                      type2_rejected);
        detail_out = buf;
        return false;
    }

    auto read_u32 = [&](size_t abs_off) -> uint32_t {
        uint32_t v = 0;
        if (abs_off + 4 <= sec->data.size()) {
            std::memcpy(&v, sec->data.data() + abs_off, sizeof(v));
        }
        return v;
    };

    uint32_t wb_abs = packed_off + key_slots.wb_aes_tables_offset;
    if (static_cast<size_t>(wb_abs) + 4 > sec->data.size()) {
        detail_out = "WB-AES key slot offset exceeds packed section";
        return false;
    }
    if (read_u32(wb_abs) != kTmKeySlotMagicWbAes) {
        detail_out = "WB-AES key slot magic mismatch";
        return false;
    }

    uint32_t arc_abs = packed_off + key_slots.arc_page_keys_offset;
    if (static_cast<size_t>(arc_abs) + 4 > sec->data.size()) {
        detail_out = "ARC page key slot offset exceeds packed section";
        return false;
    }
    if (read_u32(arc_abs) != kTmKeySlotMagicArc) {
        detail_out = "ARC page key slot magic mismatch";
        return false;
    }

    uint32_t drv_abs = packed_off + key_slots.driver_keys_offset;
    if (static_cast<size_t>(drv_abs) + 4 > sec->data.size()) {
        detail_out = "driver key slot offset exceeds packed section";
        return false;
    }
    if (read_u32(drv_abs) != kTmKeySlotMagicDriver) {
        detail_out = "driver key slot magic mismatch";
        return false;
    }

    if (key_slots.wb_aes_tables_size != kTmWbAesTableSize) {
        detail_out = "WB-AES table size mismatch";
        return false;
    }
    if (key_slots.arc_page_keys_size != kTmArcPageKeysSize) {
        detail_out = "ARC page key size mismatch";
        return false;
    }
    if (key_slots.driver_keys_size != kTmDriverKeysSize) {
        detail_out = "driver key size mismatch";
        return false;
    }
    if (key_slots.wb_aes_tables_size + key_slots.arc_page_keys_size + key_slots.driver_keys_size
        != kTmKeySlotTotalSize) {
        detail_out = "key slot total size mismatch";
        return false;
    }

    if (pe.dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        detail_out = "PE DOS signature invalid";
        return false;
    }

    {
        uint32_t e_lfanew_rich = static_cast<uint32_t>(pe.dos_header.e_lfanew);
        if (e_lfanew_rich > sizeof(IMAGE_DOS_HEADER) &&
            pe.raw_file.size() >= e_lfanew_rich) {
            const uint8_t* dos_area = pe.raw_file.data();
            size_t scan_end_rich = static_cast<size_t>(e_lfanew_rich) - 4;
            for (size_t i = sizeof(IMAGE_DOS_HEADER); i <= scan_end_rich; ++i) {
                uint32_t val = 0;
                std::memcpy(&val, dos_area + i, 4);
                if (val == 0x68636952) {
                    detail_out = "Rich header not stripped from template";
                    return false;
                }
            }
        }
        if (pe.has_rich_header) {
            detail_out = "Rich header flag indicates Rich header present";
            return false;
        }
    }

    if (pe.pe_signature != IMAGE_NT_SIGNATURE) {
        detail_out = "PE NT signature invalid";
        return false;
    }
    if (pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        detail_out = "PE optional header magic invalid";
        return false;
    }

    packed_header_t hdr{};
    std::memcpy(&hdr, sec->data.data() + packed_off, sizeof(hdr));
    if (hdr.magic != kPackedMagic || hdr.version != kPackedVersion) {
        detail_out = "packed header magic/version mismatch in template";
        return false;
    }

    if (hdr.aux_offset != 0u && hdr.aux_size == sizeof(aux_block_t)) {
        if (static_cast<size_t>(packed_off) + hdr.aux_offset + sizeof(aux_block_t) <= sec->data.size()) {
            aux_block_t aux{};
            std::memcpy(&aux, sec->data.data() + packed_off + hdr.aux_offset, sizeof(aux_block_t));
            if (aux.magic != kAuxMagic) {
                detail_out = "aux block magic mismatch in template";
                return false;
            }
            if (aux.spread_seed != kTmWatermarkMagic) {
                detail_out = "template watermark spread seed mismatch";
                return false;
            }
            bool wm_zero = true;
            for (int i = 0; i < 16; ++i) {
                if (aux.watermark[i] != 0u) { wm_zero = false; break; }
            }
            if (!wm_zero) {
                detail_out = "template watermark is not zeroed";
                return false;
            }
            if (aux.pin_reserved[0] != key_slots.wb_aes_tables_offset ||
                aux.pin_reserved[1] != key_slots.arc_page_keys_offset ||
                aux.pin_reserved[2] != key_slots.driver_keys_offset ||
                aux.pin_reserved[3] != kTmKeySlotTotalSize) {
                detail_out = "aux pin_reserved key slot offsets mismatch";
                return false;
            }
        }
    }

    const uint32_t ep = pe.optional_header.AddressOfEntryPoint;
    const pe_file::section_t* ep_sec = pe.section_from_rva(ep);
    if (!ep_sec) {
        detail_out = "entry point not inside any section";
        return false;
    }
    detail_out = "template verification passed";
    return true;
}

}
