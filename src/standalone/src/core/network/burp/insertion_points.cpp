#include "insertion_points.hpp"

#include <nlohmann/json.hpp>

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace insertion_points {

namespace {

bool ieq_ascii(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = static_cast<char>(std::tolower(static_cast<unsigned char>(a[i])));
        char cb = static_cast<char>(std::tolower(static_cast<unsigned char>(b[i])));
        if (ca != cb) return false;
    }
    return true;
}

bool find_substr(const std::string& haystack, const std::string& needle, size_t& out)
{
    auto p = haystack.find(needle);
    if (p == std::string::npos) return false;
    out = p;
    return true;
}

struct request_line_t
{
    std::string method;
    std::string uri;
    std::string version;
    size_t      method_offset = 0;
    size_t      uri_offset = 0;
    size_t      uri_length = 0;
    size_t      headers_offset = 0;
    size_t      body_offset = 0;
    bool        valid = false;
};

request_line_t parse_request_line(const std::string& raw)
{
    request_line_t out;
    auto eol = raw.find("\r\n");
    if (eol == std::string::npos) return out;
    auto sp1 = raw.find(' ');
    if (sp1 == std::string::npos || sp1 >= eol) return out;
    auto sp2 = raw.find(' ', sp1 + 1);
    if (sp2 == std::string::npos || sp2 >= eol) return out;
    out.method = raw.substr(0, sp1);
    out.uri    = raw.substr(sp1 + 1, sp2 - sp1 - 1);
    out.version = raw.substr(sp2 + 1, eol - sp2 - 1);
    out.method_offset = 0;
    out.uri_offset = sp1 + 1;
    out.uri_length = sp2 - sp1 - 1;
    out.headers_offset = eol + 2;
    auto body_sep = raw.find("\r\n\r\n", out.headers_offset);
    out.body_offset = (body_sep == std::string::npos) ? raw.size() : body_sep + 4;
    out.valid = true;
    return out;
}

struct header_view_t
{
    std::string name;
    std::string value;
    size_t      name_offset = 0;
    size_t      value_offset = 0;
    size_t      value_length = 0;
    size_t      line_end = 0;
};

std::vector<header_view_t> parse_headers(const std::string& raw, size_t headers_start, size_t body_start)
{
    std::vector<header_view_t> out;
    size_t p = headers_start;
    size_t end = (body_start >= 4) ? body_start - 4 : raw.size();
    while (p < end) {
        auto eol = raw.find("\r\n", p);
        if (eol == std::string::npos || eol > end) break;
        auto colon = raw.find(':', p);
        if (colon == std::string::npos || colon >= eol) {
            p = eol + 2;
            continue;
        }
        header_view_t h;
        h.name = raw.substr(p, colon - p);
        size_t vs = colon + 1;
        while (vs < eol && (raw[vs] == ' ' || raw[vs] == '\t')) ++vs;
        size_t ve = eol;
        while (ve > vs && (raw[ve - 1] == ' ' || raw[ve - 1] == '\t')) --ve;
        h.value = raw.substr(vs, ve - vs);
        h.name_offset = p;
        h.value_offset = vs;
        h.value_length = ve - vs;
        h.line_end = eol;
        out.push_back(std::move(h));
        p = eol + 2;
    }
    return out;
}

bool is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

std::string content_length_str(size_t n)
{
    std::ostringstream os; os << n; return os.str();
}

std::string update_content_length(const std::string& raw, const request_line_t& rl,
                                  const std::vector<header_view_t>& headers, size_t new_body_len)
{
    for (const auto& h : headers) {
        if (ieq_ascii(h.name, "Content-Length")) {
            std::string new_val = content_length_str(new_body_len);
            std::string out = raw.substr(0, h.value_offset);
            out += new_val;
            out += raw.substr(h.value_offset + h.value_length);
            return out;
        }
    }
    (void)rl;
    return raw;
}

std::vector<uint8_t> rebuild_with_uri(const std::string& raw, const request_line_t& rl, const std::string& new_uri)
{
    std::string out;
    out.reserve(raw.size() + new_uri.size());
    out += raw.substr(0, rl.uri_offset);
    out += new_uri;
    out += raw.substr(rl.uri_offset + rl.uri_length);
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> rebuild_with_header_value(const std::string& raw, const header_view_t& h, const std::string& new_value)
{
    std::string out;
    out.reserve(raw.size() + new_value.size());
    out += raw.substr(0, h.value_offset);
    out += new_value;
    out += raw.substr(h.value_offset + h.value_length);
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> rebuild_with_body(const std::string& raw, const request_line_t& rl,
                                       const std::vector<header_view_t>& headers, const std::string& new_body)
{
    std::string with_cl = update_content_length(raw, rl, headers, new_body.size());
    auto rl2 = parse_request_line(with_cl);
    if (!rl2.valid) return std::vector<uint8_t>(raw.begin(), raw.end());
    std::string out;
    out.reserve(rl2.body_offset + new_body.size());
    out += with_cl.substr(0, rl2.body_offset);
    out += new_body;
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<std::pair<size_t, size_t>> find_query_pairs(const std::string& q)
{
    std::vector<std::pair<size_t, size_t>> out;
    size_t p = 0;
    while (p < q.size()) {
        size_t amp = q.find('&', p);
        size_t eq  = q.find('=', p);
        size_t end = (amp == std::string::npos) ? q.size() : amp;
        if (eq != std::string::npos && eq < end) {
            out.emplace_back(p, eq);
        } else {
            out.emplace_back(p, end);
        }
        if (amp == std::string::npos) break;
        p = amp + 1;
    }
    return out;
}

void collect_json_leaves(const nlohmann::json& node, const std::string& jp,
                         std::vector<std::pair<std::string, std::string>>& leaves)
{
    if (node.is_object()) {
        for (auto it = node.begin(); it != node.end(); ++it)
            collect_json_leaves(it.value(), jp + "/" + it.key(), leaves);
    } else if (node.is_array()) {
        for (size_t i = 0; i < node.size(); ++i)
            collect_json_leaves(node[i], jp + "/" + std::to_string(i), leaves);
    } else if (node.is_string()) {
        leaves.emplace_back(jp, node.get<std::string>());
    } else if (node.is_number() || node.is_boolean()) {
        std::ostringstream os; os << node;
        leaves.emplace_back(jp, os.str());
    }
}

bool json_set_leaf(nlohmann::json& node, const std::string& jp, const std::string& value)
{
    if (jp.empty() || jp[0] != '/') return false;
    std::vector<std::string> parts;
    size_t p = 1;
    while (p <= jp.size()) {
        size_t q = jp.find('/', p);
        if (q == std::string::npos) q = jp.size();
        parts.push_back(jp.substr(p, q - p));
        p = q + 1;
    }
    nlohmann::json* cur = &node;
    for (size_t i = 0; i + 1 < parts.size(); ++i) {
        if (cur->is_object()) cur = &(*cur)[parts[i]];
        else if (cur->is_array()) {
            size_t idx = 0;
            try { idx = static_cast<size_t>(std::stoul(parts[i])); } catch (...) { return false; }
            if (idx >= cur->size()) return false;
            cur = &(*cur)[idx];
        } else return false;
    }
    const std::string& last = parts.back();
    if (cur->is_object()) (*cur)[last] = value;
    else if (cur->is_array()) {
        size_t idx = 0;
        try { idx = static_cast<size_t>(std::stoul(last)); } catch (...) { return false; }
        if (idx >= cur->size()) return false;
        (*cur)[idx] = value;
    } else return false;
    return true;
}

void collect_xml_text_nodes(const std::string& body, std::vector<std::pair<size_t, size_t>>& spans)
{
    size_t p = 0;
    while (p < body.size()) {
        size_t lt = body.find('<', p);
        if (lt == std::string::npos) break;
        if (lt > p) {
            std::string span = body.substr(p, lt - p);
            bool only_ws = true;
            for (char c : span) if (c != ' ' && c != '\t' && c != '\r' && c != '\n') { only_ws = false; break; }
            if (!only_ws) spans.emplace_back(p, lt);
        }
        size_t gt = body.find('>', lt);
        if (gt == std::string::npos) break;
        p = gt + 1;
    }
}

bool is_common_skipped_header(const std::string& name)
{
    static const std::set<std::string> skip = {
        "content-length", "content-type", "content-encoding", "transfer-encoding",
        "connection", "expect", "te", "trailer", "upgrade", "proxy-connection",
        "if-modified-since", "if-none-match", "if-match", "if-range",
        "accept", "accept-encoding", "accept-language", "accept-charset",
        "date"
    };
    std::string lc; lc.reserve(name.size());
    for (char c : name) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return skip.count(lc) != 0;
}

bool is_target_header(const std::string& name)
{
    static const std::set<std::string> targets = {
        "user-agent", "referer", "x-forwarded-for", "x-forwarded-host",
        "x-real-ip", "host", "authorization", "x-original-url",
        "x-rewrite-url", "x-custom-ip-authorization", "true-client-ip",
        "cluster-client-ip", "client-ip"
    };
    std::string lc; lc.reserve(name.size());
    for (char c : name) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return targets.count(lc) != 0;
}

}

std::string url_encode(const std::string& s)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

std::string url_decode(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') out.push_back(' ');
        else if (s[i] == '%' && i + 2 < s.size() && is_hex(s[i + 1]) && is_hex(s[i + 2])) {
            int v = (hex_val(s[i + 1]) << 4) | hex_val(s[i + 2]);
            out.push_back(static_cast<char>(v));
            i += 2;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

std::vector<insertion_point_t> analyze(const std::vector<uint8_t>& raw_request, const std::string& /*url*/)
{
    diag::log_tagged_fmt("insertion_points", "analyze raw_len=%zu", raw_request.size());
    std::vector<insertion_point_t> out;
    if (raw_request.empty()) {
        diag::log_tagged("insertion_points", "analyze empty_request");
        return out;
    }
    std::string raw(reinterpret_cast<const char*>(raw_request.data()), raw_request.size());
    auto rl = parse_request_line(raw);
    if (!rl.valid) {
        diag::log_tagged("insertion_points", "analyze invalid_request_line");
        return out;
    }
    diag::log_tagged_fmt("insertion_points", "analyze method=%s uri=%s", rl.method.c_str(), rl.uri.c_str());
    auto headers = parse_headers(raw, rl.headers_offset, rl.body_offset);
    diag::log_tagged_fmt("insertion_points", "analyze header_count=%zu body_offset=%zu", headers.size(), rl.body_offset);

    std::string uri = rl.uri;
    size_t qmark = uri.find('?');
    std::string path = (qmark == std::string::npos) ? uri : uri.substr(0, qmark);
    std::string query = (qmark == std::string::npos) ? std::string() : uri.substr(qmark + 1);

    if (!query.empty()) {
        auto pairs = find_query_pairs(query);
        diag::log_tagged_fmt("insertion_points", "analyze query_params_found=%zu", pairs.size());
        for (auto& pr : pairs) {
            size_t key_off = pr.first;
            size_t eq_off  = pr.second;
            if (eq_off >= query.size() || query[eq_off] != '=') continue;
            std::string name = query.substr(key_off, eq_off - key_off);
            size_t val_start = eq_off + 1;
            size_t val_end = query.find('&', val_start);
            if (val_end == std::string::npos) val_end = query.size();
            std::string raw_val = query.substr(val_start, val_end - val_start);
            std::string decoded = url_decode(raw_val);

            diag::log_tagged_fmt("insertion_points", "analyze query_param name=%s", name.c_str());
            insertion_point_t ip;
            ip.kind = "query";
            ip.name = url_decode(name);
            ip.original_value = decoded;
            ip.base_request = raw;
            ip.value_offset = rl.uri_offset + (qmark + 1) + val_start;
            ip.value_length = val_end - val_start;
            std::string captured_uri = uri;
            size_t captured_qmark = qmark;
            size_t captured_val_start = val_start;
            size_t captured_val_end   = val_end;
            ip.build = [raw, rl, captured_uri, captured_qmark, captured_val_start, captured_val_end](const std::string& injected) {
                std::string enc = url_encode(injected);
                std::string new_query = captured_uri.substr(captured_qmark + 1, captured_val_start) + enc;
                if (captured_val_end < captured_uri.size() - (captured_qmark + 1))
                    new_query += captured_uri.substr(captured_qmark + 1 + captured_val_end);
                std::string new_uri = captured_uri.substr(0, captured_qmark + 1) + new_query;
                return rebuild_with_uri(raw, rl, new_uri);
            };
            out.push_back(std::move(ip));
        }
    }

    if (!path.empty() && path.size() > 1) {
        diag::log_tagged_fmt("insertion_points", "analyze path_segments path=%s", path.c_str());
        size_t p = 1;
        size_t seg_index = 0;
        while (p < path.size()) {
            size_t slash = path.find('/', p);
            size_t end = (slash == std::string::npos) ? path.size() : slash;
            std::string seg = path.substr(p, end - p);
            if (!seg.empty()) {
                diag::log_tagged_fmt("insertion_points", "analyze path_segment seg=%s idx=%zu", seg.c_str(), seg_index);
                insertion_point_t ip;
                ip.kind = "path";
                ip.name = "seg" + std::to_string(seg_index);
                ip.original_value = url_decode(seg);
                ip.base_request = raw;
                ip.value_offset = rl.uri_offset + p;
                ip.value_length = end - p;
                std::string captured_path = path;
                std::string captured_query = query;
                size_t captured_p = p;
                size_t captured_end = end;
                ip.build = [raw, rl, captured_path, captured_query, captured_p, captured_end](const std::string& injected) {
                    std::string enc = url_encode(injected);
                    std::string new_path = captured_path.substr(0, captured_p) + enc + captured_path.substr(captured_end);
                    std::string new_uri = new_path;
                    if (!captured_query.empty()) { new_uri += '?'; new_uri += captured_query; }
                    return rebuild_with_uri(raw, rl, new_uri);
                };
                out.push_back(std::move(ip));
                ++seg_index;
            }
            if (slash == std::string::npos) break;
            p = slash + 1;
        }
    }

    std::string body(raw.begin() + static_cast<std::ptrdiff_t>(rl.body_offset), raw.end());
    std::string content_type_str;
    for (const auto& h : headers) {
        if (ieq_ascii(h.name, "Content-Type")) { content_type_str = h.value; break; }
    }
    std::string ct_lower; ct_lower.reserve(content_type_str.size());
    for (char c : content_type_str) ct_lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    diag::log_tagged_fmt("insertion_points", "analyze body_len=%zu content_type=%s", body.size(), content_type_str.c_str());

    if (!body.empty()) {
        if (ct_lower.find("application/x-www-form-urlencoded") != std::string::npos) {
            auto pairs = find_query_pairs(body);
            diag::log_tagged_fmt("insertion_points", "analyze form_body_pairs=%zu", pairs.size());
            for (auto& pr : pairs) {
                size_t key_off = pr.first;
                size_t eq_off  = pr.second;
                if (eq_off >= body.size() || body[eq_off] != '=') continue;
                std::string name = body.substr(key_off, eq_off - key_off);
                size_t val_start = eq_off + 1;
                size_t val_end = body.find('&', val_start);
                if (val_end == std::string::npos) val_end = body.size();
                std::string raw_val = body.substr(val_start, val_end - val_start);
                insertion_point_t ip;
                ip.kind = "body_form";
                ip.name = url_decode(name);
                ip.original_value = url_decode(raw_val);
                ip.base_request = raw;
                ip.value_offset = rl.body_offset + val_start;
                ip.value_length = val_end - val_start;
                std::string captured_body = body;
                size_t captured_val_start = val_start;
                size_t captured_val_end   = val_end;
                ip.build = [raw, rl, headers, captured_body, captured_val_start, captured_val_end](const std::string& injected) {
                    std::string enc = url_encode(injected);
                    std::string new_body = captured_body.substr(0, captured_val_start) + enc + captured_body.substr(captured_val_end);
                    return rebuild_with_body(raw, rl, headers, new_body);
                };
                out.push_back(std::move(ip));
            }
        } else if (ct_lower.find("application/json") != std::string::npos) {
            nlohmann::json doc;
            bool parsed = false;
            try { doc = nlohmann::json::parse(body); parsed = true; } catch (...) {}
            if (!parsed) {
                diag::log_tagged("insertion_points", "analyze json_body_parse_failed");
            }
            if (parsed) {
                diag::log_tagged("insertion_points", "analyze json_body_parsed");
                std::vector<std::pair<std::string, std::string>> leaves;
                collect_json_leaves(doc, "", leaves);
                diag::log_tagged_fmt("insertion_points", "analyze json_leaves=%zu", leaves.size());
                for (const auto& lf : leaves) {
                    insertion_point_t ip;
                    ip.kind = "body_json";
                    ip.name = lf.first;
                    ip.original_value = lf.second;
                    ip.base_request = raw;
                    ip.value_offset = 0;
                    ip.value_length = 0;
                    std::string captured_body = body;
                    std::string captured_jp = lf.first;
                    ip.build = [raw, rl, headers, captured_body, captured_jp](const std::string& injected) {
                        nlohmann::json doc2;
                        try { doc2 = nlohmann::json::parse(captured_body); } catch (...) {
                            return rebuild_with_body(raw, rl, headers, captured_body);
                        }
                        if (!json_set_leaf(doc2, captured_jp, injected))
                            return rebuild_with_body(raw, rl, headers, captured_body);
                        std::string new_body = doc2.dump();
                        return rebuild_with_body(raw, rl, headers, new_body);
                    };
                    out.push_back(std::move(ip));
                }
            }
        } else if (ct_lower.find("xml") != std::string::npos) {
            std::vector<std::pair<size_t, size_t>> spans;
            collect_xml_text_nodes(body, spans);
            diag::log_tagged_fmt("insertion_points", "analyze xml_text_nodes=%zu", spans.size());
            size_t idx = 0;
            for (const auto& sp : spans) {
                insertion_point_t ip;
                ip.kind = "body_xml";
                ip.name = "text" + std::to_string(idx++);
                ip.original_value = body.substr(sp.first, sp.second - sp.first);
                ip.base_request = raw;
                ip.value_offset = rl.body_offset + sp.first;
                ip.value_length = sp.second - sp.first;
                std::string captured_body = body;
                size_t captured_start = sp.first;
                size_t captured_end   = sp.second;
                ip.build = [raw, rl, headers, captured_body, captured_start, captured_end](const std::string& injected) {
                    std::string new_body = captured_body.substr(0, captured_start) + injected + captured_body.substr(captured_end);
                    return rebuild_with_body(raw, rl, headers, new_body);
                };
                out.push_back(std::move(ip));
            }
        } else if (ct_lower.find("multipart/form-data") != std::string::npos) {
            diag::log_tagged("insertion_points", "analyze multipart_body");
            size_t bpos = ct_lower.find("boundary=");
            std::string boundary;
            if (bpos != std::string::npos) {
                boundary = content_type_str.substr(bpos + 9);
                if (!boundary.empty() && boundary.front() == '"' && boundary.back() == '"')
                    boundary = boundary.substr(1, boundary.size() - 2);
            }
            if (!boundary.empty()) {
                diag::log_tagged_fmt("insertion_points", "analyze multipart_boundary=%s", boundary.c_str());
                std::string delim = "--" + boundary;
                size_t p = 0;
                size_t idx = 0;
                while (p < body.size()) {
                    size_t s = body.find(delim, p);
                    if (s == std::string::npos) break;
                    size_t hdr_end = body.find("\r\n\r\n", s);
                    if (hdr_end == std::string::npos) break;
                    size_t next_b = body.find(delim, hdr_end + 4);
                    if (next_b == std::string::npos) break;
                    size_t data_start = hdr_end + 4;
                    size_t data_end = next_b;
                    if (data_end >= 2 && body[data_end - 2] == '\r' && body[data_end - 1] == '\n') data_end -= 2;
                    std::string hdr_section = body.substr(s, hdr_end - s);
                    std::string field_name = "field" + std::to_string(idx++);
                    size_t nm = hdr_section.find("name=\"");
                    if (nm != std::string::npos) {
                        size_t e = hdr_section.find('"', nm + 6);
                        if (e != std::string::npos) field_name = hdr_section.substr(nm + 6, e - nm - 6);
                    }
                    diag::log_tagged_fmt("insertion_points", "analyze multipart_field name=%s idx=%zu", field_name.c_str(), idx - 1);
                    insertion_point_t ip;
                    ip.kind = "body_multipart";
                    ip.name = field_name;
                    ip.original_value = body.substr(data_start, data_end - data_start);
                    ip.base_request = raw;
                    ip.value_offset = rl.body_offset + data_start;
                    ip.value_length = data_end - data_start;
                    std::string captured_body = body;
                    size_t captured_start = data_start;
                    size_t captured_end   = data_end;
                    ip.build = [raw, rl, headers, captured_body, captured_start, captured_end](const std::string& injected) {
                        std::string new_body = captured_body.substr(0, captured_start) + injected + captured_body.substr(captured_end);
                        return rebuild_with_body(raw, rl, headers, new_body);
                    };
                    out.push_back(std::move(ip));
                    p = next_b;
                }
            }
        }
    }

    diag::log_tagged_fmt("insertion_points", "analyze scanning_headers_for_cookies_and_targets header_count=%zu", headers.size());
    for (const auto& h : headers) {
        std::string lc; lc.reserve(h.name.size());
        for (char c : h.name) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        if (lc == "cookie") {
            diag::log_tagged_fmt("insertion_points", "analyze cookie_header value_len=%zu", h.value.size());
            size_t p = 0;
            while (p < h.value.size()) {
                size_t eq = h.value.find('=', p);
                if (eq == std::string::npos) break;
                std::string cname;
                size_t name_start = p;
                while (name_start < eq && (h.value[name_start] == ' ' || h.value[name_start] == '\t')) ++name_start;
                cname = h.value.substr(name_start, eq - name_start);
                size_t val_start = eq + 1;
                size_t val_end = h.value.find(';', val_start);
                if (val_end == std::string::npos) val_end = h.value.size();
                std::string cval = h.value.substr(val_start, val_end - val_start);

                diag::log_tagged_fmt("insertion_points", "analyze cookie_param name=%s", cname.c_str());
                insertion_point_t ip;
                ip.kind = "cookie";
                ip.name = cname;
                ip.original_value = cval;
                ip.base_request = raw;
                ip.value_offset = h.value_offset + val_start;
                ip.value_length = val_end - val_start;
                header_view_t captured_h = h;
                std::string captured_val = h.value;
                size_t captured_vs = val_start;
                size_t captured_ve = val_end;
                ip.build = [raw, captured_h, captured_val, captured_vs, captured_ve](const std::string& injected) {
                    std::string new_value = captured_val.substr(0, captured_vs) + injected + captured_val.substr(captured_ve);
                    return rebuild_with_header_value(raw, captured_h, new_value);
                };
                out.push_back(std::move(ip));

                if (val_end >= h.value.size()) break;
                p = val_end + 1;
                while (p < h.value.size() && (h.value[p] == ' ' || h.value[p] == '\t')) ++p;
            }
        } else if (is_target_header(h.name) && !is_common_skipped_header(h.name)) {
            diag::log_tagged_fmt("insertion_points", "analyze target_header name=%s", h.name.c_str());
            insertion_point_t ip;
            ip.kind = "header";
            ip.name = h.name;
            ip.original_value = h.value;
            ip.base_request = raw;
            ip.value_offset = h.value_offset;
            ip.value_length = h.value_length;
            header_view_t captured_h = h;
            ip.build = [raw, captured_h](const std::string& injected) {
                return rebuild_with_header_value(raw, captured_h, injected);
            };
            out.push_back(std::move(ip));
        }
    }

    diag::log_tagged_fmt("insertion_points", "analyze complete total_points=%zu", out.size());
    return out;
}

}
}
}
