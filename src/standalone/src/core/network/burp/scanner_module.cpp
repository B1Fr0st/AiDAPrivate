#include "scanner_module.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

struct registry_t
{
    std::mutex                                   mtx;
    std::vector<module_t>                        modules;
    std::unordered_map<std::string, size_t>      by_id;
};

registry_t& reg()
{
    static registry_t r;
    return r;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string base36(uint64_t v)
{
    static const char alph[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (v == 0) return "0";
    std::string out;
    while (v > 0) { out.push_back(alph[v % 36]); v /= 36; }
    std::reverse(out.begin(), out.end());
    return out;
}

}

bool register_module(module_t mod)
{
    diag::log_tagged_fmt("scanner", "register_module id=%s probes=%s detect=%s custom_run=%s",
        mod.id.c_str(),
        mod.probes ? "yes" : "no",
        mod.detect ? "yes" : "no",
        mod.custom_run ? "yes" : "no");
    if (mod.id.empty() || (!mod.custom_run && (!mod.probes || !mod.detect))) {
        diag::log_tagged_fmt("scanner", "register_module rejected id=%s reason=%s",
            mod.id.c_str(),
            mod.id.empty() ? "empty_id" : (!mod.probes ? "no_probes" : "no_detect"));
        return false;
    }
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.mtx);
    auto it = r.by_id.find(mod.id);
    if (it != r.by_id.end()) {
        diag::log_tagged_fmt("scanner", "register_module replace id=%s idx=%zu", mod.id.c_str(), it->second);
        r.modules[it->second] = std::move(mod);
        return true;
    }
    size_t new_idx = r.modules.size();
    diag::log_tagged_fmt("scanner", "register_module new id=%s idx=%zu total=%zu", mod.id.c_str(), new_idx, new_idx + 1);
    r.by_id[mod.id] = new_idx;
    r.modules.push_back(std::move(mod));
    return true;
}

std::vector<module_t> all_modules()
{
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.mtx);
    diag::log_tagged_fmt("scanner", "all_modules returning %zu modules", r.modules.size());
    return r.modules;
}

const module_t* find(const std::string& id)
{
    diag::log_tagged_fmt("scanner", "find id=%s", id.c_str());
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.mtx);
    auto it = r.by_id.find(id);
    if (it == r.by_id.end()) {
        diag::log_tagged_fmt("scanner", "find id=%s not_found", id.c_str());
        return nullptr;
    }
    diag::log_tagged_fmt("scanner", "find id=%s found idx=%zu", id.c_str(), it->second);
    return &r.modules[it->second];
}

size_t count()
{
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.mtx);
    size_t n = r.modules.size();
    diag::log_tagged_fmt("scanner", "count=%zu", n);
    return n;
}

std::string random_marker(const std::string& prefix)
{
    static std::atomic<uint64_t> s_counter{0};
    static std::mt19937_64 s_rng{std::random_device{}()};
    static std::mutex s_mtx;
    uint64_t c = s_counter.fetch_add(1, std::memory_order_relaxed);
    uint64_t r;
    { std::lock_guard<std::mutex> lk(s_mtx); r = s_rng(); }
    std::ostringstream os;
    os << prefix << base36(now_ms()) << base36(c) << base36(r & 0xFFFFFFFFu);
    std::string marker = os.str();
    diag::log_tagged_fmt("scanner", "random_marker prefix=%s result=%s", prefix.c_str(), marker.c_str());
    return marker;
}

bool body_contains(const exchange_observed_t& resp, const std::string& needle)
{
    if (needle.empty()) return false;
    if (resp.resp_body.empty()) return false;
    auto end = resp.resp_body.end();
    auto it = std::search(resp.resp_body.begin(), end,
                          needle.begin(), needle.end());
    bool found = it != end;
    diag::log_tagged_fmt("scanner", "body_contains needle_len=%zu body_len=%zu found=%d",
        needle.size(), resp.resp_body.size(), found ? 1 : 0);
    return found;
}

bool body_contains_ci(const exchange_observed_t& resp, const std::string& needle)
{
    if (needle.empty() || resp.resp_body.empty()) return false;
    if (needle.size() > resp.resp_body.size()) return false;
    std::string nl; nl.reserve(needle.size());
    for (char c : needle) nl.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    for (size_t i = 0; i + nl.size() <= resp.resp_body.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < nl.size(); ++j) {
            char rb = static_cast<char>(std::tolower(static_cast<unsigned char>(resp.resp_body[i + j])));
            if (rb != nl[j]) { match = false; break; }
        }
        if (match) {
            diag::log_tagged_fmt("scanner", "body_contains_ci needle=%s found at offset=%zu", needle.c_str(), i);
            return true;
        }
    }
    diag::log_tagged_fmt("scanner", "body_contains_ci needle=%s not_found body_len=%zu", needle.c_str(), resp.resp_body.size());
    return false;
}

double body_length_ratio(const exchange_observed_t& a, const exchange_observed_t& b)
{
    size_t la = a.resp_body.size();
    size_t lb = b.resp_body.size();
    if (la == 0 && lb == 0) return 1.0;
    if (la == 0 || lb == 0) return 0.0;
    double ratio = static_cast<double>(std::min(la, lb)) / static_cast<double>(std::max(la, lb));
    diag::log_tagged_fmt("scanner", "body_length_ratio la=%zu lb=%zu ratio=%.4f", la, lb, ratio);
    return ratio;
}

namespace {

std::string snippet_around(const std::vector<uint8_t>& body, const std::string& needle, size_t pad)
{
    if (body.empty() || needle.empty()) return std::string();
    auto it = std::search(body.begin(), body.end(), needle.begin(), needle.end());
    if (it == body.end()) return std::string();
    size_t pos = static_cast<size_t>(it - body.begin());
    size_t start = (pos > pad) ? pos - pad : 0;
    size_t end = std::min(pos + needle.size() + pad, body.size());
    std::string out(reinterpret_cast<const char*>(body.data() + start), end - start);
    for (char& c : out) if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') c = '.';
    return out;
}

std::string render_request_brief(const exchange_observed_t& resp, const probe_t& probe)
{
    std::ostringstream os;
    os << resp.method << " " << resp.path;
    if (!resp.query.empty()) os << "?" << resp.query;
    os << " HTTP/1.1\r\nHost: " << resp.host;
    if (resp.port != 0 && resp.port != 80 && resp.port != 443) os << ":" << resp.port;
    os << "\r\n";
    for (const auto& h : resp.req_headers) {
        std::string lc = h.first;
        std::transform(lc.begin(), lc.end(), lc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lc == "host") continue;
        os << h.first << ": " << h.second << "\r\n";
    }
    os << "\r\n";
    if (!resp.req_body.empty()) {
        size_t limit = std::min(resp.req_body.size(), static_cast<size_t>(512));
        os.write(reinterpret_cast<const char*>(resp.req_body.data()), static_cast<std::streamsize>(limit));
    }
    (void)probe;
    return os.str();
}

std::string render_response_brief(const exchange_observed_t& resp)
{
    std::ostringstream os;
    os << "HTTP/1.1 " << resp.status_code << " " << resp.reason_phrase << "\r\n";
    for (const auto& h : resp.resp_headers) os << h.first << ": " << h.second << "\r\n";
    os << "\r\n";
    size_t limit = std::min(resp.resp_body.size(), static_cast<size_t>(2048));
    os.write(reinterpret_cast<const char*>(resp.resp_body.data()), static_cast<std::streamsize>(limit));
    return os.str();
}

}

issue_t make_issue(const std::string& type_key,
                   const std::string& name,
                   severity_t severity,
                   confidence_t confidence,
                   const insertion_point_t& ip,
                   const probe_t& probe,
                   const exchange_observed_t& resp,
                   const module_context_t& ctx,
                   const std::string& evidence_snippet)
{
    diag::log_tagged_fmt("scanner", "make_issue type=%s name=%s severity=%d confidence=%d ip_kind=%s ip_name=%s host=%s path=%s status=%d",
        type_key.c_str(), name.c_str(),
        static_cast<int>(severity), static_cast<int>(confidence),
        ip.kind.c_str(), ip.name.c_str(),
        resp.host.empty() ? ctx.host.c_str() : resp.host.c_str(),
        resp.path.c_str(), resp.status_code);
    issue_t iss;
    iss.type_key = type_key;
    iss.name = name;
    iss.severity = severity;
    iss.confidence = confidence;
    iss.scheme = resp.scheme.empty() ? (ctx.tls ? std::string("https") : std::string("http")) : resp.scheme;
    iss.host = resp.host.empty() ? ctx.host : resp.host;
    iss.port = resp.port == 0 ? ctx.port : resp.port;
    iss.path = resp.path;
    iss.parameter = ip.name;
    iss.insertion_point = ip.kind + (ip.name.empty() ? std::string() : (":" + ip.name));
    iss.seen_ms = now_ms();
    iss.audit_id = ctx.audit_id;
    iss.src_exchange_id = resp.id;

    evidence_t ev;
    ev.marker = probe.marker;
    ev.request_raw = render_request_brief(resp, probe);
    ev.response_raw = render_response_brief(resp);
    if (!evidence_snippet.empty()) {
        ev.marker = evidence_snippet;
    } else if (!probe.marker.empty()) {
        auto snip = snippet_around(resp.resp_body, probe.marker, 64);
        if (!snip.empty()) ev.marker = snip;
    }
    iss.evidence.push_back(std::move(ev));
    return iss;
}

}
}
}
