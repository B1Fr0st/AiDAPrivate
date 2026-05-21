#include "../scanner_module.hpp"
#include "../audit_http.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

bool insertion_point_is_request_line(const insertion_point_t& ip)
{
    return ip.value_offset < 64;
}

std::vector<uint8_t> build_cl_te_request(const std::string& base)
{
    auto eol = base.find("\r\n");
    if (eol == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    auto body_off = base.find("\r\n\r\n");
    if (body_off == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    body_off += 4;

    std::string smuggled = "0\r\n\r\nG";
    std::string out = base.substr(0, eol + 2);
    out += "Content-Length: ";
    out += std::to_string(smuggled.size());
    out += "\r\nTransfer-Encoding: chunked\r\n";

    std::string headers_section = base.substr(eol + 2, body_off - eol - 2 - 4);
    std::string lc = headers_section;
    std::transform(lc.begin(), lc.end(), lc.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string filtered;
    size_t p = 0;
    while (p < headers_section.size()) {
        size_t le = headers_section.find("\r\n", p);
        if (le == std::string::npos) le = headers_section.size();
        std::string line = headers_section.substr(p, le - p);
        std::string llc = line;
        std::transform(llc.begin(), llc.end(), llc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (llc.rfind("content-length:", 0) != 0 && llc.rfind("transfer-encoding:", 0) != 0) {
            filtered += line;
            filtered += "\r\n";
        }
        if (le == headers_section.size()) break;
        p = le + 2;
    }
    out += filtered;
    out += "\r\n";
    out += smuggled;
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> build_te_cl_request(const std::string& base)
{
    auto eol = base.find("\r\n");
    if (eol == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());

    std::string smuggled = "5\r\nGHOST\r\n0\r\n\r\n";
    std::string out = base.substr(0, eol + 2);
    out += "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n";

    auto body_off = base.find("\r\n\r\n");
    if (body_off == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    body_off += 4;
    std::string headers_section = base.substr(eol + 2, body_off - eol - 2 - 4);
    std::string filtered;
    size_t p = 0;
    while (p < headers_section.size()) {
        size_t le = headers_section.find("\r\n", p);
        if (le == std::string::npos) le = headers_section.size();
        std::string line = headers_section.substr(p, le - p);
        std::string llc = line;
        std::transform(llc.begin(), llc.end(), llc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (llc.rfind("content-length:", 0) != 0 && llc.rfind("transfer-encoding:", 0) != 0) {
            filtered += line;
            filtered += "\r\n";
        }
        if (le == headers_section.size()) break;
        p = le + 2;
    }
    out += filtered;
    out += "\r\n";
    out += smuggled;
    return std::vector<uint8_t>(out.begin(), out.end());
}

void smuggling_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_smuggling", "smuggling_run entry ip=%s:%s host=%s value_offset=%zu",
                         ip.kind.c_str(), ip.name.c_str(), ctx.host.c_str(), ip.value_offset);
    if (!insertion_point_is_request_line(ip)) {
        diag::log_tagged_fmt("mod_smuggling", "smuggling_run skip not request-line value_offset=%zu", ip.value_offset);
        return;
    }

    auto t0 = std::chrono::steady_clock::now();
    audit_http::send_options_t opt;
    opt.timeout_ms = 8000;
    diag::log_tagged_fmt("mod_smuggling", "smuggling_run fetching baseline host=%s port=%d tls=%d", ctx.host.c_str(), ctx.port, ctx.tls ? 1 : 0);
    auto baseline = audit_http::send(std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end()),
                                     ctx.host, ctx.port, ctx.tls, opt);
    if (!baseline.has_value()) {
        diag::log_tagged_fmt("mod_smuggling", "smuggling_run no baseline response host=%s", ctx.host.c_str());
        return;
    }
    auto baseline_lat = baseline->latency_ms;
    diag::log_tagged_fmt("mod_smuggling", "smuggling_run baseline status=%d latency=%llums", baseline->status_code, static_cast<unsigned long long>(baseline_lat));

    auto cl_te_raw = build_cl_te_request(ip.base_request);
    probe_t pa; pa.variant = "CL.TE"; pa.payload = std::string("Content-Length+TE chunked"); pa.marker = "CL.TE";
    diag::log_tagged_fmt("mod_smuggling", "smuggling_run sending CL.TE probe");
    auto resp_a = send(cl_te_raw, pa);
    auto t1 = std::chrono::steady_clock::now();
    if (!resp_a.has_value()) {
        long long dt = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        diag::log_tagged_fmt("mod_smuggling", "smuggling_run CL.TE no response dt=%lldms baseline=%llums", dt, static_cast<unsigned long long>(baseline_lat));
        if (dt > static_cast<long long>(baseline_lat) + 4000) {
            diag::log_tagged_fmt("mod_smuggling", "smuggling_run FINDING cl-te-hang dt=%lldms", dt);
            auto iss = make_issue("smuggling.cl-te-hang", "HTTP Request Smuggling (CL.TE, socket hang)",
                                  severity_t::high, confidence_t::tentative, ip, pa, *baseline, ctx,
                                  std::string("Socket hung beyond baseline+4s with conflicting CL/TE headers; baseline=")
                                      + std::to_string(baseline_lat) + "ms");
            iss.description = "Sending a request with conflicting Content-Length and Transfer-Encoding: chunked headers caused the connection to hang past the baseline. This pattern is consistent with desync between front-end and back-end framing.";
            iss.remediation = "Reject requests carrying both Content-Length and Transfer-Encoding at the front-end. Standardize on one framing across the proxy chain.";
            iss.cwe.push_back("CWE-444");
            issue_store::add(std::move(iss));
        }
        return;
    }
    diag::log_tagged_fmt("mod_smuggling", "smuggling_run CL.TE response status=%d", resp_a->status_code);
    if (resp_a->status_code >= 400 && resp_a->status_code < 500 &&
        baseline->status_code >= 200 && baseline->status_code < 400) {
        diag::log_tagged_fmt("mod_smuggling", "smuggling_run FINDING cl-te-rejected status=%d baseline=%d", resp_a->status_code, baseline->status_code);
        auto iss = make_issue("smuggling.cl-te-rejected", "Proxy chain disagreement on CL/TE framing",
                              severity_t::low, confidence_t::tentative, ip, pa, *resp_a, ctx,
                              std::string("Server returned ") + std::to_string(resp_a->status_code)
                                  + " for conflicting CL/TE (baseline " + std::to_string(baseline->status_code) + ")");
        iss.description = "A request with both Content-Length and Transfer-Encoding: chunked produced a different status than the baseline. This may be the front-end correctly rejecting the malformed framing, or it may indicate a smuggling-relevant disagreement.";
        iss.remediation = "Audit the proxy chain to ensure both layers reject ambiguous framing identically.";
        iss.cwe.push_back("CWE-444");
        issue_store::add(std::move(iss));
    }

    auto te_cl_raw = build_te_cl_request(ip.base_request);
    probe_t pb; pb.variant = "TE.CL"; pb.payload = std::string("TE chunked + CL=4 smuggle"); pb.marker = "TE.CL";
    diag::log_tagged_fmt("mod_smuggling", "smuggling_run sending TE.CL probe");
    auto resp_b = send(te_cl_raw, pb);
    if (resp_b.has_value()) {
        diag::log_tagged_fmt("mod_smuggling", "smuggling_run TE.CL response status=%d", resp_b->status_code);
    } else {
        diag::log_tagged_fmt("mod_smuggling", "smuggling_run TE.CL no response");
    }
    if (resp_b.has_value() && resp_b->status_code >= 400 && resp_b->status_code < 500 &&
        baseline->status_code >= 200 && baseline->status_code < 400) {
        diag::log_tagged_fmt("mod_smuggling", "smuggling_run FINDING te-cl-rejected status=%d baseline=%d", resp_b->status_code, baseline->status_code);
        auto iss = make_issue("smuggling.te-cl-rejected", "Proxy chain disagreement on TE.CL framing",
                              severity_t::low, confidence_t::tentative, ip, pb, *resp_b, ctx,
                              std::string("Server returned ") + std::to_string(resp_b->status_code)
                                  + " for TE-chunked + CL=4 (baseline " + std::to_string(baseline->status_code) + ")");
        iss.description = "A TE.CL desync probe was rejected by the server in a way that diverges from baseline, suggesting the front-end and back-end use different framing rules.";
        iss.remediation = "Standardize HTTP/1.1 framing across the entire proxy chain; reject ambiguous requests.";
        iss.cwe.push_back("CWE-444");
        issue_store::add(std::move(iss));
    }
    diag::log_tagged_fmt("mod_smuggling", "smuggling_run complete ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
}

bool register_self()
{
    module_t m;
    m.id = "smuggling";
    m.name = "HTTP Request Smuggling (differential)";
    m.category = "Protocol";
    m.max_probes_per_point = 2;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = smuggling_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
