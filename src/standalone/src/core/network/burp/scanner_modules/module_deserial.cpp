#include "../scanner_module.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

bool contains_bytes(const std::string& hay, const uint8_t* needle, size_t n)
{
    if (n == 0 || hay.size() < n) return false;
    for (size_t i = 0; i + n <= hay.size(); ++i)
        if (memcmp(hay.data() + i, needle, n) == 0) return true;
    return false;
}

bool looks_like_b64(const std::string& v)
{
    if (v.size() < 16) return false;
    int good = 0;
    for (char c : v)
    {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') good++;
        else return false;
    }
    return good >= static_cast<int>(v.size() * 0.9);
}

std::string b64_decode(const std::string& s)
{
    std::string out;
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-' || c == '+') return 62;
        if (c == '_' || c == '/') return 63;
        return -1;
    };
    int bits = 0, n = 0;
    for (char c : s)
    {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int v = val(c);
        if (v < 0) continue;
        n = (n << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(static_cast<char>((n >> bits) & 0xff)); }
    }
    return out;
}

struct detection_t { bool ok = false; std::string format; std::string sample; };

detection_t detect_inner(const std::string& value)
{
    detection_t d;
    static const uint8_t java[]  = {0xac, 0xed, 0x00, 0x05};
    if (contains_bytes(value, java, sizeof(java))) { d.ok = true; d.format = "Java ObjectInputStream"; d.sample = value.substr(0, 16); return d; }
    if (value.size() >= 2)
    {
        uint8_t b0 = static_cast<uint8_t>(value[0]);
        uint8_t b1 = static_cast<uint8_t>(value[1]);
        if (b0 == 0x80 && (b1 == 0x02 || b1 == 0x03 || b1 == 0x04 || b1 == 0x05))
        { d.ok = true; d.format = std::string("Python pickle proto ") + static_cast<char>('0' + b1); d.sample = value.substr(0, 16); return d; }
    }
    static const std::regex php_re(R"(^[OasidbN]:\d+(:|;|\{))");
    if (std::regex_search(value, php_re)) { d.ok = true; d.format = "PHP serialize()"; d.sample = value.substr(0, 32); return d; }
    static const uint8_t dnet[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff};
    if (contains_bytes(value, dnet, sizeof(dnet))) { d.ok = true; d.format = ".NET BinaryFormatter"; d.sample = value.substr(0, 16); return d; }
    if (looks_like_b64(value))
    {
        std::string decoded = b64_decode(value);
        if (!decoded.empty())
        {
            detection_t inner = detect_inner(decoded);
            if (inner.ok) { inner.format += " (base64-wrapped)"; return inner; }
        }
    }
    return d;
}

std::vector<probe_t> deserial_probes(const insertion_point_t& ip, const module_context_t&)
{
    std::vector<probe_t> out;
    out.push_back({ip.original_value + "_aida_deserial_pad", "_AIDA_DESERIAL", "passive-scan"});
    out.push_back({"!!!__corrupt__!!!", "_AIDA_DESERIAL_CORRUPT", "corrupt-payload"});
    return out;
}

std::optional<issue_t> deserial_detect(const insertion_point_t& ip, const probe_t& probe,
                                       const exchange_observed_t& resp, const module_context_t& ctx)
{
    if (probe.marker == "_AIDA_DESERIAL")
    {
        detection_t d = detect_inner(ip.original_value);
        if (!d.ok) return std::nullopt;
        auto iss = make_issue("deserial.magic-detected",
                              std::string("Deserialization marker detected: ") + d.format,
                              severity_t::high, confidence_t::tentative, ip, probe, resp, ctx,
                              std::string("Format=") + d.format + "; first bytes=" + d.sample);
        iss.description = std::string("The parameter '") + ip.name +
            "' carries a value whose first bytes match the wire format of " + d.format +
            ". If this value is deserialized by an unsafe gadget-capable library, RCE may be possible. "
            "Manually verify with a gadget chain before reporting as firm.";
        iss.remediation = "Do not deserialize untrusted data. If unavoidable, enforce a class allowlist (ObjectInputFilter / LookAheadObjectInputStream) or migrate to schema-validated JSON/Protobuf.";
        iss.cwe.push_back("CWE-502");
        return iss;
    }
    if (probe.marker == "_AIDA_DESERIAL_CORRUPT")
    {
        detection_t d = detect_inner(ip.original_value);
        if (!d.ok) return std::nullopt;
        if (resp.status_code >= 500 && ctx.baseline_status_code < 500)
        {
            auto iss = make_issue("deserial.exception-on-corrupt",
                                  "Deserialization Exception on Corrupted Input",
                                  severity_t::high, confidence_t::firm, ip, probe, resp, ctx,
                                  std::string("baseline_status=") + std::to_string(ctx.baseline_status_code)
                                  + "; probe_status=" + std::to_string(resp.status_code));
            iss.description = "Replacing a recognized serialized value with garbage produced an HTTP 5xx, while baseline returned a non-error status. "
                              "Strong indicator that the parameter is fed to a deserializer.";
            iss.remediation = "Validate the parameter format before passing to the deserializer; reject any input that fails schema validation.";
            iss.cwe.push_back("CWE-502");
            return iss;
        }
    }
    return std::nullopt;
}

bool register_self()
{
    module_t m;
    m.id = "deserial";
    m.name = "Insecure Deserialization";
    m.category = "Injection";
    m.max_probes_per_point = 2;
    m.probes = deserial_probes;
    m.detect = deserial_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
