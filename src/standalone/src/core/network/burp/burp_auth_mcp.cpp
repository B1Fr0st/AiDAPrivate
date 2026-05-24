#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_auth_mcp.hpp"
#include "auth_lab.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <sstream>
#include <string>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct url_log_t
{
    std::string host;
    std::string path;
    bool has_query = false;
    size_t length = 0;
};

url_log_t summarize_url_for_log(const std::string& url)
{
    url_log_t out;
    out.length = url.size();
    size_t cursor = 0;
    size_t scheme = url.find("://");
    if (scheme != std::string::npos) cursor = scheme + 3;
    size_t host_end = url.find_first_of("/?#", cursor);
    if (host_end == std::string::npos) host_end = url.size();
    if (host_end > cursor) out.host = url.substr(cursor, host_end - cursor);
    size_t path_start = url.find('/', cursor);
    size_t path_end = url.size();
    size_t q = url.find('?', cursor);
    size_t f = url.find('#', cursor);
    if (q != std::string::npos) path_end = q;
    if (f != std::string::npos && f < path_end) path_end = f;
    out.has_query = q != std::string::npos;
    if (path_start != std::string::npos && path_start < path_end) out.path = url.substr(path_start, path_end - path_start);
    if (out.host.empty()) out.host = "<missing>";
    if (out.path.empty()) out.path = "/";
    if (out.path.size() > 240)
    {
        out.path.resize(240);
        out.path += "...";
    }
    return out;
}

std::string sanitize_utf8_for_json(const std::string& input, bool& changed, size_t& first_bad)
{
    changed = false;
    first_bad = static_cast<size_t>(-1);
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size();) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result.push_back(static_cast<char>(c));
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size() &&
            (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80) {
            result.append(input, i, 2);
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size() &&
            (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80 &&
            (static_cast<unsigned char>(input[i + 2]) & 0xC0) == 0x80) {
            result.append(input, i, 3);
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size() &&
            (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80 &&
            (static_cast<unsigned char>(input[i + 2]) & 0xC0) == 0x80 &&
            (static_cast<unsigned char>(input[i + 3]) & 0xC0) == 0x80) {
            result.append(input, i, 4);
            i += 4;
        } else {
            if (!changed) first_bad = i;
            changed = true;
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

tool_result_t handle_basic_encode(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_basic_encode user=%s", params.value("user", std::string()).c_str());
    const std::string user = params.value("user", std::string());
    const std::string pass = params.value("pass", std::string());
    json out;
    out["header"] = auth_lab::basic_encode(user, pass);
    diag::log_tagged_fmt("mcp_burp", "auth_basic_encode ok user=%s", user.c_str());
    return tool_result_t::ok(out);
}

tool_result_t handle_basic_decode(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_basic_decode entry");
    const std::string header = params.value("header", std::string());
    std::string user, pass;
    const bool ok = auth_lab::basic_decode(header, user, pass);
    if (!ok) { diag::log_tagged_fmt("mcp_burp", "auth_basic_decode invalid_header"); return tool_result_t::error("invalid Basic header"); }
    diag::log_tagged_fmt("mcp_burp", "auth_basic_decode ok user=%s", user.c_str());
    json out;
    out["user"] = user;
    out["pass"] = pass;
    return tool_result_t::ok(out);
}

tool_result_t handle_digest_solve(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_digest_solve method=%s uri=%s", params.value("method", std::string("GET")).c_str(), params.value("uri", std::string("/")).c_str());
    const std::string method = params.value("method", std::string("GET"));
    const std::string uri = params.value("uri", std::string("/"));
    const std::string body = params.value("body", std::string());
    const std::string www = params.value("www_auth_header", std::string());
    const std::string user = params.value("user", std::string());
    const std::string pass = params.value("pass", std::string());
    const std::string cnonce = params.value("cnonce", std::string());
    if (www.empty()) return tool_result_t::error("missing www_auth_header");
    json out;
    out["authorization"] = auth_lab::digest_solve(method, uri, body, www, user, pass, cnonce);
    diag::log_tagged_fmt("mcp_burp", "auth_digest_solve ok method=%s", method.c_str());
    return tool_result_t::ok(out);
}

tool_result_t handle_ntlm_type1(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_ntlm_type1 domain=%s", params.value("domain", std::string()).c_str());
    const std::string domain = params.value("domain", std::string());
    const std::string workstation = params.value("workstation", std::string());
    json out;
    out["type1_b64"] = auth_lab::ntlm_type1(domain, workstation);
    diag::log_tagged_fmt("mcp_burp", "auth_ntlm_type1 ok");
    return tool_result_t::ok(out);
}

tool_result_t handle_ntlm_type3(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_ntlm_type3 user=%s domain=%s", params.value("user", std::string()).c_str(), params.value("domain", std::string()).c_str());
    const std::string type2 = params.value("type2_b64", std::string());
    if (type2.empty()) return tool_result_t::error("missing type2_b64");
    const std::string user = params.value("user", std::string());
    const std::string pass = params.value("pass", std::string());
    const std::string domain = params.value("domain", std::string());
    const std::string workstation = params.value("workstation", std::string());
    const std::string r = auth_lab::ntlm_type3(type2, user, pass, domain, workstation);
    if (r.empty()) { diag::log_tagged_fmt("mcp_burp", "auth_ntlm_type3 failed err=%s", auth_lab::last_error().c_str()); return tool_result_t::error(std::string("ntlm_type3 failed: ") + auth_lab::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "auth_ntlm_type3 ok user=%s", user.c_str());
    json out;
    out["type3_b64"] = r;
    return tool_result_t::ok(out);
}

tool_result_t handle_bearer(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_bearer entry");
    json out;
    out["header"] = auth_lab::bearer_header(params.value("token", std::string()));
    diag::log_tagged_fmt("mcp_burp", "auth_bearer ok");
    return tool_result_t::ok(out);
}

tool_result_t handle_pkce(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_pkce entry");
    const auto pkce = auth_lab::generate_pkce_pair();
    json out;
    out["verifier"] = pkce.verifier;
    out["challenge"] = pkce.challenge;
    out["method"] = "S256";
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_pkce ok");
    return tool_result_t::ok(out);
}

tool_result_t handle_build_auth_url(const json& params)
{
    const std::string ep = params.value("authorize_endpoint", std::string());
    const std::string cid = params.value("client_id", std::string());
    const std::string ru = params.value("redirect_uri", std::string());
    const std::string scope = params.value("scope", std::string());
    const std::string state = params.value("state", std::string());
    const std::string chal = params.value("code_challenge", std::string());
    const url_log_t endpoint_log = summarize_url_for_log(ep);
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_build_auth_url host=%s path=%s query=%d endpoint_len=%zu client_id_len=%zu redirect_uri_len=%zu scope_len=%zu has_state=%d has_challenge=%d",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query,
        endpoint_log.length, cid.size(), ru.size(), scope.size(), (int)!state.empty(), (int)!chal.empty());
    if (ep.empty() || cid.empty()) return tool_result_t::error("missing authorize_endpoint or client_id");
    json out;
    out["url"] = auth_lab::oauth2_build_auth_url(ep, cid, ru, scope, state, chal);
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_build_auth_url ok host=%s path=%s url_len=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), out["url"].is_string() ? out["url"].get_ref<const std::string&>().size() : 0);
    return tool_result_t::ok(out);
}

tool_result_t handle_exchange_code(const json& params)
{
    const std::string te = params.value("token_endpoint", std::string());
    const std::string cid = params.value("client_id", std::string());
    const std::string code = params.value("code", std::string());
    const std::string ru = params.value("redirect_uri", std::string());
    const std::string ver = params.value("code_verifier", std::string());
    const url_log_t endpoint_log = summarize_url_for_log(te);
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_exchange_code host=%s path=%s query=%d endpoint_len=%zu client_id_len=%zu code_len=%zu redirect_uri_len=%zu has_verifier=%d",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query,
        endpoint_log.length, cid.size(), code.size(), ru.size(), (int)!ver.empty());
    if (te.empty() || cid.empty() || code.empty()) return tool_result_t::error("missing required field");
    std::string at, rt;
    int exp = 0;
    if (!auth_lab::oauth2_exchange_code(te, cid, code, ru, ver, at, rt, exp)) { diag::log_tagged_fmt("mcp_burp", "auth_oauth2_exchange_code failed err=%s", auth_lab::last_error().c_str()); return tool_result_t::error(std::string("exchange failed: ") + auth_lab::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_exchange_code ok host=%s path=%s access_token_len=%zu refresh_token_len=%zu expires_in=%d",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), at.size(), rt.size(), exp);
    json out;
    out["access_token"] = at;
    out["refresh_token"] = rt;
    out["expires_in"] = exp;
    return tool_result_t::ok(out);
}

tool_result_t handle_refresh(const json& params)
{
    const std::string te = params.value("token_endpoint", std::string());
    const std::string cid = params.value("client_id", std::string());
    const std::string rt = params.value("refresh_token", std::string());
    const url_log_t endpoint_log = summarize_url_for_log(te);
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_refresh host=%s path=%s query=%d endpoint_len=%zu client_id_len=%zu refresh_token_len=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query,
        endpoint_log.length, cid.size(), rt.size());
    if (te.empty() || cid.empty() || rt.empty()) return tool_result_t::error("missing required field");
    std::string at;
    int exp = 0;
    if (!auth_lab::oauth2_refresh(te, cid, rt, at, exp)) { diag::log_tagged_fmt("mcp_burp", "auth_oauth2_refresh failed err=%s", auth_lab::last_error().c_str()); return tool_result_t::error(std::string("refresh failed: ") + auth_lab::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "auth_oauth2_refresh ok host=%s path=%s access_token_len=%zu expires_in=%d",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), at.size(), exp);
    json out;
    out["access_token"] = at;
    out["expires_in"] = exp;
    return tool_result_t::ok(out);
}

tool_result_t handle_saml_request(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_request entry");
    const std::string in = params.value("saml_b64", std::string());
    diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_request input_len=%zu", in.size());
    if (in.empty()) return tool_result_t::error("missing saml_b64");
    json out;
    bool changed = false;
    size_t first_bad = 0;
    std::string decoded = auth_lab::saml_decode_request(in);
    std::string safe = sanitize_utf8_for_json(decoded, changed, first_bad);
    out["xml"] = safe;
    out["xml_sanitized"] = changed;
    diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_request ok xml_len=%zu",
        out["xml"].is_string() ? out["xml"].get_ref<const std::string&>().size() : 0);
    if (changed) {
        diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_request sanitized invalid_utf8 first_bad=%zu decoded_len=%zu safe_len=%zu",
            first_bad, decoded.size(), safe.size());
    }
    return tool_result_t::ok(out);
}

tool_result_t handle_saml_response(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_response entry");
    const std::string in = params.value("saml_b64", std::string());
    diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_response input_len=%zu", in.size());
    if (in.empty()) return tool_result_t::error("missing saml_b64");
    json out;
    bool changed = false;
    size_t first_bad = 0;
    std::string decoded = auth_lab::saml_decode_response(in);
    std::string safe = sanitize_utf8_for_json(decoded, changed, first_bad);
    out["xml"] = safe;
    out["xml_sanitized"] = changed;
    diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_response ok xml_len=%zu",
        out["xml"].is_string() ? out["xml"].get_ref<const std::string&>().size() : 0);
    if (changed) {
        diag::log_tagged_fmt("mcp_burp", "auth_saml_decode_response sanitized invalid_utf8 first_bad=%zu decoded_len=%zu safe_len=%zu",
            first_bad, decoded.size(), safe.size());
    }
    return tool_result_t::ok(out);
}

}

void register_auth_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "burp_auth_basic_encode",
        "Build an HTTP Basic Authorization header from user and pass.",
        {{"user", "string", "Username", true}, {"pass", "string", "Password", true}},
        true, handle_basic_encode
    });

    srv.register_tool({
        "burp_auth_basic_decode",
        "Decode an HTTP Basic Authorization header back to user and pass.",
        {{"header", "string", "Authorization header value (e.g. 'Basic abc==')", true}},
        true, handle_basic_decode
    });

    srv.register_tool({
        "burp_auth_digest_solve",
        "Solve an HTTP Digest challenge and return the Authorization response value (RFC 7616, MD5/SHA-256/SHA-512-256, qop auth/auth-int).",
        {{"method", "string", "HTTP method", true},
         {"uri", "string", "Request URI", true},
         {"body", "string", "Request body (for qop=auth-int)", false},
         {"www_auth_header", "string", "WWW-Authenticate header value from server", true},
         {"user", "string", "Username", true},
         {"pass", "string", "Password", true},
         {"cnonce", "string", "Client nonce (hex, optional)", false}},
        true, handle_digest_solve
    });

    srv.register_tool({
        "burp_auth_ntlm_type1",
        "Build the NTLMSSP Type-1 negotiate message (base64).",
        {{"domain", "string", "Optional domain", false},
         {"workstation", "string", "Optional workstation", false}},
        true, handle_ntlm_type1
    });

    srv.register_tool({
        "burp_auth_ntlm_type3",
        "Build the NTLMv2 Type-3 authenticate message given the server's Type-2 challenge (base64).",
        {{"type2_b64", "string", "Server Type-2 message (base64)", true},
         {"user", "string", "Username", true},
         {"pass", "string", "Password", true},
         {"domain", "string", "Domain", false},
         {"workstation", "string", "Workstation", false}},
        true, handle_ntlm_type3
    });

    srv.register_tool({
        "burp_auth_bearer",
        "Build a Bearer Authorization header from a token.",
        {{"token", "string", "Bearer token", true}},
        true, handle_bearer
    });

    srv.register_tool({
        "burp_auth_oauth2_pkce",
        "Generate a fresh OAuth2 PKCE verifier and S256 challenge pair.",
        {},
        true, handle_pkce
    });

    srv.register_tool({
        "burp_auth_oauth2_build_auth_url",
        "Build an OAuth2 authorize URL (response_type=code).",
        {{"authorize_endpoint", "string", "Authorize endpoint", true},
         {"client_id", "string", "Client id", true},
         {"redirect_uri", "string", "Redirect URI", false},
         {"scope", "string", "Scope", false},
         {"state", "string", "State", false},
         {"code_challenge", "string", "PKCE code_challenge (S256)", false}},
        true, handle_build_auth_url
    });

    srv.register_tool({
        "burp_auth_oauth2_exchange_code",
        "Exchange an OAuth2 authorization code for an access token via the token endpoint.",
        {{"token_endpoint", "string", "Token endpoint", true},
         {"client_id", "string", "Client id", true},
         {"code", "string", "Authorization code", true},
         {"redirect_uri", "string", "Redirect URI", false},
         {"code_verifier", "string", "PKCE code_verifier", false}},
        false, handle_exchange_code
    });

    srv.register_tool({
        "burp_auth_oauth2_refresh",
        "Refresh an OAuth2 access token via the token endpoint.",
        {{"token_endpoint", "string", "Token endpoint", true},
         {"client_id", "string", "Client id", true},
         {"refresh_token", "string", "Refresh token", true}},
        false, handle_refresh
    });

    srv.register_tool({
        "burp_auth_saml_decode_request",
        "Decode a SAML SP-initiated AuthnRequest (base64 + raw deflate) and return pretty-printed XML.",
        {{"saml_b64", "string", "SAMLRequest value (URL-encoded base64)", true}},
        true, handle_saml_request
    });

    srv.register_tool({
        "burp_auth_saml_decode_response",
        "Decode a SAML Response (base64) and return pretty-printed XML.",
        {{"saml_b64", "string", "SAMLResponse value (base64)", true}},
        true, handle_saml_response
    });
}

}
}
