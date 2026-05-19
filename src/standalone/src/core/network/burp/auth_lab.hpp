#pragma once

#include <cstdint>
#include <string>

namespace aida {
namespace burp {
namespace auth_lab {

bool        initialize();
void        shutdown();

std::string basic_encode(const std::string& user, const std::string& pass);
bool        basic_decode(const std::string& header, std::string& user, std::string& pass);

std::string digest_solve(const std::string& method,
                         const std::string& uri,
                         const std::string& body,
                         const std::string& www_auth_header,
                         const std::string& user,
                         const std::string& pass,
                         const std::string& cnonce);

std::string ntlm_type1(const std::string& domain, const std::string& workstation);
std::string ntlm_type3(const std::string& type2_b64,
                       const std::string& user,
                       const std::string& pass,
                       const std::string& domain,
                       const std::string& workstation);

std::string bearer_header(const std::string& token);

struct oauth2_pkce_t
{
    std::string verifier;
    std::string challenge;
};

oauth2_pkce_t generate_pkce_pair();

std::string oauth2_build_auth_url(const std::string& authorize_endpoint,
                                  const std::string& client_id,
                                  const std::string& redirect_uri,
                                  const std::string& scope,
                                  const std::string& state,
                                  const std::string& code_challenge);

bool oauth2_exchange_code(const std::string& token_endpoint,
                          const std::string& client_id,
                          const std::string& code,
                          const std::string& redirect_uri,
                          const std::string& code_verifier,
                          std::string& access_token,
                          std::string& refresh_token,
                          int& expires_in);

bool oauth2_refresh(const std::string& token_endpoint,
                    const std::string& client_id,
                    const std::string& refresh_token,
                    std::string& access_token,
                    int& expires_in);

std::string saml_decode_request(const std::string& saml_b64);
std::string saml_decode_response(const std::string& saml_b64);

std::string last_error();

std::string base64_encode_std(const uint8_t* data, size_t len);
bool        base64_decode_std(const std::string& in, std::string& out);

}
}
}
