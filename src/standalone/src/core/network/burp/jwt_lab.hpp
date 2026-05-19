#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace jwt_lab {

struct jwt_parsed_t
{
    std::string         raw;
    std::string         header_b64;
    std::string         payload_b64;
    std::string         signature_b64;
    nlohmann::json      header;
    nlohmann::json      payload;
    std::string         alg;
    std::string         kid;
    bool                valid_structure = false;
};

struct jwt_forge_input_t
{
    nlohmann::json      header;
    nlohmann::json      payload;
    std::string         alg;
    std::string         hmac_secret;
    std::string         rsa_private_pem;
    std::string         ecdsa_private_pem;
};

struct crack_config_t
{
    std::string                 token;
    std::string                 wordlist_id;
    std::vector<std::string>    custom_words;
    size_t                      concurrency = 8;
    size_t                      max_attempts = 1000000;
};

struct crack_status_t
{
    uint64_t        id = 0;
    size_t          attempts = 0;
    bool            running = false;
    std::string     secret_found;
};

bool                        initialize();
void                        shutdown();

jwt_parsed_t                decode(const std::string& token);
std::string                 forge(const jwt_forge_input_t& in);

bool                        verify_hmac(const std::string& token, const std::string& secret);
bool                        verify_rsa(const std::string& token, const std::string& public_pem);
bool                        verify_ecdsa(const std::string& token, const std::string& public_pem);

uint64_t                    start_crack(const crack_config_t& cfg);
crack_status_t              crack_status(uint64_t id);
void                        crack_stop(uint64_t id);
std::vector<crack_status_t> list_cracks();

std::vector<std::string>    attack_alg_none(const std::string& token);
std::vector<std::string>    attack_alg_confusion(const std::string& token, const std::string& rsa_public_pem);
std::vector<std::string>    attack_kid_traversal(const std::string& token);
std::vector<std::string>    attack_jku_injection(const std::string& token, const std::string& attacker_jku_url);
std::vector<std::string>    attack_signature_strip(const std::string& token);

std::string                 base64url_encode(const uint8_t* data, size_t len);
std::string                 base64url_encode(const std::string& data);
bool                        base64url_decode(const std::string& in, std::vector<uint8_t>& out);

std::string                 last_error();

}
}
}
