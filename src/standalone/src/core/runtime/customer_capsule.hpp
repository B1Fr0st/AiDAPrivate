#pragma once

#include <cstdint>
#include <string>

namespace aida::runtime::customer_capsule
{
    struct capsule_info_t
    {
        bool present = false;
        bool valid = false;
        std::string error;
        std::string capsule_id;
        std::string base_sha256;
        std::string capsule_sha256;
    };

    struct proof_fields_t
    {
        std::string capsule_id;
        std::string base_sha256;
        std::string capsule_sha256;
        std::string proof_nonce;
        std::int64_t proof_ts = 0;
        std::string proof;
    };

    const capsule_info_t& get_capsule_info();

    bool build_validate_proof(const std::string& license_key,
                              const std::string& hwid,
                              const std::string& client_nonce,
                              proof_fields_t& out);

    bool build_heartbeat_proof(const std::string& license_key,
                               const std::string& session_token,
                               const std::string& hwid,
                               const std::string& heartbeat_nonce,
                               std::uint32_t heartbeat_count,
                               const std::string& req_seq,
                               proof_fields_t& out);
}
