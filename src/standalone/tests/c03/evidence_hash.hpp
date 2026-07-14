#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace aida::analysis::c03
{
    struct evidence_hash_result_t
    {
        bool ok = false;
        std::string sha256;
        std::string error;
    };

    evidence_hash_result_t sha256_evidence_bytes(const void* bytes, std::size_t size);
    evidence_hash_result_t sha256_evidence_text(std::string_view text);
    evidence_hash_result_t sha256_evidence_file(const std::filesystem::path& path,
        std::uint64_t maximum_bytes = 1024ULL * 1024ULL * 1024ULL);
    evidence_hash_result_t sha256_repository_evidence_file(const std::filesystem::path& repository_root,
        std::string_view relative_path, std::uint64_t maximum_bytes = 1024ULL * 1024ULL * 1024ULL);
    evidence_hash_result_t canonical_json_sha256(nlohmann::json value,
        std::string_view excluded_top_level_field = {});
    bool verify_canonical_receipt_hash(const nlohmann::json& receipt,
        std::string_view hash_field, std::string& error);
    bool is_canonical_sha256(std::string_view value) noexcept;
}
