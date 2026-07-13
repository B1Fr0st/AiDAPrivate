#pragma once

#include "workbench_contracts.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace aida::analysis {
class workspace_database_t;
}

namespace aida {
namespace workbench {

inline constexpr std::uint32_t k_persistence_codec_schema_v9 = 9;
inline constexpr std::uint32_t k_persistence_codec_schema_v8 = 8;
inline constexpr std::size_t k_persistence_codec_max_serialized_bytes = 16U << 20;
inline constexpr std::size_t k_persistence_codec_max_json_depth = 64;
inline constexpr std::size_t k_persistence_codec_max_field_count = 65536;
inline constexpr std::size_t k_persistence_codec_max_collection_elements =
    static_cast<std::size_t>(k_max_split_nodes_per_workspace) +
    static_cast<std::size_t>(k_max_documents_per_workspace) +
    static_cast<std::size_t>(k_max_views_per_workspace) +
    static_cast<std::size_t>(k_max_panels_per_workspace) +
    static_cast<std::size_t>(k_max_history_capacity);
inline constexpr std::size_t k_persistence_codec_max_envelope_bytes = 4096;

static_assert(k_persistence_codec_max_collection_elements == 17663);

constexpr const char* k_persistence_codec_kind_v9 = "workbench_persistence_v9";
constexpr const char* k_persistence_codec_kind_v8 = "workbench_persistence_v8";

enum class persistence_codec_code_t : std::uint8_t {
    ok = 0,
    invalid_json = 1,
    schema_mismatch = 2,
    corrupt_payload = 3,
    oversized_payload = 4,
    workspace_isolation_violation = 5,
    validation_failed = 6,
    normalization_failed = 7,
    fingerprint_mismatch = 8,
    v8_legacy_unsupported = 9,
    empty_input = 10,
    unknown_kind = 11,
    field_count_exceeded = 12,
    revision_conflict = 13,
    recovery_exhausted = 14
};

struct persistence_codec_limits_t final {
    std::size_t max_serialized_bytes = k_persistence_codec_max_serialized_bytes;
    std::size_t max_json_depth = k_persistence_codec_max_json_depth;
    std::size_t max_field_count = k_persistence_codec_max_field_count;
};

struct persistence_codec_result_t final {
    persistence_codec_code_t code = persistence_codec_code_t::ok;
    persistence_fingerprint_t fingerprint;
    std::uint32_t decoded_schema = 0;
    std::string detail;

    bool ok() const noexcept { return code == persistence_codec_code_t::ok; }
    explicit operator bool() const noexcept { return ok(); }
};

struct persistence_envelope_t final {
    std::uint32_t schema = 0;
    std::string kind;
    bool is_v8_legacy = false;
};

enum class unknown_document_recovery_t : std::uint8_t {
    reject = 0,
    omit = 1,
    upgrade = 2
};

class workbench_persistence_codec_t final {
public:
    static persistence_codec_result_t encode(
        const workbench_persistence_dto_t& dto,
        std::string& output,
        const persistence_codec_limits_t& limits = {});

    static persistence_codec_result_t decode(
        std::string_view input,
        workspace_id_t expected_workspace,
        workbench_persistence_dto_t& output,
        const persistence_codec_limits_t& limits = {});

    static persistence_codec_result_t decode_v8_default(
        std::string_view input,
        workspace_id_t expected_workspace,
        workbench_persistence_dto_t& output,
        const persistence_codec_limits_t& limits = {});

    static persistence_codec_result_t round_trip(
        const workbench_persistence_dto_t& dto,
        persistence_fingerprint_t& encode_fingerprint,
        persistence_fingerprint_t& decode_fingerprint,
        const persistence_codec_limits_t& limits = {});

    static bool is_corrupt(std::string_view input) noexcept;
    static bool is_oversized(std::string_view input,
                             const persistence_codec_limits_t& limits = {}) noexcept;

    static std::optional<persistence_envelope_t> peek_envelope(
        std::string_view input) noexcept;

    static std::string normalize_and_encode(
        const workbench_persistence_dto_t& dto,
        persistence_codec_result_t& result,
        const persistence_codec_limits_t& limits = {});

    static persistence_codec_result_t decode_and_normalize(
        std::string_view input,
        workspace_id_t expected_workspace,
        workbench_persistence_dto_t& output,
        persistence_fingerprint_t& fingerprint,
        const persistence_codec_limits_t& limits = {});

    static persistence_codec_result_t decode_with_recovery(
        std::string_view input,
        workspace_id_t expected_workspace,
        workspace_revision_t expected_revision,
        unknown_document_recovery_t recovery,
        workbench_persistence_dto_t& output,
        const persistence_codec_limits_t& limits = {});

    static persistence_codec_result_t check_revision_conflict(
        workspace_revision_t expected,
        workspace_revision_t observed) noexcept;
};

class workspace_database_workbench_persistence_adapter_t final
    : public workbench_persistence_adapter_t {
public:
    explicit workspace_database_workbench_persistence_adapter_t(
        std::shared_ptr<analysis::workspace_database_t> database,
        workspace_id_t workspace,
        persistence_codec_limits_t limits = {});

    workbench_error_t load(workspace_id_t workspace,
                           workbench_persistence_dto_t& output) const override;
    workbench_error_t store(const workbench_persistence_dto_t& input) override;

private:
    std::shared_ptr<analysis::workspace_database_t> database_;
    workspace_id_t workspace_;
    persistence_codec_limits_t limits_;
};

}
}
