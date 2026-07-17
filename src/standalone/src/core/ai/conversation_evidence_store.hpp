#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::conversation_store {

inline constexpr std::size_t maximum_messages = 512;
inline constexpr std::size_t maximum_evidence = 256;

struct message_t {
    std::string text;
    std::string thinking_text;
    bool is_user = false;
    bool has_thinking = false;
    std::int64_t timestamp = 0;
    int input_tokens = 0;
    int output_tokens = 0;
    int cache_read_tokens = 0;
    int cache_write_tokens = 0;
    std::string model_id;
};

struct evidence_t {
    std::string id;
    std::string project_id;
    std::string workspace_id;
    std::string session_id;
    std::string source_view_id;
    std::string source_kind;
    std::string entity_id;
    std::string display_label;
    std::string return_target;
    std::uint64_t address = 0;
    std::uint64_t revision = 0;
    std::uint64_t generation = 0;
    std::uint64_t snapshot_hash = 0;
    std::uint64_t content_hash = 0;
    std::uint64_t created_ms = 0;
    bool truncated = false;
    bool sensitive = false;
};

struct summary_t {
    std::string id;
    std::string title;
    std::int64_t created = 0;
    int message_count = 0;
    bool pinned = false;
    std::uint64_t revision = 0;
};

struct snapshot_t {
    std::string id;
    std::uint64_t revision = 0;
    std::string title;
    std::int64_t created = 0;
    bool pinned = false;
    std::vector<message_t> messages;
    std::vector<evidence_t> evidence;
    bool evidence_authoritative = false;
    bool require_absent = false;
};

enum class operation_t : std::uint8_t {
    save,
    switch_conversation,
    new_conversation,
    refresh_catalog,
    delete_conversation,
    set_pinned,
    fork_conversation,
    export_markdown,
    save_evidence,
    load_evidence
};

struct request_t {
    operation_t operation = operation_t::save;
    snapshot_t current;
    std::string target_id;
    std::uint64_t target_revision = 0;
    std::uint64_t catalog_generation = 0;
    bool pinned = false;
    std::string output_path;
};

enum class request_result_t : std::uint8_t {
    queued,
    preview_recorded,
    busy,
    rejected
};

struct completion_t {
    std::uint64_t serial = 0;
    operation_t operation = operation_t::save;
    bool success = false;
    bool partial = false;
    std::string error;
    std::uint64_t source_revision = 0;
    std::uint64_t source_catalog_generation = 0;
    std::string target_id;
    std::optional<snapshot_t> loaded;
    std::optional<summary_t> committed_summary;
    std::vector<summary_t> catalog;
    bool catalog_authoritative = false;
};

struct status_t {
    bool pending = false;
    bool failed = false;
    bool retryable = false;
    operation_t operation = operation_t::save;
    std::string stage;
    std::string error;
};

request_result_t submit(request_t request) noexcept;
std::optional<completion_t> take_completion() noexcept;
bool request_retry() noexcept;
status_t status() noexcept;
bool commit_lifecycle(request_t request, std::string& error) noexcept;

}
