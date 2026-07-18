#pragma once

#include "../analysis/code_index.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace aida::editor::language_service {

enum class capability_kind_t : std::uint8_t {
    completion,
    hover,
    signature_help,
    document_symbols,
    workspace_symbols,
    diagnostics,
    definition,
    declaration,
    implementation,
    type_definition,
    references,
    semantic_rename,
    formatting,
    range_formatting,
    code_actions
};

enum class result_state_t : std::uint8_t {
    unavailable,
    loading,
    ready,
    empty,
    cancelled,
    error
};

struct capability_t {
    bool available = false;
    std::string reason;
};

struct position_t {
    int line = 0;
    int column = 0;
};

struct document_context_t {
    std::uint64_t document_id = 0;
    std::uint64_t revision = 0;
    std::string file_path;
    std::string language_id;
    std::shared_ptr<const std::string> bounded_text_snapshot;
    std::size_t bounded_text_bytes = 0;
    bool text_snapshot_truncated = false;
    std::string text_snapshot_status;
    position_t position;
};

struct location_t {
    std::string root_path;
    std::string file_path;
    int line = 0;
    int column = 0;
    int match_length = 0;
    std::string preview;
};

struct symbol_t {
    std::string name;
    std::string kind;
    location_t location;
    std::string detail;
};

struct completion_item_t {
    std::string label;
    std::string insertion_text;
    std::string detail;
    std::string kind;
    std::string sort_key;
    bool snippet = false;
};

struct information_item_t {
    std::string label;
    std::string content;
    std::string language;
};

struct text_range_t {
    position_t start;
    position_t end;
};

struct text_edit_t {
    std::uint64_t document_id = 0;
    std::uint64_t expected_revision = 0;
    std::string file_path;
    text_range_t range;
    std::string expected_text;
    std::string replacement_text;
};

struct diagnostic_t {
    location_t location;
    std::string severity;
    std::string message;
    std::string source;
};

struct code_action_t {
    std::string id;
    std::string title;
    std::string detail;
    std::string kind;
    std::string disabled_reason;
    bool preferred = false;
    std::vector<text_edit_t> proposed_edits;
};

struct query_t {
    capability_kind_t kind = capability_kind_t::references;
    document_context_t document;
    std::string text;
    std::string replacement_text;
    std::string directory;
    text_range_t selection;
    bool has_selection = false;
    std::size_t maximum_results = 512;
};

struct query_result_t {
    result_state_t state = result_state_t::unavailable;
    capability_kind_t kind = capability_kind_t::references;
    std::uint64_t request_id = 0;
    std::uint64_t request_generation = 0;
    std::string provider_id;
    std::string provider_name;
    std::uint64_t provider_generation = 0;
    std::string root_path;
    std::uint64_t index_generation = 0;
    std::uint64_t document_id = 0;
    std::uint64_t document_revision = 0;
    std::string document_path;
    std::string query_text;
    std::string status;
    bool truncated = false;
    std::vector<location_t> locations;
    std::vector<symbol_t> symbols;
    std::vector<completion_item_t> completions;
    std::vector<information_item_t> information;
    std::vector<diagnostic_t> diagnostics;
    std::vector<text_edit_t> proposed_edits;
    std::vector<code_action_t> code_actions;
};

using query_snapshot_t = std::shared_ptr<const query_result_t>;

class provider_t {
public:
    virtual ~provider_t() = default;
    virtual std::string identity() const = 0;
    virtual std::string display_name() const = 0;
    virtual std::uint64_t generation() const noexcept = 0;
    virtual bool accepts(const document_context_t& document) const = 0;
    virtual capability_t capability(capability_kind_t kind,
        const document_context_t& document) const = 0;
    virtual query_result_t execute(const query_t& query,
        const std::atomic<bool>& cancelled) const = 0;
};

struct provider_descriptor_t {
    std::string identity;
    std::string display_name;
    std::uint64_t generation = 0;
};

struct request_result_t {
    bool accepted = false;
    std::uint64_t request_id = 0;
    std::string reason;
};

bool register_or_replace_provider(std::shared_ptr<const provider_t> provider);
bool unregister_provider(std::string_view identity, std::uint64_t generation);
std::vector<provider_descriptor_t> provider_snapshot();
std::uint64_t provider_registry_generation();
std::shared_ptr<const provider_t> provider_for(const document_context_t& document);
std::shared_ptr<const provider_t> provider_for(capability_kind_t kind,
    const document_context_t& document);
capability_t capability(capability_kind_t kind, const document_context_t& document);
std::string capability_name(capability_kind_t kind);

void synchronize_workspace(std::string workspace_root);
request_result_t rebuild_workspace_index();
bool cancel_workspace_index();
std::shared_ptr<const code_index::published_index_t> workspace_index_snapshot();
code_index::index_state_t workspace_index_state();
std::string workspace_index_status();
std::uint64_t workspace_index_task_id();

request_result_t request(query_t query);
bool cancel_request(capability_kind_t kind);
query_snapshot_t result(capability_kind_t kind);
query_result_t execute_worker_query(query_t query,
    const std::atomic<bool>& cancelled);

document_context_t active_document_context();
std::string active_query_text();
bool open_location(const location_t& location, bool open_to_side = false);
bool send_location_to_ai(const location_t& location, std::string_view provenance);
void begin_frame();
void shutdown() noexcept;

}
