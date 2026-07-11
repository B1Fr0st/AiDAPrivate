#pragma once

#include "analysis_workspace.hpp"
#include "workspace_database.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida::analysis {

enum class overlay_operation_kind_t : std::uint8_t {
    comment = 0,
    name = 1,
    bookmark = 2,
    type_declaration = 3,
    define_function = 4,
    define_code = 5,
    define_data = 6,
    undefine = 7,
    stack_variable = 8,
    delete_stack_variable = 9,
    type_application = 10,
    byte_patch = 11,
    assembly_patch = 12,
    integer_patch = 13
};

struct overlay_operation_t {
    overlay_operation_kind_t kind = overlay_operation_kind_t::comment;
    address_t address;
    std::optional<address_t> end;
    std::string name;
    std::string text;
    std::string type;
    std::string variable;
    std::string signature;
    std::vector<std::uint8_t> bytes;
    std::string assembly;
    std::string integer_type;
    std::string integer_value;
    std::int64_t stack_offset = 0;
};

struct overlay_transaction_request_t {
    std::vector<overlay_operation_t> operations;
    bool dry_run = false;
    std::optional<std::uint64_t> expected_revision;
    std::optional<std::string> idempotency_key;
};

struct overlay_operation_result_t {
    std::size_t index = 0;
    std::string entity_key;
    bool removes_value = false;
};

struct overlay_transaction_result_t {
    std::uint64_t transaction_id = 0;
    std::uint64_t revision = 0;
    bool committed = false;
    bool dry_run = false;
    bool idempotent_replay = false;
    std::vector<overlay_operation_result_t> operations;
};

struct overlay_limits_t {
    std::size_t max_operations = 4096;
    std::size_t max_patch_bytes_per_item = 1U << 20;
    std::size_t max_patch_bytes_per_transaction = 16U << 20;
    std::size_t max_assembly_bytes = 64U << 10;
    std::size_t max_assembly_statements = 4096;
    std::size_t max_name_bytes = 4096;
    std::size_t max_type_bytes = 64U << 10;
    std::size_t max_comment_bytes = 256U << 10;
    std::size_t max_idempotency_key_bytes = 256;
};

struct overlay_snapshot_t {
    std::uint64_t revision = 0;
    std::uint64_t history_cursor = 0;
    std::uint64_t history_epoch = 0;
    std::vector<std::pair<std::string, overlay_operation_t>> items;
};

class overlay_journal_t final : public workspace_lifecycle_participant_t,
                                public std::enable_shared_from_this<overlay_journal_t> {
public:
    static workspace_result_t<std::shared_ptr<overlay_journal_t>> open(
        std::shared_ptr<analysis_workspace_t> workspace,
        std::shared_ptr<workspace_database_t> database,
        overlay_limits_t limits = {});

    ~overlay_journal_t() override;
    overlay_journal_t(const overlay_journal_t&) = delete;
    overlay_journal_t& operator=(const overlay_journal_t&) = delete;

    workspace_result_t<overlay_transaction_result_t> transact(
        const overlay_transaction_request_t& request,
        const cancellation_token_t& cancel = {});
    workspace_result_t<overlay_transaction_result_t> undo(
        std::optional<std::uint64_t> expected_revision = {},
        const cancellation_token_t& cancel = {});
    workspace_result_t<overlay_transaction_result_t> redo(
        std::optional<std::uint64_t> expected_revision = {},
        const cancellation_token_t& cancel = {});

    overlay_snapshot_t snapshot() const;
    std::optional<overlay_operation_t> find(const std::string& entity_key) const;
    std::vector<overlay_operation_t> patch_operations() const;

    void request_cancel() noexcept override;
    workspace_result_t<void>
        drain(std::chrono::steady_clock::time_point deadline) override;

private:
    overlay_journal_t(std::shared_ptr<analysis_workspace_t> workspace,
                      std::shared_ptr<workspace_database_t> database,
                      overlay_limits_t limits);

    workspace_result_t<void> recover_and_load(const cancellation_token_t& cancel);
    workspace_result_t<void> reload_items();
    workspace_result_t<overlay_transaction_result_t> history_action(
        bool redo, std::optional<std::uint64_t> expected_revision,
        const cancellation_token_t& cancel);

    std::weak_ptr<analysis_workspace_t> workspace_;
    std::shared_ptr<workspace_database_t> database_;
    overlay_limits_t limits_;
    mutable std::shared_mutex state_mutex_;
    std::unordered_map<std::string, overlay_operation_t> items_;
    std::uint64_t revision_ = 0;
    std::uint64_t history_cursor_ = 0;
    std::uint64_t history_epoch_ = 1;
    cancellation_source_t cancellation_;
};

}
