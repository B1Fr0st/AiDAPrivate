#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_composite_tool_count = 4;

enum class composite_step_kind_t : std::uint8_t {
    function_snapshot = 0,
    decompile_function,
    disassemble_function,
    xref_neighbors,
    address_snapshot,
    apply_overlay_action
};

enum class composite_step_status_t : std::uint8_t {
    complete = 0,
    partial,
    unavailable,
    rejected,
    quota_exhausted,
    cancelled
};

struct composite_global_reference_t final {
    std::string addr;
    std::string name;
};

struct composite_function_snapshot_t final {
    std::string addr;
    std::string name;
    std::uint64_t size = 0;
    std::optional<std::string> prototype;
    protocol::json comments = protocol::json::object();
    std::vector<std::string> strings;
    std::vector<protocol::json> constants;
    std::vector<std::string> callers;
    std::vector<std::string> callees;
    protocol::json xrefs = protocol::json::object();
    std::uint64_t basic_block_count = 0;
    std::uint64_t cyclomatic_complexity = 0;
    std::vector<composite_global_reference_t> globals;
};

struct composite_text_snapshot_t final {
    std::optional<std::string> text;
    std::string error;
    std::uint64_t truncated = 0;
};

struct composite_xref_neighbor_t final {
    std::string addr;
    std::string type;
};

struct composite_xref_batch_t final {
    std::vector<composite_xref_neighbor_t> neighbors;
};

struct composite_address_snapshot_t final {
    std::string addr;
    std::optional<std::string> function;
    std::optional<std::string> instruction;
    std::string type;
    std::optional<std::string> name;
};

struct composite_overlay_result_t final {
    bool applied = false;
    std::string action_applied;
};

using composite_step_payload_t = std::variant<
    std::monostate,
    composite_function_snapshot_t,
    composite_text_snapshot_t,
    composite_xref_batch_t,
    composite_address_snapshot_t,
    composite_overlay_result_t>;

struct composite_step_request_t final {
    composite_step_kind_t kind = composite_step_kind_t::function_snapshot;
    std::string subject;
    std::string direction;
    std::string action;
    protocol::json action_arguments = protocol::json::object();
    std::uint64_t workspace_generation = 0;
    std::optional<std::uint64_t> expected_overlay_generation;
    std::uint64_t max_items = 0;
    std::uint64_t max_bytes = 0;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    bool permit_baseline_start = false;
    bool permit_unrequested_deep_work = false;
};

struct composite_step_response_t final {
    composite_step_status_t status = composite_step_status_t::rejected;
    composite_step_payload_t payload;
    std::string diagnostic_code;
    std::string diagnostic_message;
    std::optional<std::uint64_t> workspace_generation;
    std::optional<std::uint64_t> observed_overlay_generation;
    std::optional<std::uint64_t> committed_overlay_generation;
    std::uint64_t items_consumed = 0;
    std::uint64_t bytes_consumed = 0;
    bool baseline_started = false;
    bool unrequested_deep_work_started = false;
};

using composite_backend_t = std::function<composite_step_response_t(
    const adapter_call_context_t&,
    const composite_step_request_t&,
    const protocol::cancellation_token_t&)>;

struct composite_quota_t final {
    std::uint64_t max_steps = 512;
    std::uint64_t max_backend_items = 65536;
    std::uint64_t max_backend_bytes = 8ULL * 1024ULL * 1024ULL;
    std::uint64_t max_output_bytes = 8ULL * 1024ULL * 1024ULL;
};

struct composite_limits_t final {
    composite_quota_t hard_quota{};
    std::uint64_t max_component_functions = 64;
    std::uint64_t max_trace_nodes = 2048;
    std::uint64_t max_trace_edges = 4096;
    std::uint64_t max_neighbors_per_node = 256;
    std::uint64_t max_collection_items = 2048;
    std::uint64_t max_diagnostics = 128;
    std::uint64_t max_input_bytes = 256ULL * 1024ULL;
    std::uint64_t max_address_bytes = 1024;
    std::uint64_t max_identifier_bytes = 4096;
    std::uint64_t max_text_bytes = 1024ULL * 1024ULL;
    std::chrono::milliseconds read_timeout{120000};
    std::chrono::milliseconds component_timeout{180000};
    std::chrono::milliseconds mutation_timeout{120000};
};

struct composite_invocation_options_t final {
    std::optional<std::uint64_t> expected_workspace_generation;
    std::optional<std::uint64_t> expected_overlay_generation;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::optional<composite_quota_t> quota;
};

class composite_handlers_t final {
public:
    explicit composite_handlers_t(
        composite_backend_t backend,
        composite_limits_t limits = {});
    ~composite_handlers_t();

    composite_handlers_t(const composite_handlers_t&) = delete;
    composite_handlers_t& operator=(const composite_handlers_t&) = delete;
    composite_handlers_t(composite_handlers_t&&) = delete;
    composite_handlers_t& operator=(composite_handlers_t&&) = delete;

    protocol::mcp_result_t invoke(
        std::string_view tool_name,
        const protocol::json& arguments,
        workspace_adapter_t& adapter,
        protocol::schema_runtime_t& schemas,
        const protocol::cancellation_token_t& cancellation = protocol::cancellation_token_t{},
        const composite_invocation_options_t& options = {},
        const protocol::json& aida_metadata = protocol::json::object());

    adapter_result_t<adapter_response_t> execute_bound(
        const adapter_call_context_t& context,
        const adapter_request_t& request);

    const composite_limits_t& limits() const noexcept;

private:
    struct impl_t;
    std::unique_ptr<impl_t> impl_;
};

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t analyze_function(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation = protocol::cancellation_token_t{},
    const handlers::composite_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());

protocol::mcp_result_t analyze_component(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation = protocol::cancellation_token_t{},
    const handlers::composite_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());

protocol::mcp_result_t diff_before_after(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation = protocol::cancellation_token_t{},
    const handlers::composite_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());

protocol::mcp_result_t trace_data_flow(
    handlers::composite_handlers_t& handlers,
    workspace_adapter_t& adapter,
    protocol::schema_runtime_t& schemas,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation = protocol::cancellation_token_t{},
    const handlers::composite_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());

}
