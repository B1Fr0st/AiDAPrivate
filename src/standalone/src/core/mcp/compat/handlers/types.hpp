#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_types_tool_count = 9;

enum class type_lane_t : std::uint8_t {
    query = 0,
    overlay,
};

struct types_handler_limits_t final {
    std::size_t max_request_bytes = 1024U * 1024U;
    std::size_t max_response_bytes = 16U * 1024U * 1024U;
    std::size_t max_selector_bytes = 1024U;
    std::size_t max_name_bytes = 4096U;
    std::size_t max_type_bytes = 16384U;
    std::size_t max_address_bytes = 1024U;
    std::size_t max_decls_bytes = 65536U;
    std::size_t max_decls_count = 256U;
    std::size_t max_decl_string_bytes = 16384U;
    std::size_t max_queries_count = 256U;
    std::size_t max_filter_bytes = 4096U;
    std::size_t max_edits_count = 256U;
    std::size_t max_addrs_count = 256U;
    std::size_t max_members_per_type = 1024U;
    std::size_t max_enumerators_per_enum = 1024U;
    std::size_t max_member_name_bytes = 4096U;
    std::size_t max_member_type_bytes = 16384U;
    std::size_t max_related_types = 256U;
    std::uint64_t max_struct_size = 1048576ULL;
    std::uint64_t max_member_offset = 1048576ULL;
    std::chrono::milliseconds max_execution_time{120000};
};

const std::array<std::string_view, k_types_tool_count>& types_tool_names() noexcept;

struct overlay_member_t final {
    std::string name;
    std::string type;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
};

struct overlay_enumerator_t final {
    std::string name;
    std::int64_t value = 0;
};

struct overlay_type_t final {
    std::string name;
    std::string kind;
    std::string declaration;
    std::vector<overlay_member_t> members;
    std::vector<overlay_enumerator_t> enumerators;
    std::uint64_t size = 0;
    std::uint32_t ordinal = 0;
    std::uint64_t revision_added = 0;
    std::uint64_t revision_modified = 0;
    bool is_union = false;
    bool is_enum = false;
    bool is_typedef = false;
    bool is_ptr = false;
    bool is_func = false;
    bool is_udt = false;
    bool bitfield = false;
};

struct overlay_type_application_t final {
    std::string addr;
    std::string ty;
    std::string kind;
    std::string name;
    std::string signature;
    std::string variable;
    std::uint64_t revision = 0;
};

struct inference_result_t final {
    std::string addr;
    std::string inferred_type;
    std::string confidence;
    std::string method;
    std::string error;
    bool has_type = false;
};

struct type_relation_t final {
    std::string name;
    std::string kind;
};

struct undo_entry_t final {
    enum class action_t : std::uint8_t {
        declare_type,
        enum_upsert,
        set_type,
    };
    action_t action = action_t::declare_type;
    std::string target_name;
    std::optional<overlay_type_t> old_type;
    std::optional<overlay_type_application_t> old_application;
    std::uint64_t revision = 0;
};

class types_overlay_store_t final {
public:
    types_overlay_store_t();
    ~types_overlay_store_t();

    types_overlay_store_t(const types_overlay_store_t&) = delete;
    types_overlay_store_t& operator=(const types_overlay_store_t&) = delete;
    types_overlay_store_t(types_overlay_store_t&&) = delete;
    types_overlay_store_t& operator=(types_overlay_store_t&&) = delete;

    adapter_result_t<adapter_response_t> handle_query(
        const adapter_call_context_t& context,
        const adapter_request_t& request);

    adapter_result_t<adapter_response_t> handle_overlay(
        const adapter_call_context_t& context,
        const adapter_request_t& request);

    std::shared_ptr<types_overlay_store_t> target_scope(const target_record_t& target);

    std::uint64_t revision() const noexcept;
    bool undo();
    std::size_t type_count() const noexcept;
    std::size_t application_count() const noexcept;
    bool has_type(const std::string& name) const noexcept;
    bool has_application(const std::string& addr) const noexcept;
    const overlay_type_t* find_type(const std::string& name) const noexcept;
    const overlay_type_application_t* find_application(const std::string& addr) const noexcept;
    std::vector<std::string> all_type_names() const;
    void set_limits(const types_handler_limits_t& limits);
    void clear();

private:
    using target_scope_key_t =
        std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t>;

    static target_scope_key_t target_scope_key(const target_record_t& target) noexcept;
    adapter_result_t<adapter_response_t> handle_query_local(
        const adapter_call_context_t& context,
        const adapter_request_t& request);
    adapter_result_t<adapter_response_t> handle_overlay_local(
        const adapter_call_context_t& context,
        const adapter_request_t& request);

    protocol::json do_declare_type(const protocol::json& args);
    protocol::json do_enum_upsert(const protocol::json& args);
    protocol::json do_read_struct(const protocol::json& args);
    protocol::json do_search_structs(const protocol::json& args);
    protocol::json do_type_query(const protocol::json& args);
    protocol::json do_type_inspect(const protocol::json& args);
    protocol::json do_set_type(const protocol::json& args);
    protocol::json do_type_apply_batch(const protocol::json& args);
    protocol::json do_infer_types(const protocol::json& args);

    std::uint64_t compute_member_offset(const std::vector<overlay_member_t>& members,
                                        std::uint64_t member_size) const;
    std::uint64_t type_size_of(const std::string& type_name) const;
    std::uint64_t type_alignment_of(const std::string& type_name) const;
    std::string normalize_type_name(const std::string& type_name) const;
    bool parse_declaration(const std::string& decl, overlay_type_t& out);
    bool parse_struct_body(const std::string& body, const std::string& kind,
                           const std::string& name, overlay_type_t& out);
    bool parse_enum_body(const std::string& body, const std::string& name,
                         overlay_type_t& out);
    bool parse_typedef(const std::string& body, overlay_type_t& out);
    std::string trim(const std::string& s) const;
    std::string to_hex(std::uint64_t value) const;
    std::vector<type_relation_t> find_related_types(const std::string& name) const;
    std::string format_declaration(const overlay_type_t& type) const;
    protocol::json members_to_json(const std::vector<overlay_member_t>& members,
                                    bool include_value = false,
                                    const std::string& base_addr = {}) const;
    protocol::json enumerators_to_json(const std::vector<overlay_enumerator_t>& enumerators) const;
    void record_undo(undo_entry_t::action_t action, const std::string& target,
                     std::optional<overlay_type_t> old_type,
                     std::optional<overlay_type_application_t> old_app);
    bool apply_single_edit(const protocol::json& edit, protocol::json& result,
                           std::vector<undo_entry_t>& batch_undo);
    void rollback_batch(std::vector<undo_entry_t>& batch_undo);

    std::unordered_map<std::string, overlay_type_t> types_;
    std::unordered_map<std::string, overlay_type_application_t> applications_;
    std::vector<undo_entry_t> undo_stack_;
    std::uint64_t revision_ = 0;
    std::uint32_t next_ordinal_ = 0;
    mutable std::mutex mutex_;
    std::map<target_scope_key_t, std::shared_ptr<types_overlay_store_t>> target_scopes_;
    mutable std::mutex target_scopes_mutex_;
    types_handler_limits_t limits_;
};

class types_handlers_t final {
public:
    types_handlers_t(workspace_adapter_t& workspace,
                     protocol::schema_runtime_t& schemas,
                     types_handler_limits_t limits = {});

    types_handlers_t(const types_handlers_t&) = delete;
    types_handlers_t& operator=(const types_handlers_t&) = delete;
    types_handlers_t(types_handlers_t&&) = delete;
    types_handlers_t& operator=(types_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const types_handler_limits_t& limits() const noexcept;

    protocol::mcp_result_t invoke(
        std::string_view name,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const protocol::json& aida_metadata = protocol::json::object()) const;

private:
    protocol::mcp_result_t dispatch(
        std::size_t index,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation) const;

    workspace_adapter_t& workspace_;
    protocol::schema_runtime_t& schemas_;
    types_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_types_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using types_adapter_t = protocol::mcp_result_t (*)(
    const handlers::types_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const protocol::json&);

protocol::mcp_result_t declare_type(const handlers::types_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t enum_upsert(const handlers::types_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t read_struct(const handlers::types_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t search_structs(const handlers::types_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t type_query(const handlers::types_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t type_inspect(const handlers::types_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t set_type(const handlers::types_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t type_apply_batch(const handlers::types_handlers_t& handlers,
                                        const protocol::json& arguments,
                                        const protocol::cancellation_token_t& cancellation,
                                        const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t infer_types(const handlers::types_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata = protocol::json::object());

}
