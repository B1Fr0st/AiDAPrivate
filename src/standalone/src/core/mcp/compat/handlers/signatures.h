#pragma once

#include "../../protocol/mcp_tool_contract.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::standalone::mcp::compat::handlers {

enum class signature_architecture_t : std::uint8_t {
    unknown = 0,
    x86,
    x64,
    arm,
    thumb,
    aarch64,
    mips,
    ppc,
    riscv,
    jvm,
    dalvik,
};

struct signature_instruction_t final {
    std::uint64_t address = 0;
    signature_architecture_t architecture = signature_architecture_t::unknown;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> stable_mask;
};

struct signature_function_t final {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::string name;
};

struct signature_xref_t final {
    std::uint64_t from = 0;
    bool code = false;
};

struct signature_match_result_t final {
    std::vector<std::uint64_t> addresses;
    bool exhausted = true;
    std::string error;
};

class signature_source_t {
public:
    virtual ~signature_source_t() = default;

    virtual std::optional<std::uint64_t> resolve_address(std::string_view query) const = 0;
    virtual std::optional<signature_instruction_t> instruction_at(std::uint64_t address) const = 0;
    virtual std::optional<signature_function_t> function_containing(std::uint64_t address) const = 0;
    virtual std::vector<signature_xref_t> xrefs_to(std::uint64_t address) const = 0;
    virtual bool read_bytes(std::uint64_t address, std::size_t size,
                            std::vector<std::uint8_t>& bytes) const = 0;
    virtual signature_match_result_t find_matches(
        const std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint8_t>& stable_mask,
        std::size_t maximum_results,
        const protocol::cancellation_token_t& cancellation) const = 0;
};

struct signature_limits_t final {
    std::size_t maximum_queries = 128;
    std::size_t maximum_query_bytes = 1024;
    std::size_t maximum_signature_bytes = 4096;
    std::size_t maximum_range_bytes = 4096;
    std::size_t maximum_xrefs_per_query = 4096;
    std::size_t maximum_top = 64;
    std::size_t maximum_instruction_bytes = 64;

    bool valid() const noexcept;
};

struct signature_handler_context_t final {
    const signature_source_t* source = nullptr;
    protocol::schema_runtime_t* schemas = nullptr;
    signature_limits_t limits{};
    protocol::json aida_metadata = protocol::json::object();
};

bool is_signature_tool_name(std::string_view name) noexcept;
protocol::tool_contract_t signature_tool_contract(std::string_view name);

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t make_signature(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation);

protocol::mcp_result_t make_signature_for_function(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation);

protocol::mcp_result_t make_signature_for_range(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation);

protocol::mcp_result_t find_xref_signatures(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation);

}
