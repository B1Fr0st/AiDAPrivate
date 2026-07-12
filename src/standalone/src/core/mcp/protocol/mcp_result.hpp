#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>

namespace aida::standalone::mcp::protocol {

using json = nlohmann::json;

enum class result_error_code_t {
    cancelled,
    invalid_input,
    invalid_output,
    target_policy_rejected,
    effect_policy_rejected,
    invalid_contract,
    handler_failed,
    internal_error,
};

std::string_view canonical_error_code(result_error_code_t code) noexcept;

class mcp_result_t {
public:
    mcp_result_t(const mcp_result_t&) = default;
    mcp_result_t& operator=(const mcp_result_t&) = default;
    mcp_result_t(mcp_result_t&&) noexcept = default;
    mcp_result_t& operator=(mcp_result_t&&) noexcept = default;

    static mcp_result_t success(
        std::string text,
        const json& structured_content,
        const json& aida_metadata = json::object());

    static mcp_result_t failure(
        result_error_code_t code,
        std::string text,
        const json& details = json::object(),
        const json& aida_metadata = json::object());

    bool is_error() const noexcept;
    std::string_view text() const noexcept;
    const json& structured_content() const noexcept;
    const json& aida_metadata() const noexcept;
    std::string_view error_code() const noexcept;
    json envelope() const;
    mcp_result_t with_aida_metadata(const json& trusted_metadata) const;

private:
    mcp_result_t() = default;
    bool is_error_ = false;
    std::string text_;
    json structured_content_ = json::object();
    json aida_metadata_ = json::object();
    std::string error_code_;
};

}
