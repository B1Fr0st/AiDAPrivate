#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace aida::analysis {
struct analysis_snapshot_t;
struct workspace_image_t;
}

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_survey_tool_count = 1;

struct survey_handler_limits_t final {
    std::size_t max_request_bytes = 16U * 1024U;
    std::size_t max_response_bytes = 512U * 1024U;
    std::size_t max_selector_bytes = 1024U;
    std::size_t max_workspace_id_bytes = 1024U;
    std::size_t max_target_source_path_bytes = 32U * 1024U;
    std::size_t max_digest_bytes = 128U;
    std::size_t max_detail_level_bytes = 32U;
    std::size_t max_static_items = 64U;
    std::size_t max_collection_items = 15U;
    std::size_t max_live_items = 8U;
    std::size_t max_text_bytes = 512U;
    std::size_t max_diagnostics = 32U;
    std::size_t max_analysis_index_items = 256U * 1024U;
    std::size_t max_analysis_scan_items = 1024U * 1024U;
    std::uint64_t max_live_snapshot_bytes = 64ULL * 1024ULL * 1024ULL;
    std::chrono::milliseconds max_execution_time{30000};
};

struct survey_generation_identity_t final {
    std::string workspace_id;
    std::optional<std::uint32_t> pid;
    std::string bin_name;
    std::string normalized_source_path;
    std::string sha256;
    std::optional<std::string> md5;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    bool live = false;
    bool live_snapshot_current = true;
};

struct survey_generation_lease_t final {
    std::shared_ptr<const void> owner;
    survey_generation_identity_t identity;
    std::shared_ptr<const aida::analysis::workspace_image_t> image;
    std::shared_ptr<const aida::analysis::analysis_snapshot_t> analysis;
};

using survey_generation_acquire_t = std::function<adapter_result_t<survey_generation_lease_t>(
    const target_selector_t&,
    std::optional<std::chrono::steady_clock::time_point>)>;

const std::array<std::string_view, k_survey_tool_count>& survey_tool_names() noexcept;

class survey_handlers_t final {
public:
    survey_handlers_t(survey_generation_acquire_t acquire_generation,
                      protocol::schema_runtime_t& schemas,
                      survey_handler_limits_t limits = {});

    survey_handlers_t(const survey_handlers_t&) = delete;
    survey_handlers_t& operator=(const survey_handlers_t&) = delete;
    survey_handlers_t(survey_handlers_t&&) = delete;
    survey_handlers_t& operator=(survey_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const survey_handler_limits_t& limits() const noexcept;

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

    survey_generation_acquire_t acquire_generation_;
    protocol::schema_runtime_t& schemas_;
    survey_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_survey_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using survey_adapter_t = protocol::mcp_result_t (*)(
    const handlers::survey_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const protocol::json&);

protocol::mcp_result_t survey_binary(const handlers::survey_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const protocol::json& aida_metadata = protocol::json::object());

}
