#pragma once

#include "tool_types.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace mcp_standalone {

struct direct_dispatch_options_t {
    bool external_visible_only = true;
    cancel_token_ptr_t cancellation;
    std::uint64_t deadline_ms = 0;
    std::string request_id;
    std::string diagnostic_id;
};

class tool_registry_t final {
public:
    tool_registry_t() = default;
    tool_registry_t(const tool_registry_t&) = delete;
    tool_registry_t& operator=(const tool_registry_t&) = delete;

    bool register_tool(tool_def_t tool);
    bool replace_tool(tool_def_t tool);
    bool register_tool(
        tool_def_t tool,
        std::function<tool_result_t(
            const json&,
            const std::shared_ptr<aida::analysis::analysis_workspace_t>&)> handler);
    bool register_tool(
        tool_def_t tool,
        std::function<tool_result_t(
            const json&,
            const workspace_request_context_t&)> handler);

    void set_validation_hook(tool_validation_hook_t hook);
    bool set_dispatch_capacity(std::size_t capacity) noexcept;
    std::size_t dispatch_capacity() const noexcept;
    std::size_t active_dispatches() const noexcept;
    std::vector<tool_def_t> snapshot_tools() const;
    const std::vector<tool_def_t>& tools_view() const noexcept;
    std::optional<tool_def_t> find_tool(
        const std::string& name,
        bool external_visible_only) const;
    tool_result_t call_registered_tool(
        const std::string& name,
        const json& arguments,
        direct_dispatch_options_t options = {});

private:
    mutable std::mutex tools_mutex_;
    std::vector<tool_def_t> tools_;
    mutable std::mutex validation_mutex_;
    tool_validation_hook_t validation_hook_;
    std::atomic<std::size_t> active_dispatches_{0};
    std::atomic<std::size_t> dispatch_capacity_{64};
    std::atomic<std::uint64_t> request_sequence_{0};
};

tool_result_t invoke_registered_tool_definition(
    const tool_def_t& tool,
    const json& arguments,
    const direct_dispatch_options_t& options = {},
    const tool_validation_hook_t& validation_hook = {});

}
