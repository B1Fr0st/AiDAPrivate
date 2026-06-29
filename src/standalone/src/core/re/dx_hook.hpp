#pragma once

#include "re_common.hpp"

#include <atomic>
#include <cstdint>

namespace re::dx_hook
{
struct frame_tracking_state_t {
    std::atomic<std::uint32_t> current_frame{0};
    std::atomic<std::uint32_t> current_draw_ordinal{0};
    std::atomic<std::uint64_t> frame_start_ms{0};
    std::atomic<bool> enabled{false};
};
frame_tracking_state_t& frame_tracking_state();
void stop_dx_debug_loop(std::uint32_t pid);
void clear_dx_record_breakpoints(std::uint32_t pid);

tool_result_t find_device_vtable(const json& params);
tool_result_t hook_manage(const json& params);
tool_result_t list_bound_cbuffers(const json& params);
tool_result_t identify_bone_buffer(const json& params);
tool_result_t map_resource_to_va(const json& params);
tool_result_t dump_render_targets(const json& params);
tool_result_t find_view_matrix(const json& params);
tool_result_t verify_view_matrix(const json& params);
tool_result_t project_bones(const json& params);
tool_result_t trace_decryption(const json& params);
tool_result_t read_gpu_buffer(const json& params);
tool_result_t correlate_results(const json& params);
tool_result_t get_frame_summary(const json& params);
tool_result_t auto_narrow(const json& params);
}
