#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/analysis/workspace/analysis_workspace.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace aida::preview {

struct workspace_preview_fixture_t final {
    std::shared_ptr<analysis::analysis_workspace_t> workspace;
    std::string session_id;
    std::string source_path;
    std::string filename;
    std::string display_name;
};

enum class workspace_preview_target_t : std::uint8_t {
    static_file,
    live_process
};

void configure_workspace_preview_target(workspace_preview_target_t target);
const workspace_preview_fixture_t& workspace_preview_fixture();

}

#endif
