#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/analysis/workspace/analysis_workspace.hpp"

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

const workspace_preview_fixture_t& workspace_preview_fixture();

}

#endif
