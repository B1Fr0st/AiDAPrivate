#pragma once

#include "imgui/imgui.h"

namespace aida::ui::ide_shell {

using compatibility_renderer_t = void (*)(void* context);

void configure_io(ImGuiIO& io) noexcept;
bool initialize() noexcept;
void begin_frame() noexcept;
void end_frame() noexcept;
void shutdown() noexcept;
void render_compatibility_host(compatibility_renderer_t renderer, void* context);
bool compatibility_content_rect(ImVec2& position, ImVec2& size) noexcept;
ImGuiID root_dockspace_id() noexcept;

}
