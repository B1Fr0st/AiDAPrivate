#pragma once

#include "imgui/imgui.h"

namespace aida::ui::ide_shell {

void configure_io(ImGuiIO& io) noexcept;
bool initialize() noexcept;
void begin_frame() noexcept;
void end_frame() noexcept;
void shutdown() noexcept;
bool begin_global_chrome_surface() noexcept;
void end_global_chrome_surface() noexcept;
void render_primary_surfaces() noexcept;
float reserved_chrome_height() noexcept;
ImGuiID root_dockspace_id() noexcept;

}
