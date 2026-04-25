#pragma once

namespace memory_scanner_view {

struct ui_state_t {
	int    selected_result = -1;
	int    selected_address = -1;

	float  result_scroll_y = 0.f;
	float  result_target_scroll_y = 0.f;
	float  address_scroll_y = 0.f;
	float  address_target_scroll_y = 0.f;

	bool   result_sb_dragging = false;
	float  result_sb_drag_offset = 0.f;
	bool   address_sb_dragging = false;
	float  address_sb_drag_offset = 0.f;

	char   value_buf[256] = {};
	char   value_buf2[64] = {};

	bool   auto_refresh = false;
	float  refresh_timer = 0.f;
	float  refresh_interval = 0.5f;
};

inline ui_state_t g_ui;

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b);

}
