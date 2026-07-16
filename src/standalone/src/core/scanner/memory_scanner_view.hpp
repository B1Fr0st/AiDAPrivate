#pragma once

#include <cstdint>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "memory_interaction_context.hpp"

namespace memory_scanner_view {

enum class result_sort_t : int {
	by_index = 0,
	by_address,
	by_value,
	by_previous,
	by_module
};

struct scrollbar_state_t {
	float            scroll_y = 0.f;
	float            target_scroll_y = 0.f;
	bool             dragging = false;
	bool             track_pressed = false;
	float            drag_offset = 0.f;
	float            hover_anim = 0.f;
	float            press_anim = 0.f;
};

struct region_cache_entry_t {
	uint64_t base = 0;
	uint64_t end = 0;
	uint32_t state = 0;
	uint32_t protect = 0;
	uint32_t type = 0;
};

struct region_cache_t {
	std::mutex                          mtx;
	std::vector<region_cache_entry_t>   entries;
	uint64_t                            generation = 0;
	bool                                refreshing = false;
};

struct desc_edit_state_t {
	bool   active = false;
	int    address_index = -1;
	bool   open_from_add_dialog = false;
	uint64_t pending_add_address = 0;
	int    pending_add_value_type = 0;
	char   buf[192] = {};
};

struct ui_state_t {
	int    selected_result = -1;
	int    selected_address = -1;

	std::unordered_set<int> result_multi_sel;
	std::unordered_set<int> address_multi_sel;
	int    last_result_anchor = -1;
	int    last_address_anchor = -1;

	scrollbar_state_t result_sb;
	scrollbar_state_t address_sb;

	char   value_buf[256] = {};
	char   value_buf2[64] = {};

	bool   auto_refresh = false;
	float  refresh_timer = 0.f;
	float  refresh_interval = 0.5f;

	std::vector<float>           row_flash;
	bool                         user_scrolled_up = false;
	float                        autoscroll_pill_alpha = 0.f;

	result_sort_t result_sort_field = result_sort_t::by_index;
	bool          result_sort_desc = false;
	std::vector<int> sorted_result_indices;
	bool          sorted_indices_dirty = true;

	region_cache_t region_cache;
	uint64_t       last_region_refresh_gen = static_cast<uint64_t>(-1);
	std::vector<region_cache_entry_t> render_region_snapshot;
	uint64_t       render_region_generation = static_cast<uint64_t>(-1);

	desc_edit_state_t desc_edit;

	float       result_pane_ratio = 0.6f;
	bool        splitter_dragging = false;
	float       splitter_press_anim = 0.f;
	bool        result_pane_focused = false;
	bool        address_pane_focused = false;
	std::uint64_t last_flash_revision = static_cast<std::uint64_t>(-1);
	float       flash_revision_age = 0.f;
	std::size_t last_result_count = 0;
	memory_interaction::context_t result_context;
	memory_interaction::context_t address_context;
};

inline ui_state_t g_ui;

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b);
void render_results(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_address_list(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);

}
