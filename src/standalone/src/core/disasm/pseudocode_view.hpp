#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct DisasmFile;

namespace pseudocode_view {

struct tab_info_t {
	uint64_t    addr = 0;
	std::string label;
	std::string function_name;
	bool        loaded = false;
	bool        decompiling = false;
	bool        is_error = false;
};

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

void request_decompile(uint64_t addr, const DisasmFile* file, bool force_refresh = false);

void close_active_tab();
void close_all_tabs();
void close_tab_by_addr(uint64_t addr);
void activate_tab_by_addr(uint64_t addr);
void cancel_active_decompile();
void refresh_active_tab();
void refresh_all_tabs();

bool has_active_tab();
bool has_tab_for(uint64_t addr);
uint64_t active_tab_address();

int tab_count();
std::vector<tab_info_t> snapshot_tabs();

}
