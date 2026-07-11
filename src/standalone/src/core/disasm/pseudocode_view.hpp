#pragma once

#include "disasm_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

struct DisasmFile;

namespace pseudocode_view {

struct tab_info_t {
    std::uint64_t addr = 0;
    std::string label;
    std::string function_name;
    bool loaded = false;
    bool decompiling = false;
    bool is_error = false;
};

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            const disasm_view::workspace_context_t& context);
void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

void request_decompile(const disasm_view::workspace_context_t& context,
                       std::uint64_t address, bool force_refresh = false);
void request_decompile(std::uint64_t address, const DisasmFile* file,
                       bool force_refresh = false);

void close_active_tab(const disasm_view::workspace_context_t& context);
void close_all_tabs(const disasm_view::workspace_context_t& context);
void close_tab_by_addr(const disasm_view::workspace_context_t& context,
                       std::uint64_t address);
void activate_tab_by_addr(const disasm_view::workspace_context_t& context,
                          std::uint64_t address);
void cancel_active_decompile(const disasm_view::workspace_context_t& context);
void refresh_active_tab(const disasm_view::workspace_context_t& context);
void refresh_all_tabs(const disasm_view::workspace_context_t& context);

bool has_active_tab(const disasm_view::workspace_context_t& context);
bool has_tab_for(const disasm_view::workspace_context_t& context,
                 std::uint64_t address);
std::uint64_t active_tab_address(const disasm_view::workspace_context_t& context);
int tab_count(const disasm_view::workspace_context_t& context);
std::vector<tab_info_t> snapshot_tabs(const disasm_view::workspace_context_t& context);

void close_active_tab();
void close_all_tabs();
void close_tab_by_addr(std::uint64_t address);
void activate_tab_by_addr(std::uint64_t address);
void cancel_active_decompile();
void refresh_active_tab();
void refresh_all_tabs();
bool has_active_tab();
bool has_tab_for(std::uint64_t address);
std::uint64_t active_tab_address();
int tab_count();
std::vector<tab_info_t> snapshot_tabs();

}
