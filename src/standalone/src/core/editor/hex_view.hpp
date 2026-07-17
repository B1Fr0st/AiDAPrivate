#pragma once

#include "../disasm/disasm_view.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace hex_view {

void activate(const disasm_view::workspace_context_t& context);
bool focus_address(const disasm_view::workspace_context_t& context,
                   const aida::analysis::address_t& address,
                   std::string* error = nullptr);
bool request_live_memory(const disasm_view::workspace_context_t& context,
                         std::uint64_t address, std::size_t size);
void close(const disasm_view::workspace_context_t& context);
bool active(const disasm_view::workspace_context_t& context);
std::string source_name(const disasm_view::workspace_context_t& context);
void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            const disasm_view::workspace_context_t& context);
std::string last_error(const disasm_view::workspace_context_t& context);

}
