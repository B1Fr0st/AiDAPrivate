#pragma once

#include "../analysis/workspace/analysis_workspace.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct DisasmFile;
struct DisasmState;

namespace disasm_view {

enum class addr_format_t : int {
    va = 0,
    rva,
    file_offset
};

struct bookmark_t {
    std::uint64_t addr = 0;
    std::string label;
};

struct xref_popup_entry_t {
    std::uint64_t addr = 0;
    int type = 0;
    std::string disasm_text;
    std::string module_name;
    std::string function_name;
};

struct formatted_instruction_t {
    aida::analysis::entity_id_t instruction_id = 0;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t runtime_address = 0;
    std::string bytes;
    std::string text;
    std::string error;
};

struct mutation_state_t {
    std::uint32_t pending = 0;
    std::uint64_t overlay_revision = 0;
    std::string error;
};

struct state_t {
    addr_format_t addr_format = addr_format_t::va;
    bool show_bytes = true;
    std::optional<std::uint64_t> display_image_base;
    bool banner_selected_all = false;
    int active_section = -1;
    std::optional<aida::analysis::address_t> selection;
    float target_scroll_y = 0.0f;
    bool scroll_to_selection = false;
    bool goto_visible = false;
    char goto_buf[192] = {};
    bool xref_popup_open = false;
    aida::analysis::address_t xref_popup_address;
    char xref_popup_filter[96] = {};
    int xref_popup_selected = -1;
    std::vector<xref_popup_entry_t> xref_results;
    std::atomic<bool> xref_scanning{false};
    std::vector<bookmark_t> bookmarks;
    std::unordered_map<aida::analysis::entity_id_t, formatted_instruction_t> formatted;
    std::unordered_set<std::uint64_t> pending_format_pages;
    std::uint64_t cached_generation = 0;
    std::uint64_t cached_analysis_revision = 0;
    std::uint64_t cached_overlay_revision = 0;
    std::string format_error;
    std::string mutation_error;
    bool rebase_popup_open = false;
    char rebase_buf[64] = {};
    std::string rebase_error;
    std::atomic<bool> export_pending{false};
    std::string export_error;
    std::string export_status;
    std::atomic<std::uint32_t> pending_mutations{0};
    std::mutex mutex;
};

struct workspace_model_t;

struct workspace_context_t {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    std::shared_ptr<const aida::analysis::analysis_publication_t> publication;
    std::shared_ptr<const aida::analysis::pe_image_t> image;
    std::shared_ptr<state_t> view;
    std::shared_ptr<workspace_model_t> model;
    aida::analysis::workspace_progress_t progress;

    explicit operator bool() const noexcept {
        return workspace && publication && view && model;
    }
};

workspace_context_t capture_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);
workspace_context_t capture_selected_workspace();

std::optional<aida::analysis::address_t> typed_address(
    const workspace_context_t& context, std::uint64_t runtime_address);
std::optional<std::uint64_t> runtime_address(
    const workspace_context_t& context, const aida::analysis::address_t& address);
std::optional<std::uint64_t> provider_offset(
    const workspace_context_t& context, const aida::analysis::address_t& address);
aida::analysis::workspace_result_t<std::vector<std::uint8_t>> read_bytes(
    const workspace_context_t& context, const aida::analysis::address_t& address,
    std::size_t size);

std::string resolve_symbol(const workspace_context_t& context,
                           const aida::analysis::address_t& address);
std::string resolve_name(const workspace_context_t& context,
                         const aida::analysis::address_t& address);
std::string comment(const workspace_context_t& context,
                    const aida::analysis::address_t& address);
std::string auto_comment(const workspace_context_t& context,
                         const aida::analysis::address_t& address);
void request_format_range(const workspace_context_t& context,
                          std::size_t begin, std::size_t end);
std::optional<formatted_instruction_t> formatted_instruction(
    const workspace_context_t& context, aida::analysis::entity_id_t instruction_id);

bool queue_comment(const workspace_context_t& context,
                   const aida::analysis::address_t& address,
                   std::string text);
bool queue_rename(const workspace_context_t& context,
                  const aida::analysis::address_t& address,
                  std::string name);
bool queue_bookmark(const workspace_context_t& context,
                    const aida::analysis::address_t& address,
                    std::string label);
bool queue_patch(const workspace_context_t& context,
                 const aida::analysis::address_t& address,
                 std::vector<std::uint8_t> bytes);
bool queue_type_application(const workspace_context_t& context,
                            const aida::analysis::address_t& address,
                            std::string type);
bool queue_type_declaration(const workspace_context_t& context,
                            std::string declaration);
bool queue_type_declaration_and_application(
    const workspace_context_t& context,
    const aida::analysis::address_t& address,
    std::string declaration,
    std::string canonical_type);
mutation_state_t mutation_state(const workspace_context_t& context);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            const workspace_context_t& context, float dt);

void goto_address(std::uint64_t address, const workspace_context_t& context);
void goto_address(const aida::analysis::address_t& address,
                  const workspace_context_t& context);
void select_address(std::uint64_t address, const workspace_context_t& context,
                    bool record_history = true);
void select_address(const aida::analysis::address_t& address,
                    const workspace_context_t& context,
                    bool record_history = true);
void navigate_back(const workspace_context_t& context);
void navigate_forward(const workspace_context_t& context);
void open_xrefs(std::uint64_t address, const workspace_context_t& context);

void bump_format_generation(const workspace_context_t& context);
void bump_format_generation();
std::uint32_t format_generation(const workspace_context_t& context);

std::uint64_t enclosing_function_start(std::uint64_t address,
                                       const workspace_context_t& context);

}
