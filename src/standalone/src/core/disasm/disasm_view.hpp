#pragma once

#include "../analysis/workspace/analysis_workspace.hpp"

#include <atomic>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
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

enum class operand_color_role_t : std::uint8_t {
    reg = 0,
    imm = 1,
    keyword = 2,
    name_candidate = 3,
    sub_label = 4,
    string_ref = 5,
    reg_ptr = 6,
    plain = 7
};

struct operand_token_t {
    std::uint32_t offset = 0;
    std::uint32_t length = 0;
    std::uint8_t color_role = 0;
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
    std::size_t mnemonic_end = 0;
    std::vector<operand_token_t> tokens;
};

struct mutation_state_t {
    std::uint32_t pending = 0;
    std::uint64_t overlay_revision = 0;
    std::string error;
    bool derived_publication_pending = false;
    std::uint64_t derived_publication_revision = 0;
    std::string derived_publication_error;
};

struct presentation_snapshot_t {
    addr_format_t addr_format = addr_format_t::va;
    bool show_bytes = true;
    std::optional<std::uint64_t> display_image_base;
    int active_section = -1;
    std::optional<aida::analysis::address_t> selection;
    float scroll_y = 0.0f;
};

enum class metadata_line_kind_t : std::uint8_t {
    blank = 0,
    comment,
    banner,
    directive,
    keyword
};

enum class static_patch_mode_t : std::uint8_t {
    bytes = 0,
    nop_fill = 1,
    assembly = 2
};

struct metadata_line_t {
    std::string text;
    metadata_line_kind_t kind = metadata_line_kind_t::comment;
};

struct state_t {
    addr_format_t addr_format = addr_format_t::va;
    bool show_bytes = true;
    std::optional<std::uint64_t> display_image_base;
    bool banner_selected_all = false;
    std::size_t banner_selected_line = 0;
    std::uint64_t metadata_signature = 0;
    std::vector<metadata_line_t> metadata_lines;
    int active_section = -1;
    std::optional<aida::analysis::address_t> selection;
    float target_scroll_y = 0.0f;
    bool scroll_restore_pending = false;
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
    std::atomic<std::uint64_t> formatted_revision{0};
    struct bookmark_cache_t {
        std::shared_ptr<const std::vector<bookmark_t>> rows;
        const void* publication = nullptr;
        std::uint64_t overlay_revision = 0;
    };
    bookmark_cache_t bookmark_cache;
    struct nav_band_cache_t {
        std::vector<std::uint32_t> colors;
        const void* instructions = nullptr;
        std::size_t range_first = 0;
        std::size_t range_second = 0;
        std::size_t marker_step = 0;
        std::uint64_t formatted_revision = 0;
    };
    nav_band_cache_t nav_band_cache;
    struct prefix_width_cache_t {
        float width = 0.0f;
        int addr_format = -1;
        const void* font = nullptr;
        std::uint64_t sections_revision = 0;
        bool valid = false;
    };
    prefix_width_cache_t prefix_width_cache;
    std::unordered_set<std::uint64_t> pending_format_pages;
    std::uint64_t cached_generation = 0;
    std::uint64_t cached_analysis_revision = 0;
    std::uint64_t cached_overlay_revision = 0;
    std::string format_error;
    std::string mutation_error;
    std::atomic<bool> derived_publication_retry_pending{false};
    std::uint64_t derived_publication_revision = 0;
    std::uint64_t derived_publication_target_revision = 0;
    std::string derived_publication_error;
    bool rebase_popup_open = false;
    char rebase_buf[64] = {};
    std::string rebase_error;
    std::atomic<bool> export_pending{false};
    std::string export_error;
    std::string export_status;
    std::atomic<std::uint32_t> pending_mutations{0};
    bool static_patch_open = false;
    bool static_patch_focus_input = false;
    static_patch_mode_t static_patch_mode = static_patch_mode_t::bytes;
    aida::analysis::address_t static_patch_address;
    std::uint64_t static_patch_extent = 0;
    std::uint64_t static_patch_generation = 0;
    std::uint64_t static_patch_analysis_revision = 0;
    std::uint64_t static_patch_overlay_revision = 0;
    bool static_patch_existing = false;
    std::uint64_t static_patch_existing_size = 0;
    std::vector<std::uint8_t> static_patch_original;
    std::vector<std::uint8_t> static_patch_proposed;
    std::array<char, 196609> static_patch_input{};
    std::array<char, 256> static_patch_description{};
    std::string static_patch_error;
    std::string static_patch_parse_error;
    std::string static_patch_status;
    bool selection_initialized = false;
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
workspace_context_t capture_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    std::string_view presentation_key);
workspace_context_t capture_selected_workspace();
workspace_context_t capture_selected_workspace(std::string_view presentation_key);
void reset_presentation(std::string_view presentation_key);
void release_presentation(std::string_view presentation_key);
void clone_presentation(std::string_view source_key, std::string_view target_key);
bool capture_selected_presentation(std::string_view presentation_key,
                                   presentation_snapshot_t& snapshot);
bool restore_selected_presentation(std::string_view presentation_key,
                                   const presentation_snapshot_t& snapshot);

std::optional<aida::analysis::address_t> typed_address(
    const workspace_context_t& context, std::uint64_t runtime_address);
std::optional<std::uint64_t> runtime_address(
    const workspace_context_t& context, const aida::analysis::address_t& address);
std::optional<std::uint64_t> display_base_override(const workspace_context_t& context);
std::optional<std::uint64_t> runtime_address_with_base(
    const workspace_context_t& context, const aida::analysis::address_t& address,
    const std::optional<std::uint64_t>& base_override);
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
std::vector<bookmark_t> bookmark_snapshot(const workspace_context_t& context);
bool bookmarked(const workspace_context_t& context,
                const aida::analysis::address_t& address);
void request_format_range(const workspace_context_t& context,
                          std::size_t begin, std::size_t end);
std::optional<formatted_instruction_t> formatted_instruction(
    const workspace_context_t& context, aida::analysis::entity_id_t instruction_id);

using overlay_completion_t = std::function<void(bool, std::string)>;

bool queue_comment(const workspace_context_t& context,
                   const aida::analysis::address_t& address,
                   std::string text,
                   std::optional<std::uint64_t> required_generation = {},
                   std::optional<std::uint64_t> required_analysis_revision = {},
                   std::optional<std::uint64_t> required_overlay_revision = {},
                   overlay_completion_t completion = {});
bool queue_rename(const workspace_context_t& context,
                  const aida::analysis::address_t& address,
                  std::string name,
                  std::optional<std::uint64_t> required_generation = {},
                  std::optional<std::uint64_t> required_analysis_revision = {},
                  std::optional<std::uint64_t> required_overlay_revision = {},
                  overlay_completion_t completion = {});
bool queue_bookmark(const workspace_context_t& context,
                    const aida::analysis::address_t& address,
                    std::string label);
bool queue_patch(const workspace_context_t& context,
                 const aida::analysis::address_t& address,
                 std::vector<std::uint8_t> bytes);
bool open_static_patch_review(const workspace_context_t& context,
                              const aida::analysis::address_t& address,
                              std::uint64_t extent,
                              static_patch_mode_t mode,
                              std::string* error = nullptr);
bool open_exact_static_patch_review(const workspace_context_t& context,
                                    const aida::analysis::address_t& address,
                                    const std::vector<std::uint8_t>& expected_before,
                                    const std::vector<std::uint8_t>& reviewed_after,
                                    const std::string& provenance,
                                    std::uint64_t expected_generation,
                                    std::uint64_t expected_analysis_revision,
                                    std::uint64_t expected_overlay_revision,
                                    std::string* error = nullptr);
bool open_selected_patch_review(static_patch_mode_t mode,
                                std::string* error = nullptr);
void render_static_patch_workflow();
bool queue_type_application(const workspace_context_t& context,
                            const aida::analysis::address_t& address,
                            std::string type,
                            std::optional<std::uint64_t> required_generation = {},
                            std::optional<std::uint64_t> required_analysis_revision = {},
                            std::optional<std::uint64_t> required_overlay_revision = {},
                            overlay_completion_t completion = {});
bool queue_type_declaration(const workspace_context_t& context,
                            std::string declaration);
bool queue_type_declaration_and_application(
    const workspace_context_t& context,
    const aida::analysis::address_t& address,
    std::string declaration,
    std::string canonical_type);
mutation_state_t mutation_state(const workspace_context_t& context);
bool queue_overlay_undo(const workspace_context_t& context);
bool queue_overlay_redo(const workspace_context_t& context);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            const workspace_context_t& context, float dt);

void goto_address(std::uint64_t address, const workspace_context_t& context);
void goto_address(const aida::analysis::address_t& address,
                  const workspace_context_t& context);
bool request_goto(const workspace_context_t& context);
bool request_rebase(const workspace_context_t& context, std::string* error = nullptr);
bool request_listing_export(const workspace_context_t& context,
                            std::string* error = nullptr);
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
