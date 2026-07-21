#pragma once


#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace code_editor_widget {

enum class document_action_t : std::uint8_t {
    select_word = 0,
    select_line,
    copy_line,
    copy_path,
    duplicate_line,
    delete_line,
    move_line_up,
    move_line_down,
    toggle_line_comment,
    trim_trailing_whitespace
};

struct document_capabilities_t {
    bool text_editing = false;
    bool save = false;
    bool syntax_highlighting = false;
    bool line_comment = false;
    bool find = false;
    bool replace = false;
    bool goto_line = false;
    bool ai_diff_review = false;
    bool semantic_navigation = false;
    bool semantic_rename = false;
    bool diagnostics = false;
    bool formatting = false;
    bool language_server = false;
    bool build = false;
    bool run = false;
    bool source_debugging = false;
};

struct document_state_t {
    std::string filename;
    std::string filepath;
    std::string language;
    std::size_t content_bytes = 0;
    std::size_t line_count = 0;
    int caret_line = 0;
    int caret_column = 0;
    bool active = false;
    bool dirty = false;
    bool focused = false;
    bool large_file_mode = false;
    bool has_selection = false;
    bool streamed = false;
    bool stream_loading = false;
    std::string stream_error;
    document_capabilities_t capabilities;
};

struct document_metadata_snapshot_t {
    bool found = false;
    std::uint64_t revision = 0;
    bool dirty = false;
    int caret_line = 0;
    int caret_column = 0;
    int selection_anchor_line = 0;
    int selection_anchor_column = 0;
    bool selection_active = false;
    float scroll_x = 0.f;
    float scroll_y = 0.f;
    std::vector<int> folded_lines;
    std::string language_override;
    bool proposal_pending = false;
    bool read_only = false;
};

struct document_payload_snapshot_t : document_metadata_snapshot_t {
    std::uint64_t content_hash = 0;
    std::string content;
};

struct document_pane_render_context_t {
    std::uint64_t document_id = 0;
    std::uint64_t revision = 1;
    std::string_view content;
    std::string_view filename;
    std::string_view filepath;
    bool dirty = false;
    int caret_line = 0;
    int caret_column = 0;
    int selection_anchor_line = 0;
    int selection_anchor_column = 0;
    bool selection_active = false;
    float scroll_x = 0.f;
    float scroll_y = 0.f;
    const std::vector<int>* folded_lines = nullptr;
    std::string_view language_override;
    bool read_only = false;
    std::string_view read_only_reason;
    float alpha = 1.f;
    float accent_r = 0.f;
    float accent_g = 0.f;
    float accent_b = 0.f;
};


struct selection_t {
    int  anchor_line = 0;
    int  anchor_col  = 0;
    int  caret_line  = 0;
    int  caret_col   = 0;
    bool active      = false;

    bool has_selection() const {
        return active && (anchor_line != caret_line || anchor_col != caret_col);
    }
    void clear() { active = false; anchor_line = caret_line; anchor_col = caret_col; }
};


struct undo_entry_t {
    int start_line = 0;
    std::vector<std::string> before_lines;
    std::vector<std::string> after_lines;
    int before_caret_line = 0;
    int before_caret_col = 0;
    int after_caret_line = 0;
    int after_caret_col = 0;
    std::size_t memory_bytes = 0;
    int coalesce_kind = 0;
};


struct find_match_t {
    int line = 0;
    int col  = 0;
    int length = 0;
};

struct find_state_t {
    bool visible          = false;
    bool replace_mode     = false;
    char find_buf[256]    = {};
    char replace_buf[256] = {};
    bool case_sensitive   = false;
    bool whole_word       = false;
    bool use_regex        = false;
    int  current_match    = -1;
    int  total_matches    = 0;
    std::vector<find_match_t> match_positions;
};


struct goto_state_t {
    bool visible      = false;
    char line_buf[16] = {};
};


enum class diff_line_kind_t : int {
    context = 0,
    added,
    removed
};


struct diff_line_t {
    diff_line_kind_t kind = diff_line_kind_t::context;
    std::string      text;
    int              old_line = -1;
    int              new_line = -1;
};


enum class diff_hunk_state_t : int {
    pending = 0,
    accepted,
    rejected
};


struct diff_hunk_t {
    std::uint64_t     stable_id   = 0;
    int               old_start   = 0;
    int               old_count   = 0;
    int               new_start   = 0;
    int               new_count   = 0;
    int               added       = 0;
    int               removed     = 0;
    diff_hunk_state_t state       = diff_hunk_state_t::pending;
    std::vector<diff_line_t> lines;
};


struct pending_diff_t {
    bool                     active   = false;
    std::uint64_t            document_id = 0;
    std::uint64_t            base_revision = 0;
    std::uint64_t            base_content_hash = 0;
    std::uint64_t            proposal_id = 0;
    std::string              origin;
    std::vector<std::string> old_lines;
    std::vector<std::string> new_lines;
    std::vector<diff_hunk_t> hunks;
    int                      total_added   = 0;
    int                      total_removed = 0;

    bool fully_resolved() const {
        for (const auto& h : hunks)
            if (h.state == diff_hunk_state_t::pending) return false;
        return true;
    }
};

struct review_hunk_identity_t {
    std::uint64_t document_id = 0;
    std::uint64_t proposal_id = 0;
    std::uint64_t base_revision = 0;
    std::uint64_t stable_hunk_id = 0;

    bool valid() const noexcept {
        return document_id != 0 && proposal_id != 0 &&
            base_revision != 0 && stable_hunk_id != 0;
    }
};


void init();

bool load_document(std::uint64_t document_id, std::uint64_t revision,
                   std::string_view content, std::string_view filename,
                   std::string_view filepath, bool dirty,
                   int caret_line = 0, int caret_column = 0,
                   float scroll_x = 0.f, float scroll_y = 0.f,
                   bool replace_existing = false,
                   int selection_anchor_line = 0, int selection_anchor_column = 0,
                   bool selection_active = false,
                   const std::vector<int>& folded_lines = {},
                   std::string_view language_override = {});


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

void render_document_pane(const document_pane_render_context_t& context = {});

document_state_t document_state();

document_state_t document_state(std::uint64_t document_id);

document_capabilities_t document_capabilities();

bool request_document_action(document_action_t action);


void get_caret(int& line, int& col);

void set_caret(int line, int col);

void get_scroll(float& x, float& y);

void set_scroll(float x, float y);

void discard_document_state(std::uint64_t document_id);

bool select_document_for_actions(std::uint64_t document_id);

std::uint64_t active_document_id();

std::uint64_t document_revision();

std::uint64_t document_revision(std::uint64_t document_id);

std::string document_content(std::uint64_t document_id);

std::uint64_t document_content_fingerprint(std::uint64_t document_id);

bool get_document_caret(std::uint64_t document_id, int& line, int& col);

bool set_document_caret(std::uint64_t document_id, int line, int col);

bool get_document_scroll(std::uint64_t document_id, float& x, float& y);

bool set_document_scroll(std::uint64_t document_id, float x, float y);

document_metadata_snapshot_t document_metadata(std::uint64_t document_id);

bool set_document_language_override(std::uint64_t document_id, std::string_view language);

bool toggle_document_fold(std::uint64_t document_id, int line);

document_payload_snapshot_t document_payload(std::uint64_t document_id,
                                             std::uint64_t expected_revision = 0);

std::string caret_identifier();

bool document_dirty(std::uint64_t document_id);

void mark_document_saved(std::uint64_t document_id, std::uint64_t revision,
                         std::string_view filename, std::string_view filepath);

bool request_streamed_document(std::uint64_t document_id, std::uint64_t revision,
                               std::string_view filename, std::string_view filepath,
                               std::uint64_t byte_length);

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
bool configure_preview_stream_state(std::uint64_t document_id,
                                    std::uint64_t advertised_byte_length,
                                    bool loading,
                                    bool cancellation_requested,
                                    std::string_view error);
#endif

void trigger_undo();
void trigger_redo();
void trigger_cut();
void trigger_copy();
void trigger_paste();
void trigger_delete();
void trigger_select_all();
void open_find();
void open_replace();
void open_goto_line();

bool can_undo();
bool can_redo();
bool can_paste();
bool has_selection();

std::string selected_text(std::size_t maximum_bytes = 64U * 1024U);
bool selected_range(int& start_line, int& start_column,
    int& end_line, int& end_column);

std::string last_error();
std::uint64_t document_content_fingerprint();


bool begin_agent_edit(std::string_view origin);

bool propose_full_content(std::string_view new_content);

bool propose_document_content(std::uint64_t document_id,
                              std::uint64_t base_revision,
                              std::uint64_t base_content_hash,
                              std::string_view current_content,
                              std::string_view new_content,
                              std::string_view origin);

bool propose_replace_range(int start_line, int end_line, std::string_view replacement);

bool has_pending_diff();

const pending_diff_t& pending_diff();

int  pending_hunk_count();

bool has_pending_review_hunks();

review_hunk_identity_t review_hunk_identity(int index);

review_hunk_identity_t selected_review_hunk_identity();

int resolve_review_hunk(const review_hunk_identity_t& identity,
                        bool require_pending = true);

bool select_review_hunk(int index, bool request_focus = true);

bool select_next_pending_hunk();

bool select_previous_pending_hunk();

bool accept_hunk(int index);

bool reject_hunk(int index);

void accept_all();

void reject_all();
bool commit_resolved_diff();

void cancel_agent_edit();

}
