#include "code_editor.hpp"
#include "syntax_highlight.hpp"
#include "../helpers/globals.h"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/task_center.hpp"
#include "../debugger/source_debug_service.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/editor_preview_adapter.hpp"
#else
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "standalone_license.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <Windows.h>
#endif
#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <optional>
#include <cctype>
#include <mutex>
#include <memory>
#include <new>
#include <regex>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "fonts.hpp"
#include "ui_anim.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/executor.hpp"
#include "../helpers/diag_log.hpp"
#endif

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
namespace editor_preferences = aida::preview::editor::preferences;
#else
namespace editor_preferences = editor_config;
#endif


namespace {

const std::string& active_content();

struct line_cache_t {
    std::vector<std::string>          lines;
    std::vector<std::vector<syntax::token_t>> tokens;
    std::vector<std::uint64_t>        line_hashes;
    std::size_t                       content_bytes = 0;
    bool dirty = true;
};

static constexpr int UNDO_MAX = 100;
static constexpr std::size_t LARGE_FILE_BYTES =
    aida::editor::programming_documents::normal_editable_document_bytes;
static constexpr std::size_t LARGE_READ_ONLY_BYTES =
    aida::editor::programming_documents::maximum_editable_document_bytes + 1U;
static constexpr std::size_t MAXIMUM_VIEWABLE_BYTES =
    aida::editor::programming_documents::maximum_viewable_document_bytes;
static constexpr std::size_t HISTORY_BUDGET_BYTES = 32ULL * 1024ULL * 1024ULL;
static constexpr std::size_t LARGE_HISTORY_BUDGET_BYTES = 12ULL * 1024ULL * 1024ULL;
std::mutex     s_ghost_mtx;
std::mutex                          s_diff_mtx;

struct pending_edit_t {
    bool active = false;
    int start_line = 0;
    int old_total_lines = 0;
    std::vector<std::string> before_lines;
    int before_caret_line = 0;
    int before_caret_col = 0;
    int coalesce_kind = 0;
    bool merge_previous = false;
};

struct mapped_text_source_t {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    const char* view = nullptr;
#endif
    std::uint64_t byte_length = 0;
    std::vector<std::uint64_t> line_offsets;

    ~mapped_text_source_t() {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        if (view) UnmapViewOfFile(view);
        if (mapping) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
#endif
    }
};

struct document_runtime_t {
    std::uint64_t document_id = 0;
    std::uint64_t revision = 1;
    std::string serialized_content;
    bool serialized_dirty = false;
	std::uint64_t content_fingerprint = 0;
	std::uint64_t fingerprint_revision = 0;
    std::string filename;
    std::string filepath;
    bool active = false;
    bool dirty = false;
    bool read_only = false;
    std::string read_only_reason;
    line_cache_t cache;
    code_editor_widget::selection_t selection;
    code_editor_widget::find_state_t find;
    code_editor_widget::goto_state_t go_to;
    std::vector<code_editor_widget::undo_entry_t> undo;
    std::vector<code_editor_widget::undo_entry_t> redo;
    float scroll_y = 0.f;
    float scroll_x = 0.f;
    float target_scroll_y = 0.f;
    syntax::language_def_t language{};
    bool language_set = false;
    code_editor_widget::pending_diff_t diff;
    int diff_hover_hunk = -1;
    float diff_scroll_target = -1.f;
    std::string last_error;
    double last_edit_time = 0.0;
    int last_edit_line = -1;
    int last_edit_col = -1;
    int undo_kind = 0;
    pending_edit_t pending_edit;
    float blink_timer = 0.f;
    bool blink_on = true;
    bool focus_find_input = false;
    bool find_has_focus = false;
    char find_last_buf[256] = {};
    bool mouse_selecting = false;
    float last_click_time = 0.f;
    int click_count = 0;
    bool sb_dragging = false;
    float sb_drag_offset = 0.f;
    bool has_focus = false;
    ImGuiID widget_id = 0;
    std::string ghost_text;
    std::string ghost_pending;
    bool ghost_has_pending = false;
    float ghost_debounce = 0.f;
    int ghost_trigger_line = -1;
    int ghost_trigger_col = -1;
    bool ghost_requesting = false;
    bool request_undo = false;
    bool request_redo = false;
    bool request_cut = false;
    bool request_copy = false;
    bool request_paste = false;
    bool request_delete = false;
    bool request_select_all = false;
    bool request_find = false;
    bool request_replace = false;
    bool request_goto = false;
    std::uint32_t document_action_requests = 0;
    aida::ui::transition_t caret_move_anim;
    int prev_caret_line = 0;
    int prev_caret_col = 0;
    aida::ui::transition_t focus_anim;
    aida::ui::transition_t ghost_in;
    int ghost_visible_for_line = -1;
    int ghost_visible_for_col = -1;
    aida::ui::transition_t ghost_absorb;
    aida::ui::flash_t breadcrumb_flash;
    aida::ui::transition_t match_pulse;
    int active_match_for = -1;
    aida::ui::transition_t minimap_hover;
    bool hsb_dragging = false;
    float hsb_drag_offset = 0.f;
    std::uint64_t minimap_log_signature = 0;
    std::shared_ptr<mapped_text_source_t> mapped_source;
    std::unordered_map<int, std::string> mapped_lines;
    std::deque<int> mapped_line_lru;
	std::size_t mapped_line_cache_bytes = 0;
    std::unordered_map<int, std::vector<syntax::token_t>> mapped_tokens;
    std::unordered_map<int, std::uint64_t> mapped_hashes;
    bool stream_loading = false;
    std::string stream_error;
    std::uint64_t stream_generation = 0;
	std::shared_ptr<std::atomic<bool>> stream_dispatch_failed;
	std::shared_ptr<std::atomic<bool>> stream_cancel;
	std::uint64_t stream_task_id = 0;
    std::shared_ptr<std::atomic<bool>> find_cancel;
    std::uint64_t find_generation = 0;
	std::uint64_t find_task_id = 0;
    bool find_loading = false;
    std::string find_error;
	std::shared_ptr<std::atomic<bool>> find_dispatch_failed;
};

std::unordered_map<std::uint64_t, std::shared_ptr<document_runtime_t>> s_document_states;
std::uint64_t s_bound_document_id = 0;
std::uint64_t s_focused_document_id = 0;

document_runtime_t& state_for(std::uint64_t document_id) {
    auto& slot = s_document_states[document_id];
    if (!slot) {
        slot = std::make_shared<document_runtime_t>();
        slot->document_id = document_id;
    }
    return *slot;
}

std::shared_ptr<document_runtime_t> document_handle(std::uint64_t document_id) {
    state_for(document_id);
    return s_document_states[document_id];
}

void cancel_runtime_jobs(document_runtime_t& document) {
	if (document.stream_cancel)
		document.stream_cancel->store(true, std::memory_order_release);
	if (document.find_cancel)
		document.find_cancel->store(true, std::memory_order_release);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (document.stream_task_id != 0)
		aida::infra::executor::cancel(document.stream_task_id);
	if (document.find_task_id != 0)
		aida::infra::executor::cancel(document.find_task_id);
#endif
	document.stream_task_id = 0;
	document.find_task_id = 0;
	document.stream_cancel.reset();
	document.find_cancel.reset();
}

document_runtime_t& current_document() {
    return state_for(s_bound_document_id);
}

void bind_focused_document() {
    if (s_focused_document_id != 0 &&
        s_document_states.find(s_focused_document_id) != s_document_states.end())
        s_bound_document_id = s_focused_document_id;
}

#define s_cache current_document().cache
#define s_sel current_document().selection
#define s_find current_document().find
#define s_goto current_document().go_to
#define s_undo current_document().undo
#define s_redo current_document().redo
#define s_scroll_y current_document().scroll_y
#define s_scroll_x current_document().scroll_x
#define s_target_scroll_y current_document().target_scroll_y
#define s_lang current_document().language
#define s_lang_set current_document().language_set
#define s_diff current_document().diff
#define s_diff_hover_hunk current_document().diff_hover_hunk
#define s_diff_scroll_target current_document().diff_scroll_target
#define s_last_error current_document().last_error
#define s_last_edit_time current_document().last_edit_time
#define s_last_edit_line current_document().last_edit_line
#define s_last_edit_col current_document().last_edit_col
#define s_undo_kind current_document().undo_kind
#define s_blink_timer current_document().blink_timer
#define s_blink_on current_document().blink_on
#define s_focus_find_input current_document().focus_find_input
#define s_find_has_focus current_document().find_has_focus
#define s_find_last_buf current_document().find_last_buf
#define s_mouse_selecting current_document().mouse_selecting
#define s_last_click_time current_document().last_click_time
#define s_click_count current_document().click_count
#define s_sb_dragging current_document().sb_dragging
#define s_sb_drag_offset current_document().sb_drag_offset
#define s_has_focus current_document().has_focus
#define s_widget_id current_document().widget_id
#define s_ghost_text current_document().ghost_text
#define s_ghost_pending current_document().ghost_pending
#define s_ghost_has_pending current_document().ghost_has_pending
#define s_ghost_debounce current_document().ghost_debounce
#define s_ghost_trigger_line current_document().ghost_trigger_line
#define s_ghost_trigger_col current_document().ghost_trigger_col
#define s_ghost_requesting current_document().ghost_requesting
#define s_request_undo current_document().request_undo
#define s_request_redo current_document().request_redo
#define s_request_cut current_document().request_cut
#define s_request_copy current_document().request_copy
#define s_request_paste current_document().request_paste
#define s_request_delete current_document().request_delete
#define s_request_select_all current_document().request_select_all
#define s_request_find current_document().request_find
#define s_request_replace current_document().request_replace
#define s_request_goto current_document().request_goto
#define s_document_action_requests current_document().document_action_requests
#define s_active_document_id current_document().document_id
#define s_document_revision current_document().revision

std::string serialize_lines(const line_cache_t& cache) {
    std::string result;
    result.reserve(cache.content_bytes);
    for (std::size_t index = 0; index < cache.lines.size(); ++index) {
        if (index != 0) result.push_back('\n');
        result.append(cache.lines[index]);
    }
    return result;
}

const std::string& active_content() {
    auto& document = current_document();
    if (document.serialized_dirty && !document.cache.dirty) {
        document.serialized_content = serialize_lines(document.cache);
        document.serialized_dirty = false;
    }
    return document.serialized_content;
}

std::uint64_t line_hash(std::string_view text) {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char character : text) {
        const auto value = static_cast<unsigned char>(character);
        hash ^= value;
        hash *= 1099511628211ULL;
    }
    return hash;
}

const std::string& line_at(int idx);

bool large_file_mode() {
    return s_cache.content_bytes >= LARGE_FILE_BYTES;
}

bool large_read_only_mode() {
    return current_document().read_only || s_cache.content_bytes >= LARGE_READ_ONLY_BYTES;
}

void tokenize_line(std::size_t index) {
    if (current_document().mapped_source) {
        const int line_index = static_cast<int>(index);
        const std::string& text = line_at(line_index);
        const std::uint64_t hash = line_hash(text);
        auto& document = current_document();
        if (document.mapped_hashes[line_index] == hash) return;
        syntax::tokenize(text, s_lang, document.mapped_tokens[line_index]);
        document.mapped_hashes[line_index] = hash;
        return;
    }
    if (index >= s_cache.lines.size()) return;
    if (s_cache.tokens.size() < s_cache.lines.size())
        s_cache.tokens.resize(s_cache.lines.size());
    if (s_cache.line_hashes.size() < s_cache.lines.size())
        s_cache.line_hashes.resize(s_cache.lines.size());
    const std::uint64_t hash = line_hash(s_cache.lines[index]);
    if (s_cache.line_hashes[index] == hash) return;
    syntax::tokenize(s_cache.lines[index], s_lang, s_cache.tokens[index]);
    s_cache.line_hashes[index] = hash;
}

void tokenize_range(int first, int last) {
    if (s_cache.lines.empty()) return;
    first = std::max(0, first);
    last = std::min(last, static_cast<int>(s_cache.lines.size()) - 1);
    for (int line = first; line <= last; ++line)
        tokenize_line(static_cast<std::size_t>(line));
}

void trim_history(std::vector<code_editor_widget::undo_entry_t>& history) {
    const std::size_t budget = large_file_mode() ? LARGE_HISTORY_BUDGET_BYTES : HISTORY_BUDGET_BYTES;
    const std::size_t entry_limit = large_file_mode() ? 8U : static_cast<std::size_t>(UNDO_MAX);
    std::size_t bytes = 0;
    for (const auto& entry : history) bytes += entry.memory_bytes;
    while (!history.empty() && (history.size() > entry_limit || bytes > budget)) {
        bytes -= history.front().memory_bytes;
        history.erase(history.begin());
    }
}


void rebuild_lines() {
    if (current_document().mapped_source) {
        s_cache.lines.clear();
        s_cache.tokens.clear();
        s_cache.line_hashes.clear();
        s_cache.content_bytes = static_cast<std::size_t>(
            (std::min)(current_document().mapped_source->byte_length,
                static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())));
        s_cache.dirty = false;
        return;
    }
    s_cache.lines.clear();
    s_cache.content_bytes = 0;
    if (current_document().serialized_content.empty()) {
        s_cache.lines.push_back("");
        s_cache.tokens.clear();
        s_cache.tokens.push_back({});
        s_cache.line_hashes.assign(1, line_hash(""));
        s_cache.dirty = false;
        return;
    }

    const char* txt = current_document().serialized_content.c_str();
    const char* p = txt;
    const char* line_start = txt;
    while (*p) {
        if (*p == '\n') {
            const char* line_end = (p > line_start && *(p - 1) == '\r') ? p - 1 : p;
            s_cache.lines.emplace_back(line_start, line_end);
            line_start = p + 1;
        }
        p++;
    }
    const char* line_end = (p > line_start && *(p - 1) == '\r') ? p - 1 : p;
    s_cache.lines.emplace_back(line_start, line_end);
    s_cache.content_bytes = static_cast<std::size_t>(p - txt);

    s_cache.tokens.assign(s_cache.lines.size(), {});
    s_cache.line_hashes.assign(s_cache.lines.size(), 0);
    if (!large_file_mode())
        tokenize_range(0, static_cast<int>(s_cache.lines.size()) - 1);
    s_cache.dirty = false;
}

void rebuild_buffer_from_lines(bool content_bytes_are_current = false) {
    auto& document = current_document();
    auto& pending = document.pending_edit;
    const int new_total_lines = static_cast<int>(s_cache.lines.size());
    bool content_bytes_updated = content_bytes_are_current;
    if (pending.active) {
        const int before_count = static_cast<int>(pending.before_lines.size());
        const int after_count = (std::max)(0,
            before_count + new_total_lines - pending.old_total_lines);
        const int after_end = (std::min)(new_total_lines,
            pending.start_line + after_count);
        std::vector<std::string> after_lines;
        if (pending.start_line >= 0 && pending.start_line < after_end)
            after_lines.assign(s_cache.lines.begin() + pending.start_line,
                s_cache.lines.begin() + after_end);
        std::size_t before_bytes = 0;
        std::size_t after_bytes = 0;
        for (const auto& line : pending.before_lines) before_bytes += line.size();
        for (const auto& line : after_lines) after_bytes += line.size();
        const std::int64_t line_delta = static_cast<std::int64_t>(new_total_lines) -
            static_cast<std::int64_t>(pending.old_total_lines);
        const std::int64_t byte_delta = static_cast<std::int64_t>(after_bytes) -
            static_cast<std::int64_t>(before_bytes) + line_delta;
        const std::int64_t updated_bytes = static_cast<std::int64_t>(s_cache.content_bytes) + byte_delta;
        s_cache.content_bytes = static_cast<std::size_t>((std::max)(std::int64_t{0}, updated_bytes));
        content_bytes_updated = true;
        if (pending.before_lines != after_lines) {
            code_editor_widget::undo_entry_t entry;
            entry.start_line = pending.start_line;
            entry.before_lines = std::move(pending.before_lines);
            entry.after_lines = std::move(after_lines);
            entry.before_caret_line = pending.before_caret_line;
            entry.before_caret_col = pending.before_caret_col;
            entry.after_caret_line = s_sel.caret_line;
            entry.after_caret_col = s_sel.caret_col;
            entry.coalesce_kind = pending.coalesce_kind;
            for (const auto& line : entry.before_lines) entry.memory_bytes += line.size();
            for (const auto& line : entry.after_lines) entry.memory_bytes += line.size();
            if (pending.merge_previous && !s_undo.empty()) {
                auto& previous = s_undo.back();
                previous.after_lines = std::move(entry.after_lines);
                previous.after_caret_line = entry.after_caret_line;
                previous.after_caret_col = entry.after_caret_col;
                previous.memory_bytes = 0;
                for (const auto& line : previous.before_lines) previous.memory_bytes += line.size();
                for (const auto& line : previous.after_lines) previous.memory_bytes += line.size();
            } else {
                s_undo.push_back(std::move(entry));
            }
            trim_history(s_undo);
            s_redo.clear();
        }
        pending = {};
    }
    if (!content_bytes_updated) {
        std::size_t bytes = s_cache.lines.empty() ? 0U : s_cache.lines.size() - 1U;
        for (const auto& line : s_cache.lines) bytes += line.size();
        s_cache.content_bytes = bytes;
    }
    document.serialized_dirty = true;
    current_document().dirty = true;
    if (s_active_document_id != 0)
        ++s_document_revision;
    s_cache.tokens.resize(s_cache.lines.size());
    s_cache.line_hashes.resize(s_cache.lines.size());
}

int line_count() {
    if (current_document().mapped_source)
        return static_cast<int>((std::min)(current_document().mapped_source->line_offsets.size(),
            static_cast<std::size_t>((std::numeric_limits<int>::max)())));
    return static_cast<int>(s_cache.lines.size());
}

const std::string& line_at(int idx) {
    static const std::string empty;
    auto& document = current_document();
    if (document.mapped_source) {
        const auto& source = *document.mapped_source;
        if (idx < 0 || static_cast<std::size_t>(idx) >= source.line_offsets.size())
            return empty;
        const auto found = document.mapped_lines.find(idx);
        if (found != document.mapped_lines.end()) return found->second;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const std::uint64_t start = source.line_offsets[static_cast<std::size_t>(idx)];
        std::uint64_t end = static_cast<std::size_t>(idx + 1) < source.line_offsets.size()
            ? source.line_offsets[static_cast<std::size_t>(idx + 1)] - 1U
            : source.byte_length;
        if (end > start && source.view[end - 1U] == '\r') --end;
		constexpr std::uint64_t k_max_rendered_line = 64ULL * 1024ULL;
        const std::uint64_t bounded_end = (std::min)(end, start + k_max_rendered_line);
        std::string value(source.view + start, source.view + bounded_end);
        if (bounded_end != end)
			value.append(" [line truncated at 64 KiB; use Hex View for the complete record]");
        auto [inserted, _] = document.mapped_lines.emplace(idx, std::move(value));
		document.mapped_line_cache_bytes += inserted->second.size();
        document.mapped_line_lru.push_back(idx);
		constexpr std::size_t k_mapped_line_cache_budget = 16U * 1024U * 1024U;
        while (document.mapped_line_lru.size() > 4096U ||
			document.mapped_line_cache_bytes > k_mapped_line_cache_budget) {
            const int expired = document.mapped_line_lru.front();
            document.mapped_line_lru.pop_front();
            if (expired != idx) {
				const auto expired_line = document.mapped_lines.find(expired);
				if (expired_line != document.mapped_lines.end())
					document.mapped_line_cache_bytes -= expired_line->second.size();
                document.mapped_lines.erase(expired);
                document.mapped_tokens.erase(expired);
                document.mapped_hashes.erase(expired);
            }
        }
        return inserted->second;
#else
        return empty;
#endif
    }
    if (idx < 0 || idx >= static_cast<int>(s_cache.lines.size())) return empty;
    return s_cache.lines[static_cast<std::size_t>(idx)];
}

int line_length(int idx) { return static_cast<int>(line_at(idx).size()); }

int clamp_col(int line, int col) {
    int clamped = std::max(0, std::min(col, line_length(line)));
    const std::string& ln = line_at(line);
    while (clamped > 0 && clamped < static_cast<int>(ln.size()) &&
           (static_cast<unsigned char>(ln[static_cast<std::size_t>(clamped)]) & 0xC0) == 0x80)
        clamped--;
    return clamped;
}

int clamp_line(int line) {
    return std::max(0, std::min(line, line_count() - 1));
}


void selection_ordered(int& l0, int& c0, int& l1, int& c1) {
    if (s_sel.anchor_line < s_sel.caret_line ||
        (s_sel.anchor_line == s_sel.caret_line && s_sel.anchor_col <= s_sel.caret_col)) {
        l0 = s_sel.anchor_line; c0 = s_sel.anchor_col;
        l1 = s_sel.caret_line;  c1 = s_sel.caret_col;
    } else {
        l0 = s_sel.caret_line;  c0 = s_sel.caret_col;
        l1 = s_sel.anchor_line; c1 = s_sel.anchor_col;
    }
}

std::string get_selected_text() {
    if (!s_sel.has_selection()) return {};
    int l0, c0, l1, c1;
    selection_ordered(l0, c0, l1, c1);
    if (l0 == l1) {
        auto& ln = line_at(l0);
        c0 = std::clamp(c0, 0, static_cast<int>(ln.size()));
        c1 = std::clamp(c1, 0, static_cast<int>(ln.size()));
        return ln.substr(static_cast<std::size_t>(c0), static_cast<std::size_t>(c1 - c0));
    }
    std::string result;
    c0 = std::clamp(c0, 0, line_length(l0));
    c1 = std::clamp(c1, 0, line_length(l1));
    result += line_at(l0).substr(static_cast<std::size_t>(c0));
    result += '\n';
    for (int i = l0 + 1; i < l1; i++) {
        result += line_at(i);
        result += '\n';
    }
    result += line_at(l1).substr(0, static_cast<std::size_t>(c1));
    return result;
}

void push_undo_range(int first_line, int last_line, int coalesce_kind = 0) {
    if (current_document().read_only || current_document().pending_edit.active) return;
    first_line = clamp_line(first_line);
    last_line = clamp_line(last_line);
    if (last_line < first_line) std::swap(first_line, last_line);
    bool merge_previous = false;
    if (coalesce_kind != 0 && coalesce_kind == s_undo_kind && !s_undo.empty()) {
        double now = ImGui::GetTime();
        bool adjacent = (s_last_edit_line == s_sel.caret_line) &&
                        (std::abs(s_sel.caret_col - s_last_edit_col) <= 1);
        const auto& previous = s_undo.back();
        merge_previous = adjacent && (now - s_last_edit_time) < 1.2 &&
            previous.start_line == first_line && previous.before_lines.size() == 1 &&
            previous.after_lines.size() == 1;
    }
    auto& pending = current_document().pending_edit;
    pending.active = true;
    pending.start_line = first_line;
    pending.old_total_lines = line_count();
    pending.before_lines.assign(s_cache.lines.begin() + first_line,
        s_cache.lines.begin() + last_line + 1);
    pending.before_caret_line = s_sel.caret_line;
    pending.before_caret_col = s_sel.caret_col;
    pending.coalesce_kind = coalesce_kind;
    pending.merge_previous = merge_previous;
    s_undo_kind      = coalesce_kind;
    s_last_edit_time = ImGui::GetTime();
    s_last_edit_line = s_sel.caret_line;
    s_last_edit_col  = s_sel.caret_col;
}

void break_undo_coalescing() {
    s_undo_kind      = 0;
    s_last_edit_line = -1;
    s_last_edit_col  = -1;
}

void delete_selection() {
    if (!s_sel.has_selection()) return;
    int l0, c0, l1, c1;
    selection_ordered(l0, c0, l1, c1);
    l0 = clamp_line(l0);
    l1 = clamp_line(l1);
    c0 = clamp_col(l0, c0);
    c1 = clamp_col(l1, c1);
	push_undo_range(l0, l1);
    const std::size_t l0_idx = static_cast<std::size_t>(l0);
    const std::size_t l1_idx = static_cast<std::size_t>(l1);
    const std::size_t c0_idx = static_cast<std::size_t>(c0);
    const std::size_t c1_idx = static_cast<std::size_t>(c1);

    if (l0 == l1) {
        s_cache.lines[l0_idx].erase(c0_idx, static_cast<std::size_t>(c1 - c0));
    } else {
        std::string merged = s_cache.lines[l0_idx].substr(0, c0_idx) +
                             s_cache.lines[l1_idx].substr(c1_idx);
        s_cache.lines[l0_idx] = merged;
        s_cache.lines.erase(s_cache.lines.begin() + l0 + 1,
                            s_cache.lines.begin() + l1 + 1);
        s_cache.tokens.erase(s_cache.tokens.begin() + l0 + 1,
                             s_cache.tokens.begin() + l1 + 1);
		s_cache.line_hashes.erase(s_cache.line_hashes.begin() + l0 + 1,
			s_cache.line_hashes.begin() + l1 + 1);
    }
    s_sel.caret_line = s_sel.anchor_line = l0;
    s_sel.caret_col  = s_sel.anchor_col  = c0;
    s_sel.active = false;
    rebuild_buffer_from_lines();
}

void push_undo(int coalesce_kind = 0) {
    int first = s_sel.caret_line;
    int last = s_sel.caret_line;
    if (s_sel.has_selection()) {
        int c0 = 0;
        int c1 = 0;
        selection_ordered(first, c0, last, c1);
    }
    push_undo_range(first, last, coalesce_kind);
}

void delete_forward() {
    if (s_sel.has_selection()) {
        delete_selection();
        return;
    }
    if (s_sel.caret_col < line_length(s_sel.caret_line)) {
        push_undo();
        const int caret_line = clamp_line(s_sel.caret_line);
        auto& line = s_cache.lines[static_cast<std::size_t>(caret_line)];
        const int caret_col = clamp_col(caret_line, s_sel.caret_col);
        int delete_end = caret_col + 1;
        const int line_size = static_cast<int>(line.size());
        while (delete_end < line_size &&
               (static_cast<unsigned char>(line[static_cast<std::size_t>(delete_end)]) & 0xC0) == 0x80)
            ++delete_end;
        line.erase(static_cast<std::size_t>(caret_col),
            static_cast<std::size_t>(delete_end - caret_col));
        rebuild_buffer_from_lines();
        return;
    }
    if (s_sel.caret_line < line_count() - 1) {
        push_undo_range(s_sel.caret_line, s_sel.caret_line + 1);
        const auto caret = static_cast<std::size_t>(s_sel.caret_line);
        s_cache.lines[caret] += s_cache.lines[caret + 1];
        s_cache.lines.erase(s_cache.lines.begin() + static_cast<std::ptrdiff_t>(caret + 1));
        s_cache.tokens.erase(s_cache.tokens.begin() + static_cast<std::ptrdiff_t>(caret + 1));
		s_cache.line_hashes.erase(s_cache.line_hashes.begin() +
			static_cast<std::ptrdiff_t>(caret + 1));
        rebuild_buffer_from_lines();
    }
}

void insert_text_at_caret(const std::string& text, int coalesce_kind = 0) {
    if (s_sel.has_selection()) { delete_selection(); break_undo_coalescing(); }
    else push_undo(coalesce_kind);

    int line = clamp_line(s_sel.caret_line);
    int col  = clamp_col(line, s_sel.caret_col);
    const std::size_t line_idx = static_cast<std::size_t>(line);


    std::vector<std::string> ins_lines;
    {
        const char* p = text.c_str();
        const char* s = p;
        while (*p) {
            if (*p == '\n') {
                ins_lines.emplace_back(s, p);
                s = p + 1;
            }
            p++;
        }
        ins_lines.emplace_back(s, p);
    }

    if (ins_lines.size() == 1) {
        s_cache.lines[line_idx].insert(static_cast<std::size_t>(col), ins_lines.front());
        s_sel.caret_col = s_sel.anchor_col = col + static_cast<int>(ins_lines.front().size());
    } else {
        std::string tail = s_cache.lines[line_idx].substr(static_cast<std::size_t>(col));
        s_cache.lines[line_idx] = s_cache.lines[line_idx].substr(0, static_cast<std::size_t>(col)) + ins_lines.front();

        for (size_t i = 1; i < ins_lines.size() - 1; i++) {
            const std::size_t insertion_idx = line_idx + i;
            s_cache.lines.insert(s_cache.lines.begin() + static_cast<std::ptrdiff_t>(insertion_idx), ins_lines[i]);
            s_cache.tokens.insert(s_cache.tokens.begin() + static_cast<std::ptrdiff_t>(insertion_idx), {});
			s_cache.line_hashes.insert(s_cache.line_hashes.begin() +
				static_cast<std::ptrdiff_t>(insertion_idx), 0);
        }

        int last_idx = line + static_cast<int>(ins_lines.size()) - 1;
        std::string last_line = ins_lines.back() + tail;
        s_cache.lines.insert(s_cache.lines.begin() + static_cast<std::ptrdiff_t>(last_idx), last_line);
        s_cache.tokens.insert(s_cache.tokens.begin() + static_cast<std::ptrdiff_t>(last_idx), {});
		s_cache.line_hashes.insert(s_cache.line_hashes.begin() +
			static_cast<std::ptrdiff_t>(last_idx), 0);

        s_sel.caret_line = s_sel.anchor_line = last_idx;
        s_sel.caret_col  = s_sel.anchor_col  = static_cast<int>(ins_lines.back().size());
    }
    s_sel.active = false;
    rebuild_buffer_from_lines();
}


void clipboard_copy(const std::string& text) {
    if (text.empty()) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::editor::copy_to_clipboard(text);
#else
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (wlen <= 0) { CloseClipboard(); return; }
    size_t bytes = (static_cast<size_t>(wlen) + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hg) { CloseClipboard(); return; }
    wchar_t* dst = static_cast<wchar_t*>(GlobalLock(hg));
    if (!dst) { GlobalFree(hg); CloseClipboard(); return; }
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), dst, wlen);
    dst[wlen] = L'\0';
    GlobalUnlock(hg);
    if (!SetClipboardData(CF_UNICODETEXT, hg)) {
        GlobalFree(hg);
    }
    CloseClipboard();
#endif
}

std::string clipboard_paste() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return aida::preview::editor::paste_from_clipboard();
#else
    if (!OpenClipboard(nullptr)) return {};
    std::string result;
    HANDLE hd = GetClipboardData(CF_UNICODETEXT);
    if (hd) {
        const wchar_t* wp = static_cast<const wchar_t*>(GlobalLock(hd));
        if (wp) {
            int wlen = static_cast<int>(wcslen(wp));
            int u8 = WideCharToMultiByte(CP_UTF8, 0, wp, wlen, nullptr, 0, nullptr, nullptr);
            if (u8 > 0) {
                result.resize(static_cast<size_t>(u8));
                WideCharToMultiByte(CP_UTF8, 0, wp, wlen, result.data(), u8, nullptr, nullptr);
            }
            GlobalUnlock(hd);
        }
    } else {
        HANDLE ht = GetClipboardData(CF_TEXT);
        if (ht) {
            const char* p = static_cast<const char*>(GlobalLock(ht));
            if (p) result = p;
            GlobalUnlock(ht);
        }
    }
    CloseClipboard();
    if (!result.empty()) {
        std::string normalized;
        normalized.reserve(result.size());
        for (size_t i = 0; i < result.size(); i++) {
            if (result[i] == '\r') continue;
            normalized += result[i];
        }
        result = std::move(normalized);
    }
    return result;
#endif
}

void do_undo() {
    if (s_undo.empty()) return;
    break_undo_coalescing();
    code_editor_widget::undo_entry_t entry = std::move(s_undo.back());
    s_undo.pop_back();
    std::size_t removed_bytes = 0;
    std::size_t inserted_bytes = 0;
    for (const auto& line : entry.after_lines) removed_bytes += line.size();
    for (const auto& line : entry.before_lines) inserted_bytes += line.size();
    const std::int64_t byte_delta = static_cast<std::int64_t>(inserted_bytes) -
        static_cast<std::int64_t>(removed_bytes) +
        static_cast<std::int64_t>(entry.before_lines.size()) -
        static_cast<std::int64_t>(entry.after_lines.size());
    s_cache.content_bytes = static_cast<std::size_t>((std::max)(std::int64_t{0},
        static_cast<std::int64_t>(s_cache.content_bytes) + byte_delta));
    const auto begin = s_cache.lines.begin() + entry.start_line;
    s_cache.lines.erase(begin, begin + static_cast<std::ptrdiff_t>(entry.after_lines.size()));
    s_cache.lines.insert(s_cache.lines.begin() + entry.start_line,
        entry.before_lines.begin(), entry.before_lines.end());
	const auto token_begin = s_cache.tokens.begin() + entry.start_line;
	s_cache.tokens.erase(token_begin,
		token_begin + static_cast<std::ptrdiff_t>(entry.after_lines.size()));
	s_cache.tokens.insert(s_cache.tokens.begin() + entry.start_line,
		entry.before_lines.size(), std::vector<syntax::token_t>{});
	const auto hash_begin = s_cache.line_hashes.begin() + entry.start_line;
	s_cache.line_hashes.erase(hash_begin,
		hash_begin + static_cast<std::ptrdiff_t>(entry.after_lines.size()));
	s_cache.line_hashes.insert(s_cache.line_hashes.begin() + entry.start_line,
		entry.before_lines.size(), 0);
    s_sel.caret_line = s_sel.anchor_line = entry.before_caret_line;
    s_sel.caret_col  = s_sel.anchor_col  = entry.before_caret_col;
    s_sel.active = false;
    s_redo.push_back(std::move(entry));
    trim_history(s_redo);
    current_document().pending_edit = {};
    rebuild_buffer_from_lines(true);
}

void do_redo() {
    if (s_redo.empty()) return;
    break_undo_coalescing();
    code_editor_widget::undo_entry_t entry = std::move(s_redo.back());
    s_redo.pop_back();
    std::size_t removed_bytes = 0;
    std::size_t inserted_bytes = 0;
    for (const auto& line : entry.before_lines) removed_bytes += line.size();
    for (const auto& line : entry.after_lines) inserted_bytes += line.size();
    const std::int64_t byte_delta = static_cast<std::int64_t>(inserted_bytes) -
        static_cast<std::int64_t>(removed_bytes) +
        static_cast<std::int64_t>(entry.after_lines.size()) -
        static_cast<std::int64_t>(entry.before_lines.size());
    s_cache.content_bytes = static_cast<std::size_t>((std::max)(std::int64_t{0},
        static_cast<std::int64_t>(s_cache.content_bytes) + byte_delta));
    const auto begin = s_cache.lines.begin() + entry.start_line;
    s_cache.lines.erase(begin, begin + static_cast<std::ptrdiff_t>(entry.before_lines.size()));
    s_cache.lines.insert(s_cache.lines.begin() + entry.start_line,
        entry.after_lines.begin(), entry.after_lines.end());
	const auto token_begin = s_cache.tokens.begin() + entry.start_line;
	s_cache.tokens.erase(token_begin,
		token_begin + static_cast<std::ptrdiff_t>(entry.before_lines.size()));
	s_cache.tokens.insert(s_cache.tokens.begin() + entry.start_line,
		entry.after_lines.size(), std::vector<syntax::token_t>{});
	const auto hash_begin = s_cache.line_hashes.begin() + entry.start_line;
	s_cache.line_hashes.erase(hash_begin,
		hash_begin + static_cast<std::ptrdiff_t>(entry.before_lines.size()));
	s_cache.line_hashes.insert(s_cache.line_hashes.begin() + entry.start_line,
		entry.after_lines.size(), 0);
    s_sel.caret_line = s_sel.anchor_line = entry.after_caret_line;
    s_sel.caret_col  = s_sel.anchor_col  = entry.after_caret_col;
    s_sel.active = false;
    s_undo.push_back(std::move(entry));
    trim_history(s_undo);
    current_document().pending_edit = {};
    rebuild_buffer_from_lines(true);
}

float s_view_char_w   = 8.f;
float s_view_text_w   = 0.f;
float s_max_scroll_x  = 0.f;

void ensure_caret_visible(float vis_h, float line_h) {
    float caret_y = static_cast<float>(s_sel.caret_line) * line_h;
    if (caret_y < s_scroll_y)
        s_target_scroll_y = caret_y;
    else if (caret_y + line_h > s_scroll_y + vis_h)
        s_target_scroll_y = caret_y - vis_h + line_h * 2.f;

    if (editor_preferences::word_wrap) {
        s_scroll_x = 0.f;
        return;
    }
    if (s_view_text_w <= 0.f) return;
    float caret_x = static_cast<float>(s_sel.caret_col) * s_view_char_w;
    float pad = s_view_char_w * 4.f;
    if (caret_x - pad < s_scroll_x)
        s_scroll_x = std::max(0.f, caret_x - pad);
    else if (caret_x + pad > s_scroll_x + s_view_text_w)
        s_scroll_x = caret_x + pad - s_view_text_w;
    if (s_scroll_x > s_max_scroll_x) s_scroll_x = s_max_scroll_x;
    if (s_scroll_x < 0.f) s_scroll_x = 0.f;
}


void screen_to_linecol(float sx, float sy, float origin_x, float origin_y,
                        float gutter_w, float line_h, float char_w,
                        int& out_line, int& out_col) {
    float rel_y = sy - origin_y + s_scroll_y;
    float rel_x = sx - origin_x - gutter_w - 4.f + s_scroll_x;
    out_line = clamp_line(static_cast<int>(rel_y / line_h));
    out_col  = std::max(0, static_cast<int>((rel_x + char_w * 0.5f) / char_w));
    out_col  = clamp_col(out_line, out_col);
    const std::string& ln = line_at(out_line);
    while (out_col > 0 && out_col < static_cast<int>(ln.size()) &&
           (static_cast<unsigned char>(ln[static_cast<std::size_t>(out_col)]) & 0xC0) == 0x80)
        out_col--;
}

bool is_word_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}


void word_bounds(int line, int col, int& start, int& end) {
    auto& ln = line_at(line);
    start = std::clamp(col, 0, static_cast<int>(ln.size()));
    end   = start;
    while (start > 0 && is_word_char(ln[static_cast<std::size_t>(start - 1)])) start--;
    while (end < static_cast<int>(ln.size()) && is_word_char(ln[static_cast<std::size_t>(end)])) end++;
}

void selected_line_range(int& first, int& last) {
    if (!s_sel.has_selection()) {
        first = last = clamp_line(s_sel.caret_line);
        return;
    }
    int c0 = 0;
    int c1 = 0;
    selection_ordered(first, c0, last, c1);
    first = clamp_line(first);
    last = clamp_line(last);
    if (c1 == 0 && last > first) --last;
}

bool perform_document_action(code_editor_widget::document_action_t action) {
    using action_t = code_editor_widget::document_action_t;
    if (!current_document().active || line_count() == 0) return false;
    int first = 0;
    int last = 0;
    selected_line_range(first, last);
    switch (action) {
        case action_t::select_word: {
            int start = 0;
            int end = 0;
            word_bounds(s_sel.caret_line, s_sel.caret_col, start, end);
            s_sel.anchor_line = s_sel.caret_line;
            s_sel.anchor_col = start;
            s_sel.caret_col = end;
            s_sel.active = end > start;
            return true;
        }
        case action_t::select_line:
            s_sel.anchor_line = first;
            s_sel.anchor_col = 0;
            s_sel.caret_line = last;
            s_sel.caret_col = line_length(last);
            s_sel.active = true;
            return true;
        case action_t::copy_line: {
            std::string text;
            for (int line = first; line <= last; ++line) {
                if (!text.empty()) text.push_back('\n');
                text += line_at(line);
            }
            clipboard_copy(text);
            return true;
        }
        case action_t::copy_path:
            if (current_document().filepath.empty()) return false;
            clipboard_copy(current_document().filepath);
            return true;
        case action_t::duplicate_line: {
            push_undo();
            const auto begin = s_cache.lines.begin() + first;
            const auto end = s_cache.lines.begin() + last + 1;
            std::vector<std::string> duplicate(begin, end);
            s_cache.lines.insert(s_cache.lines.begin() + last + 1, duplicate.begin(), duplicate.end());
            const int count = last - first + 1;
            s_cache.tokens.insert(s_cache.tokens.begin() + last + 1, static_cast<std::size_t>(count), std::vector<syntax::token_t>{});
            s_cache.line_hashes.insert(s_cache.line_hashes.begin() + last + 1, static_cast<std::size_t>(count), std::uint64_t{0});
            s_sel.anchor_line = s_sel.caret_line = last + count;
            s_sel.anchor_col = s_sel.caret_col = clamp_col(s_sel.caret_line, s_sel.caret_col);
            s_sel.active = false;
            rebuild_buffer_from_lines();
            return true;
        }
        case action_t::delete_line: {
            push_undo();
            if (first == 0 && last == line_count() - 1) {
                s_cache.lines.assign(1, "");
                s_cache.tokens.assign(1, {});
                s_cache.line_hashes.assign(1, 0);
            } else {
                s_cache.lines.erase(s_cache.lines.begin() + first, s_cache.lines.begin() + last + 1);
                s_cache.tokens.erase(s_cache.tokens.begin() + first, s_cache.tokens.begin() + last + 1);
                s_cache.line_hashes.erase(s_cache.line_hashes.begin() + first, s_cache.line_hashes.begin() + last + 1);
            }
            s_sel.anchor_line = s_sel.caret_line = std::min(first, line_count() - 1);
            s_sel.anchor_col = s_sel.caret_col = 0;
            s_sel.active = false;
            rebuild_buffer_from_lines();
            return true;
        }
        case action_t::move_line_up:
            if (first <= 0) return false;
            push_undo_range(first - 1, last);
            std::rotate(s_cache.lines.begin() + first - 1, s_cache.lines.begin() + first, s_cache.lines.begin() + last + 1);
            std::rotate(s_cache.tokens.begin() + first - 1, s_cache.tokens.begin() + first, s_cache.tokens.begin() + last + 1);
            std::rotate(s_cache.line_hashes.begin() + first - 1, s_cache.line_hashes.begin() + first, s_cache.line_hashes.begin() + last + 1);
            --s_sel.anchor_line;
            --s_sel.caret_line;
            rebuild_buffer_from_lines();
            return true;
        case action_t::move_line_down:
            if (last >= line_count() - 1) return false;
            push_undo_range(first, last + 1);
            std::rotate(s_cache.lines.begin() + first, s_cache.lines.begin() + last + 1, s_cache.lines.begin() + last + 2);
            std::rotate(s_cache.tokens.begin() + first, s_cache.tokens.begin() + last + 1, s_cache.tokens.begin() + last + 2);
            std::rotate(s_cache.line_hashes.begin() + first, s_cache.line_hashes.begin() + last + 1, s_cache.line_hashes.begin() + last + 2);
            ++s_sel.anchor_line;
            ++s_sel.caret_line;
            rebuild_buffer_from_lines();
            return true;
        case action_t::toggle_line_comment: {
            if (!s_lang_set || !s_lang.line_comment || s_lang.line_comment[0] == '\0') return false;
            const std::string marker = s_lang.line_comment;
            bool remove = true;
            for (int line = first; line <= last; ++line) {
                const auto& text = s_cache.lines[static_cast<std::size_t>(line)];
                const std::size_t nonspace = text.find_first_not_of(" \t");
                if (nonspace == std::string::npos || text.compare(nonspace, marker.size(), marker) != 0) {
                    remove = false;
                    break;
                }
            }
            push_undo();
            for (int line = first; line <= last; ++line) {
                auto& text = s_cache.lines[static_cast<std::size_t>(line)];
                const std::size_t nonspace = text.find_first_not_of(" \t");
                if (nonspace == std::string::npos) continue;
                if (remove) {
                    text.erase(nonspace, marker.size());
                    if (nonspace < text.size() && text[nonspace] == ' ') text.erase(nonspace, 1);
                } else {
                    text.insert(nonspace, marker + " ");
                }
            }
            rebuild_buffer_from_lines();
            return true;
        }
        case action_t::trim_trailing_whitespace: {
            bool changed = false;
            for (const auto& text : s_cache.lines)
                if (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
                    changed = true;
                    break;
                }
            if (!changed) return false;
            push_undo_range(0, line_count() - 1);
            for (auto& text : s_cache.lines) {
                const std::size_t end = text.find_last_not_of(" \t");
                if (end == std::string::npos) text.clear();
                else text.erase(end + 1);
            }
            s_sel.caret_col = s_sel.anchor_col = clamp_col(s_sel.caret_line, s_sel.caret_col);
            rebuild_buffer_from_lines();
            return true;
        }
    }
    return false;
}


void find_all_matches() {
    s_find.match_positions.clear();
    s_find.total_matches = 0;
    s_find.current_match = -1;
    if (s_find.find_buf[0] == '\0') return;

    std::string needle = s_find.find_buf;
    if (needle.empty()) return;

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (current_document().mapped_source) {
        auto target = document_handle(s_active_document_id);
        if (target->find_cancel)
            target->find_cancel->store(true, std::memory_order_release);
		if (target->find_task_id != 0)
			aida::infra::executor::cancel(target->find_task_id);
		auto cancelled = std::make_shared<std::atomic<bool>>(false);
		auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
		target->find_cancel = cancelled;
		target->find_dispatch_failed = dispatch_failed;
        target->find_loading = true;
        target->find_error.clear();
		const std::uint64_t generation = ++target->find_generation;
		const std::string task_key = "editor.search." +
			std::to_string(s_active_document_id) + "." + std::to_string(generation);
        const auto source = target->mapped_source;
        const bool case_sensitive = s_find.case_sensitive;
        const bool whole_word = s_find.whole_word;
        const bool use_regex = s_find.use_regex;
        const std::weak_ptr<document_runtime_t> weak_target = target;
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "code_editor";
        submission.label = "code_editor.streamed_search";
        submission.thread_class = "memory_mapped_text_search";
        submission.domain = aida::infra::executor::domain_t::feature_worker;
        submission.priority = 3;
        submission.generation = generation;
        submission.ui_access_policy = "immutable_snapshots_only";
        submission.shutdown_policy = "cancel";
        submission.cancel_hook = [cancelled] { cancelled->store(true, std::memory_order_release); };
		submission.body = [source, weak_target, cancelled, dispatch_failed, generation, task_key, needle = std::move(needle),
                case_sensitive, whole_word, use_regex]() mutable {
            std::vector<code_editor_widget::find_match_t> matches;
            matches.reserve(4096);
            std::string error;
            constexpr std::size_t k_match_limit = 250000;
			try {
            std::optional<std::regex> expression;
            if (use_regex) {
                try {
                    auto flags = std::regex_constants::ECMAScript;
                    if (!case_sensitive) flags |= std::regex_constants::icase;
                    expression.emplace(needle, flags);
                } catch (const std::regex_error& failure) {
                    error = "Invalid regular expression: " + std::string(failure.what());
                }
            }
            auto is_word = [](char character) {
                const unsigned char value = static_cast<unsigned char>(character);
                return std::isalnum(value) != 0 || character == '_';
            };
            for (std::size_t line = 0; error.empty() && line < source->line_offsets.size(); ++line) {
                if ((line & 0x3FFU) == 0U && cancelled->load(std::memory_order_acquire)) break;
                const std::uint64_t start = source->line_offsets[line];
                std::uint64_t end = line + 1U < source->line_offsets.size()
                    ? source->line_offsets[line + 1U] - 1U : source->byte_length;
                if (end > start && source->view[end - 1U] == '\r') --end;
                const std::size_t length = static_cast<std::size_t>(end - start);
                if (use_regex) {
                    if (length > 4U * 1024U * 1024U) {
                        error = "Regex search cannot process a single mapped line larger than 4 MiB; use literal search or Hex View.";
                        break;
                    }
                    const std::string text(source->view + start, source->view + end);
                    for (std::sregex_iterator found(text.begin(), text.end(), *expression), finish;
                            found != finish; ++found) {
                        const int column = static_cast<int>(found->position());
                        const int count = static_cast<int>(found->length());
                        const bool left_ok = !whole_word || column == 0 || !is_word(text[static_cast<std::size_t>(column - 1)]);
                        const bool right_ok = !whole_word || column + count >= static_cast<int>(text.size()) ||
                            !is_word(text[static_cast<std::size_t>(column + count)]);
                        if (left_ok && right_ok)
                            matches.push_back({static_cast<int>(line), column, count});
                        if (matches.size() >= k_match_limit) break;
                    }
                } else if (needle.size() <= length) {
                    for (std::size_t column = 0; column + needle.size() <= length; ++column) {
                        bool equal = true;
                        for (std::size_t offset = 0; offset < needle.size(); ++offset) {
                            char left = source->view[start + column + offset];
                            char right = needle[offset];
                            if (!case_sensitive) {
                                left = static_cast<char>(std::tolower(static_cast<unsigned char>(left)));
                                right = static_cast<char>(std::tolower(static_cast<unsigned char>(right)));
                            }
                            if (left != right) { equal = false; break; }
                        }
                        if (!equal) continue;
                        const bool left_ok = !whole_word || column == 0 ||
                            !is_word(source->view[start + column - 1U]);
                        const bool right_ok = !whole_word || column + needle.size() == length ||
                            !is_word(source->view[start + column + needle.size()]);
                        if (left_ok && right_ok)
                            matches.push_back({static_cast<int>(line), static_cast<int>(column),
                                static_cast<int>(needle.size())});
                        if (matches.size() >= k_match_limit) break;
                    }
                }
                if (matches.size() >= k_match_limit) {
                    error = "Search was truncated at 250,000 matches; refine the query to navigate deterministically.";
                    break;
                }
            }
			} catch (const std::bad_alloc&) {
				matches.clear();
				error = "Mapped search exhausted its bounded allocation budget; refine the query or use Hex View.";
			}
            if (cancelled->load(std::memory_order_acquire) && error.empty())
                error = "Search was cancelled.";
            aida::ui_thread::post_options_t options;
            options.subsystem = "code_editor";
            options.label = "streamed_search_result";
            options.phase = "worker_result";
            options.owner = "code_editor.streamed_search";
            options.priority = aida::ui_thread::priority_t::critical;
			const bool posted = aida::ui_thread::post(
				[weak_target, generation, task_key, matches = std::move(matches), error = std::move(error)]() mutable {
                    const auto target_state = weak_target.lock();
                    if (!target_state || target_state->find_generation != generation) return;
					target_state->find_loading = false;
					target_state->find_dispatch_failed.reset();
					target_state->find_task_id = 0;
					target_state->find_cancel.reset();
                    target_state->find_error = std::move(error);
					const auto task_state = target_state->find_error.empty()
						? aida::ui::task_center::task_state_t::completed
						: target_state->find_error.find("cancelled") != std::string::npos
							? aida::ui::task_center::task_state_t::cancelled
							: aida::ui::task_center::task_state_t::failed;
					static_cast<void>(aida::ui::task_center::update_task(task_key,
						task_state,
						1.f, target_state->find_error.empty() ? "Search complete" : "Search failed",
						target_state->find_error.empty()
							? "Mapped text search completed." : target_state->find_error));
                    target_state->find.match_positions = std::move(matches);
                    target_state->find.total_matches =
                        static_cast<int>(target_state->find.match_positions.size());
                    target_state->find.current_match = target_state->find.total_matches == 0 ? -1 : 0;
				}, std::move(options)) == aida::ui_thread::enqueue_result_t::accepted;
			if (!posted)
				dispatch_failed->store(true, std::memory_order_release);
        };
        const auto submitted = aida::infra::executor::submit(std::move(submission));
        if (!submitted.submitted) {
			target->find_loading = false;
			target->find_dispatch_failed.reset();
			target->find_cancel.reset();
            target->find_error = "The mapped-search worker could not be scheduled: " + submitted.reject_reason;
            return;
        }
		target->find_task_id = submitted.task_id;
        aida::ui::task_center::task_registration_t registration;
		registration.id = task_key;
        registration.source = "code_editor";
        registration.owner = "Code Editor";
        registration.owner_view = "document.code";
        registration.owner_action = "edit.find";
        registration.target = current_document().filepath;
        registration.label = "Search mapped text";
        registration.stage = "Scanning memory-mapped content";
        registration.affected_entity = std::to_string(s_active_document_id);
        registration.cancellation_is_safe = true;
		registration.callbacks.focus = [document_id = s_active_document_id]() {
			const int target = file_tabs::find_document(document_id);
			if (file_tabs::is_valid_tab_index(target)) file_tabs::switch_to(target);
		};
		if (!aida::ui::task_center::register_executor_job(
				submitted.task_id, std::move(registration))) {
			aida::infra::executor::cancel(submitted.task_id);
			cancelled->store(true, std::memory_order_release);
			++target->find_generation;
			target->find_loading = false;
			target->find_dispatch_failed.reset();
			target->find_task_id = 0;
			target->find_cancel.reset();
			target->find_error = "Task Center could not own mapped search; the operation was cancelled.";
		}
        return;
    }
#endif

    if (s_find.use_regex) {
        try {
            auto flags = std::regex_constants::ECMAScript;
            if (!s_find.case_sensitive)
                flags |= std::regex_constants::icase;
            std::regex re(needle, flags);
            for (std::size_t i = 0; i < s_cache.lines.size(); i++) {
                const std::string& line = s_cache.lines[i];
                auto it  = std::sregex_iterator(line.begin(), line.end(), re);
                auto end = std::sregex_iterator();
                for (; it != end; ++it) {
                    int match_len = static_cast<int>(it->length());
                    if (match_len <= 0) continue;
                    int match_pos = static_cast<int>(it->position());
                    if (s_find.whole_word) {
                        const std::size_t match_pos_idx = static_cast<std::size_t>(match_pos);
                        const std::size_t match_end_idx = static_cast<std::size_t>(match_pos + match_len);
                        bool left_ok  = (match_pos == 0) || (!isalnum(static_cast<unsigned char>(line[match_pos_idx - 1])) && line[match_pos_idx - 1] != '_');
                        bool right_ok = (match_end_idx >= line.size()) || (!isalnum(static_cast<unsigned char>(line[match_end_idx])) && line[match_end_idx] != '_');
                        if (!left_ok || !right_ok) continue;
                    }
                    code_editor_widget::find_match_t m;
                    m.line = static_cast<int>(i);
                    m.col = match_pos;
                    m.length = match_len;
                    s_find.match_positions.push_back(m);
                }
            }
        } catch (const std::regex_error& e) {
            s_last_error = std::string("code_editor: invalid regex in live highlight: ") + e.what();
            s_find.match_positions.clear();
        } catch (...) {
            s_last_error = "code_editor: invalid regex in live highlight";
            s_find.match_positions.clear();
        }
    } else {
        if (!s_find.case_sensitive) {
            for (auto& c : needle) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        }
        int needle_len = static_cast<int>(needle.size());

        for (std::size_t i = 0; i < s_cache.lines.size(); i++) {
            std::string haystack = s_cache.lines[i];
            if (!s_find.case_sensitive) {
                for (auto& c : haystack) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            }
            size_t pos = 0;
            while ((pos = haystack.find(needle, pos)) != std::string::npos) {
                if (s_find.whole_word) {
                    bool left_ok  = (pos == 0) || (!isalnum(static_cast<unsigned char>(haystack[pos - 1])) && haystack[pos - 1] != '_');
                    const std::size_t match_end = pos + static_cast<std::size_t>(needle_len);
                    bool right_ok = (match_end >= haystack.size()) || (!isalnum(static_cast<unsigned char>(haystack[match_end])) && haystack[match_end] != '_');
                    if (!left_ok || !right_ok) { pos += 1; continue; }
                }
                code_editor_widget::find_match_t m;
                m.line = static_cast<int>(i);
                m.col = static_cast<int>(pos);
                m.length = needle_len;
                s_find.match_positions.push_back(m);
                pos += static_cast<std::size_t>(needle_len);
            }
        }
    }
    s_find.total_matches = static_cast<int>(s_find.match_positions.size());
}

void find_next() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match + 1) % static_cast<int>(s_find.match_positions.size());
    const auto& m = s_find.match_positions[static_cast<std::size_t>(s_find.current_match)];
    s_sel.caret_line = s_sel.anchor_line = m.line;
    s_sel.anchor_col = m.col;
    s_sel.caret_col  = m.col + m.length;
    s_sel.active = true;
}

void find_prev() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match - 1 + static_cast<int>(s_find.match_positions.size()))
                            % static_cast<int>(s_find.match_positions.size());
    const auto& m = s_find.match_positions[static_cast<std::size_t>(s_find.current_match)];
    s_sel.caret_line = s_sel.anchor_line = m.line;
    s_sel.anchor_col = m.col;
    s_sel.caret_col  = m.col + m.length;
    s_sel.active = true;
}

std::string compute_replacement(const std::string& line_text, const code_editor_widget::find_match_t& m) {
    std::string replacement = s_find.replace_buf;
    if (!s_find.use_regex) return replacement;
    try {
        auto flags = std::regex_constants::ECMAScript;
        if (!s_find.case_sensitive)
            flags |= std::regex_constants::icase;
        std::regex re(s_find.find_buf, flags);
        const int col = std::clamp(m.col, 0, static_cast<int>(line_text.size()));
        const int length = std::clamp(m.length, 0, static_cast<int>(line_text.size()) - col);
        std::string slice = line_text.substr(static_cast<std::size_t>(col), static_cast<std::size_t>(length));
        return std::regex_replace(slice, re, replacement,
            std::regex_constants::format_first_only);
    } catch (...) {
        return replacement;
    }
}

void replace_current() {
    if (s_find.current_match < 0 || s_find.current_match >= static_cast<int>(s_find.match_positions.size()))
        return;
    const auto& m = s_find.match_positions[static_cast<std::size_t>(s_find.current_match)];
    if (m.line < 0 || m.line >= static_cast<int>(s_cache.lines.size())) return;
    push_undo_range(m.line, m.line);
    std::string& ln = s_cache.lines[static_cast<std::size_t>(m.line)];
    int col_clamped = std::clamp(m.col, 0, static_cast<int>(ln.size()));
    int len_clamped = std::clamp(m.length, 0, static_cast<int>(ln.size()) - col_clamped);
    std::string replacement = compute_replacement(ln, m);
    ln.erase(static_cast<std::size_t>(col_clamped), static_cast<std::size_t>(len_clamped));
    ln.insert(static_cast<std::size_t>(col_clamped), replacement);
    s_sel.caret_line = s_sel.anchor_line = m.line;
    s_sel.anchor_col = col_clamped;
    s_sel.caret_col  = col_clamped + static_cast<int>(replacement.size());
    s_sel.active = true;
    rebuild_buffer_from_lines();
    find_all_matches();
}

void replace_all() {
    if (s_find.match_positions.empty()) return;
    int first_line = s_find.match_positions.front().line;
    int last_line = first_line;
    for (const auto& match : s_find.match_positions) {
        first_line = (std::min)(first_line, match.line);
        last_line = (std::max)(last_line, match.line);
    }
    push_undo_range(first_line, last_line);
    for (int i = static_cast<int>(s_find.match_positions.size()) - 1; i >= 0; i--) {
        const auto& m = s_find.match_positions[static_cast<std::size_t>(i)];
        if (m.line < 0 || m.line >= static_cast<int>(s_cache.lines.size())) continue;
        std::string& ln = s_cache.lines[static_cast<std::size_t>(m.line)];
        int col_clamped = std::clamp(m.col, 0, static_cast<int>(ln.size()));
        int len_clamped = std::clamp(m.length, 0, static_cast<int>(ln.size()) - col_clamped);
        std::string replacement = compute_replacement(ln, m);
        ln.erase(static_cast<std::size_t>(col_clamped), static_cast<std::size_t>(len_clamped));
        ln.insert(static_cast<std::size_t>(col_clamped), replacement);
    }
    rebuild_buffer_from_lines();
    find_all_matches();
}


char matching_close_bracket(char open) {
    switch (open) {
        case '(': return ')';
        case '[': return ']';
        case '{': return '}';
        case '"': return '"';
        case '\'': return '\'';
        default:  return 0;
    }
}

bool is_open_bracket(char c) {
    return c == '(' || c == '[' || c == '{';
}

bool is_close_bracket(char c) {
    return c == ')' || c == ']' || c == '}';
}

bool find_matching_bracket(int line, int col, int& out_line, int& out_col, char& out_ch) {
    const std::string& cur = line_at(line);
    char here = (col >= 0 && col < static_cast<int>(cur.size())) ? cur[static_cast<std::size_t>(col)] : 0;
    char before = (col > 0 && col - 1 < static_cast<int>(cur.size())) ? cur[static_cast<std::size_t>(col - 1)] : 0;

    int probe_line = line;
    int probe_col  = col;
    char open_ch   = 0;
    bool forward   = true;

    if (is_open_bracket(here) || is_close_bracket(here)) {
        open_ch  = here;
        forward  = is_open_bracket(here);
    } else if (is_open_bracket(before) || is_close_bracket(before)) {
        open_ch  = before;
        probe_col = col - 1;
        forward  = is_open_bracket(before);
    } else {
        return false;
    }

    char want_open  = forward ? open_ch : 0;
    char want_close = 0;
    if (forward) {
        want_close = matching_close_bracket(open_ch);
    } else {
        if (open_ch == ')') { want_open = '('; want_close = ')'; }
        else if (open_ch == ']') { want_open = '['; want_close = ']'; }
        else if (open_ch == '}') { want_open = '{'; want_close = '}'; }
    }
    if (want_open == 0 || want_close == 0) return false;

    int depth = 0;
    if (forward) {
        for (int li = probe_line; li < line_count(); ++li) {
            const std::string& ln = line_at(li);
            int start = (li == probe_line) ? probe_col : 0;
            for (int ci = start; ci < static_cast<int>(ln.size()); ++ci) {
                char c = ln[static_cast<std::size_t>(ci)];
                if (c == want_open) depth++;
                else if (c == want_close) {
                    depth--;
                    if (depth == 0) {
                        out_line = li; out_col = ci; out_ch = c;
                        return true;
                    }
                }
            }
        }
    } else {
        for (int li = probe_line; li >= 0; --li) {
            const std::string& ln = line_at(li);
            int start = (li == probe_line) ? probe_col : static_cast<int>(ln.size()) - 1;
            for (int ci = start; ci >= 0; --ci) {
                char c = ln[static_cast<std::size_t>(ci)];
                if (c == want_close) depth++;
                else if (c == want_open) {
                    depth--;
                    if (depth == 0) {
                        out_line = li; out_col = ci; out_ch = c;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}


void collect_buffer_identifiers(std::vector<std::string>& out, int around_line) {
    out.clear();
    std::unordered_set<std::string> seen;
    int total = line_count();
    int lo = std::max(0, around_line - 1500);
    int hi = std::min(total, around_line + 1500);
    for (int i = lo; i < hi; ++i) {
        const std::string& ln = s_cache.lines[static_cast<std::size_t>(i)];
        size_t j = 0;
        while (j < ln.size()) {
            unsigned char c = static_cast<unsigned char>(ln[j]);
            bool starts = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
            if (!starts) { j++; continue; }
            size_t s = j;
            while (j < ln.size()) {
                unsigned char d = static_cast<unsigned char>(ln[j]);
                bool cont = (d >= 'a' && d <= 'z') || (d >= 'A' && d <= 'Z') ||
                            (d >= '0' && d <= '9') || d == '_';
                if (!cont) break;
                j++;
            }
            if (j - s >= 3 && j - s <= 80) {
                std::string word = ln.substr(s, j - s);
                if (seen.insert(word).second)
                    out.push_back(std::move(word));
            }
        }
    }
}

bool fuzzy_subsequence_score(const std::string& lower_pat, const std::string& lower_cand, int& score) {
    if (lower_pat.empty()) { score = 0; return true; }
    size_t pi = 0;
    int s = 0;
    int prev_match = -2;
    int consecutive = 0;
    for (size_t ci = 0; ci < lower_cand.size() && pi < lower_pat.size(); ++ci) {
        if (lower_cand[ci] == lower_pat[pi]) {
            if (static_cast<int>(ci) == prev_match + 1) {
                consecutive++;
                s += 6 + consecutive * 2;
            } else {
                consecutive = 0;
                s += 2;
            }
            if (ci == 0) s += 12;
            else {
                char p = lower_cand[ci - 1];
                if (p == '_' || p == ':' || p == '.') s += 8;
            }
            prev_match = static_cast<int>(ci);
            pi++;
        }
    }
    if (pi != lower_pat.size()) return false;
    if (lower_cand.size() == lower_pat.size()) s += 4;
    s -= static_cast<int>(lower_cand.size()) / 4;
    score = s;
    return true;
}

void rebuild_autocomplete(const std::string& partial, int caret_line) {
    autocomplete::matches.clear();
    autocomplete::selected = 0;
    if (partial.size() < 2) {
        autocomplete::popup_visible = false;
        return;
    }

    std::string lower_pat = partial;
    for (auto& c : lower_pat) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

    struct cand_t { std::string text; int score; };
    std::vector<cand_t> cands;
    std::unordered_set<std::string> seen;
    seen.insert(partial);

    for (const auto& kw : autocomplete::keywords()) {
        if (kw == partial) continue;
        std::string lk = kw;
        for (auto& c : lk) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        int sc = 0;
        if (fuzzy_subsequence_score(lower_pat, lk, sc)) {
            if (seen.insert(kw).second)
                cands.push_back({ kw, sc + 6 });
        }
    }

    std::vector<std::string> idents;
    collect_buffer_identifiers(idents, caret_line);
    for (const auto& id : idents) {
        if (id == partial) continue;
        std::string li = id;
        for (auto& c : li) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        int sc = 0;
        if (fuzzy_subsequence_score(lower_pat, li, sc)) {
            if (seen.insert(id).second)
                cands.push_back({ id, sc });
        }
    }

    std::stable_sort(cands.begin(), cands.end(),
        [](const cand_t& a, const cand_t& b) { return a.score > b.score; });

    int cap = static_cast<int>(cands.size());
    if (cap > 12) cap = 12;
    for (int i = 0; i < cap; ++i)
        autocomplete::matches.push_back(cands[static_cast<std::size_t>(i)].text);

    autocomplete::partial      = partial;
    autocomplete::popup_visible = !autocomplete::matches.empty();
    autocomplete::cursor_line  = caret_line;
}


std::vector<std::string> split_to_lines(std::string_view text) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n') {
            size_t end = i;
            if (end > start && text[end - 1] == '\r') end--;
            out.emplace_back(text.substr(start, end - start));
            start = i + 1;
        }
    }
    size_t end = text.size();
    if (end > start && text[end - 1] == '\r') end--;
    out.emplace_back(text.substr(start, end - start));
    return out;
}


void compute_lcs_diff(const std::vector<std::string>& a,
                      const std::vector<std::string>& b,
                      code_editor_widget::pending_diff_t& diff)
{
    const int n = static_cast<int>(a.size());
    const int m = static_cast<int>(b.size());
    const auto& a_at = [&a](int index) -> const std::string& {
        return a[static_cast<std::size_t>(index)];
    };
    const auto& b_at = [&b](int index) -> const std::string& {
        return b[static_cast<std::size_t>(index)];
    };

    int pre = 0;
    while (pre < n && pre < m && a_at(pre) == b_at(pre)) pre++;
    int suf = 0;
    while (suf < (n - pre) && suf < (m - pre) &&
           a_at(n - 1 - suf) == b_at(m - 1 - suf)) suf++;

    const int an = n - pre - suf;
    const int bm = m - pre - suf;

    struct op_t { int kind; std::string text; int old_line; int new_line; };
    std::vector<op_t> ops;

    for (int i = 0; i < pre; ++i)
        ops.push_back({ 0, a_at(i), i, i });

    const long long dp_cells =
        static_cast<long long>(an + 1) * static_cast<long long>(bm + 1);
    const long long dp_cap = 6000000;

    if (dp_cells > dp_cap) {
        for (int i = 0; i < an; ++i)
            ops.push_back({ 2, a_at(pre + i), pre + i, -1 });
        for (int j = 0; j < bm; ++j)
            ops.push_back({ 1, b_at(pre + j), -1, pre + j });
    } else {
        std::vector<std::vector<int>> dp(static_cast<std::size_t>(an + 1),
            std::vector<int>(static_cast<std::size_t>(bm + 1), 0));
        for (int i = an - 1; i >= 0; --i) {
            for (int j = bm - 1; j >= 0; --j) {
                const std::size_t i_idx = static_cast<std::size_t>(i);
                const std::size_t j_idx = static_cast<std::size_t>(j);
                if (a_at(pre + i) == b_at(pre + j))
                    dp[i_idx][j_idx] = dp[static_cast<std::size_t>(i + 1)][static_cast<std::size_t>(j + 1)] + 1;
                else
                    dp[i_idx][j_idx] = std::max(dp[static_cast<std::size_t>(i + 1)][j_idx],
                        dp[i_idx][static_cast<std::size_t>(j + 1)]);
            }
        }

        int i = 0, j = 0;
        while (i < an && j < bm) {
            if (a_at(pre + i) == b_at(pre + j)) {
                ops.push_back({ 0, a_at(pre + i), pre + i, pre + j });
                i++; j++;
            } else if (dp[static_cast<std::size_t>(i + 1)][static_cast<std::size_t>(j)] >=
                       dp[static_cast<std::size_t>(i)][static_cast<std::size_t>(j + 1)]) {
                ops.push_back({ 2, a_at(pre + i), pre + i, -1 });
                i++;
            } else {
                ops.push_back({ 1, b_at(pre + j), -1, pre + j });
                j++;
            }
        }
        while (i < an) { ops.push_back({ 2, a_at(pre + i), pre + i, -1 }); i++; }
        while (j < bm) { ops.push_back({ 1, b_at(pre + j), -1, pre + j }); j++; }
    }

    for (int i = 0; i < suf; ++i)
        ops.push_back({ 0, a_at(n - suf + i), n - suf + i, m - suf + i });

    diff.hunks.clear();
    diff.total_added   = 0;
    diff.total_removed = 0;

    size_t idx = 0;
    while (idx < ops.size()) {
        if (ops[idx].kind == 0) { idx++; continue; }

        code_editor_widget::diff_hunk_t hunk;
        hunk.state = code_editor_widget::diff_hunk_state_t::pending;
        size_t hs = idx;
        int ctx_run = 0;
        size_t he = idx;
        while (he < ops.size()) {
            if (ops[he].kind == 0) {
                ctx_run++;
                if (ctx_run > 2) break;
            } else {
                ctx_run = 0;
            }
            he++;
        }
        while (he > hs && ops[he - 1].kind == 0) he--;

        int first_old = -1, first_new = -1, last_old = -1, last_new = -1;
        for (size_t k = hs; k < he; ++k) {
            const op_t& o = ops[k];
            code_editor_widget::diff_line_t dl;
            dl.text     = o.text;
            dl.old_line = o.old_line;
            dl.new_line = o.new_line;
            if (o.kind == 0)      dl.kind = code_editor_widget::diff_line_kind_t::context;
            else if (o.kind == 1) { dl.kind = code_editor_widget::diff_line_kind_t::added;   hunk.added++; }
            else                  { dl.kind = code_editor_widget::diff_line_kind_t::removed; hunk.removed++; }

            if (o.old_line >= 0) {
                if (first_old < 0) first_old = o.old_line;
                last_old = o.old_line;
            }
            if (o.new_line >= 0) {
                if (first_new < 0) first_new = o.new_line;
                last_new = o.new_line;
            }
            hunk.lines.push_back(std::move(dl));
        }

        hunk.old_start = first_old < 0 ? 0 : first_old;
        hunk.new_start = first_new < 0 ? 0 : first_new;
        hunk.old_count = (first_old < 0) ? 0 : (last_old - first_old + 1);
        hunk.new_count = (first_new < 0) ? 0 : (last_new - first_new + 1);

        diff.total_added   += hunk.added;
        diff.total_removed += hunk.removed;
        diff.hunks.push_back(std::move(hunk));
        idx = he;
    }
}


void rebuild_buffer_from_external(const std::string& text) {
    s_cache.lines = split_to_lines(text);
    if (s_cache.lines.empty()) s_cache.lines.push_back("");
    s_cache.tokens.assign(s_cache.lines.size(), {});
    s_cache.line_hashes.assign(s_cache.lines.size(), 0);
    s_cache.dirty = false;
    rebuild_buffer_from_lines();
}


void rebuild_pending_from_proposal(const std::string& origin,
                                   const std::vector<std::string>& old_lines,
                                   const std::vector<std::string>& new_lines,
                                   std::uint64_t document_id,
                                   std::uint64_t base_revision,
                                   std::uint64_t base_content_hash)
{
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    s_diff.active        = true;
    s_diff.document_id = document_id;
    s_diff.base_revision = base_revision;
    s_diff.base_content_hash = base_content_hash;
    s_diff.origin        = origin;
    s_diff.old_lines     = old_lines;
    s_diff.new_lines     = new_lines;
    compute_lcs_diff(old_lines, new_lines, s_diff);
    s_diff_hover_hunk    = -1;
}


std::string compose_resolved_text() {
    std::vector<std::string> result;
    result.reserve(s_diff.new_lines.size() + s_diff.old_lines.size());

    size_t old_idx = 0;
    size_t hi = 0;

    auto emit_context_until = [&](int old_target) {
        const std::size_t target = static_cast<std::size_t>(std::max(0, old_target));
        while (old_idx < target &&
               old_idx < s_diff.old_lines.size()) {
            result.push_back(s_diff.old_lines[old_idx]);
            old_idx++;
        }
    };

    while (hi < s_diff.hunks.size()) {
        const code_editor_widget::diff_hunk_t& h = s_diff.hunks[hi];

        int hunk_old_begin = h.old_count > 0 ? h.old_start : static_cast<int>(old_idx);
        if (h.old_count == 0) {
            for (const auto& dl : h.lines) {
                if (dl.kind == code_editor_widget::diff_line_kind_t::context &&
                    dl.old_line >= 0) {
                    hunk_old_begin = dl.old_line;
                    break;
                }
            }
        }
        emit_context_until(hunk_old_begin);

        if (h.state == code_editor_widget::diff_hunk_state_t::accepted) {
            for (const auto& dl : h.lines) {
                if (dl.kind == code_editor_widget::diff_line_kind_t::added ||
                    dl.kind == code_editor_widget::diff_line_kind_t::context)
                    result.push_back(dl.text);
            }
        } else {
            for (const auto& dl : h.lines) {
                if (dl.kind == code_editor_widget::diff_line_kind_t::removed ||
                    dl.kind == code_editor_widget::diff_line_kind_t::context)
                    result.push_back(dl.text);
            }
        }

        int consumed_old = 0;
        for (const auto& dl : h.lines)
            if (dl.old_line >= 0) consumed_old++;
        old_idx = static_cast<std::size_t>(std::max(0, hunk_old_begin)) +
            static_cast<std::size_t>(std::max(0, consumed_old));
        hi++;
    }

    emit_context_until(static_cast<int>(s_diff.old_lines.size()));

    std::string joined;
    for (size_t i = 0; i < result.size(); ++i) {
        if (i > 0) joined += '\n';
        joined += result[i];
    }
    return joined;
}


bool apply_resolved_diff_to_buffer() {
    std::string text = compose_resolved_text();
    if (text == active_content())
        return false;
    int caret_l = std::min(s_sel.caret_line, std::max(0, static_cast<int>(split_to_lines(text).size()) - 1));
    push_undo_range(0, line_count() - 1);
    rebuild_buffer_from_external(text);
    s_sel.caret_line = s_sel.anchor_line = clamp_line(caret_l);
    s_sel.caret_col  = s_sel.anchor_col  = clamp_col(s_sel.caret_line, s_sel.caret_col);
    s_sel.active = false;
    return true;
}


void finalize_diff_if_resolved_locked() {
    if (!s_diff.active) return;
    if (!s_diff.fully_resolved()) return;
    if (s_diff.document_id == 0 || s_diff.document_id != s_active_document_id ||
        s_diff.base_revision != s_document_revision ||
        s_diff.base_content_hash != code_editor_widget::document_content_fingerprint()) {
        s_last_error = "code_editor: document changed after review was created";
        return;
    }
    const bool applied = apply_resolved_diff_to_buffer();
    s_diff = code_editor_widget::pending_diff_t{};
    s_diff.active = false;
    s_diff_hover_hunk = -1;
    s_diff_scroll_target = -1.f;
    if (applied) {
        s_scroll_y = s_scroll_x = s_target_scroll_y = 0.f;
        break_undo_coalescing();
    }
}

}


void code_editor_widget::init() {
	s_document_states.clear();
	s_bound_document_id = 0;
	s_focused_document_id = 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::editor::ensure_fixture();
    aida::preview::editor::record("editor_init");
#else
    diag::log_tagged("editor", "init enter reset_state");
#endif
	if (s_document_states.empty()) state_for(0);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    diag::log_tagged("editor", "init done");
#endif
}

void code_editor_widget::get_caret(int& line, int& col) {
    bind_focused_document();
    line = s_sel.caret_line;
    col  = s_sel.caret_col;
}

bool code_editor_widget::load_document(std::uint64_t document_id, std::uint64_t revision,
        std::string_view content, std::string_view filename, std::string_view filepath,
        bool dirty, int caret_line, int caret_column, float scroll_x, float scroll_y,
        bool replace_existing) {
    if (document_id == 0 || revision == 0 ||
        content.size() > aida::editor::programming_documents::maximum_editable_document_bytes)
        return false;
    const auto found = s_document_states.find(document_id);
    if (found != s_document_states.end() && !replace_existing) {
        s_bound_document_id = document_id;
        return true;
    }
    auto target = document_handle(document_id);
	if (replace_existing) cancel_runtime_jobs(*target);
    target->document_id = document_id;
    target->revision = revision;
    target->serialized_content.assign(content);
    target->serialized_dirty = false;
	target->content_fingerprint = 0;
	target->fingerprint_revision = 0;
    target->filename.assign(filename);
    target->filepath.assign(filepath);
    target->active = true;
    target->dirty = dirty;
    target->read_only = false;
    target->read_only_reason.clear();
    target->cache = {};
    target->cache.dirty = true;
    target->selection = {};
    target->selection.caret_line = target->selection.anchor_line = (std::max)(0, caret_line);
    target->selection.caret_col = target->selection.anchor_col = (std::max)(0, caret_column);
    target->scroll_x = (std::max)(0.f, scroll_x);
    target->scroll_y = target->target_scroll_y = (std::max)(0.f, scroll_y);
    target->find = {};
    target->go_to = {};
    target->undo.clear();
    target->redo.clear();
    target->diff = {};
    target->mapped_source.reset();
	target->mapped_lines.clear();
	target->mapped_line_lru.clear();
	target->mapped_tokens.clear();
	target->mapped_hashes.clear();
	target->mapped_line_cache_bytes = 0;
    target->stream_loading = false;
    target->stream_error.clear();
    target->language = syntax::detect_language(target->filename);
    target->language_set = !target->filename.empty();
    s_bound_document_id = document_id;
    return true;
}

void code_editor_widget::set_caret(int line, int col) {
    if (s_cache.dirty)
        rebuild_lines();
    const int target_line = clamp_line(line);
    const int target_column = clamp_col(target_line, col);
    s_sel.caret_line = s_sel.anchor_line = target_line;
    s_sel.caret_col = s_sel.anchor_col = target_column;
    s_sel.active = false;
    s_blink_timer = 0.f;
    s_blink_on = true;
    s_target_scroll_y = static_cast<float>(target_line) *
        (std::max)(editor_preferences::font_size * 1.55f, 1.f);
    break_undo_coalescing();
}

void code_editor_widget::get_scroll(float& x, float& y) {
    bind_focused_document();
    x = s_scroll_x;
    y = s_scroll_y;
}

void code_editor_widget::set_scroll(float x, float y) {
    s_scroll_x = (std::max)(x, 0.f);
    s_scroll_y = (std::max)(y, 0.f);
    s_target_scroll_y = s_scroll_y;
}

void code_editor_widget::discard_document_state(std::uint64_t document_id) {
	const auto found = s_document_states.find(document_id);
	if (found != s_document_states.end()) cancel_runtime_jobs(*found->second);
    s_document_states.erase(document_id);
    if (s_bound_document_id == document_id)
        s_bound_document_id = 0;
    if (s_focused_document_id == document_id)
        s_focused_document_id = 0;
}

bool code_editor_widget::select_document_for_actions(std::uint64_t document_id) {
	if (document_id == 0 || s_document_states.find(document_id) == s_document_states.end())
		return false;
	s_bound_document_id = document_id;
	s_focused_document_id = document_id;
	return true;
}

std::uint64_t code_editor_widget::active_document_id() {
    return s_focused_document_id != 0 ? s_focused_document_id : s_bound_document_id;
}

std::uint64_t code_editor_widget::document_revision() {
    bind_focused_document();
    return s_document_revision;
}

std::uint64_t code_editor_widget::document_revision(std::uint64_t document_id) {
    const auto found = s_document_states.find(document_id);
    return found == s_document_states.end() ? 0 : found->second->revision;
}

std::string code_editor_widget::document_content(std::uint64_t document_id) {
    const auto found = s_document_states.find(document_id);
    if (found == s_document_states.end()) return {};
    auto& document = *found->second;
    if (document.serialized_dirty && !document.cache.dirty) {
        document.serialized_content = serialize_lines(document.cache);
        document.serialized_dirty = false;
    }
    return document.serialized_content;
}

bool code_editor_widget::document_dirty(std::uint64_t document_id) {
    const auto found = s_document_states.find(document_id);
    return found != s_document_states.end() && found->second->dirty;
}

bool code_editor_widget::get_document_caret(std::uint64_t document_id, int& line, int& col) {
    const auto found = s_document_states.find(document_id);
    if (found == s_document_states.end()) return false;
    line = found->second->selection.caret_line;
    col = found->second->selection.caret_col;
    return true;
}

bool code_editor_widget::set_document_caret(std::uint64_t document_id, int line, int col) {
	const auto found = s_document_states.find(document_id);
	if (found == s_document_states.end()) return false;
	s_bound_document_id = document_id;
	set_caret(line, col);
	return true;
}

bool code_editor_widget::get_document_scroll(std::uint64_t document_id, float& x, float& y) {
    const auto found = s_document_states.find(document_id);
    if (found == s_document_states.end()) return false;
    x = found->second->scroll_x;
    y = found->second->scroll_y;
    return true;
}

bool code_editor_widget::set_document_scroll(std::uint64_t document_id, float x, float y) {
	const auto found = s_document_states.find(document_id);
	if (found == s_document_states.end()) return false;
	found->second->scroll_x = (std::max)(x, 0.f);
	found->second->scroll_y = (std::max)(y, 0.f);
	found->second->target_scroll_y = found->second->scroll_y;
	return true;
}

code_editor_widget::document_metadata_snapshot_t
code_editor_widget::document_metadata(std::uint64_t document_id) {
    document_metadata_snapshot_t result;
    const auto found = s_document_states.find(document_id);
    if (found == s_document_states.end()) return result;
	auto& document = *found->second;
	if (document.stream_dispatch_failed &&
		document.stream_dispatch_failed->exchange(false, std::memory_order_acq_rel)) {
		const std::string task_id = "editor.stream." +
			std::to_string(document.document_id) + "." +
			std::to_string(document.stream_generation);
		++document.stream_generation;
		document.stream_loading = false;
		document.stream_error = "Large-file indexing completed, but its result could not return to the UI owner. Retry opening the document.";
		document.stream_dispatch_failed.reset();
		document.stream_task_id = 0;
		document.stream_cancel.reset();
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.f,
			"Index result dispatch failed", document.stream_error));
	}
	if (document.find_dispatch_failed &&
		document.find_dispatch_failed->exchange(false, std::memory_order_acq_rel)) {
		const std::string task_id = "editor.search." +
			std::to_string(document.document_id) + "." +
			std::to_string(document.find_generation);
		++document.find_generation;
		document.find_loading = false;
		document.find_error = "Mapped search completed, but its result could not return to the UI owner. Retry the search.";
		document.find_dispatch_failed.reset();
		document.find_task_id = 0;
		document.find_cancel.reset();
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.f,
			"Search result dispatch failed", document.find_error));
	}
    result.found = true;
    result.revision = document.revision;
    result.dirty = document.dirty;
    result.caret_line = document.selection.caret_line;
    result.caret_column = document.selection.caret_col;
    result.scroll_x = document.scroll_x;
    result.scroll_y = document.scroll_y;
    result.proposal_pending = document.diff.active;
    result.read_only = document.read_only;
    return result;
}

code_editor_widget::document_payload_snapshot_t
code_editor_widget::document_payload(std::uint64_t document_id,
        std::uint64_t expected_revision) {
    document_payload_snapshot_t result;
    const auto found = s_document_states.find(document_id);
    if (found == s_document_states.end()) return result;
    auto& document = *found->second;
    if (expected_revision != 0 && document.revision != expected_revision) return result;
    const auto metadata = document_metadata(document_id);
    static_cast<document_metadata_snapshot_t&>(result) = metadata;
    if (document.mapped_source) return result;
    if (document.serialized_dirty && !document.cache.dirty) {
        document.serialized_content = serialize_lines(document.cache);
        document.serialized_dirty = false;
    }
    result.content = document.serialized_content;
    result.content_hash = 14695981039346656037ULL;
    for (const char character : result.content) {
        result.content_hash ^= static_cast<unsigned char>(character);
        result.content_hash *= 1099511628211ULL;
    }
    result.content_hash ^= static_cast<std::uint64_t>(result.content.size());
    result.content_hash *= 1099511628211ULL;
    if (result.content_hash == 0) result.content_hash = 1;
	document.content_fingerprint = result.content_hash;
	document.fingerprint_revision = document.revision;
    return result;
}

std::uint64_t code_editor_widget::document_content_fingerprint(std::uint64_t document_id) {
	const auto found = s_document_states.find(document_id);
	if (found == s_document_states.end() || found->second->mapped_source) return 0;
	auto& document = *found->second;
	if (document.fingerprint_revision == document.revision &&
		document.content_fingerprint != 0)
		return document.content_fingerprint;
	std::uint64_t hash = 14695981039346656037ULL;
	std::size_t byte_count = 0;
	if (!document.cache.dirty) {
		for (std::size_t line = 0; line < document.cache.lines.size(); ++line) {
			if (line != 0) {
				hash ^= static_cast<unsigned char>('\n');
				hash *= 1099511628211ULL;
				++byte_count;
			}
			for (const char character : document.cache.lines[line]) {
				hash ^= static_cast<unsigned char>(character);
				hash *= 1099511628211ULL;
				++byte_count;
			}
		}
	} else {
		for (const char character : document.serialized_content) {
			hash ^= static_cast<unsigned char>(character);
			hash *= 1099511628211ULL;
			++byte_count;
		}
	}
	hash ^= static_cast<std::uint64_t>(byte_count);
	hash *= 1099511628211ULL;
	if (hash == 0) hash = 1;
	document.content_fingerprint = hash;
	document.fingerprint_revision = document.revision;
	return hash;
}

std::string code_editor_widget::caret_identifier() {
    bind_focused_document();
    if (!current_document().active) return {};
    const std::string* current_line = nullptr;
    if (current_document().mapped_source) {
        const auto found = current_document().mapped_lines.find(s_sel.caret_line);
        if (found == current_document().mapped_lines.end()) return {};
        current_line = &found->second;
    } else {
        if (s_cache.dirty || s_sel.caret_line < 0 ||
            static_cast<std::size_t>(s_sel.caret_line) >= s_cache.lines.size())
            return {};
        current_line = &s_cache.lines[static_cast<std::size_t>(s_sel.caret_line)];
    }
    const std::string& line = *current_line;
    int start = std::clamp(s_sel.caret_col, 0, static_cast<int>(line.size()));
    int end = start;
    while (start > 0 && is_word_char(line[static_cast<std::size_t>(start - 1)]) &&
            end - start < 256) --start;
    while (end < static_cast<int>(line.size()) && is_word_char(line[static_cast<std::size_t>(end)]) &&
            end - start < 256) ++end;
    return end > start ? line.substr(static_cast<std::size_t>(start),
        static_cast<std::size_t>(end - start)) : std::string{};
}

void code_editor_widget::mark_document_saved(std::uint64_t document_id,
        std::uint64_t revision, std::string_view filename, std::string_view filepath) {
    const auto found = s_document_states.find(document_id);
    if (found == s_document_states.end()) return;
    auto& document = *found->second;
    document.filename.assign(filename);
    document.filepath.assign(filepath);
	if (document.revision == revision)
		document.dirty = false;
}

bool code_editor_widget::request_streamed_document(std::uint64_t document_id,
        std::uint64_t revision, std::string_view filename, std::string_view filepath,
        std::uint64_t byte_length) {
    if (document_id == 0 || filepath.empty() || byte_length < LARGE_READ_ONLY_BYTES ||
        byte_length > MAXIMUM_VIEWABLE_BYTES)
        return false;
    auto target = document_handle(document_id);
	cancel_runtime_jobs(*target);
    target->revision = (std::max)(revision, std::uint64_t{1});
    target->filename.assign(filename);
    target->filepath.assign(filepath);
    target->active = true;
    target->dirty = false;
    target->read_only = true;
	const bool very_large_file = byte_length >=
		aida::editor::programming_documents::large_document_milestone_bytes;
	target->read_only_reason = very_large_file
		? "Files from 50 MiB through 500 MiB use cancellable, Task-Center-owned memory-mapped indexing with bounded line/token caches; editing and full-document copies are disabled."
		: "Files above 1 MiB through 50 MiB use a memory-mapped, searchable read-only view to preserve frame pacing and exact crash recovery.";
    target->stream_error.clear();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    target->stream_loading = false;
    target->stream_error = "Streamed file I/O is disabled in deterministic Studio preview mode.";
    return false;
#else
    target->stream_loading = true;
    const std::uint64_t generation = ++target->stream_generation;
    const std::string path(filepath);
    const std::string task_key = "editor.stream." + std::to_string(document_id) + "." +
        std::to_string(generation);
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
	auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
	target->stream_cancel = cancelled;
	target->stream_dispatch_failed = dispatch_failed;
    const std::weak_ptr<document_runtime_t> weak_target = target;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "code_editor";
    submission.label = "code_editor.streamed_document";
    submission.thread_class = "memory_mapped_file_index";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 2;
    submission.generation = generation;
    submission.ui_access_policy = "immutable_snapshots_only";
    submission.failure_policy = "typed_diagnostic";
    submission.shutdown_policy = "cancel";
    submission.cancel_hook = [cancelled] { cancelled->store(true, std::memory_order_release); };
    submission.body = [weak_target, cancelled, dispatch_failed, generation, byte_length, path, task_key]() {
        auto source = std::make_shared<mapped_text_source_t>();
        std::string error;
        const std::wstring wide_path = std::filesystem::path(path).wstring();
        source->file = CreateFileW(wide_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
        if (source->file == INVALID_HANDLE_VALUE) {
            error = "The large file could not be opened (Win32 " + std::to_string(GetLastError()) + ").";
        }
        LARGE_INTEGER exact_size{};
        if (error.empty() && (!GetFileSizeEx(source->file, &exact_size) || exact_size.QuadPart < 0 ||
                static_cast<std::uint64_t>(exact_size.QuadPart) != byte_length))
            error = "The large file changed size before its mapped view could be created.";
        if (error.empty()) {
            source->mapping = CreateFileMappingW(source->file, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!source->mapping)
                error = "The read-only file mapping could not be created (Win32 " +
                    std::to_string(GetLastError()) + ").";
        }
        if (error.empty()) {
            source->view = static_cast<const char*>(MapViewOfFile(source->mapping, FILE_MAP_READ, 0, 0, 0));
            if (!source->view)
                error = "The read-only file mapping could not be viewed (Win32 " +
                    std::to_string(GetLastError()) + ").";
        }
        if (error.empty()) {
			try {
				source->byte_length = byte_length;
				constexpr std::size_t k_max_mapped_lines = 16U * 1024U * 1024U;
				source->line_offsets.reserve(static_cast<std::size_t>((std::min)(
					byte_length / 48U + 1U, static_cast<std::uint64_t>(k_max_mapped_lines))));
				source->line_offsets.push_back(0);
				for (std::uint64_t offset = 0; offset < byte_length; ++offset) {
					if ((offset & 0x3FFFFFU) == 0U && cancelled->load(std::memory_order_acquire))
						break;
					if (source->view[offset] == '\0') {
						error = "The artifact contains binary NUL bytes; open it in Hex View or Binary Map.";
						break;
					}
					if (source->view[offset] == '\n') {
						if (source->line_offsets.size() >= k_max_mapped_lines) {
							error = "The mapped text exceeds the 16,777,216-line index budget; open it in Hex View or Binary Map.";
							break;
						}
						source->line_offsets.push_back(offset + 1U);
					}
				}
			} catch (const std::bad_alloc&) {
				error = "The bounded memory-mapped line index could not be allocated; close other large views or use Hex View.";
				source->line_offsets.clear();
			}
        }
        if (cancelled->load(std::memory_order_acquire) && error.empty())
            error = "Large-file indexing was cancelled.";
        aida::ui_thread::post_options_t options;
        options.subsystem = "code_editor";
        options.label = "streamed_document_result";
        options.phase = "worker_result";
        options.owner = "code_editor.streamed_document";
        options.priority = aida::ui_thread::priority_t::critical;
        const bool posted = aida::ui_thread::post(
            [weak_target, generation, task_key, source = std::move(source), error = std::move(error)]() mutable {
                const auto target_state = weak_target.lock();
                if (!target_state || target_state->stream_generation != generation) return;
                target_state->stream_loading = false;
				target_state->stream_dispatch_failed.reset();
				target_state->stream_task_id = 0;
				target_state->stream_cancel.reset();
                target_state->stream_error = std::move(error);
				const auto task_state = target_state->stream_error.empty()
					? aida::ui::task_center::task_state_t::completed
					: target_state->stream_error.find("cancelled") != std::string::npos
						? aida::ui::task_center::task_state_t::cancelled
						: aida::ui::task_center::task_state_t::failed;
				static_cast<void>(aida::ui::task_center::update_task(task_key,
					task_state,
					1.f, target_state->stream_error.empty() ? "Index complete" : "Index failed",
					target_state->stream_error.empty()
						? "Memory-mapped line index is ready." : target_state->stream_error));
                if (!target_state->stream_error.empty()) return;
                target_state->mapped_source = std::move(source);
                target_state->mapped_lines.clear();
                target_state->mapped_line_lru.clear();
				target_state->mapped_line_cache_bytes = 0;
                target_state->mapped_tokens.clear();
                target_state->mapped_hashes.clear();
                target_state->cache.content_bytes = static_cast<std::size_t>(
                    target_state->mapped_source->byte_length);
                target_state->cache.dirty = false;
			}, std::move(options)) == aida::ui_thread::enqueue_result_t::accepted;
		if (!posted)
			dispatch_failed->store(true, std::memory_order_release);
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        target->stream_loading = false;
		target->stream_dispatch_failed.reset();
		target->stream_cancel.reset();
        target->stream_error = "The large-file worker could not be scheduled: " + submitted.reject_reason;
        return false;
    }
	target->stream_task_id = submitted.task_id;
    aida::ui::task_center::task_registration_t registration;
    registration.id = task_key;
    registration.source = "code_editor";
    registration.owner = "Code Editor";
    registration.owner_view = "document.code";
    registration.owner_action = "file.open";
    registration.target = path;
    registration.label = "Index large text file";
	registration.stage = very_large_file
		? "Building bounded index for 50-500 MiB text"
		: "Building memory-mapped line index";
    registration.affected_entity = std::to_string(document_id);
    registration.cancellation_is_safe = true;
	registration.callbacks.focus = [document_id]() {
		const int target_index = file_tabs::find_document(document_id);
		if (file_tabs::is_valid_tab_index(target_index))
			file_tabs::switch_to(target_index);
	};
	if (!aida::ui::task_center::register_executor_job(
			submitted.task_id, std::move(registration))) {
		aida::infra::executor::cancel(submitted.task_id);
		cancelled->store(true, std::memory_order_release);
		++target->stream_generation;
		target->stream_loading = false;
		target->stream_dispatch_failed.reset();
		target->stream_task_id = 0;
		target->stream_cancel.reset();
		target->stream_error = "Task Center could not own large-file indexing; the operation was cancelled.";
		return false;
	}
    return true;
#endif
}

void code_editor_widget::trigger_undo()   { bind_focused_document(); s_request_undo = true; }
void code_editor_widget::trigger_redo()   { bind_focused_document(); s_request_redo = true; }
void code_editor_widget::trigger_cut()    { bind_focused_document(); s_request_cut = true; }
void code_editor_widget::trigger_copy()   { bind_focused_document(); s_request_copy = true; }
void code_editor_widget::trigger_paste()  { bind_focused_document(); s_request_paste = true; }
void code_editor_widget::trigger_delete() { bind_focused_document(); s_request_delete = true; }
void code_editor_widget::trigger_select_all() { bind_focused_document(); s_request_select_all = true; }
void code_editor_widget::open_find()      { bind_focused_document(); s_request_find = true; }
void code_editor_widget::open_replace()   { bind_focused_document(); s_request_replace = true; }
void code_editor_widget::open_goto_line() { bind_focused_document(); s_request_goto = true; }

bool code_editor_widget::can_undo() { bind_focused_document(); return !s_undo.empty(); }
bool code_editor_widget::can_redo() { bind_focused_document(); return !s_redo.empty(); }
bool code_editor_widget::can_paste() { bind_focused_document(); return !clipboard_paste().empty(); }
bool code_editor_widget::has_selection() { bind_focused_document(); return s_sel.has_selection(); }

std::string code_editor_widget::selected_text(std::size_t maximum_bytes) {
    bind_focused_document();
    if (maximum_bytes == 0 || !s_sel.has_selection())
        return {};
    std::string result = get_selected_text();
    if (result.size() > maximum_bytes)
        result.resize(maximum_bytes);
    return result;
}

bool code_editor_widget::selected_range(int& start_line, int& start_column,
        int& end_line, int& end_column) {
    bind_focused_document();
    if (!s_sel.has_selection())
        return false;
    selection_ordered(start_line, start_column, end_line, end_column);
    start_line = clamp_line(start_line);
    end_line = clamp_line(end_line);
    start_column = clamp_col(start_line, start_column);
    end_column = clamp_col(end_line, end_column);
    return true;
}

std::string code_editor_widget::last_error() {
    bind_focused_document();
    return s_last_error;
}

std::uint64_t code_editor_widget::document_content_fingerprint() {
    bind_focused_document();
    return document_content_fingerprint(s_active_document_id);
}

code_editor_widget::document_capabilities_t code_editor_widget::document_capabilities() {
    bind_focused_document();
    document_capabilities_t result;
    if (!current_document().active) return result;
    if (s_cache.dirty) rebuild_lines();
    const auto& language = syntax::detect_language(current_document().filename);
    result.text_editing = !large_read_only_mode();
    result.save = !large_read_only_mode() && !current_document().filepath.empty();
    result.syntax_highlighting = true;
    result.line_comment = language.line_comment && language.line_comment[0] != '\0';
    result.find = true;
    result.replace = !large_read_only_mode();
    result.goto_line = true;
    result.ai_diff_review = !large_file_mode();
    return result;
}

code_editor_widget::document_state_t code_editor_widget::document_state() {
    bind_focused_document();
    return document_state(s_active_document_id);
}

code_editor_widget::document_state_t code_editor_widget::document_state(
        std::uint64_t document_id) {
    document_state_t result;
    const auto found = s_document_states.find(document_id);
    if (found == s_document_states.end()) return result;
    const auto& document = *found->second;
    result.filename = document.filename;
    result.filepath = document.filepath;
    result.active = document.active;
    result.dirty = document.dirty;
    result.focused = s_focused_document_id == document_id;
    result.content_bytes = document.mapped_source
        ? static_cast<std::size_t>(document.mapped_source->byte_length)
        : document.cache.dirty ? document.serialized_content.size() : document.cache.content_bytes;
    result.line_count = document.mapped_source ? document.mapped_source->line_offsets.size()
        : document.cache.dirty ? 0U : document.cache.lines.size();
    result.caret_line = document.selection.caret_line;
    result.caret_column = document.selection.caret_col;
    result.large_file_mode = result.content_bytes >= LARGE_FILE_BYTES;
    result.has_selection = document.selection.has_selection();
    result.streamed = document.mapped_source != nullptr;
    result.stream_loading = document.stream_loading;
    result.stream_error = document.stream_error;
    result.capabilities.text_editing = document.active && !document.read_only;
    result.capabilities.save = result.capabilities.text_editing && !document.filepath.empty();
    result.capabilities.syntax_highlighting = document.active;
    result.capabilities.find = document.active;
    result.capabilities.replace = result.capabilities.text_editing;
    result.capabilities.goto_line = document.active;
    result.capabilities.ai_diff_review = result.capabilities.text_editing &&
        result.content_bytes <= LARGE_FILE_BYTES;
    if (result.active) {
        const auto& language = syntax::detect_language(document.filename);
        result.language = language.name ? language.name : "Text";
        result.capabilities.line_comment = language.line_comment && language.line_comment[0] != '\0';
    }
    return result;
}

bool code_editor_widget::request_document_action(document_action_t action) {
    bind_focused_document();
    if (!current_document().active) {
        s_last_error = "Open or create a text document first";
        return false;
    }
    const auto capabilities = document_capabilities();
    if (action == document_action_t::copy_path && current_document().filepath.empty()) {
        s_last_error = "The active document has no file path";
        return false;
    }
    if (action == document_action_t::toggle_line_comment && !capabilities.line_comment) {
        s_last_error = "The active language has no supported line-comment syntax";
        return false;
    }
    const bool mutates = action == document_action_t::duplicate_line ||
        action == document_action_t::delete_line ||
        action == document_action_t::move_line_up ||
        action == document_action_t::move_line_down ||
        action == document_action_t::toggle_line_comment ||
        action == document_action_t::trim_trailing_whitespace;
    if (mutates && current_document().read_only) {
        s_last_error = current_document().read_only_reason.empty()
            ? "This document is read-only"
            : current_document().read_only_reason;
        return false;
    }
    const std::uint32_t index = static_cast<std::uint32_t>(action);
    if (index > static_cast<std::uint32_t>(document_action_t::trim_trailing_whitespace)) {
        s_last_error = "The requested editor action is invalid";
        return false;
    }
    s_last_error.clear();
    s_document_action_requests |= 1U << index;
    return true;
}

void code_editor_widget::render_document_pane(const document_pane_render_context_t& context) {
    if (context.document_id != 0) {
        const bool existed = s_document_states.find(context.document_id) != s_document_states.end();
        s_bound_document_id = context.document_id;
        auto& document = state_for(context.document_id);
        if (!existed || (!document.dirty && document.revision != context.revision)) {
            document.serialized_content.assign(context.content);
            document.serialized_dirty = false;
			document.content_fingerprint = 0;
			document.fingerprint_revision = 0;
            document.cache.dirty = true;
            document.revision = (std::max)(context.revision, std::uint64_t{1});
            document.selection = {};
            document.undo.clear();
            document.redo.clear();
            document.diff = {};
        }
        document.filename.assign(context.filename);
        document.filepath.assign(context.filepath);
        document.active = true;
        document.dirty = document.dirty || context.dirty;
        document.read_only = context.read_only || context.content.size() >= LARGE_READ_ONLY_BYTES;
        if (context.content.size() > MAXIMUM_VIEWABLE_BYTES) {
            document.read_only = true;
            document.read_only_reason = "This artifact exceeds the 500 MiB editor-view limit; use Hex View or Binary Map.";
        } else if (!context.read_only_reason.empty()) {
            document.read_only_reason.assign(context.read_only_reason);
        } else if (context.content.size() >= LARGE_READ_ONLY_BYTES) {
            document.read_only_reason = "Files above 1 MiB through 500 MiB open in memory-mapped read-only mode; editing, replace, formatting, and AI proposals are disabled to preserve frame pacing and exact crash recovery.";
        } else {
            document.read_only_reason.clear();
        }
        if (!document.language_set && !document.filename.empty()) {
            document.language = syntax::detect_language(document.filename);
            document.language_set = true;
        }
    }
    ImVec2 origin = ImGui::GetCursorPos();
    ImVec2 available = ImGui::GetContentRegionAvail();
    if (available.x <= 1.f || available.y <= 1.f) return;
    if (!current_document().active) {
        const char* title = "No text document open";
        const char* detail = "Open or create a file to begin editing.";
        const float title_width = ImGui::CalcTextSize(title).x;
        const float detail_width = ImGui::CalcTextSize(detail).x;
        ImGui::SetCursorPos(ImVec2(origin.x + std::max(0.f, (available.x - title_width) * 0.5f),
                                   origin.y + std::max(0.f, available.y * 0.5f - ImGui::GetTextLineHeight())));
        ImGui::TextUnformatted(title);
        ImGui::SetCursorPosX(origin.x + std::max(0.f, (available.x - detail_width) * 0.5f));
        ImGui::TextDisabled("%s", detail);
        ImGui::SetCursorPos(ImVec2(origin.x, origin.y + available.y));
        return;
    }
    if (current_document().stream_loading) {
        ImGui::TextDisabled("Building a bounded memory-mapped line index for %s...",
            current_document().filename.c_str());
        ImGui::TextWrapped("The editor remains responsive; progress and cancellation are available in Task Center.");
        return;
    }
    if (!current_document().stream_error.empty()) {
        ImGui::TextUnformatted("Large-file view unavailable");
        ImGui::TextWrapped("%s", current_document().stream_error.c_str());
        return;
    }
    if (current_document().read_only) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.16f, 0.12f, 0.04f, 0.94f));
        if (ImGui::BeginChild("##aida_editor_read_only_mode", ImVec2(0.f, 40.f), true,
                ImGuiWindowFlags_NoSavedSettings)) {
            ImGui::TextUnformatted("Read-only large-file view");
            ImGui::SameLine();
            ImGui::TextDisabled("%s", current_document().read_only_reason.c_str());
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
        origin = ImGui::GetCursorPos();
        available = ImGui::GetContentRegionAvail();
    }
    render(origin.x, origin.y, available.x, available.y,
           context.alpha, context.accent_r, context.accent_g, context.accent_b);
}


bool code_editor_widget::begin_agent_edit(std::string_view origin) {
	bind_focused_document();
    if (!current_document().active) {
        s_last_error = "code_editor: begin_agent_edit called with no active document";
        return false;
    }
    if (!document_capabilities().ai_diff_review) {
        s_last_error = "code_editor: AI diff review is unavailable in large-file mode";
        return false;
    }
    std::vector<std::string> base = split_to_lines(active_content());
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    s_diff = code_editor_widget::pending_diff_t{};
    s_diff.active = true;
    s_diff.document_id = s_active_document_id;
    s_diff.base_revision = s_document_revision;
    s_diff.base_content_hash = document_content_fingerprint();
    s_diff.origin = std::string(origin);
    s_diff.old_lines = base;
    s_diff.new_lines = base;
    s_diff_hover_hunk = -1;
    return true;
}

bool code_editor_widget::propose_full_content(std::string_view new_content) {
	bind_focused_document();
    if (!current_document().active) {
        s_last_error = "code_editor: propose_full_content called with no active document";
        return false;
    }
    if (!document_capabilities().ai_diff_review) {
        s_last_error = "code_editor: AI diff review is unavailable in large-file mode";
        return false;
    }
    std::vector<std::string> old_lines = split_to_lines(active_content());
    std::vector<std::string> new_lines = split_to_lines(new_content);
    std::string origin;
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        origin = s_diff.active ? s_diff.origin : std::string("agent");
    }
    rebuild_pending_from_proposal(origin, old_lines, new_lines,
        s_active_document_id, s_document_revision, document_content_fingerprint());
    return true;
}

bool code_editor_widget::propose_document_content(
        std::uint64_t document_id,
        std::uint64_t base_revision,
        std::uint64_t base_content_hash,
        std::string_view current_content,
        std::string_view new_content,
        std::string_view origin) {
    if (document_id == 0 || base_revision == 0 || base_content_hash == 0) {
        s_last_error = "code_editor: proposal binding is incomplete";
        return false;
    }
    std::uint64_t observed_hash = 14695981039346656037ULL;
    for (const char character : current_content) {
        observed_hash ^= static_cast<unsigned char>(character);
        observed_hash *= 1099511628211ULL;
    }
    observed_hash ^= static_cast<std::uint64_t>(current_content.size());
    observed_hash *= 1099511628211ULL;
    if (observed_hash == 0)
        observed_hash = 1;
    if (observed_hash != base_content_hash) {
        s_last_error = "code_editor: proposal base content changed before review creation";
        return false;
    }
    auto& target = state_for(document_id);
    if (target.revision != base_revision) {
        target.last_error = "code_editor: document changed before review creation";
        return false;
    }
    pending_diff_t proposal;
    proposal.active = true;
    proposal.document_id = document_id;
    proposal.base_revision = base_revision;
    proposal.base_content_hash = base_content_hash;
    proposal.origin = std::string(origin);
    proposal.old_lines = split_to_lines(current_content);
    proposal.new_lines = split_to_lines(new_content);
    compute_lcs_diff(proposal.old_lines, proposal.new_lines, proposal);
    std::lock_guard<std::mutex> lock(s_diff_mtx);
    target.diff = std::move(proposal);
    target.diff_hover_hunk = -1;
    target.diff_scroll_target = -1.f;
    target.last_error.clear();
    return true;
}

bool code_editor_widget::propose_replace_range(int start_line, int end_line,
                                               std::string_view replacement) {
	bind_focused_document();
    if (!current_document().active) {
        s_last_error = "code_editor: propose_replace_range called with no active document";
        return false;
    }
    if (!document_capabilities().ai_diff_review) {
        s_last_error = "code_editor: AI diff review is unavailable in large-file mode";
        return false;
    }

    std::vector<std::string> old_lines = split_to_lines(active_content());
    int n = static_cast<int>(old_lines.size());
    if (start_line < 0) start_line = 0;
    if (end_line < start_line) end_line = start_line;
    if (start_line > n) start_line = n;
    if (end_line > n) end_line = n;

    std::vector<std::string> repl = split_to_lines(replacement);
    if (replacement.empty()) repl.clear();

    std::vector<std::string> new_lines;
    new_lines.reserve(old_lines.size());
    for (int i = 0; i < start_line && i < n; ++i)
        new_lines.push_back(old_lines[static_cast<std::size_t>(i)]);
    for (auto& r : repl)
        new_lines.push_back(std::move(r));
    for (int i = end_line; i < n; ++i)
        new_lines.push_back(old_lines[static_cast<std::size_t>(i)]);
    if (new_lines.empty()) new_lines.push_back("");

    std::string origin;
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        origin = s_diff.active ? s_diff.origin : std::string("agent");
    }
    rebuild_pending_from_proposal(origin, old_lines, new_lines,
        s_active_document_id, s_document_revision, document_content_fingerprint());
    return true;
}

bool code_editor_widget::has_pending_diff() {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    return s_diff.active && !s_diff.hunks.empty();
}

const code_editor_widget::pending_diff_t& code_editor_widget::pending_diff() {
	bind_focused_document();
    return s_diff;
}

int code_editor_widget::pending_hunk_count() {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    return static_cast<int>(s_diff.hunks.size());
}

bool code_editor_widget::accept_hunk(int index) {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active || index < 0 || index >= static_cast<int>(s_diff.hunks.size()))
        return false;
    s_diff.hunks[static_cast<std::size_t>(index)].state = code_editor_widget::diff_hunk_state_t::accepted;
    return true;
}

bool code_editor_widget::reject_hunk(int index) {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active || index < 0 || index >= static_cast<int>(s_diff.hunks.size()))
        return false;
    s_diff.hunks[static_cast<std::size_t>(index)].state = code_editor_widget::diff_hunk_state_t::rejected;
    return true;
}

void code_editor_widget::accept_all() {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active) return;
    for (auto& h : s_diff.hunks)
        h.state = code_editor_widget::diff_hunk_state_t::accepted;
}

void code_editor_widget::reject_all() {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active) return;
    for (auto& h : s_diff.hunks)
        h.state = code_editor_widget::diff_hunk_state_t::rejected;
}

bool code_editor_widget::commit_resolved_diff() {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active || !s_diff.fully_resolved())
        return false;
    if (s_diff.document_id == 0 || s_diff.document_id != s_active_document_id ||
        s_diff.base_revision != s_document_revision ||
        s_diff.base_content_hash != document_content_fingerprint()) {
        s_last_error = "code_editor: document changed after review was created";
        return false;
    }
    finalize_diff_if_resolved_locked();
    return !s_diff.active;
}

void code_editor_widget::cancel_agent_edit() {
	bind_focused_document();
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    s_diff = code_editor_widget::pending_diff_t{};
    s_diff.active = false;
    s_diff_hover_hunk = -1;
}


void code_editor_widget::render(float pos_x, float pos_y, float width, float height,
                                 float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::editor::ensure_fixture();
#endif
    if (!current_document().active)
        return;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont();
#else
    ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : g_code_font;
#endif
    if (code_font) ImGui::PushFont(code_font);

    ImGuiWindow* editor_win = ImGui::GetCurrentWindow();
    float prev_font_scale = editor_win ? editor_win->FontWindowScale : 1.f;
    {
        float want = editor_preferences::font_size;
        if (want < 8.f)  want = 8.f;
        if (want > 48.f) want = 48.f;
        float scale = want / 14.f;
        if (scale < 0.5f) scale = 0.5f;
        if (scale > 3.f)  scale = 3.f;
        ImGui::SetWindowFontScale(scale);
    }

    if (s_request_undo)   { if (!current_document().read_only) do_undo(); s_request_undo = false; }
    if (s_request_redo)   { if (!current_document().read_only) do_redo(); s_request_redo = false; }
    if (s_request_find)   { s_find.visible = true; s_find.replace_mode = false; s_request_find = false; s_focus_find_input = true; }
    if (s_request_replace){ s_find.visible = true; s_find.replace_mode = true;  s_request_replace = false; s_focus_find_input = true; }
    if (s_request_goto)   { s_goto.visible = true; s_goto.line_buf[0] = '\0'; s_request_goto = false; }

    if (!s_lang_set && !current_document().filename.empty()) {
        s_lang = syntax::detect_language(current_document().filename);
        s_lang_set = true;
    }

    if (s_cache.dirty)
        rebuild_lines();

    if (s_document_action_requests != 0) {
        const std::uint32_t requests = s_document_action_requests;
        s_document_action_requests = 0;
        for (std::uint32_t index = 0; index <= static_cast<std::uint32_t>(code_editor_widget::document_action_t::trim_trailing_whitespace); ++index)
            if ((requests & (1U << index)) != 0)
                perform_document_action(static_cast<code_editor_widget::document_action_t>(index));
    }

    if (s_request_copy) {
        const std::string selected = get_selected_text();
        if (!selected.empty())
            clipboard_copy(selected);
        s_request_copy = false;
    }
    if (s_request_cut) {
        const std::string selected = get_selected_text();
        if (!current_document().read_only && !selected.empty()) {
            clipboard_copy(selected);
            delete_selection();
        }
        s_request_cut = false;
    }
    if (s_request_paste) {
        const std::string pasted = clipboard_paste();
        if (!current_document().read_only && !pasted.empty())
            insert_text_at_caret(pasted);
        s_request_paste = false;
    }
    if (s_request_delete) {
        if (!current_document().read_only) delete_forward();
        s_request_delete = false;
    }
    if (s_request_select_all) {
        s_sel.anchor_line = 0;
        s_sel.anchor_col = 0;
        s_sel.caret_line = line_count() - 1;
        s_sel.caret_col = line_length(s_sel.caret_line);
        s_sel.active = true;
        s_request_select_all = false;
    }
    if (s_cache.dirty)
        rebuild_lines();

    const auto& th = aida::ui::resolved();
    const float a   = alpha;
    const float dt  = aida::ui::clock::dt();
    const float line_h = ImGui::GetFontSize() + 2.f;
    const float char_w = ImGui::CalcTextSize("X").x;
	const bool  show_ln = editor_preferences::show_line_numbers;
	const int   n_lines = line_count();
	const auto source_markers = source_debug_service::markers_for_path(
		current_document().filepath);
	const float source_gutter_w = current_document().filepath.empty() ? 0.f : 15.f;
	const float line_number_gutter_w = show_ln ? (ImGui::CalcTextSize("00000").x + 12.f) : 0.f;
	const float gutter_w = source_gutter_w + line_number_gutter_w;

    bool ghost_consumed_tab = false;

    auto& s_caret_move_anim = current_document().caret_move_anim;
    int& s_prev_caret_line = current_document().prev_caret_line;
    int& s_prev_caret_col = current_document().prev_caret_col;
    auto& s_focus_anim = current_document().focus_anim;
    auto& s_ghost_in = current_document().ghost_in;
    int& s_ghost_visible_for_line = current_document().ghost_visible_for_line;
    int& s_ghost_visible_for_col = current_document().ghost_visible_for_col;
    auto& s_ghost_absorb = current_document().ghost_absorb;
    auto& s_breadcrumb_flash = current_document().breadcrumb_flash;
    auto& s_match_pulse = current_document().match_pulse;
    int& s_active_match_for = current_document().active_match_for;
    auto& s_minimap_hover = current_document().minimap_hover;

    ImU32 tok_colors[static_cast<int>(syntax::token_type::COUNT)];
    syntax::get_token_colors(tok_colors,
        ((float)((th.accent_u32 >> IM_COL32_R_SHIFT) & 0xFF)),
        ((float)((th.accent_u32 >> IM_COL32_G_SHIFT) & 0xFF)),
        ((float)((th.accent_u32 >> IM_COL32_B_SHIFT) & 0xFF)), a);

    const float goto_bar_h = s_goto.visible ? 36.f : 0.f;
    const float breadcrumb_h = 28.f;
    const float minimap_w = (editor_preferences::minimap && width > 360.f && !large_file_mode()) ? 64.f : 0.f;
    const float overlay_h = goto_bar_h + breadcrumb_h;
    const float editor_y0 = pos_y + overlay_h;
    const float editor_h  = height - overlay_h;
    const float code_w = width - minimap_w;
    const float text_x0 = gutter_w + 4.f;

    s_scroll_y = aida::motion::smooth_lerp(s_scroll_y, s_target_scroll_y, 20.f, dt);
    if (std::abs(s_target_scroll_y - s_scroll_y) < 0.5f)
        s_scroll_y = s_target_scroll_y;
    float max_scroll = std::max(0.f, static_cast<float>(n_lines) * line_h - editor_h + line_h);
    s_target_scroll_y = std::max(0.f, std::min(s_target_scroll_y, max_scroll));
    s_scroll_y = std::max(0.f, std::min(s_scroll_y, max_scroll));

    int longest_line_chars = 0;
    {
        int probe_lo = std::max(0, static_cast<int>(s_scroll_y / line_h) - 4);
        int probe_hi = std::min(n_lines - 1,
                                static_cast<int>((s_scroll_y + editor_h) / line_h) + 4);
        for (int i = probe_lo; i <= probe_hi; ++i)
            longest_line_chars = std::max(longest_line_chars, line_length(i));
    }
    const float h_scrollbar_h = 9.f;
    const bool  word_wrap_on  = editor_preferences::word_wrap;
    s_view_char_w = char_w;
    s_view_text_w = (code_w - text_x0 - 14.f);
    if (s_view_text_w < char_w) s_view_text_w = char_w;
    {
        float content_w = static_cast<float>(longest_line_chars) * char_w + char_w * 2.f;
        s_max_scroll_x = word_wrap_on ? 0.f
                                      : std::max(0.f, content_w - s_view_text_w);
    }
    if (word_wrap_on) s_scroll_x = 0.f;
    if (s_scroll_x > s_max_scroll_x) s_scroll_x = s_max_scroll_x;
    if (s_scroll_x < 0.f) s_scroll_x = 0.f;

    s_blink_timer += dt;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos   = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + editor_y0;
    float bcb_x = wpos.x + pos_x;
    float bcb_y = wpos.y + pos_y + goto_bar_h;
    {
        ImDrawList* bc_dl = ImGui::GetWindowDrawList();
        ImVec2 bc_min(bcb_x, bcb_y);
        ImVec2 bc_max(bcb_x + width, bcb_y + breadcrumb_h);
        bc_dl->AddRectFilled(bc_min, bc_max, aida::ui::with_alpha(th.panel_header, a * 0.85f));
        bc_dl->AddLine(ImVec2(bc_min.x, bc_max.y - 1.f),
                       ImVec2(bc_max.x, bc_max.y - 1.f),
                       aida::ui::with_alpha(th.border_subtle, a), 1.f);

        std::string crumb_path = current_document().filename.empty() ? std::string("Untitled")
                                                                    : current_document().filename;
        std::string crumb_func;
        std::string crumb_class;
        for (int i = std::min(s_sel.caret_line, line_count() - 1); i >= 0 && (crumb_func.empty() || crumb_class.empty()); --i) {
            const std::string& ln = line_at(i);
            if (crumb_func.empty()) {
                size_t paren = ln.find('(');
                if (paren != std::string::npos && paren > 0) {
                    size_t end = paren;
                    while (end > 0 && (ln[end - 1] == ' ' || ln[end - 1] == '\t')) end--;
                    if (end > 0) {
                        size_t start = end;
                        while (start > 0 && (isalnum((unsigned char)ln[start - 1]) || ln[start - 1] == '_' || ln[start - 1] == ':')) start--;
                        if (end > start && (isalpha((unsigned char)ln[start]) || ln[start] == '_')) {
                            std::string token = ln.substr(start, end - start);
                            if (token != "if" && token != "for" && token != "while" && token != "switch"
                                && token != "return" && token != "catch" && token != "sizeof") {
                                crumb_func = token;
                            }
                        }
                    }
                }
            }
            if (crumb_class.empty()) {
                static const char* prefixes[] = { "class ", "struct ", "namespace " };
                for (auto* pref : prefixes) {
                    size_t pos = ln.find(pref);
                    if (pos != std::string::npos) {
                        size_t s = pos + std::strlen(pref);
                        size_t e = s;
                        while (e < ln.size() && (isalnum((unsigned char)ln[e]) || ln[e] == '_' || ln[e] == ':')) e++;
                        if (e > s) crumb_class = ln.substr(s, e - s);
                        break;
                    }
                }
            }
        }

        struct seg_t { std::string text; bool is_path; bool is_active; };
        std::vector<seg_t> segs;
        size_t lastsep = crumb_path.find_last_of("/\\");
        std::string parent_path = (lastsep != std::string::npos) ? crumb_path.substr(0, lastsep) : "";
        std::string name_only   = (lastsep != std::string::npos) ? crumb_path.substr(lastsep + 1) : crumb_path;
        if (!parent_path.empty()) {
            size_t prev_sep = parent_path.find_last_of("/\\");
            std::string parent_seg = (prev_sep != std::string::npos)
                ? parent_path.substr(prev_sep + 1) : parent_path;
            if (!parent_seg.empty()) segs.push_back({ parent_seg, true, false });
        }
        segs.push_back({ name_only, true, false });
        if (!crumb_class.empty()) segs.push_back({ crumb_class, false, false });
        if (!crumb_func.empty())  segs.push_back({ crumb_func,  false, true  });

        ImFont* bc_font = aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont();
        float crumb_x = bc_min.x + 12.f;
        float crumb_y = bc_min.y + (breadcrumb_h - 13.f) * 0.5f;
        float chev_w = 10.f;
        for (size_t i = 0; i < segs.size(); ++i) {
            const auto& sg = segs[i];
            float tw = bc_font->CalcTextSizeA(13.f, FLT_MAX, 0.f, sg.text.c_str()).x;
            ImVec2 chip_min(crumb_x - 4.f, crumb_y - 3.f);
            ImVec2 chip_max(crumb_x + tw + 4.f, crumb_y + 16.f);
            bool seg_hov = ImGui::IsMouseHoveringRect(chip_min, chip_max);
            ImU32 seg_col = sg.is_path ? th.text_secondary
                                       : (sg.is_active ? th.accent_u32 : th.text_primary);
            if (seg_hov) {
                bc_dl->AddRectFilled(chip_min, chip_max, aida::ui::with_alpha(th.hover_wash, a * 1.4f), 5.f);
                seg_col = th.accent_u32;
            }
            bc_dl->AddText(bc_font, 13.f, ImVec2(crumb_x, crumb_y),
                aida::ui::with_alpha(seg_col, a), sg.text.c_str());
            crumb_x += tw;
            if (i + 1 < segs.size()) {
                ImU32 chev_col = aida::ui::with_alpha(th.text_dim, a);
                float cx = crumb_x + 4.f;
                float cy = crumb_y + 6.f;
                bc_dl->AddLine(ImVec2(cx, cy - 3.f), ImVec2(cx + 3.f, cy), chev_col, 1.5f);
                bc_dl->AddLine(ImVec2(cx + 3.f, cy), ImVec2(cx, cy + 3.f), chev_col, 1.5f);
                crumb_x += chev_w + 4.f;
            }
        }
    }
    s_breadcrumb_flash.tick(dt, 2.f);

    ImGuiID id = ImGui::GetID("##code_editor_widget");
    s_widget_id = id;
    ImRect bb(ImVec2(ox, oy), ImVec2(ox + width, oy + editor_h));
    ImGui::ItemSize(ImVec2(width, height));
    if (!ImGui::ItemAdd(bb, id)) {
        ImGui::SetWindowFontScale(prev_font_scale);
        if (code_font) ImGui::PopFont();
        return;
    }

    bool diff_active = false;
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        diff_active = s_diff.active && !s_diff.hunks.empty();
    }

    if (diff_active) {
        std::unique_lock<std::mutex> lk(s_diff_mtx);
        s_scroll_x = 0.f;

        const float hdr_h = 40.f;
        ImVec2 hdr_min(ox, oy);
        ImVec2 hdr_max(ox + width, oy + hdr_h);
        dl->AddRectFilled(hdr_min, hdr_max, aida::ui::with_alpha(th.panel_header, a));
        dl->AddLine(ImVec2(hdr_min.x, hdr_max.y - 1.f), ImVec2(hdr_max.x, hdr_max.y - 1.f),
                    aida::ui::with_alpha(th.border_subtle, a), 1.f);

        ImFont* hdr_font = aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont();
        {
            std::string title = "AI Edit";
            if (!s_diff.origin.empty()) title += "  -  " + s_diff.origin;
            dl->AddText(hdr_font, 14.f, ImVec2(hdr_min.x + 14.f, hdr_min.y + 6.f),
                        aida::ui::with_alpha(th.text_primary, a), title.c_str());

            char stats[96];
            int pend = 0;
            for (const auto& h : s_diff.hunks)
                if (h.state == code_editor_widget::diff_hunk_state_t::pending) pend++;
            snprintf(stats, sizeof(stats), "+%d  -%d   %zu hunk%s   %d pending",
                     s_diff.total_added, s_diff.total_removed,
                     s_diff.hunks.size(),
                     s_diff.hunks.size() == 1 ? "" : "s", pend);
            dl->AddText(hdr_font, 12.f, ImVec2(hdr_min.x + 14.f, hdr_min.y + 22.f),
                        aida::ui::with_alpha(th.text_secondary, a), stats);
        }

        bool want_accept_all = false;
        bool want_reject_all = false;
        {
            ImGui::PushID("##diff_hdr_actions");
            const float bw = 88.f;
            const float bh = 24.f;
            float by = hdr_min.y + (hdr_h - bh) * 0.5f;
            float bx_reject = hdr_max.x - 14.f - bw;
            float bx_accept = bx_reject - 8.f - bw;

            ImVec2 mp = ImGui::GetIO().MousePos;
            auto hdr_button = [&](const char* label, float bx, ImU32 base, bool& out) {
                ImVec2 mn(bx, by), mx(bx + bw, by + bh);
                bool hov = (mp.x >= mn.x && mp.x <= mx.x && mp.y >= mn.y && mp.y <= mx.y);
                dl->AddRectFilled(mn, mx, aida::ui::with_alpha(base, (hov ? 0.32f : 0.20f) * a), 6.f);
                dl->AddRect(mn, mx, aida::ui::with_alpha(base, (hov ? 0.95f : 0.55f) * a), 6.f, 0, 1.f);
                float tw = hdr_font->CalcTextSizeA(12.f, FLT_MAX, 0.f, label).x;
                dl->AddText(hdr_font, 12.f,
                            ImVec2(mn.x + (bw - tw) * 0.5f, mn.y + (bh - 12.f) * 0.5f),
                            aida::ui::with_alpha(base, a), label);
                if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) out = true;
            };
            hdr_button("Accept All", bx_accept, th.success, want_accept_all);
            hdr_button("Reject All", bx_reject, th.error, want_reject_all);
            ImGui::PopID();
        }

        struct vis_row_t {
            int hunk = -1;
            int line_in_hunk = -1;
            bool is_hunk_head = false;
            code_editor_widget::diff_line_kind_t kind = code_editor_widget::diff_line_kind_t::context;
            const std::string* text = nullptr;
            int old_no = -1;
            int new_no = -1;
        };
        std::vector<vis_row_t> rows;
        const size_t added_reserve = s_diff.total_added > 0
            ? static_cast<size_t>(s_diff.total_added)
            : 0;
        rows.reserve(s_diff.old_lines.size() + added_reserve + s_diff.hunks.size());

        {
            int old_idx = 0;
            int gap_ctx = 3;
            for (int hi = 0; hi >= 0 && static_cast<size_t>(hi) < s_diff.hunks.size(); ++hi) {
                const code_editor_widget::diff_hunk_t& h =
                    s_diff.hunks[static_cast<size_t>(hi)];

                int hunk_old_begin = h.old_count > 0 ? h.old_start : old_idx;
                if (h.old_count == 0) {
                    for (const auto& dl2 : h.lines)
                        if (dl2.kind == code_editor_widget::diff_line_kind_t::context && dl2.old_line >= 0) {
                            hunk_old_begin = dl2.old_line; break;
                        }
                }

                int ctx_from = std::max(old_idx, hunk_old_begin - gap_ctx);
                if (hi == 0) ctx_from = std::max(0, hunk_old_begin - gap_ctx);
                if (ctx_from > old_idx && old_idx > 0) {
                    vis_row_t sep;
                    sep.kind = code_editor_widget::diff_line_kind_t::context;
                    rows.push_back(sep);
                }
                for (int li = ctx_from; li >= 0 && li < hunk_old_begin &&
                                          static_cast<size_t>(li) < s_diff.old_lines.size(); ++li) {
                    vis_row_t r;
                    r.kind = code_editor_widget::diff_line_kind_t::context;
                    r.text = &s_diff.old_lines[static_cast<size_t>(li)];
                    r.old_no = li + 1;
                    r.new_no = -1;
                    rows.push_back(r);
                }

                vis_row_t head;
                head.hunk = hi;
                head.is_hunk_head = true;
                rows.push_back(head);

                for (int k = 0; k >= 0 && static_cast<size_t>(k) < h.lines.size(); ++k) {
                    const code_editor_widget::diff_line_t& dl2 =
                        h.lines[static_cast<size_t>(k)];
                    vis_row_t r;
                    r.hunk = hi;
                    r.line_in_hunk = k;
                    r.kind = dl2.kind;
                    r.text = &dl2.text;
                    r.old_no = dl2.old_line >= 0 ? dl2.old_line + 1 : -1;
                    r.new_no = dl2.new_line >= 0 ? dl2.new_line + 1 : -1;
                    rows.push_back(r);
                }

                int consumed = 0;
                for (const auto& dl2 : h.lines)
                    if (dl2.old_line >= 0) consumed++;
                old_idx = hunk_old_begin + consumed;
            }

            const size_t tail_to = old_idx >= 0
                ? (std::min)(s_diff.old_lines.size(), static_cast<size_t>(old_idx) + static_cast<size_t>(gap_ctx))
                : 0;
            if (old_idx >= 0 && static_cast<size_t>(old_idx) < s_diff.old_lines.size()) {
                for (size_t li = static_cast<size_t>(old_idx); li < tail_to; ++li) {
                    vis_row_t r;
                    r.kind = code_editor_widget::diff_line_kind_t::context;
                    r.text = &s_diff.old_lines[li];
                    r.old_no = static_cast<int>(li) + 1;
                    rows.push_back(r);
                }
            }
        }

        const float body_y0 = oy + hdr_h;
        const float body_h  = editor_h - hdr_h;
        const float diff_gutter_w = char_w * 11.f + 16.f;
        const float sign_x = ox + diff_gutter_w + 4.f;
        const float diff_text_x = sign_x + char_w * 1.6f;

        float content_h = static_cast<float>(rows.size()) * line_h;
        float diff_max_scroll = std::max(0.f, content_h - body_h + line_h);
        if (s_diff_scroll_target < 0.f) s_diff_scroll_target = 0.f;

        bool body_hovered = ImGui::IsMouseHoveringRect(
            ImVec2(ox, body_y0), ImVec2(ox + width, body_y0 + body_h));
        if (body_hovered) {
            float wheel = ImGui::GetIO().MouseWheel;
            if (wheel != 0.f) s_diff_scroll_target -= wheel * line_h * 3.f;
        }
        s_diff_scroll_target = std::max(0.f, std::min(s_diff_scroll_target, diff_max_scroll));
        s_scroll_y = aida::motion::smooth_lerp(s_scroll_y, s_diff_scroll_target, 20.f, dt);
        if (std::abs(s_diff_scroll_target - s_scroll_y) < 0.5f) s_scroll_y = s_diff_scroll_target;
        s_scroll_y = std::max(0.f, std::min(s_scroll_y, diff_max_scroll));

        dl->PushClipRect(ImVec2(ox, body_y0), ImVec2(ox + width, body_y0 + body_h), true);

        int diff_first = std::max(0, static_cast<int>(s_scroll_y / line_h) - 1);
        const int viewport_last = static_cast<int>((s_scroll_y + body_h) / line_h) + 1;
        int diff_last = -1;
        if (!rows.empty() && viewport_last >= 0) {
            diff_last = static_cast<int>((std::min)(rows.size() - 1,
                static_cast<size_t>(viewport_last)));
        }

        ImVec2 mp = ImGui::GetIO().MousePos;
        int new_hover_hunk = -1;
        std::vector<int> accept_clicked;
        std::vector<int> reject_clicked;

        for (int ri = diff_first; ri <= diff_last; ++ri) {
            if (ri < 0 || static_cast<size_t>(ri) >= rows.size()) break;
            const vis_row_t& r = rows[static_cast<size_t>(ri)];
            float ry = body_y0 + static_cast<float>(ri) * line_h - s_scroll_y;

            if (r.is_hunk_head) {
                if (r.hunk < 0 || static_cast<size_t>(r.hunk) >= s_diff.hunks.size()) continue;
                const code_editor_widget::diff_hunk_t& h =
                    s_diff.hunks[static_cast<size_t>(r.hunk)];
                dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + code_w, ry + line_h),
                                  aida::ui::with_alpha(th.accent_glow, 0.6f * a));
                char hb[64];
                snprintf(hb, sizeof(hb), "@@ -%d,%d +%d,%d @@",
                         h.old_start + 1, h.old_count, h.new_start + 1, h.new_count);
                dl->AddText(ImVec2(ox + 10.f, ry + 1.f),
                            aida::ui::with_alpha(th.accent_u32, a), hb);

                const char* state_label =
                    h.state == code_editor_widget::diff_hunk_state_t::accepted ? "ACCEPTED" :
                    h.state == code_editor_widget::diff_hunk_state_t::rejected ? "REJECTED" : nullptr;

                const float hbw = char_w * 7.f + 10.f;
                const float hbh = line_h - 4.f;
                float hby = ry + 2.f;
                float hbx_rej = ox + code_w - 12.f - hbw;
                float hbx_acc = hbx_rej - 6.f - hbw;

                if (state_label) {
                    ImU32 sc = h.state == code_editor_widget::diff_hunk_state_t::accepted
                                   ? th.success : th.error;
                    float tw = ImGui::CalcTextSize(state_label).x;
                    dl->AddText(ImVec2(ox + code_w - 12.f - tw, ry + 1.f),
                                aida::ui::with_alpha(sc, a), state_label);
                    if (mp.x >= ox && mp.x <= ox + code_w && mp.y >= ry && mp.y < ry + line_h)
                        new_hover_hunk = r.hunk;
                } else {
                    auto mini_btn = [&](const char* lbl, float bx, ImU32 base) -> bool {
                        ImVec2 mn(bx, hby), mx(bx + hbw, hby + hbh);
                        bool hov = (mp.x >= mn.x && mp.x <= mx.x && mp.y >= mn.y && mp.y <= mx.y);
                        dl->AddRectFilled(mn, mx, aida::ui::with_alpha(base, (hov ? 0.35f : 0.18f) * a), 4.f);
                        dl->AddRect(mn, mx, aida::ui::with_alpha(base, (hov ? 1.f : 0.5f) * a), 4.f, 0, 1.f);
                        float tw = ImGui::CalcTextSize(lbl).x;
                        dl->AddText(ImVec2(mn.x + (hbw - tw) * 0.5f, mn.y + (hbh - ImGui::GetFontSize()) * 0.5f),
                                    aida::ui::with_alpha(base, a), lbl);
                        return hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
                    };
                    if (mini_btn("Accept", hbx_acc, th.success)) accept_clicked.push_back(r.hunk);
                    if (mini_btn("Reject", hbx_rej, th.error))   reject_clicked.push_back(r.hunk);
                    if (mp.x >= ox && mp.x <= ox + code_w && mp.y >= ry && mp.y < ry + line_h)
                        new_hover_hunk = r.hunk;
                }
                continue;
            }

            if (!r.text) {
                float midy = ry + line_h * 0.5f;
                for (float dx = ox + 12.f; dx < ox + code_w - 12.f; dx += 8.f)
                    dl->AddLine(ImVec2(dx, midy), ImVec2(dx + 3.f, midy),
                                aida::ui::with_alpha(th.border_subtle, a), 1.f);
                continue;
            }

            bool is_add = r.kind == code_editor_widget::diff_line_kind_t::added;
            bool is_rem = r.kind == code_editor_widget::diff_line_kind_t::removed;

            bool hunk_resolved = false;
            ImU32 wash = 0;
            ImU32 bar  = 0;
            if (is_add) {
                wash = aida::ui::with_alpha(th.success, 0.14f * a);
                bar  = aida::ui::with_alpha(th.success, 0.9f * a);
            } else if (is_rem) {
                wash = aida::ui::with_alpha(th.error, 0.14f * a);
                bar  = aida::ui::with_alpha(th.error, 0.9f * a);
            }
            if (r.hunk >= 0 && static_cast<size_t>(r.hunk) < s_diff.hunks.size()) {
                const code_editor_widget::diff_hunk_t& h =
                    s_diff.hunks[static_cast<size_t>(r.hunk)];
                hunk_resolved = h.state != code_editor_widget::diff_hunk_state_t::pending;
                if (h.state == code_editor_widget::diff_hunk_state_t::rejected && is_add) {
                    wash = aida::ui::with_alpha(th.text_dim, 0.06f * a);
                    bar  = aida::ui::with_alpha(th.text_dim, 0.4f * a);
                } else if (h.state == code_editor_widget::diff_hunk_state_t::accepted && is_rem) {
                    wash = aida::ui::with_alpha(th.text_dim, 0.06f * a);
                    bar  = aida::ui::with_alpha(th.text_dim, 0.4f * a);
                }
            }

            if (wash) dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + code_w, ry + line_h), wash);
            if (bar)  dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + 3.f, ry + line_h), bar);

            if (r.hunk >= 0 && r.hunk == s_diff_hover_hunk && !hunk_resolved)
                dl->AddRectFilled(ImVec2(ox + 3.f, ry), ImVec2(ox + code_w, ry + line_h),
                                  aida::ui::with_alpha(th.accent_u32, 0.05f * a));

            char numbuf[24];
            if (r.old_no > 0)
                snprintf(numbuf, sizeof(numbuf), "%5d", r.old_no);
            else
                snprintf(numbuf, sizeof(numbuf), "     ");
            dl->AddText(ImVec2(ox + 6.f, ry + 1.f),
                        aida::ui::with_alpha(th.text_lineno, a), numbuf);
            if (r.new_no > 0)
                snprintf(numbuf, sizeof(numbuf), "%5d", r.new_no);
            else
                snprintf(numbuf, sizeof(numbuf), "     ");
            dl->AddText(ImVec2(ox + 6.f + char_w * 5.5f, ry + 1.f),
                        aida::ui::with_alpha(th.text_lineno, a), numbuf);

            const char* sign = is_add ? "+" : (is_rem ? "-" : " ");
            ImU32 sign_col = is_add ? aida::ui::with_alpha(th.success, a)
                          : is_rem ? aida::ui::with_alpha(th.error, a)
                          : aida::ui::with_alpha(th.text_dim, a);
            dl->AddText(ImVec2(sign_x, ry + 1.f), sign_col, sign);

            std::vector<syntax::token_t> toks;
            syntax::tokenize(*r.text, s_lang, toks);
            float tx = diff_text_x - s_scroll_x;
            float dim = (is_rem ? 0.92f : 1.f) * (hunk_resolved ? 0.55f : 1.f);
            for (const auto& tk : toks) {
                const size_t token_start = static_cast<size_t>(tk.start);
                const size_t token_length = static_cast<size_t>(tk.length);
                if (token_start > r.text->size() || token_length > r.text->size() - token_start) continue;
                if (tk.type == syntax::token_type::whitespace) {
                    for (size_t kk = 0; kk < token_length; ++kk) {
                        char c = (*r.text)[token_start + kk];
                        tx += (c == '\t')
                            ? char_w * static_cast<float>(editor_preferences::tab_size)
                            : char_w;
                    }
                    continue;
                }
                ImU32 col = tok_colors[static_cast<int>(tk.type)];
                col = aida::ui::with_alpha(col, dim);
                const char* ts = r.text->c_str() + token_start;
                dl->AddText(ImVec2(tx, ry + 1.f), col, ts, ts + token_length);
                if (is_rem)
                    dl->AddLine(ImVec2(tx, ry + line_h * 0.5f + 1.f),
	                                ImVec2(tx + static_cast<float>(token_length) * char_w,
	                                       ry + line_h * 0.5f + 1.f),
                                aida::ui::with_alpha(th.error, 0.5f * a), 1.f);
                tx += static_cast<float>(token_length) * char_w;
            }
        }

        dl->AddLine(ImVec2(ox + diff_gutter_w, body_y0),
                    ImVec2(ox + diff_gutter_w, body_y0 + body_h),
                    aida::ui::with_alpha(th.border_subtle, a), 1.f);

        dl->PopClipRect();

        if (content_h > body_h) {
            const float sb_w = 10.f;
            float track_x = ox + code_w - sb_w - 2.f;
            float track_y0 = body_y0 + 2.f;
            float track_h = body_h - 4.f;
            float ratio = body_h / content_h;
            float thumb_h = std::max(24.f, track_h * ratio);
            float range = content_h - body_h;
            float thumb_y = track_y0 + (range > 0.f ? (s_scroll_y / range) * (track_h - thumb_h) : 0.f);
            dl->AddRectFilled(ImVec2(track_x, thumb_y), ImVec2(track_x + sb_w, thumb_y + thumb_h),
                              aida::ui::with_alpha(th.text_secondary, 0.35f * a), 3.f);
        }

        s_diff_hover_hunk = new_hover_hunk;

        lk.unlock();
        for (int hi : accept_clicked)
            aida::ui::application_ui::execute_editor_hunk_action(hi,
                "editor.ai.accept_hunk", aida::ui::action_invocation_source_t::context_menu);
        for (int hi : reject_clicked)
            aida::ui::application_ui::execute_editor_hunk_action(hi,
                "editor.ai.reject_hunk", aida::ui::action_invocation_source_t::context_menu);
        if (want_accept_all)
            aida::ui::application_ui::execute_action(
                "editor.ai.accept_all", aida::ui::action_invocation_source_t::context_menu);
        if (want_reject_all)
            aida::ui::application_ui::execute_action(
                "editor.ai.reject_all", aida::ui::action_invocation_source_t::context_menu);
        lk.lock();

        {
            char buf[160];
            snprintf(buf, sizeof(buf), "%s%s  -  AI Edit (+%d -%d)",
                     current_document().filename.empty() ? "Untitled" : current_document().filename.c_str(),
                     current_document().dirty ? " *" : "",
                     s_diff.total_added, s_diff.total_removed);
            globals::ui::status_file_info = buf;
        }

        finalize_diff_if_resolved_locked();

        ImGui::SetWindowFontScale(prev_font_scale);
        if (code_font) ImGui::PopFont();
        return;
    }

    s_diff_scroll_target = -1.f;

    bool mouse_over_find_bar = false;
    if (s_find.visible) {
        const float fb_w = 420.f;
        const float fb_h = s_find.replace_mode ? (28.f * 2 + 5.f * 3) : (28.f + 5.f * 2);
        const float fb_x = ox + width - fb_w - 20.f;
        const float fb_y = wpos.y + pos_y + 2.f;
        ImVec2 mp = ImGui::GetIO().MousePos;
        mouse_over_find_bar = (mp.x >= fb_x && mp.x <= fb_x + fb_w && mp.y >= fb_y && mp.y <= fb_y + fb_h);
    }

    bool hovered = ImGui::IsMouseHoveringRect(bb.Min, bb.Max);
    if (mouse_over_find_bar) hovered = false;

    bool input_blocked = (file_tabs::pending_close_idx >= 0)
        || globals::ui::process_attach_open
        || globals::ui::driver_status_open
        || globals::ui::shortcuts_dialog_open
        || globals::ui::mcp_servers_dialog_open
        || globals::ui::command_palette_open
        || ImGui::IsPopupOpen("##aida_editor_context");
    if (input_blocked) hovered = false;

    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        ImGui::SetActiveID(id, ImGui::GetCurrentWindow());
        ImGui::SetFocusID(id, ImGui::GetCurrentWindow());
        s_has_focus = true;
    }
    if (s_has_focus && !hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        s_has_focus = false;
        if (ImGui::GetActiveID() == id)
            ImGui::ClearActiveID();
    }
    if (s_has_focus)
        s_focused_document_id = s_active_document_id;
    aida::ui::application_ui::set_editor_focus(s_has_focus, s_find_has_focus);

    if (s_has_focus && s_focus_anim.is_finished() && s_focus_anim.progress < 1.f)
        s_focus_anim.start(0.10f, aida::motion::ease::out_quint);
    if (!s_has_focus && s_focus_anim.is_finished() && s_focus_anim.progress > 0.f)
        s_focus_anim.start_reverse(0.18f, aida::motion::ease::in_quint);
    s_focus_anim.tick(dt);
    float focus_blend = s_focus_anim.eased();

    if (hovered) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_TextInput);
        float wheel  = ImGui::GetIO().MouseWheel;
        float wheelh = ImGui::GetIO().MouseWheelH;
        bool  h_intent = ImGui::GetIO().KeyShift;
        if (h_intent && wheel != 0.f && !word_wrap_on) {
            s_scroll_x -= wheel * char_w * 6.f;
        } else if (wheel != 0.f) {
            s_target_scroll_y -= wheel * line_h * 3.f;
        }
        if (wheelh != 0.f && !word_wrap_on)
            s_scroll_x -= wheelh * char_w * 6.f;
        if (s_scroll_x > s_max_scroll_x) s_scroll_x = s_max_scroll_x;
        if (s_scroll_x < 0.f) s_scroll_x = 0.f;
    }

    int first_row = std::max(0, static_cast<int>(s_scroll_y / line_h) - 1);
    int last_row  = std::min(n_lines - 1, static_cast<int>((s_scroll_y + editor_h) / line_h) + 1);
    tokenize_range(first_row - 8, last_row + 8);

    dl->PushClipRect(ImVec2(ox, oy), ImVec2(ox + code_w, oy + editor_h), true);

	if (show_ln) {
        dl->AddLine(ImVec2(ox + gutter_w, oy),
                    ImVec2(ox + gutter_w, oy + editor_h),
                    aida::ui::with_alpha(th.border_subtle, a), 1.f);
    }

    if (editor_preferences::highlight_current_line && focus_blend > 0.001f) {
        float cy = oy + static_cast<float>(s_sel.caret_line) * line_h - s_scroll_y;
        if (cy >= oy - line_h && cy <= oy + editor_h) {
            dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + code_w, cy + line_h),
                              aida::ui::with_alpha(th.hover_wash, focus_blend * 0.85f * a));
            dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + 2.f, cy + line_h),
                              aida::ui::with_alpha(th.accent_u32, focus_blend * 0.55f * a));
        }
    }

    if (s_sel.caret_line != s_prev_caret_line || s_sel.caret_col != s_prev_caret_col) {
        if (s_caret_move_anim.is_finished())
            s_caret_move_anim.start(0.120f, aida::motion::ease::out_quint);
        else
            s_caret_move_anim.progress = 0.f;
    }
    s_caret_move_anim.tick(dt);
    if (s_caret_move_anim.active) {
        float pe = s_caret_move_anim.eased();
        float prev_x = ox + text_x0 + static_cast<float>(s_prev_caret_col) * char_w - s_scroll_x;
        float prev_y = oy + static_cast<float>(s_prev_caret_line) * line_h - s_scroll_y;
        float cur_x  = ox + text_x0 + static_cast<float>(s_sel.caret_col) * char_w - s_scroll_x;
        float cur_y  = oy + static_cast<float>(s_sel.caret_line) * line_h - s_scroll_y;
        float gx = prev_x + (cur_x - prev_x) * pe;
        float gy = prev_y + (cur_y - prev_y) * pe;
        if (gy >= oy - line_h && gy <= oy + editor_h) {
            dl->AddRectFilled(ImVec2(gx - 2.f, gy), ImVec2(gx + 6.f, gy + line_h),
                aida::ui::with_alpha(th.accent_glow, (1.f - pe) * a));
        }
    }
    if (s_caret_move_anim.is_finished() && s_caret_move_anim.progress >= 0.999f) {
        s_prev_caret_line = s_sel.caret_line;
        s_prev_caret_col  = s_sel.caret_col;
    }

    {
        const int max_indent_render = 16;
        int tab = std::max(1, editor_preferences::tab_size);
        for (int i = first_row; i <= last_row; i++) {
            const std::string& ln = line_at(i);
            int leading = 0;
            for (char c : ln) {
                if (c == ' ') leading++;
                else if (c == '\t') leading += tab;
                else break;
            }
            if (leading <= 0) continue;
            int levels = std::min(max_indent_render, leading / tab);
            float ly = oy + static_cast<float>(i) * line_h - s_scroll_y;
            for (int lv = 1; lv <= levels; ++lv) {
                float gx = ox + text_x0 + static_cast<float>(lv * tab) * char_w
                    - s_scroll_x - char_w * 0.5f;
                bool active = (s_sel.caret_line == i) && (lv * tab <= leading);
                ImU32 col = active ? aida::ui::with_alpha(th.accent_dim, 0.45f * a)
                                   : aida::ui::with_alpha(th.border_subtle, 0.6f * a);
                dl->AddLine(ImVec2(gx, ly), ImVec2(gx, ly + line_h), col, 1.f);
            }
        }
    }


    if (s_sel.has_selection()) {
        int l0, c0, l1, c1;
        selection_ordered(l0, c0, l1, c1);
        ImU32 sel_col = aida::ui::with_alpha(th.selection, a);
        for (int i = std::max(first_row, l0); i <= std::min(last_row, l1); i++) {
            float ly = oy + static_cast<float>(i) * line_h - s_scroll_y;
            float sx0, sx1;
            if (i == l0 && i == l1) {
                sx0 = ox + text_x0 + static_cast<float>(c0) * char_w - s_scroll_x;
                sx1 = ox + text_x0 + static_cast<float>(c1) * char_w - s_scroll_x;
            } else if (i == l0) {
                sx0 = ox + text_x0 + static_cast<float>(c0) * char_w - s_scroll_x;
                sx1 = ox + text_x0 + static_cast<float>(line_length(i)) * char_w
                    - s_scroll_x + char_w;
            } else if (i == l1) {
                sx0 = ox + text_x0 - s_scroll_x;
                sx1 = ox + text_x0 + static_cast<float>(c1) * char_w - s_scroll_x;
            } else {
                sx0 = ox + text_x0 - s_scroll_x;
                sx1 = ox + text_x0 + static_cast<float>(line_length(i)) * char_w
                    - s_scroll_x + char_w;
            }
            sx0 = std::max(sx0, ox + text_x0);
            sx1 = std::min(sx1, ox + code_w - 4.f);
            if (sx1 > sx0) {
                dl->AddRectFilled(ImVec2(sx0, ly), ImVec2(sx1, ly + line_h), sel_col);
            }
        }
    }


    if (s_find.visible && !s_find.match_positions.empty()) {
        if (s_active_match_for != s_find.current_match) {
            s_active_match_for = s_find.current_match;
            s_match_pulse.start(aida::motion::dur::md, aida::motion::ease::out_quint);
        }
        s_match_pulse.tick(dt);
        ImU32 match_col  = aida::ui::with_alpha(th.accent_dim, 0.32f * a);
        float pulse = aida::ui::clock::pulse(1.5f, 0.55f, 1.f);
        ImU32 active_col = aida::ui::with_alpha(th.accent_u32, 0.55f * pulse * a);
        for (int mi = 0; mi >= 0 && static_cast<size_t>(mi) < s_find.match_positions.size(); mi++) {
            const auto& m = s_find.match_positions[static_cast<size_t>(mi)];
            int ml = m.line;
            int mc = m.col;
            int mlen = m.length;
            if (ml < first_row || ml > last_row) continue;
            float my = oy + static_cast<float>(ml) * line_h - s_scroll_y;
            float mx0 = ox + text_x0 + static_cast<float>(mc) * char_w - s_scroll_x;
            float mx1 = mx0 + static_cast<float>(mlen) * char_w;
            mx1 = std::min(mx1, ox + code_w - 4.f);
            if (mx1 <= mx0) continue;
            bool is_active = (mi == s_find.current_match);
            dl->AddRectFilled(ImVec2(mx0, my), ImVec2(mx1, my + line_h),
                              is_active ? active_col : match_col);
            if (is_active) {
                dl->AddRect(ImVec2(mx0 - 1.f, my),
                            ImVec2(mx1 + 1.f, my + line_h),
                            aida::ui::with_alpha(th.accent_u32, 0.85f * pulse * a),
                            2.f, 0, 1.2f);
                aida::ui::blur::render_inner_glow(dl,
                    ImVec2(mx0 - 2.f, my - 1.f),
                    ImVec2(mx1 + 2.f, my + line_h + 1.f),
                    2.f, aida::ui::with_alpha(th.accent_glow, a), 2);
            }
        }
    }


    for (int i = first_row; i <= last_row; i++) {
        float y = oy + static_cast<float>(i) * line_h - s_scroll_y;


        if (i & 1)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + gutter_w, y + line_h - 1.f),
                              aida::ui::with_alpha(th.text_primary, 0.012f * a));

		if (source_gutter_w > 0.f && source_markers.markers) {
			const auto found = std::lower_bound(source_markers.markers->begin(),
				source_markers.markers->end(), static_cast<std::uint32_t>(i + 1),
				[](const source_debug_service::line_marker_t& marker,
					std::uint32_t line) { return marker.line < line; });
			if (found != source_markers.markers->end() && found->line ==
				static_cast<std::uint32_t>(i + 1)) {
				ImU32 marker_color = th.text_dim;
				switch (found->state) {
				case source_debug_service::binding_state_t::bound: marker_color = th.error; break;
				case source_debug_service::binding_state_t::pending: marker_color = th.warning; break;
				case source_debug_service::binding_state_t::unbound: marker_color = th.text_secondary; break;
				case source_debug_service::binding_state_t::stale: marker_color = th.warning; break;
				case source_debug_service::binding_state_t::error: marker_color = th.error; break;
				}
				dl->AddCircleFilled(ImVec2(ox + source_gutter_w * 0.5f,
					y + line_h * 0.5f), 4.25f,
					aida::ui::with_alpha(marker_color, a));
				dl->AddCircle(ImVec2(ox + source_gutter_w * 0.5f,
					y + line_h * 0.5f), 4.25f,
					aida::ui::with_alpha(th.text_primary, 0.55f * a));
			}
		}


        if (show_ln) {
            char ln_buf[8];
            snprintf(ln_buf, sizeof(ln_buf), "%5d", i + 1);
            ImU32 ln_col = (i == s_sel.caret_line)
                ? aida::ui::with_alpha(th.accent_u32, 0.85f * a)
                : aida::ui::with_alpha(th.text_lineno, a);
			dl->AddText(ImVec2(ox + source_gutter_w + 4.f, y + 1.f), ln_col, ln_buf);
        }


        if (i >= 0 && i < static_cast<int>(s_cache.tokens.size()) &&
            i < static_cast<int>(s_cache.lines.size())) {
            const std::size_t line_idx = static_cast<std::size_t>(i);
            const auto& toks = current_document().mapped_source
                ? current_document().mapped_tokens[i]
                : s_cache.tokens[line_idx];
            const auto& ln = line_at(i);
            float tx = ox + text_x0 - s_scroll_x;

            for (auto& tok : toks) {
                const std::size_t token_start = static_cast<std::size_t>(tok.start);
                const std::size_t token_length = static_cast<std::size_t>(tok.length);
                if (token_start > ln.size() || token_length > ln.size() - token_start) continue;
                if (tok.type == syntax::token_type::whitespace) {

                    for (uint32_t k = 0; k < tok.length; k++) {
                        char c = ln[token_start + static_cast<std::size_t>(k)];
                        if (c == '\t')
                            tx += char_w * static_cast<float>(editor_preferences::tab_size);
                        else
                            tx += char_w;
                    }
                    continue;
                }

                ImU32 col = tok_colors[static_cast<std::size_t>(tok.type)];
                const char* ts = ln.c_str() + static_cast<std::ptrdiff_t>(token_start);
                const char* te = ts + static_cast<std::ptrdiff_t>(token_length);


                float tok_w = static_cast<float>(token_length) * char_w;
                if (tx + tok_w < ox + text_x0 || tx > ox + code_w) {
                    tx += tok_w;
                    continue;
                }

                dl->AddText(ImVec2(tx, y + 1.f), col, ts, te);
                tx += tok_w;
            }
        }
    }


    if (editor_preferences::bracket_match && s_has_focus && !s_sel.has_selection()) {
        int br_open_line = -1, br_open_col = -1;
        const std::string& cl = line_at(s_sel.caret_line);
        char here   = (s_sel.caret_col >= 0 && s_sel.caret_col < static_cast<int>(cl.size()))
                          ? cl[static_cast<std::size_t>(s_sel.caret_col)] : 0;
        char before = (s_sel.caret_col > 0 && s_sel.caret_col - 1 < static_cast<int>(cl.size()))
                          ? cl[static_cast<std::size_t>(s_sel.caret_col - 1)] : 0;
        if (is_open_bracket(here) || is_close_bracket(here)) {
            br_open_line = s_sel.caret_line; br_open_col = s_sel.caret_col;
        } else if (is_open_bracket(before) || is_close_bracket(before)) {
            br_open_line = s_sel.caret_line; br_open_col = s_sel.caret_col - 1;
        }
        if (br_open_line >= 0) {
            int mline = -1, mcol = -1;
            char mch = 0;
            bool found = find_matching_bracket(br_open_line, br_open_col, mline, mcol, mch);
            ImU32 box_col = found ? aida::ui::with_alpha(th.accent_u32, 0.55f * a)
                                  : aida::ui::with_alpha(th.error, 0.55f * a);
            ImU32 fill_col = found ? aida::ui::with_alpha(th.accent_glow, a)
                                   : aida::ui::with_alpha(th.error, 0.18f * a);
            auto draw_box = [&](int bl, int bc) {
                float bx = ox + text_x0 + static_cast<float>(bc) * char_w - s_scroll_x;
                float by = oy + static_cast<float>(bl) * line_h - s_scroll_y;
                if (by < oy - line_h || by > oy + editor_h) return;
                dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + char_w, by + line_h), fill_col, 2.f);
                dl->AddRect(ImVec2(bx, by), ImVec2(bx + char_w, by + line_h), box_col, 2.f, 0, 1.f);
            };
            draw_box(br_open_line, br_open_col);
            if (found) draw_box(mline, mcol);
        }
    }


    if (s_has_focus) {
        float caret_alpha_pulse = aida::ui::clock::pulse(2.0f, 0.30f, 1.0f);
        float cx = ox + text_x0 + static_cast<float>(s_sel.caret_col) * char_w - s_scroll_x;
        float cy = oy + static_cast<float>(s_sel.caret_line) * line_h - s_scroll_y;
        if (cy >= oy - line_h && cy <= oy + editor_h) {
            dl->AddLine(ImVec2(cx, cy), ImVec2(cx, cy + line_h),
                        aida::ui::with_alpha(th.accent_hover, caret_alpha_pulse * a), 1.5f);
            dl->AddLine(ImVec2(cx, cy + line_h - 1.f),
                        ImVec2(cx, cy + line_h),
                        aida::ui::with_alpha(th.accent_u32, caret_alpha_pulse * a * 0.85f), 2.f);
        }
    }


#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const bool ghost_text_enabled = aida::preview::editor::ghost_text_enabled;
#else
    const bool ghost_text_enabled = g_sa_settings.ghost_text_enabled;
#endif
    if (ghost_text_enabled && s_has_focus && !current_document().read_only) {

        {
            std::lock_guard<std::mutex> lk(s_ghost_mtx);
            if (s_ghost_has_pending) {
                s_ghost_text = std::move(s_ghost_pending);
                s_ghost_pending.clear();
                s_ghost_has_pending = false;
                s_ghost_requesting = false;
            }
        }


        if (s_sel.caret_line != s_ghost_trigger_line || s_sel.caret_col != s_ghost_trigger_col) {
            s_ghost_debounce = 0.f;
            s_ghost_trigger_line = s_sel.caret_line;
            s_ghost_trigger_col  = s_sel.caret_col;
            s_ghost_text.clear();
        }


        if (s_ghost_text.empty() && !s_ghost_requesting && s_ghost_debounce < 0.5f) {
            s_ghost_debounce += dt;
            if (s_ghost_debounce >= 0.5f && n_lines > 0) {

                int ctx_start = (std::max)(0, s_sel.caret_line - 20);
                std::string context;
                context.reserve(2048);
                for (int i = ctx_start; i < n_lines && i <= s_sel.caret_line; i++) {
                    const std::string& ln = line_at(i);
                    if (i == s_sel.caret_line) {
                        int col = std::clamp(s_sel.caret_col, 0, static_cast<int>(ln.size()));
                        context.append(ln, 0, static_cast<std::size_t>(col));
                    } else {
                        context += ln;
                        context += '\n';
                    }
                }

                if (!context.empty()) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                    s_ghost_requesting = true;
                    std::string result = aida::preview::editor::complete(context);
                    {
                        std::lock_guard<std::mutex> lk(s_ghost_mtx);
                        s_ghost_pending = std::move(result);
                        s_ghost_has_pending = true;
                    }
                    aida::preview::editor::record("ghost_completion", context);
#else
                    if (g_sa_ai_client) {
                    uint64_t gt = standalone_license::inline_gate_check(
                        standalone_license::gate_editor_ghost);
                    if (standalone_license::verify_gate_token(
                            standalone_license::gate_editor_ghost, gt) < 0.5) {
                        s_ghost_debounce = 0.f;
                    } else {
                    s_ghost_requesting = true;
                    aida::infra::executor::submission_t sub;
                    sub.owner_subsystem = "code_editor";
                    sub.label = "code_editor.ghost_completion";
                    sub.thread_class = "bounded_task";
                    sub.domain = aida::infra::executor::domain_t::feature_worker;
                    sub.priority = 3;
                    const std::weak_ptr<document_runtime_t> target_document =
                        document_handle(s_active_document_id);
                    sub.body = [context, target_document]() {
                        std::string prompt = "Complete the following code. Output ONLY the completion text (the part that comes after the cursor), nothing else. No explanation, no markdown. If there's nothing meaningful to suggest, output nothing.\n\n```\n" + context + "```";
                        std::vector<std::pair<std::string, std::string>> empty_history;
                        std::string result = g_sa_ai_client->chat_blocking(prompt, empty_history);

                        if (result.size() > 6 && result.substr(0, 3) == "```") {
                            auto nl = result.find('\n');
                            if (nl != std::string::npos) result = result.substr(nl + 1);
                            if (result.size() >= 3 && result.substr(result.size()-3) == "```")
                                result.resize(result.size()-3);
                        }

                        auto nl = result.find('\n');
                        if (nl != std::string::npos) result.resize(nl);

                        while (!result.empty() && (result.back() == ' ' || result.back() == '\t' || result.back() == '\r'))
                            result.pop_back();

                        if (result.find("Error:") == 0 || result.find("error") == 0 ||
                            result.find("{\"error\"") != std::string::npos ||
                            result.find("API returned status") != std::string::npos) {
                            result.clear();
                        }

                        if (const auto target = target_document.lock()) {
                            std::lock_guard<std::mutex> lk(s_ghost_mtx);
                            target->ghost_pending = std::move(result);
                            target->ghost_has_pending = true;
                        }
                    };
                    if (!aida::infra::executor::submit(std::move(sub)).submitted)
                        s_ghost_requesting = false;
                    }
                    }
#endif
                }
            }
        }


        if (!s_ghost_text.empty()) {
            if (s_ghost_visible_for_line != s_sel.caret_line || s_ghost_visible_for_col != s_sel.caret_col) {
                s_ghost_visible_for_line = s_sel.caret_line;
                s_ghost_visible_for_col  = s_sel.caret_col;
                s_ghost_in.start(0.150f, aida::motion::ease::out_quint);
            }
            s_ghost_in.tick(dt);
            s_ghost_absorb.tick(dt);
            float gv = s_ghost_in.eased();
            float absorb = s_ghost_absorb.is_finished() ? 0.f : (1.f - s_ghost_absorb.eased());
            float vis_alpha = (gv * 0.45f + 0.05f) * a * (1.f - s_ghost_absorb.eased() * 0.6f);
            float gx = ox + text_x0 + static_cast<float>(s_sel.caret_col) * char_w - s_scroll_x;
            float gy = oy + static_cast<float>(s_sel.caret_line) * line_h - s_scroll_y;
            if (gy >= oy - line_h && gy <= oy + editor_h) {
                ImU32 ghost_col = aida::ui::with_alpha(th.text_dim, vis_alpha);
                dl->AddText(ImVec2(gx, gy + 1.f), ghost_col, s_ghost_text.c_str());
            }
            (void)absorb;

            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
                s_ghost_absorb.start(0.18f, aida::motion::ease::out_quint);
                insert_text_at_caret(s_ghost_text);
                s_ghost_text.clear();
                s_ghost_visible_for_line = -1;
                s_ghost_visible_for_col  = -1;
                ghost_consumed_tab = true;
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
                s_ghost_text.clear();
                s_ghost_in.reset();
                s_ghost_visible_for_line = -1;
                s_ghost_visible_for_col  = -1;
            }
        } else {
            s_ghost_visible_for_line = -1;
            s_ghost_visible_for_col  = -1;
        }
    }


    if ((s_has_focus || hovered) && !input_blocked) {
        ImVec2 mp = ImGui::GetIO().MousePos;
        bool in_editor = mp.x >= ox && mp.x < ox + code_w - 14.f &&
            mp.y >= oy && mp.y <= oy + editor_h;
        bool in_text = mp.x >= ox + text_x0 && mp.x < ox + code_w - 14.f && mp.y >= oy && mp.y <= oy + editor_h;
		if (mouse_over_find_bar) {
			in_editor = false;
			in_text = false;
		}
		const bool in_source_gutter = source_gutter_w > 0.f &&
			mp.x >= ox && mp.x < ox + source_gutter_w &&
			mp.y >= oy && mp.y <= oy + editor_h;
		if (in_source_gutter) {
			const int marker_line = clamp_line(static_cast<int>(
				(mp.y - oy + s_scroll_y) / line_h));
			if (source_markers.markers) {
				const auto found = std::lower_bound(source_markers.markers->begin(),
					source_markers.markers->end(),
					static_cast<std::uint32_t>(marker_line + 1),
					[](const source_debug_service::line_marker_t& marker,
						std::uint32_t line) { return marker.line < line; });
				if (found != source_markers.markers->end() && found->line ==
					static_cast<std::uint32_t>(marker_line + 1))
					ImGui::SetTooltip("Source breakpoint: %s\n%s\nF9 toggles this definition",
						source_debug_service::binding_state_label(found->state),
						found->detail.c_str());
				else
					ImGui::SetTooltip("Set persistent source breakpoint at line %d (F9)",
						marker_line + 1);
			} else {
				ImGui::SetTooltip("Set persistent source breakpoint at line %d (F9)",
					marker_line + 1);
			}
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				s_sel.anchor_line = s_sel.caret_line = marker_line;
				s_sel.anchor_col = s_sel.caret_col = 0;
				s_sel.active = false;
				std::string ignored;
				static_cast<void>(source_debug_service::request_toggle(
					current_document().filepath,
					static_cast<std::uint32_t>(marker_line + 1), &ignored));
			}
		}

		if (in_text && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            int ml, mc;
            screen_to_linecol(mp.x, mp.y, ox, oy, gutter_w, line_h, char_w, ml, mc);


            float now = static_cast<float>(ImGui::GetTime());
            if (now - s_last_click_time < 0.3f) s_click_count++;
            else s_click_count = 1;
            s_last_click_time = now;

            if (s_click_count == 2) {
                int ws, we;
                word_bounds(ml, mc, ws, we);
                s_sel.anchor_line = s_sel.caret_line = ml;
                s_sel.anchor_col = ws;
                s_sel.caret_col  = we;
                s_sel.active = true;
            } else if (s_click_count >= 3) {

                s_sel.anchor_line = s_sel.caret_line = ml;
                s_sel.anchor_col = 0;
                s_sel.caret_col  = line_length(ml);
                s_sel.active = true;
            } else {
                bool shift = ImGui::GetIO().KeyShift;
                if (!shift) {
                    s_sel.anchor_line = ml;
                    s_sel.anchor_col  = mc;
                }
                s_sel.caret_line = ml;
                s_sel.caret_col  = mc;
                s_sel.active = shift;
                s_mouse_selecting = true;
            }
            s_blink_timer = 0.f; s_blink_on = true;
            break_undo_coalescing();
        }

        if (s_mouse_selecting && !s_sb_dragging && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            int ml, mc;
            screen_to_linecol(mp.x, mp.y, ox, oy, gutter_w, line_h, char_w, ml, mc);
            s_sel.caret_line = ml;
            s_sel.caret_col  = mc;
            s_sel.active = true;
        }

        if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
            s_mouse_selecting = false;

        const bool pointer_context = in_editor && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
        const bool keyboard_context = s_has_focus &&
            (ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
             (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)));
        if (pointer_context) {
            if (!s_sel.has_selection()) {
                int line = 0;
                int column = 0;
                screen_to_linecol(mp.x, mp.y, ox, oy, gutter_w, line_h, char_w, line, column);
                s_sel.anchor_line = s_sel.caret_line = line;
                s_sel.anchor_col = s_sel.caret_col = column;
                s_sel.active = false;
            }
            s_has_focus = true;
            aida::ui::application_ui::set_editor_focus(true, false);
            aida::ui::application_ui::open_editor_context_menu(
                aida::ui::context_menu_open_origin_t::pointer);
        } else if (keyboard_context) {
            aida::ui::application_ui::open_editor_context_menu(
                ImGui::IsKeyPressed(ImGuiKey_Menu, false)
                    ? aida::ui::context_menu_open_origin_t::menu_key
                    : aida::ui::context_menu_open_origin_t::shift_f10);
        }
    }

    aida::ui::application_ui::render_editor_context_menu();


    if (s_has_focus && !input_blocked && !s_find_has_focus) {
        auto& io = ImGui::GetIO();
        bool ctrl  = io.KeyCtrl;
        bool shift = io.KeyShift;


        ImGui::SetKeyOwner(ImGuiKey_Enter, id);
        ImGui::SetKeyOwner(ImGuiKey_KeypadEnter, id);
        ImGui::SetKeyOwner(ImGuiKey_Tab, id);
        ImGui::SetKeyOwner(ImGuiKey_Escape, id);


        aida::ui::application_ui::process_editor_shortcuts();

        auto move_caret = [&](int new_line, int new_col) {
            if (shift) s_sel.active = true;
            else { s_sel.active = false; s_sel.anchor_line = new_line; s_sel.anchor_col = new_col; }
            s_sel.caret_line = new_line;
            s_sel.caret_col  = new_col;
            s_blink_timer = 0.f; s_blink_on = true;
            break_undo_coalescing();
            ensure_caret_visible(editor_h, line_h);
        };

        if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow, true)) {
            int nl = s_sel.caret_line, nc = s_sel.caret_col;
            if (ctrl) {
                if (nc == 0 && nl > 0) {
                    nl--;
                    nc = line_length(nl);
                } else if (nc > 0) {
                    const std::string& ln = line_at(nl);
                    while (nc > 0 && !is_word_char(ln[static_cast<std::size_t>(nc - 1)])) nc--;
                    while (nc > 0 && is_word_char(ln[static_cast<std::size_t>(nc - 1)])) nc--;
                }
            } else if (nc > 0) {
                const std::string& ln = line_at(nl);
                nc--;
                while (nc > 0 &&
                       (static_cast<unsigned char>(ln[static_cast<std::size_t>(nc)]) & 0xC0) == 0x80)
                    nc--;
            } else if (nl > 0) {
                nl--; nc = line_length(nl);
            }
            move_caret(nl, nc);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_RightArrow, true)) {
            int nl = s_sel.caret_line, nc = s_sel.caret_col;
            if (ctrl) {
                if (nc >= line_length(nl) && nl < line_count() - 1) {
                    nl++;
                    nc = 0;
                } else {
                    const std::string& ln = line_at(nl);
                    int len = static_cast<int>(ln.size());
                    nc = std::max(0, nc);
                    while (nc < len && is_word_char(ln[static_cast<std::size_t>(nc)])) nc++;
                    while (nc < len && !is_word_char(ln[static_cast<std::size_t>(nc)])) nc++;
                }
            } else if (nc < line_length(nl)) {
                const std::string& ln = line_at(nl);
                int len = static_cast<int>(ln.size());
                nc++;
                while (nc < len &&
                       (static_cast<unsigned char>(ln[static_cast<std::size_t>(nc)]) & 0xC0) == 0x80)
                    nc++;
            } else if (nl < line_count() - 1) {
                nl++; nc = 0;
            }
            move_caret(nl, nc);
        }
        else if (!io.KeyAlt && !(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
            int nl = std::max(0, s_sel.caret_line - 1);
            int nc = clamp_col(nl, s_sel.caret_col);
            move_caret(nl, nc);
        }
        else if (!io.KeyAlt && !(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
            int nl = std::min(line_count() - 1, s_sel.caret_line + 1);
            int nc = clamp_col(nl, s_sel.caret_col);
            move_caret(nl, nc);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_Home, true)) {
            if (ctrl) move_caret(0, 0);
            else move_caret(s_sel.caret_line, 0);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_End, true)) {
            if (ctrl) move_caret(line_count() - 1, line_length(line_count() - 1));
            else move_caret(s_sel.caret_line, line_length(s_sel.caret_line));
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_PageUp, false)) {
            int page = std::max(1, static_cast<int>(editor_h / line_h) - 2);
            int nl = std::max(0, s_sel.caret_line - page);
            move_caret(nl, clamp_col(nl, s_sel.caret_col));
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) {
            int page = std::max(1, static_cast<int>(editor_h / line_h) - 2);
            int nl = std::min(line_count() - 1, s_sel.caret_line + page);
            move_caret(nl, clamp_col(nl, s_sel.caret_col));
        }


        if (!current_document().read_only && !ctrl && ImGui::IsKeyPressed(ImGuiKey_Enter, true) &&
            !(autocomplete::popup_visible && !autocomplete::matches.empty())) {

            std::string indent;
            char prev_ch = 0;
            char next_ch = 0;
            if (s_sel.caret_line >= 0 && s_sel.caret_line < static_cast<int>(s_cache.lines.size())) {
                auto& ln = s_cache.lines[static_cast<std::size_t>(s_sel.caret_line)];
                for (char c : ln) {
                    if (c == ' ' || c == '\t') indent += c;
                    else break;
                }
                int cc = clamp_col(s_sel.caret_line, s_sel.caret_col);
                if (cc > 0 && cc - 1 < static_cast<int>(ln.size())) prev_ch = ln[static_cast<std::size_t>(cc - 1)];
                if (cc >= 0 && cc < static_cast<int>(ln.size())) next_ch = ln[static_cast<std::size_t>(cc)];
            }
            bool between_pair = (prev_ch == '{' && next_ch == '}') ||
                                (prev_ch == '(' && next_ch == ')') ||
                                (prev_ch == '[' && next_ch == ']');
            break_undo_coalescing();
            if (between_pair) {
                std::string extra(static_cast<std::size_t>(std::max(1, editor_preferences::tab_size)), ' ');
                insert_text_at_caret("\n" + indent + extra + "\n" + indent);
                int target_line = s_sel.caret_line - 1;
                s_sel.caret_line = s_sel.anchor_line = clamp_line(target_line);
                s_sel.caret_col  = s_sel.anchor_col  =
                    static_cast<int>(indent.size()) + static_cast<int>(extra.size());
                s_sel.active = false;
            } else {
                if (prev_ch == '{' || prev_ch == '(' || prev_ch == '[' ||
                    prev_ch == ':')
                    indent += std::string(static_cast<std::size_t>(std::max(1, editor_preferences::tab_size)), ' ');
                insert_text_at_caret("\n" + indent);
            }
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!current_document().read_only && ctrl && ImGui::IsKeyPressed(ImGuiKey_Backspace, true)) {
            if (s_sel.has_selection()) {
                delete_selection();
            } else if (s_sel.caret_col > 0) {
                push_undo();
                const int caret_line = clamp_line(s_sel.caret_line);
                auto& ln = s_cache.lines[static_cast<std::size_t>(caret_line)];
                int col = clamp_col(caret_line, s_sel.caret_col);
                int start = col;

                while (start > 0 && (ln[static_cast<std::size_t>(start - 1)] == ' ' || ln[static_cast<std::size_t>(start - 1)] == '\t'))
                    start--;

                if (start > 0) {

                    while (start > 0 && (isalnum(static_cast<unsigned char>(ln[static_cast<std::size_t>(start - 1)])) || ln[static_cast<std::size_t>(start - 1)] == '_'))
                        start--;
                }

                if (start == col)
                    start = col - 1;
                ln.erase(static_cast<std::size_t>(start), static_cast<std::size_t>(col - start));
                s_sel.caret_col = s_sel.anchor_col = start;
                rebuild_buffer_from_lines();
            } else if (s_sel.caret_line > 0) {
                push_undo_range(s_sel.caret_line - 1, s_sel.caret_line);
                int prev = s_sel.caret_line - 1;
                const std::size_t prev_idx = static_cast<std::size_t>(prev);
                const std::size_t caret_idx = static_cast<std::size_t>(s_sel.caret_line);
                int prev_len = static_cast<int>(s_cache.lines[prev_idx].size());
                s_cache.lines[prev_idx] += s_cache.lines[caret_idx];
                s_cache.lines.erase(s_cache.lines.begin() + static_cast<std::ptrdiff_t>(caret_idx));
                s_cache.tokens.erase(s_cache.tokens.begin() + static_cast<std::ptrdiff_t>(caret_idx));
				s_cache.line_hashes.erase(s_cache.line_hashes.begin() +
					static_cast<std::ptrdiff_t>(caret_idx));
                s_sel.caret_line = s_sel.anchor_line = prev;
                s_sel.caret_col  = s_sel.anchor_col  = prev_len;
                rebuild_buffer_from_lines();
            }
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!current_document().read_only && !ctrl && ImGui::IsKeyPressed(ImGuiKey_Backspace, true)) {
            if (s_sel.has_selection()) {
                delete_selection();
                break_undo_coalescing();
            } else if (s_sel.caret_col > 0) {
                push_undo();
                break_undo_coalescing();
                const int caret_line = clamp_line(s_sel.caret_line);
                auto& ln = s_cache.lines[static_cast<std::size_t>(caret_line)];
                const int caret_col = clamp_col(caret_line, s_sel.caret_col);
                int del_start = caret_col - 1;
                while (del_start > 0 &&
                       (static_cast<unsigned char>(ln[static_cast<std::size_t>(del_start)]) & 0xC0) == 0x80)
                    del_start--;
                int del_len = caret_col - del_start;
                char prev_c = ln[static_cast<std::size_t>(del_start)];
                char next_c = (caret_col < static_cast<int>(ln.size()))
                                  ? ln[static_cast<std::size_t>(caret_col)] : 0;
                bool pair = editor_preferences::bracket_match &&
                            ((prev_c == '(' && next_c == ')') ||
                             (prev_c == '[' && next_c == ']') ||
                             (prev_c == '{' && next_c == '}') ||
                             (prev_c == '"' && next_c == '"') ||
                             (prev_c == '\'' && next_c == '\''));
                if (pair) ln.erase(static_cast<std::size_t>(del_start), static_cast<std::size_t>(del_len + 1));
                else      ln.erase(static_cast<std::size_t>(del_start), static_cast<std::size_t>(del_len));
                s_sel.caret_col = s_sel.anchor_col = del_start;
                rebuild_buffer_from_lines();
            } else if (s_sel.caret_line > 0) {
                push_undo_range(s_sel.caret_line - 1, s_sel.caret_line);
                int prev = s_sel.caret_line - 1;
                const std::size_t prev_idx = static_cast<std::size_t>(prev);
                const std::size_t caret_idx = static_cast<std::size_t>(s_sel.caret_line);
                int prev_len = static_cast<int>(s_cache.lines[prev_idx].size());
                s_cache.lines[prev_idx] += s_cache.lines[caret_idx];
                s_cache.lines.erase(s_cache.lines.begin() + static_cast<std::ptrdiff_t>(caret_idx));
                s_cache.tokens.erase(s_cache.tokens.begin() + static_cast<std::ptrdiff_t>(caret_idx));
				s_cache.line_hashes.erase(s_cache.line_hashes.begin() +
					static_cast<std::ptrdiff_t>(caret_idx));
                s_sel.caret_line = s_sel.anchor_line = prev;
                s_sel.caret_col  = s_sel.anchor_col  = prev_len;
                rebuild_buffer_from_lines();
            }
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!current_document().read_only && !ctrl && shift && !ghost_consumed_tab &&
                 !(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_Tab, true)) {

            int tab = std::max(1, editor_preferences::tab_size);
            if (s_sel.has_selection()) {
                int l0, c0, l1, c1;
                selection_ordered(l0, c0, l1, c1);
                (void)c0;
                l0 = clamp_line(l0);
                l1 = clamp_line(l1);
                int end_line = (c1 == 0 && l1 > l0) ? l1 - 1 : l1;
                push_undo();
                break_undo_coalescing();
                for (int li = l0; li <= end_line && li < line_count(); ++li) {
                    std::string& ln = s_cache.lines[static_cast<std::size_t>(li)];
                    int removed = 0;
                    if (!ln.empty() && ln[0] == '\t') { ln.erase(0, 1); removed = 1; }
                    else {
                        while (removed < tab && !ln.empty() && ln[0] == ' ') {
                            ln.erase(0, 1);
                            removed++;
                        }
                    }
                    if (li == s_sel.anchor_line)
                        s_sel.anchor_col = std::max(0, s_sel.anchor_col - removed);
                    if (li == s_sel.caret_line)
                        s_sel.caret_col = std::max(0, s_sel.caret_col - removed);
                }
                rebuild_buffer_from_lines();
            } else {
                const int caret_line = clamp_line(s_sel.caret_line);
                std::string& ln = s_cache.lines[static_cast<std::size_t>(caret_line)];
                int removed = 0;
                if (!ln.empty() && ln[0] == '\t') { ln.erase(0, 1); removed = 1; }
                else {
                    while (removed < tab && !ln.empty() && ln[0] == ' ') {
                        ln.erase(0, 1);
                        removed++;
                    }
                }
                if (removed > 0) {
                    push_undo();
                    break_undo_coalescing();
                    s_sel.caret_col = s_sel.anchor_col = std::max(0, s_sel.caret_col - removed);
                    rebuild_buffer_from_lines();
                }
            }
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!current_document().read_only && !ctrl && !ghost_consumed_tab &&
                 !(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_Tab, true)) {

            int tab = std::max(1, editor_preferences::tab_size);
            if (s_sel.has_selection() &&
                s_sel.anchor_line != s_sel.caret_line) {
                int l0, c0, l1, c1;
                selection_ordered(l0, c0, l1, c1);
                (void)c0;
                l0 = clamp_line(l0);
                l1 = clamp_line(l1);
                int end_line = (c1 == 0 && l1 > l0) ? l1 - 1 : l1;
                push_undo();
                break_undo_coalescing();
                std::string pad(static_cast<std::size_t>(tab), ' ');
                for (int li = l0; li <= end_line && li < line_count(); ++li) {
                    const std::size_t line_idx = static_cast<std::size_t>(li);
                    if (s_cache.lines[line_idx].empty()) continue;
                    s_cache.lines[line_idx].insert(0, pad);
                    if (li == s_sel.anchor_line) s_sel.anchor_col += tab;
                    if (li == s_sel.caret_line)  s_sel.caret_col  += tab;
                }
                rebuild_buffer_from_lines();
            } else {
                int col = clamp_col(s_sel.caret_line, s_sel.caret_col);
                int to_next = tab - (col % tab);
                if (to_next <= 0) to_next = tab;
                std::string spaces(static_cast<std::size_t>(to_next), ' ');
                insert_text_at_caret(spaces);
                break_undo_coalescing();
            }
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            if (s_find.visible) s_find.visible = false;
            else if (s_goto.visible) s_goto.visible = false;
            else if (autocomplete::popup_visible) {
                autocomplete::popup_visible = false;
                autocomplete::matches.clear();
            }
        }


        if (!ctrl && !current_document().read_only) {
            for (int k = 0; k < io.InputQueueCharacters.Size; k++) {
                ImWchar ch = io.InputQueueCharacters[k];
                if (ch < 32) continue;
                std::string utf8;
                uint32_t cp = static_cast<uint32_t>(ch);
                if (cp < 0x80) {
                    utf8.push_back(static_cast<char>(cp));
                } else if (cp < 0x800) {
                    utf8.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else if (cp < 0x10000) {
                    utf8.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    utf8.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else if (cp < 0x110000) {
                    utf8.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    utf8.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else {
                    continue;
                }

                char ascii = (cp < 0x80) ? static_cast<char>(cp) : 0;
                bool handled_bracket = false;

                if (editor_preferences::bracket_match && ascii != 0) {
                    const std::string& cl = line_at(s_sel.caret_line);
                    const int caret_col = s_sel.caret_col;
                    char next_ch = (caret_col >= 0 && caret_col < static_cast<int>(cl.size()))
                                       ? cl[static_cast<std::size_t>(caret_col)] : 0;

                    if (is_close_bracket(ascii) && next_ch == ascii && !s_sel.has_selection()) {
                        s_sel.caret_col = s_sel.anchor_col = s_sel.caret_col + 1;
                        s_sel.active = false;
                        handled_bracket = true;
                        break_undo_coalescing();
                    } else if (ascii == '"' && next_ch == '"' && !s_sel.has_selection()) {
                        s_sel.caret_col = s_sel.anchor_col = s_sel.caret_col + 1;
                        s_sel.active = false;
                        handled_bracket = true;
                        break_undo_coalescing();
                    } else if (is_open_bracket(ascii) ||
                               (ascii == '"' &&
                                (next_ch == 0 || next_ch == ')' || next_ch == ']' ||
                                 next_ch == '}' || next_ch == ' ' || next_ch == '\t' ||
                                 next_ch == ','))) {
                        if (s_sel.has_selection()) {
                            std::string sel = get_selected_text();
                            char close = (ascii == '"') ? '"' : matching_close_bracket(ascii);
                            insert_text_at_caret(std::string(1, ascii) + sel + std::string(1, close));
                            break_undo_coalescing();
                        } else {
                            char close = (ascii == '"') ? '"' : matching_close_bracket(ascii);
                            insert_text_at_caret(std::string(1, ascii) + std::string(1, close));
                            s_sel.caret_col = s_sel.anchor_col = s_sel.caret_col - 1;
                            break_undo_coalescing();
                        }
                        handled_bracket = true;
                    }
                }

                if (!handled_bracket) {
                    int kind = 0;
                    if (ascii != 0) {
                        bool word = (ascii >= 'a' && ascii <= 'z') ||
                                    (ascii >= 'A' && ascii <= 'Z') ||
                                    (ascii >= '0' && ascii <= '9') || ascii == '_';
                        kind = word ? 1 : 2;
                    }
                    insert_text_at_caret(utf8, kind);
                    if (kind == 2) break_undo_coalescing();
                }
                ensure_caret_visible(editor_h, line_h);


                if (editor_preferences::auto_complete && autocomplete::enabled && ascii != 0) {
                    bool word_ch = (ascii >= 'a' && ascii <= 'z') ||
                                   (ascii >= 'A' && ascii <= 'Z') ||
                                   (ascii >= '0' && ascii <= '9') || ascii == '_';
                    if (word_ch) {
                        int cursor = s_sel.caret_col;
                        int ws = cursor;
                        const int caret_line = clamp_line(s_sel.caret_line);
                        auto& ln = s_cache.lines[static_cast<std::size_t>(caret_line)];
                        cursor = clamp_col(caret_line, cursor);
                        ws = cursor;
                        while (ws > 0 && (isalnum(static_cast<unsigned char>(ln[static_cast<std::size_t>(ws - 1)])) || ln[static_cast<std::size_t>(ws - 1)] == '_'))
                            ws--;
                        if (cursor > ws) {
                            rebuild_autocomplete(ln.substr(static_cast<std::size_t>(ws), static_cast<std::size_t>(cursor - ws)), caret_line);
                            autocomplete::cursor_col = s_sel.caret_col;
                        } else {
                            autocomplete::popup_visible = false;
                            autocomplete::matches.clear();
                        }
                    } else {
                        autocomplete::popup_visible = false;
                        autocomplete::matches.clear();
                    }
                }
            }
        }


        if (autocomplete::popup_visible && !autocomplete::matches.empty()) {
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
                autocomplete::selected = (autocomplete::selected - 1 + static_cast<int>(autocomplete::matches.size()))
                    % static_cast<int>(autocomplete::matches.size());
            }
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
                autocomplete::selected = (autocomplete::selected + 1) % static_cast<int>(autocomplete::matches.size());
            }
            if (!current_document().read_only &&
                (ImGui::IsKeyPressed(ImGuiKey_Tab, false) || ImGui::IsKeyPressed(ImGuiKey_Enter, false))) {
                if (autocomplete::selected >= 0 && autocomplete::selected < static_cast<int>(autocomplete::matches.size())) {

                    int cursor = s_sel.caret_col;
                    int ws = cursor;
                    const int caret_line = clamp_line(s_sel.caret_line);
                    auto& ln = s_cache.lines[static_cast<std::size_t>(caret_line)];
                    cursor = clamp_col(caret_line, cursor);
                    ws = cursor;
                    while (ws > 0 && (isalnum(static_cast<unsigned char>(ln[static_cast<std::size_t>(ws - 1)])) || ln[static_cast<std::size_t>(ws - 1)] == '_'))
                        ws--;
                    push_undo();
                    break_undo_coalescing();
                    const std::string& chosen = autocomplete::matches[static_cast<std::size_t>(autocomplete::selected)];
                    ln.erase(static_cast<std::size_t>(ws), static_cast<std::size_t>(cursor - ws));
                    ln.insert(static_cast<std::size_t>(ws), chosen);
                    s_sel.caret_col = s_sel.anchor_col = ws + static_cast<int>(chosen.size());
                    rebuild_buffer_from_lines();
                }
                autocomplete::popup_visible = false;
                autocomplete::matches.clear();
            }
        }
    }


    dl->PopClipRect();


    {
        char buf[128];
        if (current_document().filename.empty())
            snprintf(buf, sizeof(buf), "Untitled  Ln %d, Col %d",
                     s_sel.caret_line + 1, s_sel.caret_col + 1);
        else
            snprintf(buf, sizeof(buf), "%s%s  Ln %d, Col %d",
                     current_document().filename.c_str(),
                     current_document().dirty ? " *" : "",
                     s_sel.caret_line + 1, s_sel.caret_col + 1);
        globals::ui::status_file_info = buf;
    }


    if (autocomplete::popup_visible && !autocomplete::matches.empty() && s_has_focus) {
        const int   total = static_cast<int>(autocomplete::matches.size());
        const int   max_visible = 8;
        const float popup_w = 280.f;
        const float ac_item_h = 24.f;
        const int   visible = std::min(total, max_visible);
        const float popup_h = static_cast<float>(visible) * ac_item_h + 10.f;

        int sel = autocomplete::selected;
        if (sel < 0) sel = 0;
        if (sel >= total) sel = total - 1;
        autocomplete::selected = sel;
        int top = 0;
        if (sel >= max_visible) top = sel - max_visible + 1;
        if (top > total - visible) top = std::max(0, total - visible);

        float sx = ox + text_x0 + static_cast<float>(autocomplete::cursor_col) * char_w - s_scroll_x;
        float sy = oy + static_cast<float>(autocomplete::cursor_line + 1) * line_h - s_scroll_y + 4.f;
        if (sx + popup_w > ox + code_w) sx = ox + code_w - popup_w - 4.f;
        if (sx < ox + text_x0) sx = ox + text_x0;
        if (sy + popup_h > oy + editor_h)
            sy = oy + static_cast<float>(autocomplete::cursor_line) * line_h - s_scroll_y - popup_h;

        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 pmin(sx, sy);
        ImVec2 pmax(sx + popup_w, sy + popup_h);
        aida::ui::blur::render_drop_shadow(fdl, pmin, pmax, 10.f, 4, 0.40f, ImVec2(0.f, 4.f));
        aida::ui::blur::render_glass_fill(fdl, pmin, pmax, 10.f, a);
        aida::ui::blur::render_glass_border(fdl, pmin, pmax, 10.f, a, 1.f);

        std::string lower_pat = autocomplete::partial;
        for (auto& c : lower_pat) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

        const auto& kws = autocomplete::keywords();
        std::unordered_set<std::string> kw_set(kws.begin(), kws.end());

        int accepted_idx = -1;
        ImVec2 mp = ImGui::GetIO().MousePos;

        for (int row = 0; row < visible; ++row) {
            int mi = top + row;
            float iy = sy + 5.f + static_cast<float>(row) * ac_item_h;
            float text_y = iy + (ac_item_h - ImGui::GetFontSize()) * 0.5f;
            const std::string& match = autocomplete::matches[static_cast<std::size_t>(mi)];

            ImVec2 row_min(sx + 3.f, iy);
            ImVec2 row_max(sx + popup_w - 3.f, iy + ac_item_h);
            bool row_hov = (mp.x >= row_min.x && mp.x <= row_max.x &&
                            mp.y >= row_min.y && mp.y <= row_max.y);
            if (row_hov) autocomplete::selected = mi;

            if (mi == autocomplete::selected) {
                fdl->AddRectFilled(row_min, row_max,
                    aida::ui::with_alpha(th.accent_dim, 0.55f * a), 6.f);
                fdl->AddRectFilled(ImVec2(sx + 3.f, iy), ImVec2(sx + 5.f, iy + ac_item_h),
                    aida::ui::with_alpha(th.accent_u32, a), 1.f);
            } else if (row_hov) {
                fdl->AddRectFilled(row_min, row_max,
                    aida::ui::with_alpha(th.hover_wash, 1.4f * a), 6.f);
            }

            float tx = sx + 14.f;
            std::size_t pi = 0;
            for (std::size_t ci = 0; ci < match.size(); ++ci) {
                char glyph[2] = { match[ci], 0 };
                char lc = static_cast<char>(tolower(static_cast<unsigned char>(match[ci])));
                bool hit = (pi < lower_pat.size() && lc == lower_pat[pi]);
                ImU32 col = hit ? aida::ui::with_alpha(th.accent_u32, a)
                                : aida::ui::with_alpha(th.text_primary, 0.90f * a);
                if (hit) pi++;
                fdl->AddText(ImVec2(tx, text_y), col, glyph);
                tx += ImGui::CalcTextSize(glyph).x;
            }

            const char* kind = kw_set.count(match) ? "kw" : "id";
            ImU32 kind_col = kw_set.count(match)
                ? aida::ui::with_alpha(th.syn_keyword, 0.85f * a)
                : aida::ui::with_alpha(th.text_dim, 0.85f * a);
            float kw_w = ImGui::CalcTextSize(kind).x;
            fdl->AddText(ImVec2(sx + popup_w - 12.f - kw_w, text_y), kind_col, kind);

            if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                accepted_idx = mi;
        }

        if (total > visible) {
            float track_x = sx + popup_w - 6.f;
            float track_y0 = sy + 5.f;
            float track_h = static_cast<float>(visible) * ac_item_h;
            float thumb_h = std::max(16.f, track_h * static_cast<float>(visible) / static_cast<float>(total));
            float thumb_y = track_y0 +
                (track_h - thumb_h) * static_cast<float>(top) /
                static_cast<float>(std::max(1, total - visible));
            fdl->AddRectFilled(ImVec2(track_x, thumb_y),
                ImVec2(track_x + 3.f, thumb_y + thumb_h),
                aida::ui::with_alpha(th.text_secondary, 0.4f * a), 2.f);
        }

        if (accepted_idx >= 0 && accepted_idx < total) {
            int cursor = s_sel.caret_col;
            int ws = cursor;
            const int caret_line = clamp_line(s_sel.caret_line);
            auto& ln = s_cache.lines[static_cast<std::size_t>(caret_line)];
            cursor = clamp_col(caret_line, cursor);
            ws = cursor;
            while (ws > 0 && (isalnum(static_cast<unsigned char>(ln[static_cast<std::size_t>(ws - 1)])) || ln[static_cast<std::size_t>(ws - 1)] == '_'))
                ws--;
            push_undo();
            break_undo_coalescing();
            const std::string& chosen = autocomplete::matches[static_cast<std::size_t>(accepted_idx)];
            ln.erase(static_cast<std::size_t>(ws), static_cast<std::size_t>(cursor - ws));
            ln.insert(static_cast<std::size_t>(ws), chosen);
            s_sel.caret_col = s_sel.anchor_col = ws + static_cast<int>(chosen.size());
            rebuild_buffer_from_lines();
            autocomplete::popup_visible = false;
            autocomplete::matches.clear();
        }
    }


    if (s_find.visible) {

        ImVec4 accent_col = th.accent;
        ImVec4 bg     = ImGui::ColorConvertU32ToFloat4(th.panel_header);
        ImVec4 bg_inp = ImGui::ColorConvertU32ToFloat4(th.bg_base);
        ImVec4 txt1   = ImGui::ColorConvertU32ToFloat4(th.text_primary);
        ImVec4 txt2   = ImGui::ColorConvertU32ToFloat4(th.text_secondary);
        ImVec4 txt_d  = ImGui::ColorConvertU32ToFloat4(th.text_dim);

        const float row_h       = 28.f;
        const float bar_pad_x   = 8.f;
        const float bar_pad_y   = 5.f;
        const float input_w     = 200.f;
        const float btn_sz      = 26.f;
        const float bar_w       = 420.f;
        const float total_bar_h = s_find.replace_mode ? (row_h * 2 + bar_pad_y * 3) : (row_h + bar_pad_y * 2);
        const float bar_x       = ox + width - bar_w - 20.f;
        const float bar_y       = wpos.y + pos_y + 2.f;

        ImGui::SetNextWindowPos(ImVec2(bar_x, bar_y), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(bar_w, total_bar_h), ImGuiCond_Always);

        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(bar_pad_x, bar_pad_y));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.f);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(3.f, 3.f));
        ImGui::PushStyleColor(ImGuiCol_WindowBg, bg);
        ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, 0.35f)));

        ImGuiWindowFlags find_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
            ImGuiWindowFlags_AlwaysAutoResize;
#ifdef IMGUI_HAS_DOCK
        find_flags |= ImGuiWindowFlags_NoDocking;
#endif

        bool find_open = true;
        ImGui::Begin("##find_bar", &find_open, find_flags);
        s_find_has_focus = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);


        auto draw_instant_tooltip = [&](const char* tooltip) {
            if (!tooltip || !*tooltip) return;
            if (!ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone | ImGuiHoveredFlags_NoSharedDelay |
                ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_AllowWhenBlockedByPopup)) return;
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.f, 6.f));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.f);
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(tooltip);
            ImGui::EndTooltip();
            ImGui::PopStyleVar(2);
        };


        auto centered_button = [&](const char* label, const ImVec2& size, ImGuiButtonFlags flags = 0) -> bool {
            const float text_h = ImGui::GetFontSize();
            const float pad_y = (size.y - text_h) * 0.5f;
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2.f, pad_y < 0.f ? 0.f : pad_y));
            bool clicked = ImGui::ButtonEx(label, size, flags);
            ImGui::PopStyleVar();
            return clicked;
        };


        auto toggle_button = [&](const char* label, bool& state, const char* id_suffix, const char* tooltip) -> bool {
            ImGui::PushID(id_suffix);
            ImVec2 sz(btn_sz, row_h);
            bool was = state;
            if (state) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_col.x, accent_col.y, accent_col.z, 0.25f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_col.x, accent_col.y, accent_col.z, 0.35f));
                ImGui::PushStyleColor(ImGuiCol_Text, accent_col);
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.f, 0.f, 0.f, 0.f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(txt2.x, txt2.y, txt2.z, 0.4f));
                ImGui::PushStyleColor(ImGuiCol_Text, txt2);
            }
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            if (centered_button(label, sz)) state = !state;
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);
            draw_instant_tooltip(tooltip);
            ImGui::PopID();
            return state != was;
        };


        auto icon_button = [&](const char* label, const char* id_suffix, const char* tooltip, float w = 26.f) -> bool {
            ImGui::PushID(id_suffix);
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.f, 0.f, 0.f, 0.f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(txt_d.x, txt_d.y, txt_d.z, 0.3f));
            ImGui::PushStyleColor(ImGuiCol_Text, txt2);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            bool clicked = centered_button(label, ImVec2(w, row_h));
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);
            draw_instant_tooltip(tooltip);
            ImGui::PopID();
            return clicked;
        };


        {
            const char* chev = s_find.replace_mode ? "v" : ">";
            if (icon_button(chev, "chevron", "Toggle Replace", 20.f))
                s_find.replace_mode = !s_find.replace_mode;
            ImGui::SameLine();
        }


        {
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, (row_h - ImGui::GetFontSize()) * 0.5f - 1.f));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, bg_inp);
            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(bg_inp.x + 0.03f, bg_inp.y + 0.03f, bg_inp.z + 0.03f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(bg_inp.x + 0.05f, bg_inp.y + 0.05f, bg_inp.z + 0.05f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_Text, txt1);
            ImGui::PushItemWidth(input_w);
            if (s_focus_find_input) {
                ImGui::SetKeyboardFocusHere();
                s_focus_find_input = false;
            }
            bool enter_pressed = ImGui::InputText("##find_input", s_find.find_buf,
                sizeof(s_find.find_buf), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
            bool edited = ImGui::IsItemEdited();
            ImGui::PopItemWidth();
            ImGui::PopStyleColor(4);
            ImGui::PopStyleVar(2);


            if (edited && strcmp(s_find.find_buf, s_find_last_buf) != 0) {
                memcpy(s_find_last_buf, s_find.find_buf, sizeof(s_find.find_buf));
                find_all_matches();
                if (!s_find.match_positions.empty()) {
                    s_find.current_match = -1;
                    find_next();
                    ensure_caret_visible(editor_h, line_h);
                }
            }


            if (enter_pressed) {
                if (ImGui::GetIO().KeyShift)
                    find_prev();
                else
                    find_next();
                ensure_caret_visible(editor_h, line_h);
                s_focus_find_input = true;
            }
            ImGui::SameLine();
        }


        if (toggle_button("Aa", s_find.case_sensitive, "case", "Match Case")) {
            find_all_matches();
            if (!s_find.match_positions.empty()) {
                s_find.current_match = -1;
                find_next();
                ensure_caret_visible(editor_h, line_h);
            }
        }
        ImGui::SameLine();

        if (toggle_button("W", s_find.whole_word, "ww", "Whole Word")) {
            find_all_matches();
            if (!s_find.match_positions.empty()) {
                s_find.current_match = -1;
                find_next();
                ensure_caret_visible(editor_h, line_h);
            }
        }
        ImGui::SameLine();

        if (toggle_button(".*", s_find.use_regex, "rx", "Regular Expression")) {
            find_all_matches();
            if (!s_find.match_positions.empty()) {
                s_find.current_match = -1;
                find_next();
                ensure_caret_visible(editor_h, line_h);
            }
        }
        ImGui::SameLine();


        {
            char match_buf[32];
            if (s_find.find_buf[0] == '\0') {
                match_buf[0] = '\0';
            } else if (current_document().find_loading) {
                snprintf(match_buf, sizeof(match_buf), "Searching...");
            } else if (s_find.total_matches == 0) {
                snprintf(match_buf, sizeof(match_buf), "No results");
            } else {
                snprintf(match_buf, sizeof(match_buf), "%d of %d",
                         s_find.current_match >= 0 ? s_find.current_match + 1 : 0, s_find.total_matches);
            }
            if (match_buf[0]) {
                bool no_match = !current_document().find_loading &&
                    (s_find.total_matches == 0 && s_find.find_buf[0] != '\0');
                ImVec4 mc = no_match ? ImGui::ColorConvertU32ToFloat4(th.error) : txt2;
                ImGui::PushStyleColor(ImGuiCol_Text, mc);
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (row_h - ImGui::GetFontSize()) * 0.5f);
                ImGui::TextUnformatted(match_buf);
                if (!current_document().find_error.empty() && ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", current_document().find_error.c_str());
                ImGui::PopStyleColor();
                ImGui::SameLine();
            }
        }


        if (icon_button("\xc3\x97", "close", "Close (Esc)")) {
            s_find.visible = false;
            s_find_has_focus = false;
            s_has_focus = true;
        }


        if (s_find.replace_mode) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 22.f);

            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, (row_h - ImGui::GetFontSize()) * 0.5f - 1.f));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, bg_inp);
            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(bg_inp.x + 0.03f, bg_inp.y + 0.03f, bg_inp.z + 0.03f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(bg_inp.x + 0.05f, bg_inp.y + 0.05f, bg_inp.z + 0.05f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_Text, txt1);
            ImGui::PushItemWidth(input_w);
            ImGui::InputText("##replace_input", s_find.replace_buf, sizeof(s_find.replace_buf));
            ImGui::PopItemWidth();
            ImGui::PopStyleColor(4);
            ImGui::PopStyleVar(2);
            ImGui::SameLine();

            if (icon_button("R1", "repl_one", "Replace"))    replace_current();
            ImGui::SameLine();
            if (icon_button("R*", "repl_all", "Replace All")) replace_all();
        }


        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            s_find.visible = false;
            s_find_has_focus = false;
            s_has_focus = true;
        }

        ImGui::End();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(4);


        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilledMultiColor(
            ImVec2(bar_x + 4.f, bar_y + total_bar_h),
            ImVec2(bar_x + bar_w - 4.f, bar_y + total_bar_h + 6.f),
            IM_COL32(0, 0, 0, static_cast<int>(40 * a)), IM_COL32(0, 0, 0, static_cast<int>(40 * a)),
            IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
    } else {
        s_find_has_focus = false;
    }


    if (s_goto.visible) {
        float gy = wpos.y + pos_y;
        float gw = 240.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 gmin(ox + 10.f, gy + 2.f);
        ImVec2 gmax(ox + 10.f + gw, gy + goto_bar_h - 2.f);
        aida::ui::blur::render_drop_shadow(fdl, gmin, gmax, 10.f, 3, 0.30f, ImVec2(0.f, 3.f));
        aida::ui::blur::render_glass_fill(fdl, gmin, gmax, 10.f, a);
        aida::ui::blur::render_glass_border(fdl, gmin, gmax, 10.f, a, 1.f);

        ImGui::SetCursorPos(ImVec2(pos_x + 18.f, pos_y + 6.f));
        ImGui::PushID("##editor_goto_overlay");
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.bg_base, 0.65f)));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(th.text_primary));
        ImGui::SetNextItemWidth(140.f);
        bool go = ImGui::InputTextWithHint("##goto_line", "line", s_goto.line_buf, sizeof(s_goto.line_buf),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsDecimal);
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);

        ImGui::SameLine();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2.f);
        bool clicked_go = aida::ui::components::button("Go",
            aida::ui::components::button_kind_t::primary,
            aida::ui::components::size_t_::sm);
        ImGui::PopID();

        if (clicked_go || go) {
            int n = atoi(s_goto.line_buf);
            if (n >= 1 && n <= line_count()) {
                s_sel.caret_line = s_sel.anchor_line = n - 1;
                s_sel.caret_col  = s_sel.anchor_col  = 0;
                s_sel.active = false;
                ensure_caret_visible(editor_h, line_h);
                s_goto.visible = false;
            }
        }
    }


    {
        float total_content = static_cast<float>(n_lines) * line_h;
        if (total_content > editor_h) {
            const float sb_w   = 10.f;
            const float sb_pad = 2.f;
            float track_x  = ox + code_w - sb_w - sb_pad;
            float track_y0 = oy + sb_pad;
            float track_h  = editor_h - sb_pad * 2.f;

            float ratio       = editor_h / total_content;
            float thumb_h     = std::max(20.f, track_h * ratio);
            float scroll_range = total_content - editor_h;
            float thumb_y     = track_y0 + (scroll_range > 0.f
                ? (s_scroll_y / scroll_range) * (track_h - thumb_h) : 0.f);

            bool sb_hov = ImGui::IsMouseHoveringRect(
                ImVec2(track_x - 4.f, track_y0),
                ImVec2(track_x + sb_w + 4.f, track_y0 + track_h));

            ImGuiID sb_hov_id = ImGui::GetID("##code_sb_hov");
            float sb_a = ImGui::GetStateStorage()->GetFloat(sb_hov_id, 0.f);
            sb_a = aida::motion::smooth_lerp(sb_a, (sb_hov || s_sb_dragging) ? 1.f : 0.f, 14.f, dt);
            ImGui::GetStateStorage()->SetFloat(sb_hov_id, sb_a);

            if (sb_a > 0.01f) {

                dl->AddRectFilled(ImVec2(track_x, track_y0),
                    ImVec2(track_x + sb_w, track_y0 + track_h),
                    aida::ui::with_alpha(th.text_primary, 0.04f * sb_a * a), 3.f);


                bool thumb_hov = ImGui::IsMouseHoveringRect(
                    ImVec2(track_x - 2.f, thumb_y),
                    ImVec2(track_x + sb_w + 2.f, thumb_y + thumb_h));
                ImU32 thumb_col = aida::ui::with_alpha(
                    (thumb_hov || s_sb_dragging) ? th.accent_u32 : th.text_secondary,
                    (thumb_hov || s_sb_dragging ? 0.55f : 0.30f) * sb_a * a);
                dl->AddRectFilled(ImVec2(track_x, thumb_y),
                    ImVec2(track_x + sb_w, thumb_y + thumb_h),
                    thumb_col, 3.f);
            }

            if (sb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                float my = ImGui::GetIO().MousePos.y;
                if (my < thumb_y || my > thumb_y + thumb_h) {
                    float click_ratio = (my - track_y0 - thumb_h * 0.5f) / (track_h - thumb_h);
                    click_ratio = std::max(0.f, std::min(1.f, click_ratio));
                    s_target_scroll_y = click_ratio * scroll_range;
                }
                s_sb_dragging = true;
                s_sb_drag_offset = ImGui::GetIO().MousePos.y - thumb_y;
            }

            if (s_sb_dragging) {
                if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                    float my = ImGui::GetIO().MousePos.y - s_sb_drag_offset;
                    float drag_ratio = (my - track_y0) / (track_h - thumb_h);
                    drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                    s_target_scroll_y = drag_ratio * scroll_range;
                    s_scroll_y = s_target_scroll_y;
                } else {
                    s_sb_dragging = false;
                }
            }
        }
    }

    if (!word_wrap_on && s_max_scroll_x > 0.5f) {
        bool& s_hsb_dragging = current_document().hsb_dragging;
        float& s_hsb_drag_offset = current_document().hsb_drag_offset;

        const float sb_h   = h_scrollbar_h;
        const float sb_pad = 2.f;
        float track_x0 = ox + text_x0;
        float track_y  = oy + editor_h - sb_h - sb_pad;
        float track_w  = code_w - text_x0 - 14.f;
        if (track_w < 30.f) track_w = 30.f;

        float total_w   = s_max_scroll_x + track_w;
        float ratio     = track_w / total_w;
        float thumb_w   = std::max(28.f, track_w * ratio);
        float thumb_x   = track_x0 + (s_max_scroll_x > 0.f
            ? (s_scroll_x / s_max_scroll_x) * (track_w - thumb_w) : 0.f);

        bool hsb_hov = ImGui::IsMouseHoveringRect(
            ImVec2(track_x0, track_y - 3.f),
            ImVec2(track_x0 + track_w, track_y + sb_h + 3.f));

        ImGuiID hsb_id = ImGui::GetID("##code_hsb_hov");
        float hsb_a = ImGui::GetStateStorage()->GetFloat(hsb_id, 0.f);
        hsb_a = aida::motion::smooth_lerp(hsb_a, (hsb_hov || s_hsb_dragging) ? 1.f : 0.f, 14.f, dt);
        ImGui::GetStateStorage()->SetFloat(hsb_id, hsb_a);

        if (hsb_a > 0.01f) {
            dl->AddRectFilled(ImVec2(track_x0, track_y),
                ImVec2(track_x0 + track_w, track_y + sb_h),
                aida::ui::with_alpha(th.text_primary, 0.04f * hsb_a * a), 3.f);
            bool thumb_hov = ImGui::IsMouseHoveringRect(
                ImVec2(thumb_x, track_y - 2.f),
                ImVec2(thumb_x + thumb_w, track_y + sb_h + 2.f));
            ImU32 thumb_col = aida::ui::with_alpha(
                (thumb_hov || s_hsb_dragging) ? th.accent_u32 : th.text_secondary,
                (thumb_hov || s_hsb_dragging ? 0.55f : 0.30f) * hsb_a * a);
            dl->AddRectFilled(ImVec2(thumb_x, track_y),
                ImVec2(thumb_x + thumb_w, track_y + sb_h), thumb_col, 3.f);
        }

        if (hsb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            float mx = ImGui::GetIO().MousePos.x;
            if (mx < thumb_x || mx > thumb_x + thumb_w) {
                float click_ratio = (mx - track_x0 - thumb_w * 0.5f) / (track_w - thumb_w);
                click_ratio = std::max(0.f, std::min(1.f, click_ratio));
                s_scroll_x = click_ratio * s_max_scroll_x;
            }
            s_hsb_dragging = true;
            s_hsb_drag_offset = ImGui::GetIO().MousePos.x - thumb_x;
        }
        if (s_hsb_dragging) {
            if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                float mx = ImGui::GetIO().MousePos.x - s_hsb_drag_offset;
                float drag_ratio = (track_w - thumb_w) > 0.f
                    ? (mx - track_x0) / (track_w - thumb_w) : 0.f;
                drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                s_scroll_x = drag_ratio * s_max_scroll_x;
            } else {
                s_hsb_dragging = false;
            }
        }
    }

    if (minimap_w > 0.f && n_lines > 1) {
        float mm_x = ox + code_w;
        float mm_y = oy;
        float mm_h = editor_h;
        ImVec2 mm_min(mm_x, mm_y);
        ImVec2 mm_max(mm_x + minimap_w, mm_y + mm_h);

        bool mm_hov = ImGui::IsMouseHoveringRect(mm_min, mm_max);
        float mm_hov_v = s_minimap_hover.eased();
        if (mm_hov && s_minimap_hover.is_finished() && s_minimap_hover.progress < 1.f)
            s_minimap_hover.start(0.18f, aida::motion::ease::out_quint);
        if (!mm_hov && s_minimap_hover.is_finished() && s_minimap_hover.progress > 0.f)
            s_minimap_hover.start_reverse(0.18f, aida::motion::ease::in_quint);
        s_minimap_hover.tick(dt);

        aida::ui::blur::render_glass_fill(dl, mm_min, mm_max, 0.f, a);
        dl->AddLine(ImVec2(mm_x, mm_y), ImVec2(mm_x, mm_y + mm_h),
            aida::ui::with_alpha(th.border_subtle, a), 1.f);

        bool tokens_missing = s_cache.tokens.empty() ||
                              s_cache.tokens.size() < s_cache.lines.size();
        if (!tokens_missing) {
            for (std::size_t i = 0; i < s_cache.tokens.size(); ++i) {
                if (!s_cache.tokens[i].empty()) break;
                if (i < s_cache.lines.size() && !s_cache.lines[i].empty()) {
                    tokens_missing = true;
                    break;
                }
            }
        }
        if (tokens_missing && !s_cache.lines.empty()) {
            s_cache.tokens.assign(s_cache.lines.size(), {});
            for (std::size_t i = 0; i < s_cache.lines.size(); ++i)
                syntax::tokenize(s_cache.lines[i], s_lang, s_cache.tokens[i]);
        }

        std::uint64_t& s_minimap_log_signature = current_document().minimap_log_signature;
        uint64_t cur_signature = static_cast<uint64_t>(current_document().filename.size()) ^
                                 (static_cast<uint64_t>(n_lines) << 16) ^
                                 (static_cast<uint64_t>(s_cache.tokens.size()) << 32);
        if (cur_signature != s_minimap_log_signature) {
            s_minimap_log_signature = cur_signature;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            aida::preview::editor::record("minimap_render", current_document().filename);
#else
            diag::log_tagged_fmt("minimap",
                "render tokens=%zu lines=%zu w=%.1f h=%.1f file=%s",
                s_cache.tokens.size(), s_cache.lines.size(),
                minimap_w, mm_h,
                current_document().filename.empty() ? "<unnamed>" : current_document().filename.c_str());
#endif
        }

        float natural_line_h = (n_lines > 0) ? (mm_h / static_cast<float>(n_lines)) : 1.f;
        float mm_line_h = natural_line_h;
        if (mm_line_h > 4.f) mm_line_h = 4.f;
        if (mm_line_h < 1.f) mm_line_h = 1.f;
        float mm_char_step = (minimap_w - 8.f) / 80.f;
        if (mm_char_step < 0.6f) mm_char_step = 0.6f;

        bool sampled = (natural_line_h < 1.f);
        int row_count = sampled
            ? static_cast<int>(std::ceil(mm_h / mm_line_h))
            : n_lines;
        if (row_count < 0) row_count = 0;

        float base_alpha = 0.75f + mm_hov_v * 0.20f;
        if (base_alpha < 0.65f) base_alpha = 0.65f;
        if (base_alpha > 1.f) base_alpha = 1.f;

        for (int row = 0; row < row_count; row++) {
            int i = sampled
                ? static_cast<int>(((static_cast<float>(row) + 0.5f) /
                                    static_cast<float>(row_count)) * static_cast<float>(n_lines))
                : row;
            if (i < 0) i = 0;
            if (i >= n_lines) break;
            const std::size_t line_index = static_cast<std::size_t>(i);
            if (line_index >= s_cache.tokens.size() || line_index >= s_cache.lines.size()) break;

            float ly = mm_y + static_cast<float>(row) * mm_line_h;
            if (ly + mm_line_h < mm_y) continue;
            if (ly > mm_y + mm_h) break;

            const auto& toks = s_cache.tokens[line_index];
            const auto& ln_text = s_cache.lines[line_index];
            float lx = mm_x + 4.f;
            for (const auto& tok : toks) {
                if (tok.type == syntax::token_type::whitespace) {
                    for (uint32_t k = 0; k < tok.length; k++) {
                        const std::size_t character_index = static_cast<std::size_t>(tok.start) +
                                                            static_cast<std::size_t>(k);
                        if (character_index >= ln_text.size()) break;
                        char c = ln_text[character_index];
                        if (c == '\t') lx += mm_char_step * static_cast<float>(editor_preferences::tab_size);
                        else lx += mm_char_step;
                    }
                    continue;
                }
                if (tok.length == 0) continue;
                const std::size_t token_start = static_cast<std::size_t>(tok.start);
                if (token_start >= ln_text.size()) continue;
                const std::size_t available = ln_text.size() - token_start;
                const uint32_t eff_len = static_cast<uint32_t>(
                    std::min(static_cast<std::size_t>(tok.length), available));
                if (eff_len == 0) continue;
                ImU32 tc = tok_colors[static_cast<std::size_t>(tok.type)];
                tc = aida::ui::with_alpha(tc, base_alpha * a);
                float seg_w = static_cast<float>(eff_len) * mm_char_step;
                if (lx + seg_w > mm_max.x - 4.f) seg_w = (mm_max.x - 4.f) - lx;
                if (seg_w < 0.5f) { lx += static_cast<float>(eff_len) * mm_char_step; continue; }
                dl->AddRectFilled(ImVec2(lx, ly + 0.5f),
                                  ImVec2(lx + seg_w, ly + mm_line_h - 0.5f), tc);
                lx += static_cast<float>(eff_len) * mm_char_step;
                if (lx > mm_max.x - 4.f) break;
            }
        }

        if (n_lines > 0) {
            const float content_height = static_cast<float>(n_lines) * line_h;
            float view_y0 = mm_y + (s_scroll_y / std::max(1.f, content_height)) * mm_h;
            float view_h  = (editor_h / std::max(1.f, content_height)) * mm_h;
            if (view_h < 12.f) view_h = 12.f;
            if (view_y0 + view_h > mm_y + mm_h) view_y0 = mm_y + mm_h - view_h;
            ImVec2 vmin(mm_x + 1.f, view_y0);
            ImVec2 vmax(mm_max.x - 1.f, view_y0 + view_h);
            dl->AddRectFilled(vmin, vmax,
                aida::ui::with_alpha(th.accent_glow, (0.55f + mm_hov_v * 0.35f) * a), 4.f);
            dl->AddRect(vmin, vmax,
                aida::ui::with_alpha(th.accent_u32, (0.45f + mm_hov_v * 0.35f) * a),
                4.f, 0, 1.f);
        }

        const int caret_line = clamp_line(s_sel.caret_line);
        float caret_mm_y = mm_y + (static_cast<float>(caret_line) /
                                   std::max(1.f, static_cast<float>(n_lines))) * mm_h;
        dl->AddLine(ImVec2(mm_x + 2.f, caret_mm_y),
                    ImVec2(mm_max.x - 2.f, caret_mm_y),
                    aida::ui::with_alpha(th.accent_u32, 0.65f * a), 1.f);

        if (mm_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            float local = (ImGui::GetIO().MousePos.y - mm_y) / mm_h;
            if (local < 0.f) local = 0.f;
            if (local > 1.f) local = 1.f;
            s_target_scroll_y = local * std::max(
                0.f, static_cast<float>(n_lines) * line_h - editor_h * 0.5f);
        }
        if (mm_hov && ImGui::IsMouseDown(ImGuiMouseButton_Left) && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.f)) {
            float local = (ImGui::GetIO().MousePos.y - mm_y) / mm_h;
            if (local < 0.f) local = 0.f;
            if (local > 1.f) local = 1.f;
            s_target_scroll_y = local * std::max(
                0.f, static_cast<float>(n_lines) * line_h - editor_h * 0.5f);
        }
    }

    ImGui::SetWindowFontScale(prev_font_scale);
    if (code_font) ImGui::PopFont();
}
