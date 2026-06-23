#include "disasm_view.hpp"
#include "nav_history.hpp"
#include "zydis_disasm.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include "../../helpers/helpers.h"
#include "ui_anim.hpp"
#include "decompiler_engine.hpp"
#include "pseudocode_view.hpp"
#include "aob_generator.hpp"
#include "scan_hub_view.hpp"
#include "standalone_settings.hpp"
#include "symbol_store.hpp"
#include "auto_comment_store.hpp"
#include "builtin_typelib.hpp"
#include "event_bus.hpp"
#include "pdb_events.hpp"
#include "xref_engine.hpp"
#include "cfg_view.hpp"
#include "comment_dialog.hpp"
#include "comment_store.hpp"
#include "rename_dialog.hpp"
#include "rename_store.hpp"
#include "source_reconstruct_view.hpp"
#include "disasm_theme.hpp"
#include "xref_index.hpp"
#include "function_index.hpp"
#include "symbol_classifier.hpp"
#include "file_metadata_banner.hpp"
#include "../ui/theme.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/fonts.hpp"

extern DisasmState g_disasm;

namespace disasm_view {

static float s_xref_anim_t = 0.f;
static float s_first_load_anim = 0.f;
static int   s_last_known_n = 0;
static std::unordered_map<int, aida::ui::hover_state_t> s_row_hover;
static std::unordered_map<int, aida::ui::hover_state_t> s_banner_row_hover;
static std::unordered_map<int, float> s_row_entrance;
static aida::ui::flash_t s_branch_flash;

struct banner_line_t {
    std::string text;
    ImU32       color = 0;
    bool        is_directive = false;
};
static std::vector<banner_line_t> s_banner_cache;
static int s_banner_line_count = 0;
static std::atomic<uint64_t> s_banner_cache_signature{0};

static std::atomic<uint64_t> s_throttle_until_ns{0};
static std::atomic<uint32_t> s_last_attached_pid{0xFFFFFFFFu};
static std::atomic<uint64_t> s_last_loaded_image_base{0xFFFFFFFFFFFFFFFFull};
static std::atomic<uint64_t> s_visible_warm_last_ns{0};
static std::atomic<uint32_t> s_format_gen{1};
static std::atomic<uint64_t> s_render_log_last_ns{0};
static std::atomic<uint64_t> s_render_ms_accum_us{0};
static std::atomic<uint32_t> s_render_log_frames{0};
static std::atomic<uint64_t> s_render_log_rows_accum{0};
static std::atomic<uint64_t> s_bytes_overflow_log_last_ns{0};
static std::atomic<uint64_t> s_bytes_overflow_log_seen{0};
static std::atomic<uint32_t> s_bytes_overflow_log_max_len{0};

static inline uint64_t now_ns() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

static std::string trim_middle_to_width(ImFont* font, float font_size, const std::string& text, float max_w) {
    if (text.empty() || max_w <= 0.f) return std::string();
    if (!font || font->CalcTextSizeA(font_size, FLT_MAX, 0.f, text.c_str()).x <= max_w)
        return text;
    const char* ellipsis = "...";
    const float ellipsis_w = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, ellipsis).x;
    if (ellipsis_w > max_w) return std::string();
    size_t keep = text.size();
    while (keep > 0) {
        size_t left = (keep + 1) / 2;
        size_t right = keep / 2;
        if (left + right >= text.size()) {
            --keep;
            continue;
        }
        std::string candidate = text.substr(0, left) + ellipsis + text.substr(text.size() - right);
        if (font->CalcTextSizeA(font_size, FLT_MAX, 0.f, candidate.c_str()).x <= max_w)
            return candidate;
        --keep;
    }
    return std::string();
}

static std::string format_byte_preview(const uint8_t* bytes, int len, int max_pairs, const char* overflow_suffix) {
    if (!bytes || len <= 0 || max_pairs <= 0) return std::string();
    char bytes_buf[128] = {};
    int boff = 0;
    int show_n = len < max_pairs ? len : max_pairs;
    for (int b = 0; b < show_n && boff + 4 < static_cast<int>(sizeof(bytes_buf)); ++b) {
        boff += std::snprintf(bytes_buf + boff, sizeof(bytes_buf) - boff,
            b ? " %02X" : "%02X", static_cast<unsigned int>(bytes[b]));
    }
    if (len > max_pairs && overflow_suffix && boff + 4 < static_cast<int>(sizeof(bytes_buf))) {
        std::snprintf(bytes_buf + boff, sizeof(bytes_buf) - boff, "%s", overflow_suffix);
    }
    return std::string(bytes_buf);
}

static std::string format_repeated_byte_preview(uint8_t value, uint64_t len, int max_pairs, const char* overflow_suffix) {
    if (len == 0 || max_pairs <= 0) return std::string();
    char bytes_buf[128] = {};
    int boff = 0;
    int show_n = len < static_cast<uint64_t>(max_pairs) ? static_cast<int>(len) : max_pairs;
    for (int b = 0; b < show_n && boff + 4 < static_cast<int>(sizeof(bytes_buf)); ++b) {
        boff += std::snprintf(bytes_buf + boff, sizeof(bytes_buf) - boff,
            b ? " %02X" : "%02X", static_cast<unsigned int>(value));
    }
    if (len > static_cast<uint64_t>(max_pairs) && overflow_suffix && boff + 4 < static_cast<int>(sizeof(bytes_buf))) {
        std::snprintf(bytes_buf + boff, sizeof(bytes_buf) - boff, "%s", overflow_suffix);
    }
    return std::string(bytes_buf);
}

static std::string byte_width_probe(int max_pairs, const char* overflow_suffix) {
    uint8_t probe[16] = {};
    for (int i = 0; i < 16; ++i) probe[i] = 0xFFu;
    return format_byte_preview(probe, max_pairs + 1, max_pairs, overflow_suffix);
}

static inline bool throttle_active() {
    uint64_t until = s_throttle_until_ns.load(std::memory_order_acquire);
    if (until == 0) return false;
    return now_ns() < until;
}

static inline void throttle_arm(uint64_t window_ms) {
    s_throttle_until_ns.store(now_ns() + window_ms * 1000000ull, std::memory_order_release);
}

static void copy_text_to_clipboard(const std::string& text)
{
#ifdef _WIN32
    if (!::OpenClipboard(nullptr)) return;
    ::EmptyClipboard();
    HGLOBAL hg = ::GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hg) {
        if (auto* p = ::GlobalLock(hg)) {
            std::memcpy(p, text.c_str(), text.size() + 1);
            ::GlobalUnlock(hg);
            if (!::SetClipboardData(CF_TEXT, hg))
                ::GlobalFree(hg);
        } else {
            ::GlobalFree(hg);
        }
    }
    ::CloseClipboard();
#else
    (void)text;
#endif
}

struct colored_run_t {
    ImU32       color = 0;
    std::string text;
};

struct instr_cache_entry_t {
    uint32_t                                       gen = 0;
    uint8_t                                        raw_sig[16] = {};
    int                                            raw_len = 0;
    bool                                           ops_valid = false;
    std::string                                    ops_subst;
    std::vector<colored_run_t>                     ops_runs;
    std::vector<float>                             ops_run_widths;
    float                                          ops_total_width = 0.f;
    bool                                           mnem_valid = false;
    std::string                                    mnem_str;
    bool                                           bytes_valid = false;
    std::string                                    bytes_str;
    bool                                           inj_valid = false;
    std::vector<function_index::injection_row_t>   before_rows;
    std::vector<function_index::injection_row_t>   after_rows;
    std::string                                    inline_label;
    bool                                           xref_valid = false;
    std::vector<xref_index::annotation_t>          xref_at_func;
    bool                                           xref_more_at_func = false;
    bool                                           xref_inline_valid = false;
    std::vector<xref_index::annotation_t>          xref_inline;
    bool                                           xref_inline_more = false;
    bool                                           seg_addr_valid = false;
    std::string                                    seg_addr_str;
    std::string                                    seg_part_str;
    std::string                                    addr_part_str;
    float                                          seg_part_width = 0.f;
    std::string                                    cmt_trimmed;
    std::string                                    cmt_source;
    float                                          cmt_trimmed_for_width = -1.f;
    bool                                           cmt_truncated = false;
    float                                          cmt_drawn_width = 0.f;
    bool                                           composed_valid = false;
    std::string                                    composed_cmt_str;
    std::string                                    composed_tooltip_str;
    bool                                           composed_multiline = false;
    uint64_t                                       composed_branch_target = 0;
    uint64_t                                       composed_imm = 0;
    bool                                           composed_has_imm = false;
    bool                                           composed_has_mnem_override = false;
    std::string                                    composed_mnem_override_token;
};

static std::unordered_map<uint64_t, instr_cache_entry_t> s_instr_cache_hot;
static std::unordered_map<uint64_t, instr_cache_entry_t> s_instr_cache_cold;

static std::atomic<bool>                       s_pdb_subscriptions_armed{false};
static aida::events::subscription_handle_t     s_pdb_loaded_subscription;
static aida::events::subscription_handle_t     s_pdb_unloaded_subscription;

static inline void instr_cache_clear_all() {
    s_instr_cache_hot.clear();
    s_instr_cache_cold.clear();
}

static inline void instr_cache_bound_size() {
    constexpr size_t kCap = 65536;
    constexpr size_t kColdCap = kCap / 2;
    if (s_instr_cache_hot.size() > kCap) {
        if (!s_instr_cache_cold.empty()) {
            s_instr_cache_cold.clear();
        }
        s_instr_cache_cold = std::move(s_instr_cache_hot);
        s_instr_cache_hot.clear();
        s_instr_cache_hot.reserve(kCap / 2);
    }
    if (s_instr_cache_cold.size() > kColdCap) {
        size_t to_drop = s_instr_cache_cold.size() - kColdCap;
        auto it = s_instr_cache_cold.begin();
        while (to_drop > 0 && it != s_instr_cache_cold.end()) {
            it = s_instr_cache_cold.erase(it);
            --to_drop;
        }
    }
}

static inline instr_cache_entry_t& instr_cache_slot(uint64_t addr, uint32_t gen,
                                                    const uint8_t* raw, int raw_len)
{
    auto hot_it = s_instr_cache_hot.find(addr);
    if (hot_it == s_instr_cache_hot.end()) {
        auto cold_it = s_instr_cache_cold.find(addr);
        if (cold_it != s_instr_cache_cold.end()) {
            hot_it = s_instr_cache_hot.emplace(addr, std::move(cold_it->second)).first;
            s_instr_cache_cold.erase(cold_it);
        } else {
            hot_it = s_instr_cache_hot.emplace(addr, instr_cache_entry_t{}).first;
        }
    }
    auto& e = hot_it->second;
    bool reset = (e.gen != gen);
    int sig_len = raw_len < 16 ? raw_len : 16;
    if (!reset) {
        if (e.raw_len != raw_len) reset = true;
        else if (sig_len > 0 && std::memcmp(e.raw_sig, raw, static_cast<size_t>(sig_len)) != 0) reset = true;
    }
    if (reset) {
        e.gen = gen;
        e.raw_len = raw_len;
        std::memset(e.raw_sig, 0, sizeof(e.raw_sig));
        if (sig_len > 0) std::memcpy(e.raw_sig, raw, static_cast<size_t>(sig_len));
        e.ops_valid = false;
        e.ops_subst.clear();
        e.ops_runs.clear();
        e.ops_run_widths.clear();
        e.ops_total_width = 0.f;
        e.mnem_valid = false;
        e.mnem_str.clear();
        e.bytes_valid = false;
        e.bytes_str.clear();
        e.inj_valid = false;
        e.before_rows.clear();
        e.after_rows.clear();
        e.inline_label.clear();
        e.xref_valid = false;
        e.xref_at_func.clear();
        e.xref_more_at_func = false;
        e.xref_inline_valid = false;
        e.xref_inline.clear();
        e.xref_inline_more = false;
        e.seg_addr_valid = false;
        e.seg_addr_str.clear();
        e.seg_part_str.clear();
        e.addr_part_str.clear();
        e.seg_part_width = 0.f;
        e.cmt_trimmed.clear();
        e.cmt_source.clear();
        e.cmt_trimmed_for_width = -1.f;
        e.cmt_truncated = false;
        e.cmt_drawn_width = 0.f;
        e.composed_valid = false;
        e.composed_cmt_str.clear();
        e.composed_tooltip_str.clear();
        e.composed_multiline = false;
        e.composed_branch_target = 0;
        e.composed_imm = 0;
        e.composed_has_imm = false;
        e.composed_has_mnem_override = false;
        e.composed_mnem_override_token.clear();
    }
    return e;
}

void bump_format_generation() {
    s_format_gen.fetch_add(1u, std::memory_order_release);
}

uint32_t format_generation() {
    return s_format_gen.load(std::memory_order_acquire);
}

struct line_layout_t {
    std::vector<int>      start_row;
    std::vector<int>      before_extent;
    std::vector<int>      after_extent;
    std::vector<int>      before_row_count;
    std::vector<int>      proc_xref_extra;
    std::vector<int>      inline_label_extra;
    std::vector<int>      inline_xref_extra;
    std::vector<uint8_t>  align_extra;
    std::vector<uint8_t>  hidden;
    int                   total_rows = 0;
    int                   banner_rows = 0;
    uint32_t              built_gen = 0;
    int                   built_n = 0;
    uint64_t              built_addr_first = 0;
    uint64_t              built_addr_last = 0;
    uint64_t              built_fi_state_sig = 0;
    uint64_t              built_at_ns = 0;
    bool                  ready = false;
    bool                  virtual_flat = false;
};

static line_layout_t s_layout;
static constexpr int kVirtualFlatStaticLayoutThreshold = 250000;

template <typename T>
static void release_layout_vector(std::vector<T>& v) {
    std::vector<T>().swap(v);
}

static int saturated_row_count(int banner_lines, int n) {
    if (n <= 0) return std::max(0, banner_lines);
    if (banner_lines > INT_MAX - n) return INT_MAX;
    return banner_lines + n;
}

static bool should_use_virtual_flat_layout(int n) {
    return n >= kVirtualFlatStaticLayoutThreshold
        && function_index::detail::static_pe_active();
}

static bool layout_uses_virtual_flat() {
    return s_layout.ready && s_layout.virtual_flat;
}

static bool layout_instr_hidden(int i) {
    if (layout_uses_virtual_flat()) return false;
    return i >= 0
        && i < static_cast<int>(s_layout.hidden.size())
        && s_layout.hidden[i] != 0;
}

static int layout_instr_start_row(int i, int banner_lines) {
    if (i < 0) return 0;
    if (layout_uses_virtual_flat()) return s_layout.banner_rows + i;
    if (s_layout.ready && i < static_cast<int>(s_layout.start_row.size())) {
        return s_layout.start_row[i];
    }
    return banner_lines + i;
}

static int layout_before_extent_for(int i) {
    if (layout_uses_virtual_flat()) return 0;
    return i >= 0 && i < static_cast<int>(s_layout.before_extent.size())
        ? s_layout.before_extent[i]
        : 0;
}

static int layout_before_row_count_for(int i, int fallback) {
    if (layout_uses_virtual_flat()) return 0;
    return i >= 0 && i < static_cast<int>(s_layout.before_row_count.size())
        ? s_layout.before_row_count[i]
        : fallback;
}

static int layout_proc_xref_extra_for(int i, int fallback) {
    if (layout_uses_virtual_flat()) return 0;
    return i >= 0 && i < static_cast<int>(s_layout.proc_xref_extra.size())
        ? s_layout.proc_xref_extra[i]
        : fallback;
}

static int layout_inline_xref_extra_for(int i, int fallback) {
    if (layout_uses_virtual_flat()) return 0;
    return i >= 0 && i < static_cast<int>(s_layout.inline_xref_extra.size())
        ? s_layout.inline_xref_extra[i]
        : fallback;
}

struct layout_row_metrics_t {
    int  before_count = 0;
    int  after_count = 0;
    int  proc_xref_count = 0;
    int  inline_xref_count = 0;
    bool has_proc_header = false;
    bool has_inline_label = false;
    bool is_align_start = false;
    bool has_noreturn_separator = false;
    uint64_t align_end = 0;
};

static uint64_t function_index_state_signature() {
    auto& fc = function_index::detail::cache();
    uint64_t built_seq = fc.built_seq.load(std::memory_order_acquire);
    std::shared_lock<std::shared_mutex> lk(fc.mutex);
    uint64_t sig = fc.bounds_state.load(std::memory_order_acquire);
    sig = (sig << 32) ^ static_cast<uint64_t>(fc.sorted_starts.size());
    sig ^= static_cast<uint64_t>(fc.align_run_starts.size()) << 8;
    sig ^= static_cast<uint64_t>(fc.by_start.size()) << 16;
    sig ^= built_seq * 0x9E3779B97F4A7C15ull;
    return sig;
}

static layout_row_metrics_t compute_row_metrics(uint64_t va,
                                                uint64_t align_skip_end_in)
{
    layout_row_metrics_t m;
    if (align_skip_end_in != 0 && va < align_skip_end_in) {
        m.is_align_start = false;
        m.align_end = align_skip_end_in;
        return m;
    }

    function_index::detail::align_run_t arun;
    if (function_index::is_align_row_start(va)
        && function_index::align_run_at(va, &arun))
    {
        m.is_align_start = true;
        m.align_end = arun.end;
        return m;
    }

    std::vector<function_index::injection_row_t> before_rows = function_index::rows_before(va);
    std::vector<function_index::injection_row_t> after_rows  = function_index::rows_after(va);
    m.before_count = static_cast<int>(before_rows.size());
    m.after_count  = static_cast<int>(after_rows.size());
    for (const auto& br : before_rows) {
        if (br.kind == function_index::injection_t::proc_header) {
            m.has_proc_header = true;
            break;
        }
    }
    if (m.has_proc_header) {
        std::vector<xref_index::annotation_t> xrefs = xref_index::query_to(va, 6);
        if (xrefs.size() > 1) {
            m.proc_xref_count = static_cast<int>(xrefs.size()) - 1;
        }
    }

    std::string inline_lbl = function_index::inline_label_at(va);
    if (inline_lbl.empty()) {
        std::vector<xref_index::annotation_t> probe = xref_index::query_to(va, 1);
        bool jump_xref = false;
        for (const auto& a : probe) {
            if (a.kind == xref_index::kind_t::code && a.edge == xref_index::edge_t::jump) {
                jump_xref = true;
                break;
            }
        }
        if (jump_xref && function_index::is_inside_known_function(va)) {
            std::string loc = function_index::loc_label_for(va);
            if (!loc.empty()) inline_lbl = loc + ":";
        }
    }
    if (!inline_lbl.empty()) {
        m.has_inline_label = true;
        std::vector<xref_index::annotation_t> xrefs_label = xref_index::query_to(va, 6);
        if (xrefs_label.size() > 1) {
            m.inline_xref_count = static_cast<int>(xrefs_label.size()) - 1;
        }
    }
    if (function_index::is_noreturn_call_at(va)) {
        m.has_noreturn_separator = true;
    }
    return m;
}

static void rebuild_layout(const std::vector<AsmInstr>& instrs,
                           int banner_lines,
                           uint32_t cur_gen,
                           uint64_t fi_sig)
{
    const int n = static_cast<int>(instrs.size());
    if (should_use_virtual_flat_layout(n)) {
        release_layout_vector(s_layout.start_row);
        release_layout_vector(s_layout.before_extent);
        release_layout_vector(s_layout.after_extent);
        release_layout_vector(s_layout.before_row_count);
        release_layout_vector(s_layout.proc_xref_extra);
        release_layout_vector(s_layout.inline_label_extra);
        release_layout_vector(s_layout.inline_xref_extra);
        release_layout_vector(s_layout.align_extra);
        release_layout_vector(s_layout.hidden);

        s_layout.total_rows = saturated_row_count(banner_lines, n);
        s_layout.banner_rows = banner_lines;
        s_layout.built_gen = cur_gen;
        s_layout.built_n = n;
        s_layout.built_addr_first = (n > 0) ? instrs.front().addr : 0;
        s_layout.built_addr_last  = (n > 0) ? instrs.back().addr  : 0;
        s_layout.built_fi_state_sig = fi_sig;
        s_layout.built_at_ns = now_ns();
        s_layout.ready = true;
        s_layout.virtual_flat = true;
        diag::log_tagged_fmt("disasm_view",
            "rebuild_layout_virtual_flat n=%d threshold=%d total_rows=%d",
            n, kVirtualFlatStaticLayoutThreshold, s_layout.total_rows);
        return;
    }

    s_layout.virtual_flat = false;
    s_layout.start_row.assign(static_cast<size_t>(n), 0);
    s_layout.before_extent.assign(static_cast<size_t>(n), 0);
    s_layout.after_extent.assign(static_cast<size_t>(n), 0);
    s_layout.before_row_count.assign(static_cast<size_t>(n), 0);
    s_layout.proc_xref_extra.assign(static_cast<size_t>(n), 0);
    s_layout.inline_label_extra.assign(static_cast<size_t>(n), 0);
    s_layout.inline_xref_extra.assign(static_cast<size_t>(n), 0);
    s_layout.align_extra.assign(static_cast<size_t>(n), 0);
    s_layout.hidden.assign(static_cast<size_t>(n), 0);

    int cursor = banner_lines;
    uint64_t align_skip_end = 0;
    int last_visible_i = -1;

    for (int i = 0; i < n; ++i) {
        const uint64_t va = instrs[i].addr;
        if (align_skip_end != 0 && va < align_skip_end) {
            s_layout.hidden[i] = 1;
            s_layout.start_row[i] = (last_visible_i >= 0)
                ? s_layout.start_row[last_visible_i]
                : cursor;
            continue;
        }
        if (align_skip_end != 0 && va >= align_skip_end) {
            align_skip_end = 0;
        }

        layout_row_metrics_t m = compute_row_metrics(va, align_skip_end);

        if (m.is_align_start) {
            s_layout.start_row[i] = cursor;
            s_layout.align_extra[i] = 1;
            s_layout.before_extent[i] = 0;
            s_layout.after_extent[i] = 0;
            s_layout.proc_xref_extra[i] = 0;
            s_layout.inline_label_extra[i] = 0;
            s_layout.inline_xref_extra[i] = 0;
            cursor += 2;
            align_skip_end = m.align_end;
            last_visible_i = i;
            continue;
        }

        int proc_xref_extra = m.proc_xref_count;
        int inline_label_rows = m.has_inline_label ? 2 : 0;
        int inline_xref_extra = m.has_inline_label ? m.inline_xref_count : 0;
        int before_extent = m.before_count + proc_xref_extra + inline_label_rows + inline_xref_extra;
        int noreturn_extra = m.has_noreturn_separator ? 1 : 0;
        int after_extent  = m.after_count + noreturn_extra;

        cursor += before_extent;
        s_layout.start_row[i] = cursor;
        s_layout.before_extent[i] = before_extent;
        s_layout.after_extent[i]  = after_extent;
        s_layout.before_row_count[i] = m.before_count;
        s_layout.proc_xref_extra[i] = proc_xref_extra;
        s_layout.inline_label_extra[i] = inline_label_rows;
        s_layout.inline_xref_extra[i]  = inline_xref_extra;
        cursor += 1;
        cursor += after_extent;
        last_visible_i = i;
    }

    s_layout.total_rows = cursor;
    s_layout.banner_rows = banner_lines;
    s_layout.built_gen = cur_gen;
    s_layout.built_n = n;
    s_layout.built_addr_first = (n > 0) ? instrs.front().addr : 0;
    s_layout.built_addr_last  = (n > 0) ? instrs.back().addr  : 0;
    s_layout.built_fi_state_sig = fi_sig;
    s_layout.built_at_ns = now_ns();
    s_layout.ready = true;
}

static inline int layout_instr_row_height(int i) {
    if (i < 0) return 1;
    if (layout_uses_virtual_flat()) return 1;
    if (i >= static_cast<int>(s_layout.start_row.size())) return 1;
    if (s_layout.hidden[i]) return 0;
    return 1 + s_layout.align_extra[i] + s_layout.after_extent[i];
}

static inline int layout_instr_block_start(int i) {
    if (i < 0) return 0;
    if (layout_uses_virtual_flat()) return s_layout.banner_rows + i;
    if (i >= static_cast<int>(s_layout.start_row.size())) return 0;
    return s_layout.start_row[i] - s_layout.before_extent[i];
}

static inline int layout_instr_block_end(int i) {
    if (i < 0) return 0;
    if (layout_uses_virtual_flat()) return s_layout.banner_rows + i + 1;
    if (i >= static_cast<int>(s_layout.start_row.size())) return 0;
    if (s_layout.hidden[i]) return s_layout.start_row[i];
    return s_layout.start_row[i] + 1 + s_layout.align_extra[i] + s_layout.after_extent[i];
}

static int layout_first_visible_instr(int first_vrow, int banner_lines) {
    if (layout_uses_virtual_flat()) {
        if (s_layout.built_n <= 0) return -1;
        int row = first_vrow - s_layout.banner_rows;
        if (row < 0) row = 0;
        if (row >= s_layout.built_n) row = s_layout.built_n - 1;
        return row;
    }
    const int n = static_cast<int>(s_layout.start_row.size());
    if (n <= 0) return -1;
    if (first_vrow < banner_lines) return 0;
    int lo = 0;
    int hi = n - 1;
    int ans = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int block_end = layout_instr_block_end(mid);
        if (block_end > first_vrow) {
            ans = mid;
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return ans;
}

static int layout_last_visible_instr(int last_vrow) {
    if (layout_uses_virtual_flat()) {
        if (s_layout.built_n <= 0) return -1;
        int row = last_vrow - s_layout.banner_rows;
        if (row < 0) row = 0;
        if (row >= s_layout.built_n) row = s_layout.built_n - 1;
        return row;
    }
    const int n = static_cast<int>(s_layout.start_row.size());
    if (n <= 0) return -1;
    int lo = 0;
    int hi = n - 1;
    int ans = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int block_start = layout_instr_block_start(mid);
        if (block_start <= last_vrow) {
            ans = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return ans;
}

static inline float layout_instr_target_scroll_y(int idx, float line_h) {
    if (layout_uses_virtual_flat() && idx >= 0 && idx < s_layout.built_n) {
        return static_cast<float>(s_layout.banner_rows + idx) * line_h;
    }
    if (s_layout.ready && idx >= 0 && idx < static_cast<int>(s_layout.start_row.size())) {
        return static_cast<float>(s_layout.start_row[idx]) * line_h;
    }
    return static_cast<float>(idx + s_banner_line_count) * line_h;
}

static void on_pdb_loaded_event(const aida::events::event_pdb_loaded& ev) {
    if (!ev.success) return;
    bump_format_generation();
}

static void on_pdb_unloaded_event(const aida::events::event_pdb_unloaded& ev) {
    if (ev.module_name.empty()) {
        auto_comment_store::clear();
    } else {
        auto mod = symbol_classifier::find_module_by_name(ev.module_name);
        if (mod && mod->size > 0) {
            auto_comment_store::clear_module(mod->base, mod->size);
        }
    }
    bump_format_generation();
}

static void ensure_pdb_event_subscriptions() {
    if (s_pdb_subscriptions_armed.load(std::memory_order_acquire)) return;
    bool expected = false;
    if (!s_pdb_subscriptions_armed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;

    s_pdb_loaded_subscription = aida::events::subscribe(
        aida::events::event_pdb_loaded_def,
        [](const aida::events::event_pdb_loaded& ev) {
            on_pdb_loaded_event(ev);
        });

    s_pdb_unloaded_subscription = aida::events::subscribe(
        aida::events::event_pdb_unloaded_def,
        [](const aida::events::event_pdb_unloaded& ev) {
            on_pdb_unloaded_event(ev);
        });

    symbol_classifier::subscribe_pdb_events();

    if (!s_pdb_loaded_subscription.valid() && !s_pdb_unloaded_subscription.valid()) {
        s_pdb_subscriptions_armed.store(false, std::memory_order_release);
    }
}

static void on_attach_state_changed() {
    xref_index::on_attach_changed();
    function_index::on_attach_changed();
    symbol_classifier::on_attach_changed();
    s_visible_warm_last_ns.store(0, std::memory_order_release);
    s_format_gen.fetch_add(1u, std::memory_order_release);
    instr_cache_clear_all();
    throttle_arm(120);
}

enum class layout_row_kind_t : int {
    instruction,
    inline_label,
    function_banner,
    attributes_line,
    prototype_line,
    proc_header,
    var_decl,
    proc_endp,
    endp_separator,
    label_line,
    spacer_line,
    xref_continuation
};

struct layout_row_t {
    layout_row_kind_t                  kind = layout_row_kind_t::instruction;
    int                                instr_index = -1;
    uint64_t                           addr = 0;
    std::string                        text;
    function_index::injection_t        injection_kind = function_index::injection_t::spacer_line;
    xref_index::annotation_t           xref_ann;
    bool                               has_xref = false;
    bool                               xref_more = false;
};

struct frame_var_cache_t {
    uint64_t                                            func_start = 0;
    std::unordered_map<int64_t, std::string>            offset_to_name;
    std::unordered_map<int64_t, uint32_t>               offset_to_size;
    std::unordered_map<uint64_t, std::string>           rsp_access_at_va;
    std::unordered_map<uint64_t, std::string>           mnem_override_at_va;
    int64_t                                             entry_to_exit_sp_delta = 0;
    uint64_t                                            prologue_locals_size = 0;
    uint32_t                                            saved_reg_count = 0;
    bool                                                bp_based = false;
    bool                                                sp_based = false;
    bool                                                sp_analysis_failed = false;
    bool                                                is_entry_stub = false;
    bool                                                is_user_main = false;
    std::string                                         user_main_kind;
    bool                                                resolved = false;
};

static std::string ida_section_name_for_va(const DisasmFile& file, uint64_t va) {
    if (file.image_base == 0) return std::string();
    if (va < file.image_base) return std::string();
    if (auto cached = xref_index::detail::lookup_cached_module(va)) {
        if (cached->base != 0 && !cached->sections.empty()) {
            uint32_t rva = static_cast<uint32_t>(va - cached->base);
            for (const auto& s : cached->sections) {
                if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
                    return s.name;
            }
        }
    }
    return std::string(".text");
}

static std::string format_segment_address(const DisasmFile& file, uint64_t addr,
    const std::string& section_override)
{
    std::string seg = section_override.empty() ? ida_section_name_for_va(file, addr) : section_override;
    if (seg.empty()) seg = ".text";
    char buf[64];
    addr_format_t fmt = g_state.addr_format;
    if (fmt == addr_format_t::rva && file.image_base != 0 && addr >= file.image_base) {
        uint64_t rva = addr - file.image_base;
        std::snprintf(buf, sizeof(buf), "%s:+%08llX",
            seg.c_str(), static_cast<unsigned long long>(rva));
    } else {
        std::snprintf(buf, sizeof(buf), "%s:%016llX",
            seg.c_str(), static_cast<unsigned long long>(addr));
    }
    return std::string(buf);
}

static std::string ida_xref_kind_label(const xref_index::annotation_t& a) {
    if (a.kind == xref_index::kind_t::data) {
        switch (a.edge) {
            case xref_index::edge_t::offset_ref: return std::string("DATA XREF: ");
            case xref_index::edge_t::call_proc: return std::string("DATA XREF: ");
            case xref_index::edge_t::jump:      return std::string("DATA XREF: ");
        }
        return std::string("DATA XREF: ");
    }
    return std::string("CODE XREF: ");
}

static const char* ida_xref_arrow_utf8(bool up) {
    return up ? "^" : "v";
}

static const char* ida_xref_edge_letter(const xref_index::annotation_t& a) {
    if (a.kind == xref_index::kind_t::data) {
        return a.edge == xref_index::edge_t::offset_ref ? "o" : "r";
    }
    switch (a.edge) {
        case xref_index::edge_t::call_proc:  return "p";
        case xref_index::edge_t::jump:       return "j";
        case xref_index::edge_t::offset_ref: return "o";
    }
    return "j";
}

static std::string ida_format_xref_comment(const xref_index::annotation_t& a, bool more) {
    std::string out = "; ";
    out += ida_xref_kind_label(a);
    out += a.source_label;
    out += ida_xref_arrow_utf8(a.up);
    out += ida_xref_edge_letter(a);
    if (more) out += " ...";
    return out;
}

static frame_var_cache_t& var_cache_slot() {
    static thread_local frame_var_cache_t s;
    return s;
}

static void prime_var_cache(uint64_t func_start) {
    auto& c = var_cache_slot();
    if (c.resolved && c.func_start == func_start) return;
    c.func_start = func_start;
    c.offset_to_name.clear();
    c.offset_to_size.clear();
    c.rsp_access_at_va.clear();
    c.mnem_override_at_va.clear();
    c.entry_to_exit_sp_delta = 0;
    c.prologue_locals_size = 0;
    c.saved_reg_count = 0;
    c.bp_based = false;
    c.sp_based = false;
    c.sp_analysis_failed = false;
    c.is_entry_stub = false;
    c.is_user_main = false;
    c.user_main_kind.clear();
    c.resolved = true;
    if (func_start == 0) return;

    auto& fc = function_index::detail::cache();
    std::shared_lock<std::shared_mutex> lk(fc.mutex);
    auto it = fc.by_start.find(func_start);
    if (it == fc.by_start.end()) return;
    const auto& rec = it->second;
    for (const auto& v : rec.vars) {
        c.offset_to_name[v.offset] = v.name;
        c.offset_to_size[v.offset] = v.size;
    }
    c.rsp_access_at_va = rec.rsp_access_substitution;
    c.mnem_override_at_va = rec.insn_kind_override;
    c.entry_to_exit_sp_delta = rec.entry_to_exit_sp_delta;
    c.prologue_locals_size = rec.prologue_locals_size;
    c.bp_based = rec.bp_based;
    c.sp_based = rec.sp_based;
    c.sp_analysis_failed = rec.sp_analysis_failed;
    c.is_entry_stub = rec.is_entry_stub;
    c.is_user_main = rec.is_user_main;
    c.user_main_kind = rec.user_main_kind;
    uint32_t cnt = 0;
    for (const auto& kv : rec.insn_kind_override) {
        const std::string& s = kv.second;
        if (s.size() >= 2 && s[0] == 'r' && s[1] == '_') ++cnt;
    }
    c.saved_reg_count = cnt;
}

static bool lookup_named_offset(int64_t offset, std::string& out_name) {
    auto& c = var_cache_slot();
    auto it = c.offset_to_name.find(offset);
    if (it == c.offset_to_name.end()) return false;
    out_name = it->second;
    return true;
}

static bool lookup_rsp_substitution_at(uint64_t va, std::string& out_name) {
    auto& c = var_cache_slot();
    auto it = c.rsp_access_at_va.find(va);
    if (it == c.rsp_access_at_va.end()) return false;
    out_name = it->second;
    return true;
}

static bool lookup_mnem_override_at(uint64_t va, std::string& out_name) {
    auto& c = var_cache_slot();
    auto it = c.mnem_override_at_va.find(va);
    if (it == c.mnem_override_at_va.end()) return false;
    out_name = it->second;
    return true;
}

static bool parse_signed_hex_after(const char* p, int64_t& out) {
    if (!p || !*p) return false;
    char sign = '+';
    if (*p == '+' || *p == '-') { sign = *p; ++p; }
    while (*p == ' ') ++p;
    if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    char* end = nullptr;
    unsigned long long v = std::strtoull(p, &end, 16);
    if (end == p) return false;
    int64_t sv = static_cast<int64_t>(v);
    if (sign == '-') sv = -sv;
    out = sv;
    return true;
}

static int extract_operand_size(const std::string& ops, size_t before_pos)
{
    static const struct { const char* tag; int size; } kTable[] = {
        { "zmmword ptr", 64 },
        { "ymmword ptr", 32 },
        { "xmmword ptr", 16 },
        { "tbyte ptr",   10 },
        { "qword ptr",    8 },
        { "fword ptr",    6 },
        { "dword ptr",    4 },
        { "word ptr",     2 },
        { "byte ptr",     1 }
    };
    if (before_pos == 0 || before_pos > ops.size()) return 0;
    std::string head = ops.substr(0, before_pos);
    for (auto& e : kTable) {
        size_t pos = 0;
        size_t taglen = std::strlen(e.tag);
        while ((pos = head.find(e.tag, pos)) != std::string::npos) {
            bool prev_ok = (pos == 0)
                || !((head[pos - 1] >= 'a' && head[pos - 1] <= 'z')
                  || (head[pos - 1] >= 'A' && head[pos - 1] <= 'Z')
                  || (head[pos - 1] >= '0' && head[pos - 1] <= '9')
                  || head[pos - 1] == '_');
            if (prev_ok) return e.size;
            pos += taglen;
        }
    }
    return 0;
}

static std::string synthesize_data_name(uint64_t target, int op_size,
                                        symbol_classifier::kind_t k)
{
    char syn[64];
    if (k == symbol_classifier::kind_t::string
        || k == symbol_classifier::kind_t::string_ascii
        || k == symbol_classifier::kind_t::string_unicode) {
        std::snprintf(syn, sizeof(syn), "asc_%llX",
            static_cast<unsigned long long>(target));
        return syn;
    }
    if (k == symbol_classifier::kind_t::external_import
        || k == symbol_classifier::kind_t::imp_function) {
        std::snprintf(syn, sizeof(syn), "__imp_unk_%llX",
            static_cast<unsigned long long>(target));
        return syn;
    }
    if (op_size > 0) {
        std::snprintf(syn, sizeof(syn), "%s_%llX",
            symbol_classifier::data_prefix_for_size(op_size),
            static_cast<unsigned long long>(target));
        return syn;
    }
    if (k == symbol_classifier::kind_t::data
        || k == symbol_classifier::kind_t::data_byte
        || k == symbol_classifier::kind_t::data_word
        || k == symbol_classifier::kind_t::data_dword
        || k == symbol_classifier::kind_t::data_qword
        || k == symbol_classifier::kind_t::data_xmmword
        || k == symbol_classifier::kind_t::data_ymmword
        || k == symbol_classifier::kind_t::data_zmmword
        || k == symbol_classifier::kind_t::data_tbyte
        || k == symbol_classifier::kind_t::data_unknown) {
        std::snprintf(syn, sizeof(syn), "unk_%llX",
            static_cast<unsigned long long>(target));
        return syn;
    }
    if (k == symbol_classifier::kind_t::regular_function
        || k == symbol_classifier::kind_t::library_function
        || k == symbol_classifier::kind_t::lumina_function
        || k == symbol_classifier::kind_t::label) {
        std::snprintf(syn, sizeof(syn), "sub_%llX",
            static_cast<unsigned long long>(target));
        return syn;
    }
    return std::string();
}

static std::string resolve_or_synthesize_data(uint64_t target, int op_size)
{
    std::string sym = symbol_store::resolve_symbol_exact(target);
    if (sym.empty()) sym = symbol_store::resolve_symbol(target);
    symbol_classifier::kind_t k = symbol_classifier::classify(target);
    if (sym.empty()) {
        if (k == symbol_classifier::kind_t::regular_function
            || k == symbol_classifier::kind_t::library_function
            || k == symbol_classifier::kind_t::lumina_function
            || k == symbol_classifier::kind_t::entry_point
            || k == symbol_classifier::kind_t::main_function
            || k == symbol_classifier::kind_t::winmain_function
            || k == symbol_classifier::kind_t::dllmain_function
            || k == symbol_classifier::kind_t::jump_thunk
            || k == symbol_classifier::kind_t::label) {
            sym = function_index::synthetic_name(target);
        }
        if (sym.empty()) {
            sym = synthesize_data_name(target, op_size, k);
        }
    }
    if (!sym.empty()) {
        auto bang = sym.find('!');
        if (bang != std::string::npos) sym = sym.substr(bang + 1);
        if ((k == symbol_classifier::kind_t::external_import
             || k == symbol_classifier::kind_t::imp_function)
            && sym.compare(0, 6, "__imp_") != 0) {
            sym = "__imp_" + sym;
        }
    }
    return sym;
}

static bool parse_signed_hex_run(const char* p, size_t avail, int64_t& out, size_t& consumed)
{
    if (avail == 0) return false;
    size_t i = 0;
    int sign = 0;
    if (p[i] == '+' || p[i] == '-') { sign = (p[i] == '-') ? -1 : 1; ++i; if (i >= avail) return false; }
    while (i < avail && p[i] == ' ') ++i;
    if (i + 1 >= avail) return false;
    if (p[i] != '0' || (p[i + 1] != 'x' && p[i + 1] != 'X')) return false;
    i += 2;
    size_t hex_start = i;
    while (i < avail) {
        char c = p[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            ++i;
        } else {
            break;
        }
    }
    if (i == hex_start) return false;
    char buf[24];
    size_t hl = i - hex_start;
    if (hl >= sizeof(buf)) hl = sizeof(buf) - 1;
    std::memcpy(buf, p + hex_start, hl);
    buf[hl] = '\0';
    unsigned long long v = std::strtoull(buf, nullptr, 16);
    int64_t sv = static_cast<int64_t>(v);
    if (sign < 0) sv = -sv;
    out = sv;
    consumed = i;
    return true;
}

static bool lookup_struct_field_at_base_va(uint64_t base_va, int64_t disp, int op_size,
                                           std::string& out_struct_name, std::string& out_field_name)
{
    out_struct_name.clear();
    out_field_name.clear();
    if (base_va == 0 || disp < 0) return false;

    auto mod = symbol_classifier::find_module_by_address(base_va);
    if (!mod) return false;

    auto bindings = symbol_classifier::get_struct_bindings(mod);
    if (!bindings || bindings->empty()) return false;

    const symbol_classifier::detail::struct_binding_t* match = nullptr;
    for (const auto& kv : *bindings) {
        if (kv.second.base_va == base_va) {
            match = &kv.second;
            break;
        }
    }
    if (!match) return false;

    const uint32_t udisp = static_cast<uint32_t>(disp);
    auto it = match->field_by_offset.find(udisp);
    if (it != match->field_by_offset.end()) {
        const auto& field = match->fields[it->second];
        if (op_size > 0 && field.size > 0
            && static_cast<uint32_t>(op_size) != field.size) {
            return false;
        }
        out_struct_name = match->struct_name;
        out_field_name = field.name;
        return !out_field_name.empty();
    }

    for (const auto& f : match->fields) {
        if (f.size == 0) continue;
        if (udisp < f.offset || udisp >= f.offset + f.size) continue;
        const uint32_t inner = udisp - f.offset;
        if (op_size > 0 && static_cast<uint32_t>(op_size) > f.size - inner) continue;
        out_struct_name = match->struct_name;
        if (inner == 0) {
            out_field_name = f.name;
        } else {
            char buf[96];
            std::snprintf(buf, sizeof(buf), "%s+0x%X", f.name.c_str(),
                static_cast<unsigned>(inner));
            out_field_name.assign(buf);
        }
        return !out_field_name.empty();
    }

    return false;
}

static bool resolve_struct_binding_by_name(std::string_view sym, uint64_t& out_base_va,
                                           std::string& out_struct_name)
{
    out_base_va = 0;
    out_struct_name.clear();
    if (sym.empty()) return false;

    if (sym.size() > 5 && (sym[0] == 's' || sym[0] == 'S')
        && (sym[1] == 't' || sym[1] == 'T')
        && (sym[2] == 'r' || sym[2] == 'R')
        && (sym[3] == 'u' || sym[3] == 'U')
        && sym[4] == '_') {
        std::string hex_part(sym.substr(5));
        if (!hex_part.empty()) {
            char* end = nullptr;
            uint64_t va = std::strtoull(hex_part.c_str(), &end, 16);
            if (end && *end == '\0' && va != 0) {
                out_base_va = va;
                return true;
            }
        }
    }

    std::string sym_str(sym);
    uint64_t addr = symbol_store::resolve_name_to_addr(sym_str);
    if (addr == 0) return false;

    auto mod = symbol_classifier::find_module_by_address(addr);
    if (!mod) return false;
    auto bindings = symbol_classifier::get_struct_bindings(mod);
    if (!bindings) return false;
    for (const auto& kv : *bindings) {
        if (kv.second.base_va == addr) {
            out_base_va = addr;
            out_struct_name = kv.second.struct_name;
            return true;
        }
    }
    return false;
}

static inline bool is_ident_start_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static inline bool is_ident_body_char(char c) {
    return is_ident_start_char(c) || (c >= '0' && c <= '9') || c == '!';
}

static inline bool is_hex_digit_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

namespace ida_demangle {

using PFN_UnDecorateSymbolName = DWORD (WINAPI*)(PCSTR DecoratedName, PSTR UnDecoratedName, DWORD UndecoratedLength, DWORD Flags);

static std::once_flag s_dbghelp_init_once;
static PFN_UnDecorateSymbolName s_pfn_undecorate = nullptr;

static void init_undecorate() {
    std::call_once(s_dbghelp_init_once, []() {
        HMODULE h = GetModuleHandleW(L"dbghelp.dll");
        if (!h) h = LoadLibraryW(L"dbghelp.dll");
        if (h) {
            s_pfn_undecorate = reinterpret_cast<PFN_UnDecorateSymbolName>(
                GetProcAddress(h, "UnDecorateSymbolName"));
        }
    });
}

static bool demangle_msvc(const std::string& mangled, std::string& out_pretty) {
    out_pretty.clear();
    if (mangled.empty()) return false;
    if (mangled[0] != '?' && mangled.compare(0, 2, "_?") != 0) return false;
    init_undecorate();
    if (!s_pfn_undecorate) return false;
    std::unique_lock<std::mutex> dbghelp_lk(pdb_parser::g_dbghelp_call_mutex, std::try_to_lock);
    if (!dbghelp_lk.owns_lock()) return false;
    constexpr DWORD UNDNAME_COMPLETE = 0x0000;
    constexpr DWORD UNDNAME_NO_LEADING_UNDERSCORES = 0x0001;
    constexpr DWORD UNDNAME_NO_MS_KEYWORDS = 0x0002;
    constexpr DWORD UNDNAME_NO_FUNCTION_RETURNS = 0x0004;
    constexpr DWORD UNDNAME_NO_ALLOCATION_MODEL = 0x0008;
    constexpr DWORD UNDNAME_NO_ALLOCATION_LANGUAGE = 0x0010;
    constexpr DWORD UNDNAME_NO_THISTYPE = 0x0060;
    constexpr DWORD UNDNAME_NO_ACCESS_SPECIFIERS = 0x0080;
    constexpr DWORD UNDNAME_NO_THROW_SIGNATURES = 0x0100;
    constexpr DWORD UNDNAME_NO_MEMBER_TYPE = 0x0200;
    constexpr DWORD UNDNAME_NO_RETURN_UDT_MODEL = 0x0400;
    DWORD flags = UNDNAME_COMPLETE
        | UNDNAME_NO_LEADING_UNDERSCORES
        | UNDNAME_NO_MS_KEYWORDS
        | UNDNAME_NO_FUNCTION_RETURNS
        | UNDNAME_NO_ALLOCATION_MODEL
        | UNDNAME_NO_ALLOCATION_LANGUAGE
        | UNDNAME_NO_THISTYPE
        | UNDNAME_NO_ACCESS_SPECIFIERS
        | UNDNAME_NO_THROW_SIGNATURES
        | UNDNAME_NO_MEMBER_TYPE
        | UNDNAME_NO_RETURN_UDT_MODEL;
    char buf[1024] = {};
    DWORD r = s_pfn_undecorate(mangled.c_str(), buf, static_cast<DWORD>(sizeof(buf)), flags);
    if (r == 0) return false;
    out_pretty.assign(buf, r);
    if (out_pretty.empty()) return false;
    if (out_pretty == mangled) return false;
    return true;
}

}

namespace ida_api_args {

struct api_arg_table_t {
    const char* name;
    const char* args[8];
};

static const api_arg_table_t kApiArgs[] = {
    { "??2@YAPEAX_K@Z",            { "Size", nullptr } },
    { "operator new",               { "Size", nullptr } },
    { "??3@YAXPEAX_K@Z",            { "Block", "Size", nullptr } },
    { "operator delete",            { "Block", nullptr } },
    { "memcpy",                     { "Dst", "Src", "Size", nullptr } },
    { "memcpy_s",                   { "Dst", "DstSize", "Src", "Size", nullptr } },
    { "memmove",                    { "Dst", "Src", "Size", nullptr } },
    { "memset",                     { "Dst", "Val", "Size", nullptr } },
    { "memcmp",                     { "Buf1", "Buf2", "Size", nullptr } },
    { "strcpy",                     { "Dst", "Src", nullptr } },
    { "strcpy_s",                   { "Dst", "DstSize", "Src", nullptr } },
    { "strncpy",                    { "Dst", "Src", "Size", nullptr } },
    { "strcat",                     { "Dst", "Src", nullptr } },
    { "strlen",                     { "Str", nullptr } },
    { "strcmp",                     { "Str1", "Str2", nullptr } },
    { "strncmp",                    { "Str1", "Str2", "Size", nullptr } },
    { "_invoke_watson",             { "Expression", "FunctionName", "FileName", "LineNo", "Reserved", nullptr } },
    { "atexit",                     { "Func", nullptr } },
    { "_CxxThrowException",         { "ThrowInfo", "Object", nullptr } },
    { "RaiseException",             { "ExceptionCode", "ExceptionFlags", "NumberOfArguments", "Arguments", nullptr } },
    { "HeapAlloc",                  { "hHeap", "dwFlags", "dwBytes", nullptr } },
    { "HeapFree",                   { "hHeap", "dwFlags", "lpMem", nullptr } },
    { "HeapReAlloc",                { "hHeap", "dwFlags", "lpMem", "dwBytes", nullptr } },
    { "VirtualAlloc",               { "lpAddress", "dwSize", "flAllocationType", "flProtect", nullptr } },
    { "VirtualFree",                { "lpAddress", "dwSize", "dwFreeType", nullptr } },
    { "VirtualProtect",             { "lpAddress", "dwSize", "flNewProtect", "lpflOldProtect", nullptr } },
    { "LoadLibraryA",               { "lpLibFileName", nullptr } },
    { "LoadLibraryW",               { "lpLibFileName", nullptr } },
    { "LoadLibraryExA",             { "lpLibFileName", "hFile", "dwFlags", nullptr } },
    { "LoadLibraryExW",             { "lpLibFileName", "hFile", "dwFlags", nullptr } },
    { "GetProcAddress",             { "hModule", "lpProcName", nullptr } },
    { "GetModuleHandleA",           { "lpModuleName", nullptr } },
    { "GetModuleHandleW",           { "lpModuleName", nullptr } },
    { "CreateFileA",                { "lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile", nullptr } },
    { "CreateFileW",                { "lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile", nullptr } },
    { "ReadFile",                   { "hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped", nullptr } },
    { "WriteFile",                  { "hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpNumberOfBytesWritten", "lpOverlapped", nullptr } },
    { "CloseHandle",                { "hObject", nullptr } },
    { "SetFilePointerEx",           { "hFile", "liDistanceToMove", "lpNewFilePointer", "dwMoveMethod", nullptr } },
    { "GetLastError",               { nullptr } },
    { "SetLastError",               { "dwErrCode", nullptr } },
    { "ExitProcess",                { "uExitCode", nullptr } },
    { "TerminateProcess",           { "hProcess", "uExitCode", nullptr } },
};

static const char* const* args_for(const std::string& fname) {
    if (fname.empty()) return nullptr;
    for (const auto& e : kApiArgs) {
        if (fname == e.name) return e.args;
    }
    if (fname.size() > 2 && fname[0] == '_' && fname[1] != '_') {
        std::string alt = fname.substr(1);
        for (const auto& e : kApiArgs) {
            if (alt == e.name) return e.args;
        }
    }
    return nullptr;
}

}

static std::string strip_module_prefix_fast(std::string s) {
    auto bang = s.find('!');
    if (bang != std::string::npos) s = s.substr(bang + 1);
    return s;
}

static std::string resolve_import_via_iat(uint64_t iat_va) {
    if (iat_va == 0) return std::string();
    std::string fi = function_index::iat_symbol_at(iat_va);
    if (!fi.empty()) return strip_module_prefix_fast(fi);
    std::string name;
    if (symbol_classifier::lookup_import_by_iat(iat_va, name) && !name.empty()) {
        return strip_module_prefix_fast(name);
    }
    return std::string();
}

static std::string demangle_or_self(const std::string& name) {
    std::string out;
    if (name.empty()) return name;
    if (name[0] != '?' && (name.size() < 2 || name[0] != '_' || name[1] != '?')) return name;
    if (ida_demangle::demangle_msvc(name, out) && !out.empty()) return out;
    return name;
}

static std::string demangle_tail_comment(const std::string& mangled) {
    if (mangled.empty()) return std::string();
    if (mangled[0] != '?' && (mangled.size() < 2 || mangled[0] != '_' || mangled[1] != '?')) return std::string();
    std::string pretty;
    if (!ida_demangle::demangle_msvc(mangled, pretty)) return std::string();
    if (pretty.empty() || pretty == mangled) return std::string();
    return pretty;
}

static bool resolve_memory_operand_va(const AsmInstr& ins,
                                      uint64_t target,
                                      int op_size,
                                      std::string& out_sym,
                                      std::string& out_seg_prefix,
                                      bool& out_drop_brackets)
{
    out_sym.clear();
    out_seg_prefix.clear();
    out_drop_brackets = false;
    if (target == 0) return false;
    const bool is_lea = (ins.mnem[0] == 'l' && ins.mnem[1] == 'e' && ins.mnem[2] == 'a' && ins.mnem[3] == '\0');

    {
        std::string imp_name = resolve_import_via_iat(target);
        if (!imp_name.empty()) {
            if (imp_name.size() >= 6 && imp_name.compare(0, 6, "__imp_") == 0)
                imp_name = imp_name.substr(6);
            out_sym = imp_name;
            out_seg_prefix = "cs:";
            out_drop_brackets = true;
            return true;
        }
    }

    {
        std::string data_name;
        bool data_is_function = false;
        if (function_index::data_symbol_entry_at(target, data_name, data_is_function)
            && !data_name.empty())
        {
            out_sym = data_name;
            if (data_is_function && is_lea) {
                out_drop_brackets = true;
            }
            else {
                out_seg_prefix = "cs:";
                out_drop_brackets = true;
            }
            return true;
        }
    }

    {
        std::string exact = symbol_store::resolve_symbol_exact(target);
        exact = strip_module_prefix_fast(exact);
        if (!exact.empty()) {
            out_sym = exact;
            if (!ins.is_call && !ins.is_branch && !is_lea) {
                out_seg_prefix = "cs:";
            }
            out_drop_brackets = true;
            return true;
        }
    }

    if (function_index::is_inside_known_function(target)
        || function_index::func_start_for(target) == target)
    {
        std::string fn = function_index::synthetic_name(target);
        if (!fn.empty()) {
            out_sym = fn;
            out_drop_brackets = true;
            if (!is_lea && !ins.is_call && !ins.is_branch) {
                out_seg_prefix = "cs:";
            }
            return true;
        }
    }

    {
        std::string fallback = resolve_or_synthesize_data(target, op_size);
        if (!fallback.empty()) {
            out_sym = fallback;
            if (!is_lea
                && (fallback.size() >= 6 && fallback.compare(0, 6, "__imp_") == 0))
            {
                out_sym = fallback.substr(6);
                out_seg_prefix = "cs:";
                out_drop_brackets = true;
            }
            return true;
        }
    }

    return false;
}

static std::string substitute_operand_text(const AsmInstr& ins, const DisasmFile& file)
{
    std::string base(ins.ops);
    if (base.empty()) return base;

    auto try_replace_hex = [&](const std::string& src, uint64_t target,
                              const std::string& replacement) -> std::string {
        char hex_buf[32];
        std::snprintf(hex_buf, sizeof(hex_buf), "0x%llX", static_cast<unsigned long long>(target));
        size_t pos = src.find(hex_buf);
        if (pos == std::string::npos) {
            std::snprintf(hex_buf, sizeof(hex_buf), "0x%llx", static_cast<unsigned long long>(target));
            pos = src.find(hex_buf);
        }
        if (pos == std::string::npos) {
            std::snprintf(hex_buf, sizeof(hex_buf), "%llXh", static_cast<unsigned long long>(target));
            pos = src.find(hex_buf);
        }
        if (pos == std::string::npos) return src;
        std::string out = src.substr(0, pos) + replacement
                          + src.substr(pos + std::strlen(hex_buf));
        return out;
    };

    if ((ins.is_branch || ins.is_call) && ins.branch_target != 0) {
        uint64_t target = ins.branch_target;
        std::string sym = function_index::synthetic_name(target);
        if (!sym.empty()) {
            symbol_classifier::kind_t k = symbol_classifier::classify(target);
            if (k == symbol_classifier::kind_t::external_import) {
                if (sym.compare(0, 6, "__imp_") != 0)
                    sym = "__imp_" + sym;
            }
            base = try_replace_hex(base, target, sym);
        }
    }

    {
        size_t bp_pos = base.find("[ebp");
        if (bp_pos == std::string::npos) bp_pos = base.find("[rbp");
        if (bp_pos != std::string::npos) {
            size_t close = base.find(']', bp_pos);
            if (close != std::string::npos) {
                size_t off_start = bp_pos + 4;
                if (off_start < base.size() && (base[off_start] == '+' || base[off_start] == '-')) {
                    int64_t parsed = 0;
                    if (parse_signed_hex_after(base.c_str() + off_start, parsed)) {
                        std::string named;
                        if (lookup_named_offset(parsed, named) && !named.empty()) {
                            base = base.substr(0, bp_pos + 4) + "+" + named
                                   + base.substr(close);
                        }
                    }
                }
            }
        }
    }

    {
        std::string rsp_named;
        if (lookup_rsp_substitution_at(ins.addr, rsp_named) && !rsp_named.empty()) {
            size_t sp_pos = base.find("[rsp");
            size_t alt_pos = base.find("[esp");
            if (sp_pos == std::string::npos
                || (alt_pos != std::string::npos && alt_pos < sp_pos))
            {
                sp_pos = alt_pos;
            }
            if (sp_pos != std::string::npos) {
                size_t close = base.find(']', sp_pos);
                if (close != std::string::npos) {
                    size_t after_reg = sp_pos + 4;
                    if (after_reg < base.size()
                        && (base[after_reg] == ']'
                            || base[after_reg] == '+'
                            || base[after_reg] == '-'))
                    {
                        int64_t entry_rel = 0;
                        uint64_t func_start = 0;
                        uint64_t locals_size = 0;
                        std::string prefix;
                        if (function_index::rsp_entry_relative_at(ins.addr, &entry_rel,
                            &func_start, &locals_size) && locals_size != 0)
                        {
                            char hb[24];
                            std::snprintf(hb, sizeof(hb), "%llXh",
                                static_cast<unsigned long long>(locals_size));
                            prefix = std::string("+") + hb;
                        }
                        std::string repl = "[rsp" + prefix + "+" + rsp_named;
                        base = base.substr(0, sp_pos) + repl + base.substr(close);
                    }
                }
            }
        }
    }

    {
        size_t ds_pos = base.find("ds:0x");
        if (ds_pos != std::string::npos) {
            size_t hex_start = ds_pos + 5;
            uint64_t target = 0;
            if (sscanf_s(base.c_str() + hex_start - 2, "%llx", &target) == 1
                && target != 0)
            {
                int op_size = extract_operand_size(base, ds_pos);
                std::string sym = resolve_or_synthesize_data(target, op_size);
                if (!sym.empty()) {
                    char hex_b[32];
                    std::snprintf(hex_b, sizeof(hex_b), "0x%llX",
                        static_cast<unsigned long long>(target));
                    std::string h_lo = hex_b;
                    std::snprintf(hex_b, sizeof(hex_b), "0x%llx",
                        static_cast<unsigned long long>(target));
                    std::string h_lo2 = hex_b;
                    size_t found = base.find(h_lo);
                    if (found == std::string::npos) found = base.find(h_lo2);
                    if (found != std::string::npos) {
                        size_t take = (base.compare(found, h_lo.size(), h_lo) == 0)
                                      ? h_lo.size() : h_lo2.size();
                        base = base.substr(0, found) + sym + base.substr(found + take);
                    }
                }
            }
        }
    }

    {
        size_t scan_pos = 0;
        const bool is_lea_outer = (ins.mnem[0] == 'l' && ins.mnem[1] == 'e' && ins.mnem[2] == 'a' && ins.mnem[3] == '\0');
        while (scan_pos < base.size()) {
            size_t rip_pos = base.find("[rip", scan_pos);
            if (rip_pos == std::string::npos) break;
            size_t after_rip = rip_pos + 4;
            while (after_rip < base.size() && base[after_rip] == ' ') ++after_rip;
            if (after_rip >= base.size() || (base[after_rip] != '+' && base[after_rip] != '-')) {
                size_t close = base.find(']', rip_pos);
                if (close == std::string::npos) break;
                size_t close_pos = base.find(']', after_rip);
                if (close_pos != std::string::npos && after_rip == close_pos) {
                    uint64_t target = ins.addr + ins.len;
                    int op_size = extract_operand_size(base, rip_pos);
                    std::string sym;
                    std::string seg_prefix;
                    bool drop_brackets = false;
                    if (resolve_memory_operand_va(ins, target, op_size, sym, seg_prefix, drop_brackets)
                        && !sym.empty())
                    {
                        std::string repl;
                        if (!seg_prefix.empty()) {
                            repl = seg_prefix + sym;
                            base = base.substr(0, rip_pos) + repl + base.substr(close + 1);
                            scan_pos = rip_pos + repl.size();
                        }
                        else if (is_lea_outer || drop_brackets) {
                            repl = sym;
                            base = base.substr(0, rip_pos) + repl + base.substr(close + 1);
                            scan_pos = rip_pos + repl.size();
                        }
                        else {
                            repl = "[" + sym;
                            base = base.substr(0, rip_pos) + repl + base.substr(close);
                            scan_pos = rip_pos + repl.size();
                        }
                        continue;
                    }
                }
                scan_pos = close + 1;
                continue;
            }
            int64_t disp = 0;
            size_t consumed = 0;
            if (!parse_signed_hex_run(base.c_str() + after_rip,
                                      base.size() - after_rip, disp, consumed)) {
                scan_pos = after_rip + 1;
                continue;
            }
            size_t close_pos = after_rip + consumed;
            while (close_pos < base.size() && base[close_pos] == ' ') ++close_pos;
            if (close_pos >= base.size() || base[close_pos] != ']') {
                scan_pos = after_rip + consumed;
                continue;
            }
            uint64_t target = ins.addr + ins.len + static_cast<uint64_t>(disp);
            int op_size = extract_operand_size(base, rip_pos);
            std::string sym;
            std::string seg_prefix;
            bool drop_brackets = false;
            if (resolve_memory_operand_va(ins, target, op_size, sym, seg_prefix, drop_brackets)
                && !sym.empty())
            {
                std::string repl;
                if (!seg_prefix.empty()) {
                    repl = seg_prefix + sym;
                    base = base.substr(0, rip_pos) + repl + base.substr(close_pos + 1);
                    scan_pos = rip_pos + repl.size();
                }
                else if (is_lea_outer || drop_brackets) {
                    repl = sym;
                    base = base.substr(0, rip_pos) + repl + base.substr(close_pos + 1);
                    scan_pos = rip_pos + repl.size();
                }
                else {
                    repl = "[" + sym;
                    base = base.substr(0, rip_pos) + repl + base.substr(close_pos);
                    scan_pos = rip_pos + repl.size();
                }
            } else {
                scan_pos = close_pos + 1;
            }
        }
    }

    {
        size_t scan_pos = 0;
        while (scan_pos < base.size()) {
            size_t br_pos = base.find('[', scan_pos);
            if (br_pos == std::string::npos) break;
            size_t hx = br_pos + 1;
            while (hx < base.size() && base[hx] == ' ') ++hx;
            if (hx + 1 >= base.size() || base[hx] != '0' || (base[hx + 1] != 'x' && base[hx + 1] != 'X')) {
                scan_pos = br_pos + 1;
                continue;
            }
            size_t hex_run_start = hx + 2;
            size_t hex_run_end = hex_run_start;
            while (hex_run_end < base.size()) {
                char c = base[hex_run_end];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    ++hex_run_end;
                else break;
            }
            if (hex_run_end == hex_run_start) {
                scan_pos = br_pos + 1;
                continue;
            }
            size_t after = hex_run_end;
            while (after < base.size() && base[after] == ' ') ++after;
            if (after >= base.size() || base[after] != ']') {
                scan_pos = br_pos + 1;
                continue;
            }
            char buf[24];
            size_t hl = hex_run_end - hex_run_start;
            if (hl >= sizeof(buf)) hl = sizeof(buf) - 1;
            std::memcpy(buf, base.c_str() + hex_run_start, hl);
            buf[hl] = '\0';
            uint64_t target = std::strtoull(buf, nullptr, 16);
            if (target == 0) {
                scan_pos = after + 1;
                continue;
            }
            int op_size = extract_operand_size(base, br_pos);

            std::string seg_prefix;
            std::string sym;
            bool drop_brackets = false;
            const bool is_lea = (ins.mnem[0] == 'l' && ins.mnem[1] == 'e' && ins.mnem[2] == 'a' && ins.mnem[3] == '\0');

            if (resolve_memory_operand_va(ins, target, op_size, sym, seg_prefix, drop_brackets)
                && !sym.empty())
            {
                std::string repl;
                if (!seg_prefix.empty()) {
                    repl = seg_prefix + sym;
                    base = base.substr(0, br_pos) + repl + base.substr(after + 1);
                    scan_pos = br_pos + repl.size();
                }
                else if (is_lea || drop_brackets) {
                    repl = sym;
                    base = base.substr(0, br_pos) + repl + base.substr(after + 1);
                    scan_pos = br_pos + repl.size();
                }
                else {
                    repl = "[" + sym;
                    base = base.substr(0, br_pos) + repl + base.substr(after);
                    scan_pos = br_pos + repl.size();
                }
            } else {
                scan_pos = after + 1;
            }
        }
    }

    {
        size_t scan_pos = 0;
        while (scan_pos < base.size()) {
            size_t br_pos = base.find('[', scan_pos);
            if (br_pos == std::string::npos) break;
            size_t name_start = br_pos + 1;
            while (name_start < base.size() && base[name_start] == ' ') ++name_start;
            if (name_start >= base.size() || !is_ident_start_char(base[name_start])) {
                scan_pos = br_pos + 1;
                continue;
            }
            size_t name_end = name_start;
            while (name_end < base.size() && is_ident_body_char(base[name_end])) ++name_end;
            if (name_end == name_start) {
                scan_pos = br_pos + 1;
                continue;
            }
            size_t sep = name_end;
            while (sep < base.size() && base[sep] == ' ') ++sep;
            if (sep >= base.size() || (base[sep] != '+' && base[sep] != '-')) {
                scan_pos = name_end;
                continue;
            }
            int64_t disp = 0;
            size_t consumed = 0;
            if (!parse_signed_hex_run(base.c_str() + sep, base.size() - sep, disp, consumed)) {
                scan_pos = sep + 1;
                continue;
            }
            size_t close_pos = sep + consumed;
            while (close_pos < base.size() && base[close_pos] == ' ') ++close_pos;
            if (close_pos >= base.size() || base[close_pos] != ']') {
                scan_pos = sep + consumed;
                continue;
            }
            std::string_view sym_view(base.c_str() + name_start, name_end - name_start);
            uint64_t bound_va = 0;
            std::string struct_name_unused;
            if (!resolve_struct_binding_by_name(sym_view, bound_va, struct_name_unused) || bound_va == 0) {
                scan_pos = close_pos + 1;
                continue;
            }
            int op_size = extract_operand_size(base, br_pos);
            std::string struct_name_resolved;
            std::string field_name;
            if (!lookup_struct_field_at_base_va(bound_va, disp, op_size,
                                                struct_name_resolved, field_name)) {
                scan_pos = close_pos + 1;
                continue;
            }
            if (field_name.empty()) {
                scan_pos = close_pos + 1;
                continue;
            }
            std::string base_token(sym_view);
            std::string replacement = "[" + base_token + "->" + field_name + "]";
            base = base.substr(0, br_pos) + replacement + base.substr(close_pos + 1);
            scan_pos = br_pos + replacement.size();
        }
    }

    (void)file;
    return base;
}

namespace ida_export {

static constexpr int kColBytes      = 23;
static constexpr int kColName       = 53;
static constexpr int kColMnem       = 69;
static constexpr int kColOps        = 77;
static constexpr int kColComment    = 93;
static constexpr int kBytesBlockW   = 47;
static constexpr int kMnemBlockW    = 8;
static constexpr int kMaxBytesShown = 10;
static const char* const kEllipsisUtf8 = "\xe2\x80\xa6";

static int visual_length(const std::string& s) {
    int v = 0;
    for (size_t i = 0; i < s.size(); ) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) { v += 1; i += 1; }
        else if ((c & 0xE0) == 0xC0) { v += 1; i += 2; }
        else if ((c & 0xF0) == 0xE0) { v += 1; i += 3; }
        else if ((c & 0xF8) == 0xF0) { v += 1; i += 4; }
        else { v += 1; i += 1; }
    }
    return v;
}

static void pad_to_visual_col(std::string& s, int target) {
    int v = visual_length(s);
    while (v < target) { s += ' '; ++v; }
}

static std::string addr_prefix(const std::string& seg, uint64_t addr) {
    char buf[96];
    const char* sp = seg.empty() ? ".text" : seg.c_str();
    std::snprintf(buf, sizeof(buf), "%s:%016llX", sp, static_cast<unsigned long long>(addr));
    return std::string(buf);
}

static std::string section_for(uint64_t va) {
    if (auto cached = xref_index::detail::lookup_cached_module(va)) {
        if (cached->base != 0 && !cached->sections.empty()) {
            if (va >= cached->base) {
                uint64_t rva64 = va - cached->base;
                if (rva64 <= 0xFFFFFFFFull) {
                    uint32_t rva = static_cast<uint32_t>(rva64);
                    for (const auto& s : cached->sections) {
                        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
                            return s.name;
                    }
                }
            }
        }
    }
    return std::string(".text");
}

static std::string ida_mnemonic(const std::string& m) {
    if (m == "ret")   return "retn";
    if (m == "iret")  return "iretn";
    if (m == "iretd") return "iretn";
    if (m == "iretq") return "iretnq";
    if (m == "jnbe")  return "ja";
    if (m == "jna")   return "jbe";
    if (m == "jnae")  return "jb";
    if (m == "jc")    return "jb";
    if (m == "jae")   return "jnb";
    if (m == "jnc")   return "jnb";
    if (m == "je")    return "jz";
    if (m == "jne")   return "jnz";
    if (m == "jnle")  return "jg";
    if (m == "jnl")   return "jge";
    if (m == "jng")   return "jle";
    if (m == "jnge")  return "jl";
    if (m == "cmovnbe") return "cmova";
    if (m == "cmovna")  return "cmovbe";
    if (m == "cmovnae") return "cmovb";
    if (m == "cmovae")  return "cmovnb";
    if (m == "cmovc")   return "cmovb";
    if (m == "cmovnc")  return "cmovnb";
    if (m == "cmove")   return "cmovz";
    if (m == "cmovne")  return "cmovnz";
    if (m == "cmovnle") return "cmovg";
    if (m == "cmovnl")  return "cmovge";
    if (m == "cmovng")  return "cmovle";
    if (m == "cmovnge") return "cmovl";
    if (m == "setnbe")  return "seta";
    if (m == "setna")   return "setbe";
    if (m == "setnae")  return "setb";
    if (m == "setae")   return "setnb";
    if (m == "setc")    return "setb";
    if (m == "setnc")   return "setnb";
    if (m == "sete")    return "setz";
    if (m == "setne")   return "setnz";
    if (m == "setnle")  return "setg";
    if (m == "setnl")   return "setge";
    if (m == "setng")   return "setle";
    if (m == "setnge")  return "setl";
    return m;
}

static std::string format_unsigned_hex(uint64_t v) {
    if (v < 0xAull) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
        return std::string(buf);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
    std::string s(buf);
    if (s[0] >= 'A' && s[0] <= 'F') s.insert(0, 1, '0');
    s += 'h';
    return s;
}

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static bool is_ident_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

static std::string convert_operands_to_ida(const std::string& ops) {
    std::string out;
    out.reserve(ops.size() + 16);

    size_t i = 0;
    while (i < ops.size()) {
        if (i + 1 < ops.size() && ops[i] == '0' && (ops[i + 1] == 'x' || ops[i + 1] == 'X')) {
            bool prev_is_ident = (!out.empty() && is_ident_char(out.back()));
            if (prev_is_ident) {
                out += ops[i++];
                continue;
            }
            size_t start = i + 2;
            size_t end = start;
            while (end < ops.size() && is_hex_char(ops[end])) ++end;
            if (end == start) {
                out += ops[i];
                out += ops[i + 1];
                i += 2;
                continue;
            }
            uint64_t val = 0;
            for (size_t k = start; k < end; ++k) {
                char ch = ops[k];
                val <<= 4;
                if (ch >= '0' && ch <= '9') val |= static_cast<uint64_t>(ch - '0');
                else if (ch >= 'A' && ch <= 'F') val |= static_cast<uint64_t>(ch - 'A' + 10);
                else val |= static_cast<uint64_t>(ch - 'a' + 10);
            }
            out += format_unsigned_hex(val);
            i = end;
            continue;
        }

        if (i + 1 < ops.size() && ops[i] == '*' && ops[i + 1] == '1') {
            char nxt = (i + 2 < ops.size()) ? ops[i + 2] : '\0';
            if (nxt == ']' || nxt == '+' || nxt == '-' || nxt == ',' || nxt == ' ' || nxt == '\0') {
                i += 2;
                continue;
            }
        }

        out += ops[i++];
    }

    return out;
}

static std::string resolve_branch_symbol(uint64_t target) {
    if (target == 0) return std::string();

    std::string thunk_name = function_index::thunk_target_name_for(target);
    if (!thunk_name.empty()) return thunk_name;

    std::string label = function_index::inline_label_at(target);
    if (!label.empty()) {
        if (label.back() == ':') label.pop_back();
        return label;
    }

    if (function_index::is_inside_known_function(target)) {
        std::string loc = function_index::loc_label_for(target);
        if (!loc.empty()) return loc;
    }

    return function_index::synthetic_name(target);
}

static std::string build_call_tail_comment(uint64_t target,
                                           const std::string& resolved_branch_sym)
{
    std::string demangled = demangle_tail_comment(resolved_branch_sym);
    if (!demangled.empty()) return demangled;

    if (target != 0) {
        std::string sym = symbol_store::resolve_symbol_exact(target);
        sym = strip_module_prefix_fast(sym);
        if (!sym.empty() && sym != resolved_branch_sym) {
            std::string d2 = demangle_tail_comment(sym);
            if (!d2.empty()) return d2;
        }
    }
    return std::string();
}

static std::string build_instruction_line(const AsmInstr& ins,
                                          const DisasmFile& file,
                                          const std::string& seg,
                                          const std::string& user_comment_full,
                                          const std::string& xref_comment_full)
{
    std::string line = addr_prefix(seg, ins.addr);
    line += ' ';

    int v = visual_length(line);
    int target_bytes_end = 22 + kBytesBlockW;

    int byte_count = ins.len > 0 ? ins.len : 0;
    int shown = std::min(byte_count, kMaxBytesShown);
    for (int b = 0; b < shown; ++b) {
        if (b > 0) { line += ' '; ++v; }
        char hb[4];
        std::snprintf(hb, sizeof(hb), "%02X", static_cast<unsigned int>(ins.raw[b]));
        line += hb;
        v += 2;
    }
    if (byte_count > kMaxBytesShown) {
        line += kEllipsisUtf8;
        v += 1;
    }
    while (v < target_bytes_end) { line += ' '; ++v; }

    std::string mnem = ida_mnemonic(std::string(ins.mnem));

    function_index::directive_override_t dir_ov;
    bool has_dir_override = function_index::directive_override_at(ins.addr, &dir_ov);

    if (has_dir_override) {
        if (dir_ov.kind == function_index::directive_kind_t::align) {
            mnem = "align";
        }
        else if (dir_ov.kind == function_index::directive_kind_t::db) {
            mnem = "db";
        }
    }

    std::string ops;
    bool emitted_branch_sym = false;
    std::string branch_sym_resolved;
    if (has_dir_override) {
        if (dir_ov.kind == function_index::directive_kind_t::align) {
            ops = format_unsigned_hex(static_cast<uint64_t>(dir_ov.value));
        }
        else if (dir_ov.kind == function_index::directive_kind_t::db) {
            char hb[16];
            std::snprintf(hb, sizeof(hb), "0%02Xh", static_cast<unsigned int>(dir_ov.value));
            ops = hb;
        }
    } else if ((ins.is_branch || ins.is_call) && ins.branch_target != 0) {
        uint64_t target = ins.branch_target;
        std::string sym = resolve_branch_symbol(target);
        symbol_classifier::kind_t k = symbol_classifier::classify(target);
        if (k == symbol_classifier::kind_t::external_import) {
            if (sym.compare(0, 6, "__imp_") != 0) sym = "__imp_" + sym;
        }
        if (!sym.empty()) {
            branch_sym_resolved = sym;
            ops = sym;
            if (ins.is_branch && !ins.is_call) {
                int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(ins.addr);
                if (diff >= -128 && diff <= 127) {
                    ops = std::string("short ") + ops;
                }
            }
            emitted_branch_sym = true;
        }
    }
    if (!has_dir_override && !emitted_branch_sym) {
        std::string raw_ops = substitute_operand_text(ins, file);
        ops = convert_operands_to_ida(raw_ops);
    }

    line += mnem;
    v = visual_length(line);
    int op_col = target_bytes_end + kMnemBlockW;
    if (!ops.empty()) {
        if (v < op_col) {
            while (v < op_col) { line += ' '; ++v; }
        } else {
            line += ' ';
            ++v;
        }
        line += ops;
    }

    std::string comment;
    if (!xref_comment_full.empty()) {
        comment = xref_comment_full;
    } else if (!user_comment_full.empty()) {
        comment = user_comment_full;
    } else {
        std::string auto_cmt = function_index::inline_comment_at(ins.addr);
        if (!auto_cmt.empty()) {
            comment = std::string("; ") + auto_cmt;
        }
        else if (emitted_branch_sym) {
            std::string tail = build_call_tail_comment(ins.branch_target, branch_sym_resolved);
            if (!tail.empty()) comment = std::string("; ") + tail;
        }
    }
    if (comment.empty() && ins.has_imm && !has_dir_override) {
        uint64_t imm = ins.imm_unsigned;
        if (imm >= 0x20 && imm <= 0x7E && imm != 0x60) {
            char ch = static_cast<char>(imm);
            char buf[16];
            std::snprintf(buf, sizeof(buf), "; '%c'", ch);
            comment = buf;
        }
    }
    if (!comment.empty()) {
        v = visual_length(line);
        int comment_col = std::max(kColComment, v + 2);
        while (v < comment_col) { line += ' '; ++v; }
        line += comment;
    }

    return line;
}

static std::string build_injection_line(const std::string& seg,
                                        uint64_t addr,
                                        function_index::injection_t kind,
                                        const std::string& text,
                                        const std::string& tail_comment)
{
    std::string line = addr_prefix(seg, addr);
    if (kind == function_index::injection_t::spacer_line) return line;
    pad_to_visual_col(line, kColName);
    line += text;
    if (!tail_comment.empty()) {
        int v = visual_length(line);
        int comment_col = std::max(kColComment, v + 2);
        while (v < comment_col) { line += ' '; ++v; }
        line += tail_comment;
    }
    return line;
}

static std::string build_xref_continuation_line(const std::string& seg,
                                                uint64_t addr,
                                                const std::string& xref_comment)
{
    std::string line = addr_prefix(seg, addr);
    pad_to_visual_col(line, kColComment);
    line += xref_comment;
    return line;
}

static std::string build_align_lines(const std::string& seg,
                                     const function_index::detail::align_run_t& arun)
{
    std::string out;
    std::string lbl_line = addr_prefix(seg, arun.addr);
    pad_to_visual_col(lbl_line, kColName);
    char lbl_buf[40];
    std::snprintf(lbl_buf, sizeof(lbl_buf), "algn_%llX:",
        static_cast<unsigned long long>(arun.addr));
    lbl_line += lbl_buf;
    std::vector<xref_index::annotation_t> xrefs_at_align = xref_index::query_to(arun.addr, 6);
    bool xrefs_align_more = xref_index::has_more(arun.addr, 6);
    if (!xrefs_at_align.empty()) {
        int v_align = visual_length(lbl_line);
        int comment_col = std::max(kColComment, v_align + 2);
        while (v_align < comment_col) { lbl_line += ' '; ++v_align; }
        bool head_more = xrefs_align_more && xrefs_at_align.size() == 1;
        lbl_line += ida_format_xref_comment(xrefs_at_align[0], head_more);
    }
    out += lbl_line;
    out += "\r\n";
    for (size_t xi = 1; xi < xrefs_at_align.size(); ++xi) {
        std::string cont = addr_prefix(seg, arun.addr);
        pad_to_visual_col(cont, kColComment);
        bool last_more = (xi + 1 == xrefs_at_align.size()) && xrefs_align_more;
        cont += ida_format_xref_comment(xrefs_at_align[xi], last_more);
        out += cont;
        out += "\r\n";
    }

    std::string code_line = addr_prefix(seg, arun.addr);
    code_line += ' ';
    int v = visual_length(code_line);
    int target_bytes_end = 22 + kBytesBlockW;
    uint64_t run_len = (arun.end > arun.addr) ? (arun.end - arun.addr) : 0;
    int shown = static_cast<int>(std::min<uint64_t>(run_len, kMaxBytesShown));
    for (int b = 0; b < shown; ++b) {
        if (b > 0) { code_line += ' '; ++v; }
        char hb[4];
        std::snprintf(hb, sizeof(hb), "%02X", static_cast<unsigned int>(arun.fill_byte));
        code_line += hb;
        v += 2;
    }
    if (run_len > static_cast<uint64_t>(kMaxBytesShown)) {
        code_line += kEllipsisUtf8;
        v += 1;
    }
    while (v < target_bytes_end) { code_line += ' '; ++v; }
    char align_buf[40];
    std::snprintf(align_buf, sizeof(align_buf), "align %s",
        format_unsigned_hex(static_cast<uint64_t>(arun.alignment)).c_str());
    code_line += align_buf;
    out += code_line;
    return out;
}

static std::string build_header_banner(const DisasmFile& file,
                                       const std::vector<AsmInstr>& instrs,
                                       int lo)
{
    std::string out;
    if (instrs.empty()) return out;

    uint64_t first_addr = instrs[static_cast<size_t>(lo)].addr;
    std::string seg = section_for(first_addr);
    auto& cache = file_metadata_banner::detail::cache();

    std::string fmb_source_path;
    const bool live_attached = g_disasm.live_mode
        && g_disasm.live_base != 0
        && g_disasm.live_size != 0;
    if (live_attached) {
        const uint64_t live_base = g_disasm.live_base;
        const uint32_t live_size = static_cast<uint32_t>(
            (g_disasm.live_size > 0xFFFFFFFFull) ? 0xFFFFFFFFu : g_disasm.live_size);
        const uint32_t live_pid = g_disasm.live_pid;
        const std::string live_name = g_disasm.live_module.empty()
            ? std::string("(live image)")
            : g_disasm.live_module;
        file_metadata_banner::detail::ensure_started_for_image(live_base, live_size, live_pid, live_name);
        fmb_source_path = live_name;
    } else if (!file.path.empty() && file.path.compare(0, 7, "live://") != 0) {
        fmb_source_path = file.path;
        file_metadata_banner::detail::ensure_started_for(file.path);
    } else if (!file.filename.empty()) {
        fmb_source_path = file.filename;
    }

    std::string sha;
    std::string md5;
    std::string crc32_v;
    std::string compiler;
    std::string file_name;
    std::string format_text;
    std::string app_type;
    std::string os_type;
    uint64_t image_base = file.image_base;
    uint32_t timestamp = 0;
    std::string timestamp_text;
    std::vector<file_metadata_banner::section_info_t> sections;
    int state = 0;
    {
        std::lock_guard<std::mutex> lk(cache.mtx);
        state = cache.state.load(std::memory_order_acquire);
        sha = cache.sha256;
        md5 = cache.md5;
        crc32_v = cache.crc32;
        compiler = cache.compiler;
        file_name = cache.source_path.empty() ? fmb_source_path : cache.source_path;
        format_text = cache.format_text;
        app_type = cache.app_type;
        os_type = cache.os_type;
        if (cache.image_base != 0) image_base = cache.image_base;
        timestamp = cache.timestamp;
        timestamp_text = cache.timestamp_text;
        sections = cache.sections;
    }
    const bool ready = (state == static_cast<int>(file_metadata_banner::compute_state_t::ready));
    const bool failed = (state == static_cast<int>(file_metadata_banner::compute_state_t::failed));
    if (!ready) {
        const char* placeholder = failed ? "(unavailable)" : "(computing...)";
        if (sha.empty()) sha = placeholder;
        if (md5.empty()) md5 = placeholder;
        if (crc32_v.empty()) crc32_v = placeholder;
        if (compiler.empty()) compiler = placeholder;
        if (format_text.empty()) format_text = placeholder;
        if (app_type.empty()) app_type = placeholder;
        if (os_type.empty()) os_type = placeholder;
    }
    if (file_name.empty()) file_name = file.filename;

    auto emit_line = [&](const std::string& text) {
        std::string line = addr_prefix(seg, first_addr);
        if (!text.empty()) {
            pad_to_visual_col(line, kColName);
            line += text;
        }
        out += line;
        out += "\r\n";
    };

    emit_line(";");
    emit_line("; +-------------------------------------------------------------------------+");
    emit_line("; |             AiDA - Reverse-engineering toolkit by AiDA Team             |");
    emit_line("; |                          aida.app - Standalone                          |");
    emit_line("; +-------------------------------------------------------------------------+");
    emit_line(";");

    char buf[512];
    std::snprintf(buf, sizeof(buf), "; Input SHA256 : %s", sha.c_str());
    emit_line(buf);
    std::snprintf(buf, sizeof(buf), "; Input MD5    : %s", md5.c_str());
    emit_line(buf);
    std::snprintf(buf, sizeof(buf), "; Input CRC32  : %s", crc32_v.c_str());
    emit_line(buf);
    std::snprintf(buf, sizeof(buf), "; Compiler     : %s", compiler.c_str());
    emit_line(buf);
    emit_line("");

    std::snprintf(buf, sizeof(buf), "; File Name   : %s", file_name.c_str());
    emit_line(buf);
    std::snprintf(buf, sizeof(buf), "; Format      : %s", format_text.c_str());
    emit_line(buf);
    std::snprintf(buf, sizeof(buf), "; Imagebase   : %llX",
        static_cast<unsigned long long>(image_base));
    emit_line(buf);
    if (ready) {
        std::snprintf(buf, sizeof(buf), "; Timestamp   : %08X (%s)", timestamp, timestamp_text.c_str());
    } else {
        std::snprintf(buf, sizeof(buf), "; Timestamp   : (computing...)");
    }
    emit_line(buf);

    const file_metadata_banner::section_info_t* primary = nullptr;
    int section_index = 1;
    if (ready && !sections.empty()) {
        for (size_t i = 0; i < sections.size(); ++i) {
            if (sections[i].characteristics & IMAGE_SCN_MEM_EXECUTE) {
                primary = &sections[i];
                section_index = static_cast<int>(i + 1);
                break;
            }
        }
        if (!primary) {
            primary = &sections.front();
            section_index = 1;
        }
    }
    if (primary) {
        std::snprintf(buf, sizeof(buf), "; Section %d. (virtual address %08X)",
            section_index, primary->virtual_address);
        emit_line(buf);
        std::snprintf(buf, sizeof(buf), "; Virtual size                  : %08X ( %u.)",
            primary->virtual_size, static_cast<unsigned int>(primary->virtual_size));
        emit_line(buf);
        std::snprintf(buf, sizeof(buf), "; Section size in file          : %08X ( %u.)",
            primary->raw_size, static_cast<unsigned int>(primary->raw_size));
        emit_line(buf);
        std::snprintf(buf, sizeof(buf), "; Offset to raw data for section: %08X",
            primary->raw_offset);
        emit_line(buf);
        std::string flags_text = file_metadata_banner::detail::section_flags_text(primary->characteristics);
        std::snprintf(buf, sizeof(buf), "; Flags %08X: %s",
            primary->characteristics, flags_text.c_str());
        emit_line(buf);
        if (primary->alignment == 0)
            std::snprintf(buf, sizeof(buf), "; Alignment     : default");
        else
            std::snprintf(buf, sizeof(buf), "; Alignment     : %u", primary->alignment);
        emit_line(buf);
    }
    std::snprintf(buf, sizeof(buf), "; OS type         :  %s", os_type.c_str());
    emit_line(buf);
    std::snprintf(buf, sizeof(buf), "; Application type:  %s", app_type.c_str());
    emit_line(buf);
    emit_line("");

    emit_line("                .686p");
    emit_line("                .mmx");
    emit_line("                .model flat");
    emit_line("");

    emit_line("; ===========================================================================");
    emit_line("");

    emit_line("; Segment type: Pure code");
    emit_line("; Segment permissions: Read/Execute");

    {
        const char* seg_word = seg.c_str();
        std::string seg_name_for_decl = seg;
        if (!seg_name_for_decl.empty() && seg_name_for_decl[0] == '.')
            seg_name_for_decl = "_" + seg_name_for_decl.substr(1);
        std::snprintf(buf, sizeof(buf), "%-15s segment para public 'CODE' use64",
            seg_name_for_decl.c_str());
        emit_line(buf);
        std::snprintf(buf, sizeof(buf), "                assume cs:%s", seg_name_for_decl.c_str());
        emit_line(buf);
        char org_buf[40];
        std::snprintf(org_buf, sizeof(org_buf), "                ;org %llXh",
            static_cast<unsigned long long>(first_addr));
        emit_line(org_buf);
        emit_line("                assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing");
        emit_line("");
        (void)seg_word;
    }

    return out;
}

static std::string build_listing(const DisasmFile& file,
                                 const std::vector<AsmInstr>& instrs,
                                 int lo, int hi)
{
    std::string out;
    if (instrs.empty()) return out;
    if (lo < 0) lo = 0;
    if (hi >= static_cast<int>(instrs.size())) hi = static_cast<int>(instrs.size()) - 1;
    if (lo > hi) return out;

    out.reserve(static_cast<size_t>(hi - lo + 1) * 160);

    if (lo == 0) {
        out += build_header_banner(file, instrs, lo);
    }

    uint64_t align_skip_end = 0;
    uint64_t primed_func_start = 0;

    for (int i = lo; i <= hi; ++i) {
        const AsmInstr& ins = instrs[i];

        if (align_skip_end != 0) {
            if (ins.addr < align_skip_end) continue;
            align_skip_end = 0;
        }

        uint64_t enclosing_func = function_index::func_start_for(ins.addr);
        if (enclosing_func != 0 && enclosing_func != primed_func_start) {
            prime_var_cache(enclosing_func);
            primed_func_start = enclosing_func;
        }

        std::string seg = section_for(ins.addr);

        function_index::detail::align_run_t arun;
        if (function_index::is_align_row_start(ins.addr)
            && function_index::align_run_at(ins.addr, &arun))
        {
            out += build_align_lines(seg, arun);
            out += "\r\n";
            align_skip_end = arun.end;
            continue;
        }

        std::vector<function_index::injection_row_t> before_rows = function_index::rows_before(ins.addr);
        std::vector<xref_index::annotation_t> xrefs_at_func;
        bool xrefs_more = false;
        bool has_proc_header = false;
        for (const auto& br : before_rows) {
            if (br.kind == function_index::injection_t::proc_header) {
                has_proc_header = true;
                break;
            }
        }
        if (has_proc_header) {
            xrefs_at_func = xref_index::query_to(ins.addr, 6);
            xrefs_more = xref_index::has_more(ins.addr, 6);
        }

        for (const auto& br : before_rows) {
            if (br.kind == function_index::injection_t::proc_header && !xrefs_at_func.empty()) {
                std::string xref_head = ida_format_xref_comment(xrefs_at_func[0],
                    xrefs_more && xrefs_at_func.size() == 1);
                out += build_injection_line(seg, ins.addr, br.kind, br.text, xref_head);
                out += "\r\n";
                for (size_t xi = 1; xi < xrefs_at_func.size(); ++xi) {
                    bool last_more = (xi + 1 == xrefs_at_func.size()) && xrefs_more;
                    std::string xt = ida_format_xref_comment(xrefs_at_func[xi], last_more);
                    out += build_xref_continuation_line(seg, ins.addr, xt);
                    out += "\r\n";
                }
            } else {
                out += build_injection_line(seg, ins.addr, br.kind, br.text, std::string());
                out += "\r\n";
            }
        }

        std::string inline_label = function_index::inline_label_at(ins.addr);
        if (inline_label.empty()) {
            std::vector<xref_index::annotation_t> xrefs_probe = xref_index::query_to(ins.addr, 1);
            bool any_code_xref = false;
            for (const auto& a : xrefs_probe) {
                if (a.kind == xref_index::kind_t::code && a.edge == xref_index::edge_t::jump) {
                    any_code_xref = true;
                    break;
                }
            }
            if (any_code_xref && function_index::is_inside_known_function(ins.addr)) {
                std::string loc = function_index::loc_label_for(ins.addr);
                if (!loc.empty()) inline_label = loc + ":";
            }
        }
        if (!inline_label.empty()) {
            out += addr_prefix(seg, ins.addr);
            out += "\r\n";
            std::vector<xref_index::annotation_t> xrefs_at_label = xref_index::query_to(ins.addr, 6);
            bool xrefs_label_more = xref_index::has_more(ins.addr, 6);
            std::string head_xref;
            if (!xrefs_at_label.empty()) {
                head_xref = ida_format_xref_comment(xrefs_at_label[0],
                    xrefs_label_more && xrefs_at_label.size() == 1);
            }
            out += build_injection_line(seg, ins.addr,
                function_index::injection_t::label_line, inline_label, head_xref);
            out += "\r\n";
            for (size_t xi = 1; xi < xrefs_at_label.size(); ++xi) {
                bool last_more = (xi + 1 == xrefs_at_label.size()) && xrefs_label_more;
                std::string xt = ida_format_xref_comment(xrefs_at_label[xi], last_more);
                out += build_xref_continuation_line(seg, ins.addr, xt);
                out += "\r\n";
            }
        }

        std::string user_cmt;
        if (comment_store::has(ins.addr)) {
            user_cmt = "; " + comment_store::get(ins.addr);
        }
        out += build_instruction_line(ins, file, seg, user_cmt, std::string());
        out += "\r\n";

        if (function_index::is_noreturn_call_at(ins.addr)) {
            std::string sep_line = addr_prefix(seg, ins.addr);
            pad_to_visual_col(sep_line, kColName);
            sep_line += "; ---------------------------------------------------------------------------";
            out += sep_line;
            out += "\r\n";
        }

        std::vector<function_index::injection_row_t> after_rows = function_index::rows_after(ins.addr);
        for (const auto& ar : after_rows) {
            out += build_injection_line(seg, ins.addr, ar.kind, ar.text, std::string());
            out += "\r\n";
        }

    }

    return out;
}

}

static inline ImU32 default_operand_color(const AsmInstr& ins) {
    if (ins.is_call) return disasm_theme::sub_label();
    if (ins.is_branch) return disasm_theme::loc_label();
    if (ins.is_nop) return disasm_theme::mnem_nop();
    return disasm_theme::reg();
}

static void append_colored_run(std::vector<colored_run_t>& out, ImU32 color, const char* text, size_t len) {
    if (len == 0) return;
    if (!out.empty() && out.back().color == color) {
        out.back().text.append(text, len);
        return;
    }
    colored_run_t run;
    run.color = color;
    run.text.assign(text, len);
    out.push_back(std::move(run));
}

static void build_operand_colored_runs(const AsmInstr& ins,
                                       const std::string& subst,
                                       std::vector<colored_run_t>& out)
{
    out.clear();
    if (subst.empty()) return;

    const ImU32 default_color = default_operand_color(ins);
    const char* s = subst.c_str();
    const size_t n = subst.size();
    size_t i = 0;

    while (i < n) {
        char c = s[i];

        if (is_ident_start_char(c)) {
            size_t start = i;
            ++i;
            while (i < n && is_ident_body_char(s[i])) ++i;
            std::string tok(s + start, i - start);

            bool tok_is_hex_h = false;
            if (tok.size() >= 2) {
                char last = tok.back();
                if (last == 'h' || last == 'H') {
                    bool all_hex = true;
                    for (size_t k = 0; k + 1 < tok.size(); ++k) {
                        if (!is_hex_digit_char(tok[k])) { all_hex = false; break; }
                    }
                    if (all_hex) tok_is_hex_h = true;
                }
            }

            const bool is_seg_prefix = (tok.size() == 2)
                && (tok == "cs" || tok == "ds" || tok == "ss"
                    || tok == "es" || tok == "fs" || tok == "gs")
                && i < n && s[i] == ':';

            ImU32 color = default_color;
            if (tok_is_hex_h) {
                color = disasm_theme::immediate_num();
            } else if (is_seg_prefix) {
                color = disasm_theme::segment_ref();
            } else {
                symbol_classifier::kind_t k = symbol_classifier::classify_name(tok);
                if (k != symbol_classifier::kind_t::unknown) {
                    color = disasm_theme::color_for_kind(static_cast<int>(k));
                }
            }

            append_colored_run(out, color, tok.data(), tok.size());

            if (is_seg_prefix) {
                append_colored_run(out, color, ":", 1);
                ++i;
            }
            continue;
        }

        if (c == '0' && i + 1 < n && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
            size_t start = i;
            i += 2;
            while (i < n && is_hex_digit_char(s[i])) ++i;
            if (i < n && (s[i] == 'h' || s[i] == 'H')) ++i;
            append_colored_run(out, disasm_theme::immediate_num(), s + start, i - start);
            continue;
        }

        if (c >= '0' && c <= '9') {
            size_t start = i;
            ++i;
            while (i < n && is_hex_digit_char(s[i])) ++i;
            bool has_h = false;
            if (i < n && (s[i] == 'h' || s[i] == 'H')) {
                has_h = true;
                ++i;
            }
            if (has_h) {
                append_colored_run(out, disasm_theme::immediate_num(), s + start, i - start);
            } else {
                while (i < n && s[i] >= '0' && s[i] <= '9') ++i;
                append_colored_run(out, disasm_theme::immediate_num(), s + start, i - start);
            }
            continue;
        }

        size_t start = i;
        ++i;
        while (i < n) {
            char nc = s[i];
            if (is_ident_start_char(nc)) break;
            if (nc == '0' && i + 1 < n && (s[i + 1] == 'x' || s[i + 1] == 'X')) break;
            if (nc >= '0' && nc <= '9') break;
            ++i;
        }
        append_colored_run(out, default_color, s + start, i - start);
    }
}

static void rebuild_banner_lines(const DisasmFile& file) {
    s_banner_cache.clear();
    auto& cache = file_metadata_banner::detail::cache();

    std::string fmb_source_path;
    const bool live_attached = g_disasm.live_mode
        && g_disasm.live_base != 0
        && g_disasm.live_size != 0;
    if (live_attached) {
        const uint64_t live_base = g_disasm.live_base;
        const uint32_t live_size = static_cast<uint32_t>(
            (g_disasm.live_size > 0xFFFFFFFFull) ? 0xFFFFFFFFu : g_disasm.live_size);
        const uint32_t live_pid = g_disasm.live_pid;
        const std::string live_name = g_disasm.live_module.empty()
            ? std::string("(live image)")
            : g_disasm.live_module;
        file_metadata_banner::detail::ensure_started_for_image(live_base, live_size, live_pid, live_name);
        fmb_source_path = live_name;
    } else if (!file.path.empty() && file.path.compare(0, 7, "live://") != 0) {
        fmb_source_path = file.path;
        file_metadata_banner::detail::ensure_started_for(file.path);
    } else if (!file.filename.empty()) {
        fmb_source_path = file.filename;
    }

    std::string sha;
    std::string md5;
    std::string crc32_v;
    std::string compiler;
    std::string file_name;
    std::string format_text;
    std::string app_type;
    std::string os_type;
    uint64_t image_base = file.image_base;
    uint32_t timestamp = 0;
    std::string timestamp_text;
    std::vector<file_metadata_banner::section_info_t> sections;
    int state = 0;
    {
        std::lock_guard<std::mutex> lk(cache.mtx);
        state = cache.state.load(std::memory_order_acquire);
        sha = cache.sha256;
        md5 = cache.md5;
        crc32_v = cache.crc32;
        compiler = cache.compiler;
        file_name = cache.source_path.empty() ? fmb_source_path : cache.source_path;
        format_text = cache.format_text;
        app_type = cache.app_type;
        os_type = cache.os_type;
        if (cache.image_base != 0) image_base = cache.image_base;
        timestamp = cache.timestamp;
        timestamp_text = cache.timestamp_text;
        sections = cache.sections;
    }
    const bool ready = (state == static_cast<int>(file_metadata_banner::compute_state_t::ready));
    const bool failed = (state == static_cast<int>(file_metadata_banner::compute_state_t::failed));
    if (!ready) {
        const char* placeholder = failed ? "(unavailable)" : "(computing...)";
        if (sha.empty()) sha = placeholder;
        if (md5.empty()) md5 = placeholder;
        if (crc32_v.empty()) crc32_v = placeholder;
        if (compiler.empty()) compiler = placeholder;
        if (format_text.empty()) format_text = placeholder;
        if (app_type.empty()) app_type = placeholder;
        if (os_type.empty()) os_type = placeholder;
    }
    if (file_name.empty()) file_name = file.filename;

    auto push_comment = [&](std::string text) {
        banner_line_t bl;
        bl.text = std::move(text);
        bl.color = disasm_theme::comment();
        s_banner_cache.push_back(std::move(bl));
    };
    auto push_banner = [&](std::string text) {
        banner_line_t bl;
        bl.text = std::move(text);
        bl.color = disasm_theme::banner();
        s_banner_cache.push_back(std::move(bl));
    };
    auto push_directive = [&](std::string text) {
        banner_line_t bl;
        bl.text = std::move(text);
        bl.color = disasm_theme::directive();
        bl.is_directive = true;
        s_banner_cache.push_back(std::move(bl));
    };
    auto push_keyword = [&](std::string text) {
        banner_line_t bl;
        bl.text = std::move(text);
        bl.color = disasm_theme::keyword();
        s_banner_cache.push_back(std::move(bl));
    };
    auto push_blank = [&]() {
        banner_line_t bl;
        bl.color = disasm_theme::comment();
        s_banner_cache.push_back(std::move(bl));
    };

    push_comment(";");
    push_banner("; +-------------------------------------------------------------------------+");
    push_banner("; |             AiDA - Reverse-engineering toolkit by AiDA Team             |");
    push_banner("; |                          aida.app - Standalone                          |");
    push_banner("; +-------------------------------------------------------------------------+");
    push_comment(";");

    char buf[512];
    std::snprintf(buf, sizeof(buf), "; Input SHA256 : %s", sha.c_str());
    push_comment(buf);
    std::snprintf(buf, sizeof(buf), "; Input MD5    : %s", md5.c_str());
    push_comment(buf);
    std::snprintf(buf, sizeof(buf), "; Input CRC32  : %s", crc32_v.c_str());
    push_comment(buf);
    std::snprintf(buf, sizeof(buf), "; Compiler     : %s", compiler.c_str());
    push_comment(buf);
    push_blank();

    std::snprintf(buf, sizeof(buf), "; File Name   : %s", file_name.c_str());
    push_comment(buf);
    std::snprintf(buf, sizeof(buf), "; Format      : %s", format_text.c_str());
    push_comment(buf);
    std::snprintf(buf, sizeof(buf), "; Imagebase   : %llX",
        static_cast<unsigned long long>(image_base));
    push_comment(buf);
    if (ready) {
        std::snprintf(buf, sizeof(buf), "; Timestamp   : %08X (%s)", timestamp, timestamp_text.c_str());
    } else {
        std::snprintf(buf, sizeof(buf), "; Timestamp   : (computing...)");
    }
    push_comment(buf);

    const file_metadata_banner::section_info_t* primary = nullptr;
    int section_index = 1;
    if (ready && !sections.empty()) {
        for (size_t i = 0; i < sections.size(); ++i) {
            if (sections[i].characteristics & IMAGE_SCN_MEM_EXECUTE) {
                primary = &sections[i];
                section_index = static_cast<int>(i + 1);
                break;
            }
        }
        if (!primary) {
            primary = &sections.front();
            section_index = 1;
        }
    }
    if (primary) {
        std::snprintf(buf, sizeof(buf), "; Section %d. (virtual address %08X)",
            section_index, primary->virtual_address);
        push_comment(buf);
        std::snprintf(buf, sizeof(buf), "; Virtual size                  : %08X ( %u.)",
            primary->virtual_size, static_cast<unsigned int>(primary->virtual_size));
        push_comment(buf);
        std::snprintf(buf, sizeof(buf), "; Section size in file          : %08X ( %u.)",
            primary->raw_size, static_cast<unsigned int>(primary->raw_size));
        push_comment(buf);
        std::snprintf(buf, sizeof(buf), "; Offset to raw data for section: %08X",
            primary->raw_offset);
        push_comment(buf);
        std::string flags_text = file_metadata_banner::detail::section_flags_text(primary->characteristics);
        std::snprintf(buf, sizeof(buf), "; Flags %08X: %s",
            primary->characteristics, flags_text.c_str());
        push_comment(buf);
        if (primary->alignment == 0)
            std::snprintf(buf, sizeof(buf), "; Alignment     : default");
        else
            std::snprintf(buf, sizeof(buf), "; Alignment     : %u", primary->alignment);
        push_comment(buf);
    } else {
        push_comment("; Section 1. (virtual address (computing...))");
        push_comment("; Virtual size                  : (computing...)");
        push_comment("; Section size in file          : (computing...)");
        push_comment("; Offset to raw data for section: (computing...)");
        push_comment("; Flags        : (computing...)");
        push_comment("; Alignment     : (computing...)");
    }
    std::snprintf(buf, sizeof(buf), "; OS type         :  %s", os_type.c_str());
    push_comment(buf);
    std::snprintf(buf, sizeof(buf), "; Application type:  %s", app_type.c_str());
    push_comment(buf);
    push_blank();

    push_directive(".686p");
    push_directive(".mmx");
    push_directive(".model flat");
    push_blank();

    push_banner("; ===========================================================================");
    push_blank();

    push_keyword("; Segment type: Pure code");
    push_keyword("; Segment permissions: Read/Execute");

    std::string seg_name = "_text";
    {
        if (!file.instrs.empty()) {
            std::string s = ida_export::section_for(file.instrs.front().addr);
            if (!s.empty() && s[0] == '.') seg_name = "_" + s.substr(1);
            else if (!s.empty()) seg_name = s;
        }
    }
    std::snprintf(buf, sizeof(buf), "%s segment para public 'CODE' use64", seg_name.c_str());
    push_keyword(buf);
    std::snprintf(buf, sizeof(buf), "assume cs:%s", seg_name.c_str());
    push_keyword(buf);
    uint64_t first_addr = file.instrs.empty() ? image_base : file.instrs.front().addr;
    std::snprintf(buf, sizeof(buf), ";org %llXh",
        static_cast<unsigned long long>(first_addr));
    push_comment(buf);
    push_keyword("assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing");
}

static inline char mnem_lc(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

static int classify_mnemonic_family(const char* mnem) {
    if (!mnem || !*mnem) return disasm_theme::kind_mnem_other;
    char m[16] = {};
    int len = 0;
    while (mnem[len] && len < 15) {
        m[len] = mnem_lc(mnem[len]);
        ++len;
    }
    if (len == 0) return disasm_theme::kind_mnem_other;

    if (len == 3 && m[0] == 'n' && m[1] == 'o' && m[2] == 'p') return disasm_theme::kind_mnem_nop;

    if (len == 3 && m[0] == 'r' && m[1] == 'e' && m[2] == 't') return disasm_theme::kind_mnem_ret;
    if (len == 4 && m[0] == 'r' && m[1] == 'e' && m[2] == 't' && (m[3] == 'n' || m[3] == 'f')) return disasm_theme::kind_mnem_ret;
    if (len >= 4 && m[0] == 'i' && m[1] == 'r' && m[2] == 'e' && m[3] == 't') return disasm_theme::kind_mnem_ret;
    if (len == 6 && m[0] == 's' && m[1] == 'y' && m[2] == 's' && m[3] == 'r' && m[4] == 'e' && m[5] == 't') return disasm_theme::kind_mnem_ret;

    if (len == 4 && m[0] == 'c' && m[1] == 'a' && m[2] == 'l' && m[3] == 'l') return disasm_theme::kind_mnem_call;

    if (m[0] == 'j') return disasm_theme::kind_mnem_branch;
    if (len >= 4 && m[0] == 'l' && m[1] == 'o' && m[2] == 'o' && m[3] == 'p') return disasm_theme::kind_mnem_branch;

    if (len == 3 && m[0] == 'i' && m[1] == 'n' && m[2] == 't') return disasm_theme::kind_mnem_int;
    if (len == 4 && m[0] == 'i' && m[1] == 'n' && m[2] == 't' && (m[3] == '3' || m[3] == 'o')) return disasm_theme::kind_mnem_int;
    if (len == 3 && m[0] == 'u' && m[1] == 'd' && m[2] == '2') return disasm_theme::kind_mnem_int;
    if (len == 5 && m[0] == 's' && m[1] == 'y' && m[2] == 's' && m[3] == 'c' && m[4] == 'a') return disasm_theme::kind_mnem_int;

    if ((len == 3 && m[0] == 'h' && m[1] == 'l' && m[2] == 't')
        || (len == 3 && m[0] == 'c' && m[1] == 'l' && m[2] == 'i')
        || (len == 3 && m[0] == 's' && m[1] == 't' && m[2] == 'i')
        || (len == 5 && m[0] == 'c' && m[1] == 'p' && m[2] == 'u' && m[3] == 'i' && m[4] == 'd')
        || (len == 5 && m[0] == 'r' && m[1] == 'd' && m[2] == 't' && m[3] == 's' && m[4] == 'c')
        || (len == 6 && m[0] == 'r' && m[1] == 'd' && m[2] == 't' && m[3] == 's' && m[4] == 'c' && m[5] == 'p')
        || (len == 6 && m[0] == 'x' && m[1] == 'g' && m[2] == 'e' && m[3] == 't' && m[4] == 'b' && m[5] == 'v')
        || (len == 6 && m[0] == 'x' && m[1] == 's' && m[2] == 'e' && m[3] == 't' && m[4] == 'b' && m[5] == 'v')
        || (len == 4 && m[0] == 'l' && m[1] == 'o' && m[2] == 'c' && m[3] == 'k')
        || (len == 6 && m[0] == 'i' && m[1] == 'n' && m[2] == 'v' && m[3] == 'l' && m[4] == 'p' && m[5] == 'g')
        || (len == 5 && m[0] == 'm' && m[1] == 'w' && m[2] == 'a' && m[3] == 'i' && m[4] == 't')
        || (len == 7 && m[0] == 'm' && m[1] == 'o' && m[2] == 'n' && m[3] == 'i' && m[4] == 't' && m[5] == 'o' && m[6] == 'r')
        || (len >= 2 && m[0] == 'i' && m[1] == 'n' && (len == 2 || m[2] == 's' || m[2] == 'b'))
        || (len >= 3 && m[0] == 'o' && m[1] == 'u' && m[2] == 't')
        || (len >= 4 && m[0] == 'l' && m[1] == 'g' && m[2] == 'd' && m[3] == 't')
        || (len >= 4 && m[0] == 'l' && m[1] == 'i' && m[2] == 'd' && m[3] == 't')
        || (len >= 4 && m[0] == 's' && m[1] == 'g' && m[2] == 'd' && m[3] == 't')
        || (len >= 4 && m[0] == 's' && m[1] == 'i' && m[2] == 'd' && m[3] == 't')
        || (len >= 6 && m[0] == 's' && m[1] == 'w' && m[2] == 'a' && m[3] == 'p' && m[4] == 'g' && m[5] == 's')
        || (len >= 5 && m[0] == 'w' && m[1] == 'r' && m[2] == 'm' && m[3] == 's' && m[4] == 'r')
        || (len >= 5 && m[0] == 'r' && m[1] == 'd' && m[2] == 'm' && m[3] == 's' && m[4] == 'r')
        || (len >= 6 && m[0] == 'w' && m[1] == 'b' && m[2] == 'i' && m[3] == 'n' && m[4] == 'v' && m[5] == 'd')
        || (len == 3 && m[0] == 'l' && m[1] == 't' && m[2] == 'r')
        || (len == 3 && m[0] == 's' && m[1] == 't' && m[2] == 'r'))
        return disasm_theme::kind_mnem_priv;

    if (len >= 3 && m[0] == 'r' && m[1] == 'e' && m[2] == 'p') return disasm_theme::kind_mnem_string;
    if ((len >= 4 && (m[0] == 'm' && (m[1] == 'o' && m[2] == 'v' && m[3] == 's')))
        || (len >= 4 && m[0] == 'l' && m[1] == 'o' && m[2] == 'd' && m[3] == 's')
        || (len >= 4 && m[0] == 's' && m[1] == 't' && m[2] == 'o' && m[3] == 's')
        || (len >= 4 && m[0] == 's' && m[1] == 'c' && m[2] == 'a' && m[3] == 's')
        || (len >= 4 && m[0] == 'c' && m[1] == 'm' && m[2] == 'p' && m[3] == 's'))
        return disasm_theme::kind_mnem_string;

    if (len >= 4 && m[0] == 'c' && m[1] == 'm' && m[2] == 'o' && m[3] == 'v')
        return disasm_theme::kind_mnem_data;

    if (len >= 3 && m[0] == 's' && m[1] == 'e' && m[2] == 't')
        return disasm_theme::kind_mnem_logic;

    if (m[0] == 'v' && len >= 3) return disasm_theme::kind_mnem_sse;
    if (len == 3 && m[0] == 'p' && (m[1] == 'o' && m[2] == 'r')) return disasm_theme::kind_mnem_sse;
    if (len == 4 && m[0] == 'p' && m[1] == 'x' && m[2] == 'o' && m[3] == 'r') return disasm_theme::kind_mnem_sse;
    if (m[0] == 'p' && len >= 4 &&
        !(m[1] == 'u' && m[2] == 's' && m[3] == 'h') &&
        !(m[1] == 'o' && m[2] == 'p'))
        return disasm_theme::kind_mnem_sse;
    if (len >= 5 && (m[len-2] == 'p' && m[len-1] == 's')) return disasm_theme::kind_mnem_sse;
    if (len >= 5 && (m[len-2] == 'p' && m[len-1] == 'd')) return disasm_theme::kind_mnem_sse;
    if (len >= 5 && (m[len-2] == 's' && m[len-1] == 's')) return disasm_theme::kind_mnem_sse;
    if (len >= 5 && (m[len-2] == 's' && m[len-1] == 'd')) return disasm_theme::kind_mnem_sse;

    if ((len == 3 && ((m[0] == 'a' && m[1] == 'd' && m[2] == 'd')
                      || (m[0] == 's' && m[1] == 'u' && m[2] == 'b')
                      || (m[0] == 'm' && m[1] == 'u' && m[2] == 'l')
                      || (m[0] == 'd' && m[1] == 'i' && m[2] == 'v')
                      || (m[0] == 'i' && m[1] == 'n' && m[2] == 'c')
                      || (m[0] == 'd' && m[1] == 'e' && m[2] == 'c')
                      || (m[0] == 'n' && m[1] == 'e' && m[2] == 'g')
                      || (m[0] == 'a' && m[1] == 'd' && m[2] == 'c')
                      || (m[0] == 's' && m[1] == 'b' && m[2] == 'b')))
        || (len == 4 && ((m[0] == 'i' && m[1] == 'm' && m[2] == 'u' && m[3] == 'l')
                         || (m[0] == 'i' && m[1] == 'd' && m[2] == 'i' && m[3] == 'v')))
        || (len == 6 && m[0] == 'p' && m[1] == 'o' && m[2] == 'p' && m[3] == 'c' && m[4] == 'n' && m[5] == 't')
        || (len == 5 && m[0] == 'l' && m[1] == 'z' && m[2] == 'c' && m[3] == 'n' && m[4] == 't')
        || (len == 5 && m[0] == 't' && m[1] == 'z' && m[2] == 'c' && m[3] == 'n' && m[4] == 't')
        || (len == 3 && m[0] == 'b' && m[1] == 's' && (m[2] == 'r' || m[2] == 'f')))
        return disasm_theme::kind_mnem_arith;

    if ((len == 3 && ((m[0] == 'a' && m[1] == 'n' && m[2] == 'd')
                      || (m[0] == 'x' && m[1] == 'o' && m[2] == 'r')
                      || (m[0] == 'n' && m[1] == 'o' && m[2] == 't')
                      || (m[0] == 'r' && m[1] == 'o' && m[2] == 'l')
                      || (m[0] == 'r' && m[1] == 'o' && m[2] == 'r')
                      || (m[0] == 's' && m[1] == 'h' && m[2] == 'l')
                      || (m[0] == 's' && m[1] == 'h' && m[2] == 'r')
                      || (m[0] == 's' && m[1] == 'a' && m[2] == 'l')
                      || (m[0] == 's' && m[1] == 'a' && m[2] == 'r')
                      || (m[0] == 'r' && m[1] == 'c' && m[2] == 'l')
                      || (m[0] == 'r' && m[1] == 'c' && m[2] == 'r')))
        || (len == 2 && m[0] == 'o' && m[1] == 'r')
        || (len == 4 && ((m[0] == 't' && m[1] == 'e' && m[2] == 's' && m[3] == 't'))))
        return disasm_theme::kind_mnem_logic;

    if ((len == 3 && ((m[0] == 'm' && m[1] == 'o' && m[2] == 'v')
                      || (m[0] == 'l' && m[1] == 'e' && m[2] == 'a')
                      || (m[0] == 'p' && m[1] == 'o' && m[2] == 'p')))
        || (len == 4 && m[0] == 'p' && m[1] == 'u' && m[2] == 's' && m[3] == 'h')
        || (len == 4 && ((m[0] == 'x' && m[1] == 'c' && m[2] == 'h' && m[3] == 'g')
                         || (m[0] == 'x' && m[1] == 'a' && m[2] == 'd' && m[3] == 'd')))
        || (len >= 5 && m[0] == 'm' && m[1] == 'o' && m[2] == 'v')
        || (len >= 5 && m[0] == 'c' && m[1] == 'm' && m[2] == 'p' && m[3] == 'x' && m[4] == 'c')
        || (len == 5 && m[0] == 'b' && m[1] == 's' && m[2] == 'w' && m[3] == 'a' && m[4] == 'p')
        || (len == 5 && m[0] == 'e' && m[1] == 'n' && m[2] == 't' && m[3] == 'e' && m[4] == 'r')
        || (len == 5 && m[0] == 'l' && m[1] == 'e' && m[2] == 'a' && m[3] == 'v' && m[4] == 'e'))
        return disasm_theme::kind_mnem_data;

    if (len == 3 && m[0] == 'c' && m[1] == 'm' && m[2] == 'p') return disasm_theme::kind_mnem_arith;

    return disasm_theme::kind_mnem_other;
}

static ImU32 mnemonic_color(const AsmInstr& ins, float a) {
    if (ins.is_nop)
        return aida::ui::with_alpha(disasm_theme::mnem_nop(), a * 0.85f);
    if (ins.is_call)
        return aida::ui::with_alpha(disasm_theme::mnem_call(), a);
    if (ins.is_ret)
        return aida::ui::with_alpha(disasm_theme::mnem_ret(), a);
    int family = classify_mnemonic_family(ins.mnem);
    if (family != disasm_theme::kind_mnem_other)
        return aida::ui::with_alpha(disasm_theme::color_for_kind(family), a);
    if (ins.is_priv)
        return aida::ui::with_alpha(disasm_theme::mnem_priv(), a);
    if (ins.is_branch)
        return aida::ui::with_alpha(disasm_theme::mnem_branch(), a);
    return aida::ui::with_alpha(disasm_theme::mnem_other(), a);
}


static int find_instr_at(uint64_t addr, const DisasmFile& file) {
    if (file.instrs.empty()) return -1;

    int lo = 0, hi = static_cast<int>(file.instrs.size()) - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (file.instrs[mid].addr == addr) return mid;
        if (file.instrs[mid].addr < addr) lo = mid + 1;
        else hi = mid - 1;
    }
    return (lo < static_cast<int>(file.instrs.size())) ? lo : static_cast<int>(file.instrs.size()) - 1;
}

static uint64_t find_enclosing_function_start(uint64_t addr, const DisasmFile& file) {
    if (addr == 0) return 0;

    uint64_t pdata_start = function_index::detail::lookup_function_start_for_addr(addr);
    if (pdata_start != 0) return pdata_start;

    if (file.instrs.empty()) return addr;
    int idx = find_instr_at(addr, file);
    if (idx < 0 || idx >= static_cast<int>(file.instrs.size())) return addr;
    if (file.instrs[idx].addr != addr && idx + 1 < static_cast<int>(file.instrs.size())
        && file.instrs[idx + 1].addr == addr)
        ++idx;

    const int max_scan = 65536;
    int last_terminator = -1;
    for (int i = idx - 1; i >= 0 && (idx - i) <= max_scan; --i) {
        const auto& ip = file.instrs[i];
        if (ip.is_ret) { last_terminator = i; break; }
        if (ip.is_priv && ip.len == 1 && ip.raw[0] == 0xCC) { last_terminator = i; break; }
    }

    int candidate;
    if (last_terminator >= 0 && last_terminator + 1 < static_cast<int>(file.instrs.size())) {
        candidate = last_terminator + 1;
    } else {
        candidate = 0;
    }

    while (candidate < static_cast<int>(file.instrs.size())) {
        const auto& cp = file.instrs[candidate];
        if (cp.is_nop) { ++candidate; continue; }
        if (cp.is_priv && cp.len == 1 && cp.raw[0] == 0xCC) { ++candidate; continue; }
        break;
    }
    if (candidate <= idx && candidate < static_cast<int>(file.instrs.size()))
        return file.instrs[candidate].addr;

    return addr;
}

uint64_t enclosing_function_start(uint64_t addr, const DisasmFile& file) {
    return find_enclosing_function_start(addr, file);
}

static uint64_t follow_thunk_chain(uint64_t entry) {
    uint64_t cur = entry;
    for (int hops = 0; hops < 8; ++hops) {
        if (cur == 0) break;
        if (!function_index::is_thunk(cur)) break;
        uint64_t next = function_index::thunk_target(cur);
        if (next == 0 || next == cur) break;
        cur = next;
    }
    return cur;
}

static thread_local bool s_nav_history_suppress_push = false;

void goto_address(uint64_t addr, DisasmState& disasm) {
    auto& st = g_state;
    int idx = find_instr_at(addr, disasm.file);
    diag::log_tagged_fmt("disasm_goto",
        "goto_address addr=0x%llX resolved_row=%d sections=%zu instrs=%zu",
        static_cast<unsigned long long>(addr), idx,
        disasm.file.sections.size(), disasm.file.instrs.size());
    if (idx < 0) return;


    if (st.selected_row >= 0) {

        if (st.nav_pos + 1 < static_cast<int>(st.nav_history.size()))
            st.nav_history.resize(st.nav_pos + 1);
        st.nav_history.push_back(st.selected_row);
        st.nav_pos = static_cast<int>(st.nav_history.size()) - 1;

        if (!s_nav_history_suppress_push
            && st.selected_row < static_cast<int>(disasm.file.instrs.size())) {
            uint64_t prev_addr = disasm.file.instrs[st.selected_row].addr;
            if (prev_addr != addr)
                nav_history::push(prev_addr);
        }
    }

    st.selected_row = idx;
    st.sel_anchor = idx;
    st.sel_extent = idx;
    st.sel_dragging = false;
    st.sel_anchor_sub = INT_MIN;
    st.sel_extent_sub = INT_MIN;
    st.sel_anchor_px  = -1.f;
    st.sel_extent_px  = -1.f;
    st.banner_selected_row = -1;
    st.banner_sel_anchor = -1;
    st.banner_sel_extent = -1;
    st.banner_sel_dragging = false;
    float target = layout_instr_target_scroll_y(idx, 18.f);
    st.target_scroll_y = target;
    st.scroll_y = target;
    st.goto_flash_row = idx;
    st.goto_flash_t = 1.f;
}

void navigate_back() {
    auto& st = g_state;
    if (st.nav_pos <= 0 || st.nav_history.empty()) {
        diag::log_tagged_fmt("disasm", "navigate_back rejected nav_pos=%d history_size=%zu",
            st.nav_pos, st.nav_history.size());
        return;
    }
    st.nav_pos--;
    diag::log_tagged_fmt("disasm", "navigate_back nav_pos=%d -> row=%d",
        st.nav_pos, st.nav_history[st.nav_pos]);
    st.selected_row = st.nav_history[st.nav_pos];
    st.sel_anchor = st.selected_row;
    st.sel_extent = st.selected_row;
    st.sel_dragging = false;
    st.sel_anchor_sub = INT_MIN;
    st.sel_extent_sub = INT_MIN;
    st.sel_anchor_px  = -1.f;
    st.sel_extent_px  = -1.f;
    st.banner_selected_row = -1;
    st.banner_sel_anchor = -1;
    st.banner_sel_extent = -1;
    st.banner_sel_dragging = false;
    {
        float t = layout_instr_target_scroll_y(st.selected_row, 18.f);
        st.target_scroll_y = t;
        st.scroll_y = t;
    }
    st.goto_flash_row = st.selected_row;
    st.goto_flash_t = 1.f;
}

void navigate_forward() {
    auto& st = g_state;
    if (st.nav_pos + 1 >= static_cast<int>(st.nav_history.size())) {
        diag::log_tagged_fmt("disasm", "navigate_forward rejected nav_pos=%d history_size=%zu",
            st.nav_pos, st.nav_history.size());
        return;
    }
    st.nav_pos++;
    diag::log_tagged_fmt("disasm", "navigate_forward nav_pos=%d -> row=%d",
        st.nav_pos, st.nav_history[st.nav_pos]);
    st.selected_row = st.nav_history[st.nav_pos];
    st.sel_anchor = st.selected_row;
    st.sel_extent = st.selected_row;
    st.sel_dragging = false;
    st.sel_anchor_sub = INT_MIN;
    st.sel_extent_sub = INT_MIN;
    st.sel_anchor_px  = -1.f;
    st.sel_extent_px  = -1.f;
    st.banner_selected_row = -1;
    st.banner_sel_anchor = -1;
    st.banner_sel_extent = -1;
    st.banner_sel_dragging = false;
    {
        float t = layout_instr_target_scroll_y(st.selected_row, 18.f);
        st.target_scroll_y = t;
        st.scroll_y = t;
    }
    st.goto_flash_row = st.selected_row;
    st.goto_flash_t = 1.f;
}

static int xref_type_from_annotation(const xref_index::annotation_t& ann,
                                     const AsmInstr* decoded)
{
    if (decoded && decoded->len > 0) {
        xref_engine::xref_type_t t = xref_engine::detail::classify_instruction(*decoded);
        return static_cast<int>(t);
    }
    if (ann.kind == xref_index::kind_t::data) {
        return static_cast<int>(xref_engine::xref_type_t::data_ref);
    }
    switch (ann.edge) {
    case xref_index::edge_t::call_proc:
        return static_cast<int>(xref_engine::xref_type_t::call);
    case xref_index::edge_t::jump:
        return static_cast<int>(xref_engine::xref_type_t::jump);
    case xref_index::edge_t::offset_ref:
    default:
        return static_cast<int>(xref_engine::xref_type_t::lea);
    }
}

static bool try_instant_xref_lookup(uint64_t addr, uint64_t func_start)
{
    auto& st = g_state;

    if (addr == 0) return false;

    const size_t limit = 4096;
    std::vector<xref_index::annotation_t> primary = xref_index::query_to(addr, limit);
    std::vector<xref_index::annotation_t> secondary;
    if (func_start != 0 && func_start != addr) {
        secondary = xref_index::query_to(func_start, limit);
    }

    if (primary.empty() && secondary.empty()) {
        return false;
    }

    std::string mod_name_for_module;
    {
        auto cached = xref_index::detail::lookup_cached_module(addr);
        if (!cached && func_start != 0) {
            cached = xref_index::detail::lookup_cached_module(func_start);
        }
        if (cached) mod_name_for_module = cached->name;
    }

    auto append_entries = [&](const std::vector<xref_index::annotation_t>& anns,
                              std::vector<xref_popup_entry_t>& out)
    {
        for (const auto& ann : anns) {
            if (ann.source_addr == 0) continue;

            std::vector<uint8_t> bytes;
            bool got = false;
            if (driver_bridge::attached_pid() != 0) {
                got = driver_bridge::read_memory(ann.source_addr, 16, bytes);
            }
            if (!got) {
                got = static_analysis::read_bytes_from_pe(g_disasm.file, ann.source_addr, 16, bytes);
            }

            AsmInstr ins{};
            ins.len = 0;
            if (got && !bytes.empty()) {
                int avail = static_cast<int>(bytes.size());
                if (avail > 15) avail = 15;
                ins = zydis_decode_one(bytes.data(), avail, ann.source_addr);
            }

            xref_popup_entry_t e;
            e.addr = ann.source_addr;
            e.type = xref_type_from_annotation(ann, ins.len > 0 ? &ins : nullptr);
            if (ins.len > 0) {
                char buf[256];
                std::snprintf(buf, sizeof(buf), "%s %s", ins.mnem, ins.ops);
                e.disasm_text = buf;
            }
            e.module_name = mod_name_for_module;
            {
                std::string rn = rename_store::get(ann.source_addr);
                if (!rn.empty()) {
                    e.function_name = rn;
                } else {
                    std::string sym = symbol_store::resolve_symbol(ann.source_addr);
                    if (!sym.empty()) {
                        e.function_name = sym;
                    } else if (!ann.source_label.empty()) {
                        e.function_name = ann.source_label;
                    }
                }
            }
            out.push_back(std::move(e));
        }
    };

    std::vector<xref_popup_entry_t> results;
    results.reserve(primary.size() + secondary.size());
    append_entries(primary, results);
    append_entries(secondary, results);

    std::sort(results.begin(), results.end(),
        [](const xref_popup_entry_t& a, const xref_popup_entry_t& b) {
            return a.addr < b.addr;
        });
    results.erase(std::unique(results.begin(), results.end(),
        [](const xref_popup_entry_t& a, const xref_popup_entry_t& b) {
            return a.addr == b.addr;
        }), results.end());

    {
        std::lock_guard<std::mutex> lk(st.xref_mutex);
        st.xref_results = std::move(results);
    }
    st.xref_scanning.store(false);

    diag::log_tagged_critical_fmt("xref",
        "instant_xref_index_hit addr=0x%llX func_start=0x%llX primary=%zu secondary=%zu",
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long long>(func_start),
        primary.size(),
        secondary.size());

    return true;
}

static void launch_xref_scan(uint64_t addr, uint64_t func_start = 0)
{
    auto& st = g_state;
    st.xref_scanning.store(true);
    st.xref_popup_selected = -1;
    st.xref_popup_scroll = 0.f;
    st.xref_popup_target_scroll = 0.f;

    diag::log_tagged_critical_fmt("xref", "launch addr=0x%llX func_start=0x%llX",
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long long>(func_start));

    bool posted = work_queue::post([addr, func_start]() {
        diag::log_tagged_critical_fmt("xref", "thread_entry addr=0x%llX func_start=0x%llX",
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(func_start));

        auto modules = driver_bridge::enumerate_modules();
        diag::log_tagged_critical_fmt("xref", "modules_enumerated count=%zu",
            modules.size());

        uint64_t search_base = 0;
        uint64_t search_size = 0;
        std::string mod_name;

        bool use_static = false;

        const bool pe_loaded = g_disasm.file.loaded && !g_disasm.file.sections.empty();
        const uint64_t pe_size = pe_loaded ? static_analysis::total_image_size(g_disasm.file) : 0;
        const bool addr_in_pe = pe_loaded && pe_size > 0
            && addr >= g_disasm.file.image_base
            && addr <  g_disasm.file.image_base + pe_size;

        diag::log_tagged_critical_fmt("xref",
            "pe_loaded=%d pe_size=0x%llX image_base=0x%llX addr_in_pe=%d",
            pe_loaded ? 1 : 0,
            static_cast<unsigned long long>(pe_size),
            static_cast<unsigned long long>(g_disasm.file.image_base),
            addr_in_pe ? 1 : 0);

        for (auto& m : modules) {
            if (addr >= m.base && addr < m.base + m.size) {
                search_base = m.base;
                search_size = m.size;
                mod_name = m.name;
                diag::log_tagged_critical_fmt("xref",
                    "module_match name=%s base=0x%llX size=0x%llX",
                    m.name.c_str(),
                    static_cast<unsigned long long>(m.base),
                    static_cast<unsigned long long>(m.size));
                break;
            }
        }

        if (search_size == 0 && addr_in_pe) {
            use_static = true;
            search_base = g_disasm.file.image_base;
            search_size = pe_size;
            mod_name = g_disasm.file.filename;
            diag::log_tagged_critical("xref", "path=static_pe_addr_match");
        }

        if (search_size == 0 && !modules.empty()) {
            search_base = modules[0].base;
            search_size = modules[0].size;
            mod_name = modules[0].name;
            diag::log_tagged_critical_fmt("xref",
                "path=fallback_modules0 name=%s base=0x%llX size=0x%llX",
                modules[0].name.c_str(),
                static_cast<unsigned long long>(modules[0].base),
                static_cast<unsigned long long>(modules[0].size));
        }

        if (search_size == 0 && pe_loaded && pe_size > 0) {
            use_static = true;
            search_base = g_disasm.file.image_base;
            search_size = pe_size;
            mod_name = g_disasm.file.filename;
            diag::log_tagged_critical("xref", "path=fallback_static_pe");
        }

        if (search_size == 0) {
            diag::log_tagged_critical("xref", "exit_no_range");
            g_state.xref_scanning.store(false);
            return;
        }

        diag::log_tagged_critical_fmt("xref",
            "scan_begin base=0x%llX size=0x%llX use_static=%d mod=%s",
            static_cast<unsigned long long>(search_base),
            static_cast<unsigned long long>(search_size),
            use_static ? 1 : 0,
            mod_name.c_str());

        const size_t page_size = 4096;
        std::vector<xref_popup_entry_t> found;
        uint64_t pages_done = 0;
        uint64_t pages_with_data = 0;
        uint64_t insns_decoded = 0;
        uint64_t targets_resolved = 0;
        uint64_t targets_in_pe = 0;
        uint64_t branches_seen = 0;
        uint64_t memops_seen = 0;
        uint64_t memops_rip = 0;
        uint64_t nearest_diff = UINT64_MAX;
        uint64_t nearest_target = 0;
        uint64_t nearest_source = 0;
        const uint64_t fuzz_window = 0x40;
        std::vector<uint64_t> sample_targets;
        sample_targets.reserve(32);

        for (uint64_t offset = 0; offset < search_size; offset += page_size) {
            size_t chunk = page_size;
            if (offset + chunk > search_size)
                chunk = static_cast<size_t>(search_size - offset);

            std::vector<uint8_t> page_data;
            bool got_page = false;

            if (!use_static)
                got_page = driver_bridge::read_memory(search_base + offset, chunk, page_data);

            if (!got_page)
                got_page = static_analysis::read_bytes_from_pe(g_disasm.file, search_base + offset, chunk, page_data);

            ++pages_done;
            if (!got_page || page_data.empty())
                continue;
            ++pages_with_data;

            const uint8_t* data = page_data.data();
            int sz = static_cast<int>(page_data.size());
            int pos = 0;

            while (pos < sz) {
                int avail = sz - pos;
                if (avail > 15) avail = 15;

                uint64_t ins_addr = search_base + offset + pos;
                AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);
                if (ins.len <= 0) ins.len = 1;
                ++insns_decoded;
                if (ins.is_call || ins.is_branch) ++branches_seen;
                if (ins.has_mem_op) {
                    ++memops_seen;
                    if (ins.mem_op.base_reg == static_cast<uint16_t>(ZYDIS_REGISTER_RIP))
                        ++memops_rip;
                }

                uint64_t resolved = 0;
                if (xref_engine::detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved)) {
                    ++targets_resolved;
                    if (resolved >= search_base && resolved < search_base + search_size) {
                        ++targets_in_pe;
                        if (sample_targets.size() < 32) {
                            bool dup = false;
                            for (auto& t : sample_targets) { if (t == resolved) { dup = true; break; } }
                            if (!dup) sample_targets.push_back(resolved);
                        }
                        uint64_t diff = resolved > addr ? resolved - addr : addr - resolved;
                        if (diff < nearest_diff) {
                            nearest_diff = diff;
                            nearest_target = resolved;
                            nearest_source = ins_addr;
                        }
                    }
                    bool hit_addr = (resolved == addr);
                    bool hit_func = (func_start != 0 && func_start != addr && resolved == func_start);
                    if (hit_addr || hit_func) {
                        xref_popup_entry_t e;
                        e.addr = ins_addr;
                        e.type = static_cast<int>(xref_engine::detail::classify_instruction(ins));
                        char buf[256];
                        snprintf(buf, sizeof(buf), "%s %s", ins.mnem, ins.ops);
                        e.disasm_text = buf;
                        e.module_name = mod_name;
                        {
                            std::string rn = rename_store::get(ins_addr);
                            e.function_name = !rn.empty() ? rn : symbol_store::resolve_symbol(ins_addr);
                        }
                        found.push_back(std::move(e));
                    }
                }
                pos += ins.len;
            }

            uint64_t page_va = search_base + offset;
            uint64_t aligned_start = (page_va + 7ull) & ~7ull;
            if (aligned_start >= page_va && aligned_start < page_va + static_cast<uint64_t>(sz)) {
                size_t scan_start = static_cast<size_t>(aligned_start - page_va);
                for (size_t p = scan_start; p + 8 <= static_cast<size_t>(sz); p += 8) {
                    uint64_t v;
                    std::memcpy(&v, data + p, sizeof(v));
                    bool hit_addr = (v == addr);
                    bool hit_func = (func_start != 0 && func_start != addr && v == func_start);
                    if (!hit_addr && !hit_func) continue;
                    uint64_t ref_va = page_va + static_cast<uint64_t>(p);
                    xref_popup_entry_t e;
                    e.addr = ref_va;
                    e.type = static_cast<int>(xref_engine::xref_type_t::data_ref);
                    char buf[64];
                    snprintf(buf, sizeof(buf), "dq 0x%llX",
                        static_cast<unsigned long long>(v));
                    e.disasm_text = buf;
                    e.module_name = mod_name;
                    {
                        std::string rn = rename_store::get(ref_va);
                        e.function_name = !rn.empty() ? rn : symbol_store::resolve_symbol(ref_va);
                    }
                    found.push_back(std::move(e));
                }
            }

            if ((pages_done & 0x3FF) == 0) {
                diag::log_tagged_critical_fmt("xref",
                    "scan_progress pages=%llu/%llu hits=%zu",
                    static_cast<unsigned long long>(pages_done),
                    static_cast<unsigned long long>(search_size / page_size),
                    found.size());
            }
        }

        diag::log_tagged_critical_fmt("xref",
            "scan_done pages=%llu data_pages=%llu insns=%llu branches=%llu memops=%llu memops_rip=%llu resolved=%llu in_pe=%llu hits=%zu",
            static_cast<unsigned long long>(pages_done),
            static_cast<unsigned long long>(pages_with_data),
            static_cast<unsigned long long>(insns_decoded),
            static_cast<unsigned long long>(branches_seen),
            static_cast<unsigned long long>(memops_seen),
            static_cast<unsigned long long>(memops_rip),
            static_cast<unsigned long long>(targets_resolved),
            static_cast<unsigned long long>(targets_in_pe),
            found.size());

        if (nearest_diff != UINT64_MAX) {
            diag::log_tagged_critical_fmt("xref",
                "nearest_resolved_target target=0x%llX source=0x%llX diff=0x%llX (queried=0x%llX)",
                static_cast<unsigned long long>(nearest_target),
                static_cast<unsigned long long>(nearest_source),
                static_cast<unsigned long long>(nearest_diff),
                static_cast<unsigned long long>(addr));
        }

        for (size_t si = 0; si < sample_targets.size(); ++si) {
            diag::log_tagged_critical_fmt("xref",
                "sample_target[%zu]=0x%llX", si,
                static_cast<unsigned long long>(sample_targets[si]));
        }

        {
            std::lock_guard<std::mutex> lk(g_state.xref_mutex);
            g_state.xref_results = std::move(found);
        }
        g_state.xref_scanning.store(false);
        diag::log_tagged_critical("xref", "thread_exit");
    });

    if (!posted) {
        diag::log_tagged_critical("xref", "post_failed");
        st.xref_scanning.store(false);
    }
}

static float s_close_btn_anim = 0.f;
static float s_copy_addr_anim = 0.f;
static float s_copy_all_anim = 0.f;
static int   s_xref_hover_row = -1;
static float s_xref_hover_anim = 0.f;

static const char* xref_strip_module_prefix(const std::string& fn) {
    size_t pos = fn.find('!');
    if (pos == std::string::npos) return fn.c_str();
    return fn.c_str() + pos + 1;
}

static std::string xref_truncate_to_width(const std::string& s, ImFont* font, float font_size, float max_w) {
    if (s.empty() || max_w <= 0.f) return std::string();
    ImVec2 full = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, s.c_str());
    if (full.x <= max_w) return s;
    const char* ellipsis = "..";
    ImVec2 ell_sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, ellipsis);
    float budget = max_w - ell_sz.x;
    if (budget <= 0.f) return std::string(ellipsis);
    size_t lo = 0;
    size_t hi = s.size();
    while (lo < hi) {
        size_t mid = (lo + hi + 1) / 2;
        ImVec2 sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, s.c_str(), s.c_str() + mid);
        if (sz.x <= budget) lo = mid;
        else hi = mid - 1;
    }
    std::string out;
    out.reserve(lo + 2);
    out.append(s, 0, lo);
    out.append(ellipsis);
    return out;
}

static void xref_address_split(uint64_t addr, char* hex_buf, size_t hex_cap, int& first_nonzero) {
    snprintf(hex_buf, hex_cap, "%016llX", static_cast<unsigned long long>(addr));
    first_nonzero = 0;
    while (first_nonzero < 15 && hex_buf[first_nonzero] == '0')
        ++first_nonzero;
}

static void render_xref_popup(float pos_x, float pos_y, float width, float height,
                               float alpha, float accent_r, float accent_g, float accent_b,
                               DisasmState& disasm, float dt)
{
    (void)pos_x;
    (void)pos_y;
    (void)width;
    (void)height;

    auto& st = g_state;

    float target_fade = st.xref_popup_open ? 1.f : 0.f;
    st.xref_popup_fade = ui_anim::smooth_lerp(st.xref_popup_fade, target_fade, 14.f, dt);

    if (st.xref_popup_fade < 0.01f && !st.xref_popup_open)
        return;

    float fa = alpha * st.xref_popup_fade;
    const auto& tk = aida::ui::resolved();
    const auto _ta = [fa](ImU32 c) -> ImU32 { return aida::ui::with_alpha(c, fa); };
    ImDrawList* fdl = ImGui::GetForegroundDrawList();

    std::vector<xref_popup_entry_t> results_copy;
    {
        std::lock_guard<std::mutex> lk(st.xref_mutex);
        results_copy = st.xref_results;
    }
    bool scanning = st.xref_scanning.load();
    bool has_results = !results_copy.empty();
    bool show_empty_state = !has_results && !scanning;
    bool show_scanning_state = scanning && !has_results;

    ImGuiViewport* vp = ImGui::GetMainViewport();
    float vp_px = vp->Pos.x;
    float vp_py = vp->Pos.y;
    float vp_pw = vp->Size.x;
    float vp_ph = vp->Size.y;

    {
        ImU32 dim_col = tk.is_dark
            ? IM_COL32(0, 0, 0, static_cast<int>(238 * fa))
            : aida::ui::with_alpha(tk.text_primary, 0.63f * fa);
        fdl->AddRectFilled(ImVec2(vp_px, vp_py), ImVec2(vp_px + vp_pw, vp_py + vp_ph),
            dim_col);
    }

    float popup_w;
    float popup_h;
    if (show_empty_state) {
        popup_w = 520.f;
        popup_h = 280.f;
    } else if (show_scanning_state) {
        popup_w = 520.f;
        popup_h = 220.f;
    } else {
        popup_w = std::min(820.f, vp_pw * 0.86f);
        popup_h = std::min(640.f, vp_ph * 0.84f);
    }

    float max_w = vp_pw - 24.f;
    float max_h = vp_ph - 24.f;
    if (max_w < 240.f) max_w = 240.f;
    if (max_h < 160.f) max_h = 160.f;
    if (popup_w > max_w) popup_w = max_w;
    if (popup_h > max_h) popup_h = max_h;

    float cx = vp_px + vp_pw * 0.5f;
    float cy = vp_py + vp_ph * 0.5f;

    float t_back = ui_anim::ease_out_back(std::clamp(st.xref_popup_fade * 1.2f, 0.f, 1.f));
    float scale = 0.92f + 0.08f * t_back;
    float pw = popup_w * scale;
    float ph = popup_h * scale;
    float px = cx - pw * 0.5f;
    float py = cy - ph * 0.5f + (1.f - t_back) * 12.f;

    for (int g = 4; g >= 1; --g) {
        float expand = static_cast<float>(g) * 4.f;
        int ga = static_cast<int>(22 * fa / static_cast<float>(g));
        fdl->AddRect(ImVec2(px - expand, py - expand),
            ImVec2(px + pw + expand, py + ph + expand),
            IM_COL32(0, 0, 0, ga), 10.f + expand, 0, 1.f);
    }
    for (int g = 3; g >= 1; --g) {
        float expand = static_cast<float>(g) * 3.f;
        int ga = static_cast<int>(18 * fa / static_cast<float>(g));
        fdl->AddRect(ImVec2(px - expand, py - expand),
            ImVec2(px + pw + expand, py + ph + expand),
            IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                     static_cast<int>(accent_b * 255), ga), 10.f + expand, 0, 1.f);
    }

    float body_fa = fa < 1.f ? std::sqrt(fa) : 1.f;
    {
        ImU32 body_col = aida::ui::with_alpha(tk.panel_bg, body_fa);
        fdl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
            body_col, 8.f);
    }
    fdl->AddRect(ImVec2(px, py), ImVec2(px + pw, py + ph),
        IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                 static_cast<int>(accent_b * 255), static_cast<int>(90 * fa)), 8.f, 0, 1.5f);

    char title_buf[256];
    if (!st.xref_popup_target_name.empty()) {
        snprintf(title_buf, sizeof(title_buf), "Xrefs to %s  (0x%llX)",
                 st.xref_popup_target_name.c_str(),
                 static_cast<unsigned long long>(st.xref_popup_addr));
    } else {
        snprintf(title_buf, sizeof(title_buf), "Xrefs to 0x%llX",
                 static_cast<unsigned long long>(st.xref_popup_addr));
    }

    float header_h = 38.f;
    ui_anim::render_popup_header(fdl, px, py, pw, header_h,
                                  title_buf, accent_r, accent_g, accent_b, fa);

    if (ui_anim::render_popup_close_button(fdl, px, py, pw, header_h, fa, s_close_btn_anim, dt))
        st.xref_popup_open = false;

    float toolbar_y = py + header_h;
    float toolbar_h = 32.f;
    fdl->AddRectFilled(ImVec2(px, toolbar_y), ImVec2(px + pw, toolbar_y + toolbar_h),
        _ta(tk.panel_header));
    fdl->AddLine(ImVec2(px, toolbar_y + toolbar_h - 1.f), ImVec2(px + pw, toolbar_y + toolbar_h - 1.f),
        _ta(tk.border_subtle));

    float btn_x = px + 10.f;
    float btn_y = toolbar_y + 5.f;

    if (!has_results) {
        float bw_addr = ui_anim::toolbar_button_width("Copy Address");
        fdl->AddRectFilled(ImVec2(btn_x - 2.f, btn_y - 2.f),
                           ImVec2(btn_x + bw_addr + 2.f, btn_y + 22.f + 2.f),
                           aida::ui::with_alpha(IM_COL32(255, 255, 255, 10), fa),
                           4.f);
    }
    if (ui_anim::render_toolbar_button(fdl, "Copy Address", btn_x, btn_y,
                                        accent_r, accent_g, accent_b, fa, s_copy_addr_anim, dt,
                                        false, !has_results)) {
        if (st.xref_popup_selected >= 0 && st.xref_popup_selected < static_cast<int>(results_copy.size())) {
            char addr_buf_copy[20];
            snprintf(addr_buf_copy, sizeof(addr_buf_copy), "%llX",
                     static_cast<unsigned long long>(results_copy[static_cast<size_t>(st.xref_popup_selected)].addr));
            ImGui::SetClipboardText(addr_buf_copy);
        }
    }
    btn_x += ui_anim::toolbar_button_width("Copy Address") + 4.f;

    if (!has_results) {
        float bw_all = ui_anim::toolbar_button_width("Copy All");
        fdl->AddRectFilled(ImVec2(btn_x - 2.f, btn_y - 2.f),
                           ImVec2(btn_x + bw_all + 2.f, btn_y + 22.f + 2.f),
                           aida::ui::with_alpha(IM_COL32(255, 255, 255, 10), fa),
                           4.f);
    }
    if (ui_anim::render_toolbar_button(fdl, "Copy All", btn_x, btn_y,
                                        accent_r, accent_g, accent_b, fa, s_copy_all_anim, dt,
                                        false, !has_results)) {
        std::string all_text;
        for (auto& e : results_copy) {
            const char* fn = e.function_name.empty() ? "" : xref_strip_module_prefix(e.function_name);
            char line_buf[320];
            if (fn && *fn) {
                snprintf(line_buf, sizeof(line_buf), "%016llX  %-40s  %s\n",
                         static_cast<unsigned long long>(e.addr), fn, e.disasm_text.c_str());
            } else {
                snprintf(line_buf, sizeof(line_buf), "%016llX  %s\n",
                         static_cast<unsigned long long>(e.addr), e.disasm_text.c_str());
            }
            all_text += line_buf;
        }
        if (!all_text.empty())
            ImGui::SetClipboardText(all_text.c_str());
    }

    char count_buf[40];
    if (scanning && !has_results) {
        snprintf(count_buf, sizeof(count_buf), "Searching...");
    } else if (scanning && has_results) {
        snprintf(count_buf, sizeof(count_buf), "%zu (scanning)", results_copy.size());
    } else {
        snprintf(count_buf, sizeof(count_buf), "%zu result%s",
                 results_copy.size(),
                 results_copy.size() == 1 ? "" : "s");
    }
    ImVec2 count_ts = ImGui::CalcTextSize(count_buf);
    float count_pill_w = count_ts.x + 16.f;
    float count_pill_x = px + pw - count_pill_w - 12.f;
    float count_pill_y = toolbar_y + (toolbar_h - (count_ts.y + 4.f)) * 0.5f;
    ImU32 pill_color = scanning ? tk.accent_dim : (has_results ? tk.accent_u32 : tk.text_dim);
    ui_anim::render_status_pill(fdl, count_pill_x, count_pill_y, count_buf, pill_color, fa);

    if (scanning && has_results) {
        s_xref_anim_t += dt * 5.f;
        float spinner_x = count_pill_x - 14.f;
        float spinner_y = count_pill_y + (count_ts.y + 4.f) * 0.5f;
        ImU32 spin_col = aida::ui::with_alpha(tk.accent_u32, fa);
        ui_anim::render_spinner(fdl, spinner_x, spinner_y, 6.f, 2.f, spin_col, s_xref_anim_t);
    }

    float toolbar_end = toolbar_y + toolbar_h;
    const float footer_h = 30.f;
    const float card_h = 56.f;
    const float card_gap = 6.f;
    const float row_pitch = card_h + card_gap;
    const float list_pad_top = 8.f;
    const float list_pad_x = 10.f;
    float list_y = toolbar_end + list_pad_top;
    float list_h = ph - header_h - toolbar_h - list_pad_top - footer_h - 4.f;
    if (list_h < 1.f) list_h = 1.f;

    if (has_results) {
        float content_h = static_cast<float>(results_copy.size()) * row_pitch;
        int n_results = static_cast<int>(results_copy.size());

        bool list_hovered = ImGui::IsMouseHoveringRect(ImVec2(px, list_y), ImVec2(px + pw, list_y + list_h));
        if (list_hovered) {
            float wheel = ImGui::GetIO().MouseWheel;
            if (wheel != 0.f)
                st.xref_popup_target_scroll -= wheel * row_pitch * 1.2f;
        }

        if (st.xref_popup_open) {
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
                st.xref_popup_selected = std::min(st.xref_popup_selected + 1, n_results - 1);
                if (st.xref_popup_selected < 0) st.xref_popup_selected = 0;
                float sel_y = static_cast<float>(st.xref_popup_selected) * row_pitch;
                if (sel_y < st.xref_popup_target_scroll)
                    st.xref_popup_target_scroll = sel_y;
                if (sel_y + row_pitch > st.xref_popup_target_scroll + list_h)
                    st.xref_popup_target_scroll = sel_y + row_pitch - list_h;
            }
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
                st.xref_popup_selected = std::max(st.xref_popup_selected - 1, 0);
                float sel_y = static_cast<float>(st.xref_popup_selected) * row_pitch;
                if (sel_y < st.xref_popup_target_scroll)
                    st.xref_popup_target_scroll = sel_y;
                if (sel_y + row_pitch > st.xref_popup_target_scroll + list_h)
                    st.xref_popup_target_scroll = sel_y + row_pitch - list_h;
            }
            if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) && st.xref_popup_selected >= 0 &&
                st.xref_popup_selected < n_results) {
                goto_address(results_copy[static_cast<size_t>(st.xref_popup_selected)].addr, disasm);
                st.xref_popup_open = false;
            }
        }

        float max_scroll = std::max(0.f, content_h - list_h);
        st.xref_popup_target_scroll = std::max(0.f, std::min(st.xref_popup_target_scroll, max_scroll));
        ui_anim::smooth_scroll(st.xref_popup_scroll, st.xref_popup_target_scroll, 16.f, dt);

        fdl->PushClipRect(ImVec2(px + 2.f, list_y), ImVec2(px + pw - 14.f, list_y + list_h), true);

        int first_vis = static_cast<int>(st.xref_popup_scroll / row_pitch);
        int last_vis = first_vis + static_cast<int>(list_h / row_pitch) + 2;
        if (first_vis < 0) first_vis = 0;
        if (last_vis > n_results) last_vis = n_results;

        ImFont* code_font = aida::ui::fonts::code();
        if (!code_font) code_font = ImGui::GetFont();
        ImFont* body_font = aida::ui::fonts::body();
        if (!body_font) body_font = ImGui::GetFont();
        ImFont* body_strong_font = aida::ui::fonts::body_strong();
        if (!body_strong_font) body_strong_font = body_font;
        ImFont* caption_font = aida::ui::fonts::caption();
        if (!caption_font) caption_font = body_font;

        const float addr_font_size = 14.f;
        const float fn_font_size = 14.f;
        const float code_font_size = 13.f;
        const float badge_font_size = 12.5f;
        const float module_font_size = 13.5f;

        int hovered_now = -1;

        for (int i = first_vis; i < last_vis; ++i) {
            float ry = list_y + static_cast<float>(i) * row_pitch - st.xref_popup_scroll;
            if (ry + card_h < list_y || ry > list_y + list_h) continue;

            auto& e = results_copy[static_cast<size_t>(i)];

            ImVec2 rmin(px + list_pad_x, ry);
            ImVec2 rmax(px + pw - 14.f - 4.f, ry + card_h);

            bool row_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
            bool row_sel = (st.xref_popup_selected == i);

            if (row_hov) hovered_now = i;

            if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                st.xref_popup_selected = i;

            if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                goto_address(e.addr, disasm);
                st.xref_popup_open = false;
            }

            float row_entrance = 1.f;
            if (st.xref_popup_fade < 0.95f) {
                float delay = static_cast<float>(i - first_vis) * 0.03f;
                float t = (st.xref_popup_fade - delay) / (1.f - delay);
                if (t < 0.f) t = 0.f;
                if (t > 1.f) t = 1.f;
                row_entrance = t;
            }
            float row_alpha = fa * row_entrance;
            float entrance_dy = (1.f - row_entrance) * 6.f;
            rmin.y += entrance_dy;
            rmax.y += entrance_dy;

            ImU32 type_col_full;
            ImU32 type_col_soft;
            const char* type_str;
            switch (e.type) {
            case 0:  type_str = "CALL"; type_col_full = tk.info;          type_col_soft = tk.info_soft;    break;
            case 1:  type_str = "JMP";  type_col_full = tk.warning;       type_col_soft = tk.warning_soft; break;
            case 2:  type_str = "Jcc";  type_col_full = tk.warning;       type_col_soft = tk.warning_soft; break;
            case 3:  type_str = "LEA";  type_col_full = tk.success;       type_col_soft = tk.success_soft; break;
            default: type_str = "DATA"; type_col_full = tk.text_secondary;type_col_soft = tk.hover_wash;   break;
            }

            ImU32 card_bg = row_sel
                ? aida::ui::with_alpha(tk.selection,  row_alpha * 0.55f)
                : (row_hov ? aida::ui::with_alpha(tk.hover_wash, row_alpha * 2.0f)
                           : (tk.is_dark
                                ? aida::ui::with_alpha(IM_COL32(255, 255, 255, 8), row_alpha)
                                : aida::ui::with_alpha(IM_COL32(0, 0, 0, 6), row_alpha)));
            fdl->AddRectFilled(rmin, rmax, card_bg, 7.f);

            ImU32 card_border = row_sel
                ? aida::ui::with_alpha(tk.accent_u32, row_alpha * 0.70f)
                : (row_hov ? aida::ui::with_alpha(tk.accent_dim, row_alpha * 0.50f)
                           : aida::ui::with_alpha(tk.border_subtle, row_alpha));
            fdl->AddRect(rmin, rmax, card_border, 7.f, 0, row_sel ? 1.4f : 1.f);

            if (row_sel) {
                fdl->AddRectFilled(
                    ImVec2(rmin.x - 1.f, rmin.y + 4.f),
                    ImVec2(rmin.x + 3.f, rmax.y - 4.f),
                    aida::ui::with_alpha(tk.accent_u32, row_alpha), 2.f);
            }

            float inner_x = rmin.x + 12.f;
            float inner_top = rmin.y + 6.f;
            float inner_bottom = rmax.y - 6.f;
            float top_y = inner_top + 1.f;
            float bot_y = inner_top + 26.f;

            ImVec2 tsz = body_strong_font->CalcTextSizeA(badge_font_size, FLT_MAX, 0.f, type_str);
            float badge_w = tsz.x + 16.f;
            float badge_h = 20.f;
            float badge_y = top_y;
            fdl->AddRectFilled(ImVec2(inner_x, badge_y),
                ImVec2(inner_x + badge_w, badge_y + badge_h),
                aida::ui::with_alpha(type_col_soft, row_alpha * 4.5f), 4.f);
            fdl->AddRect(ImVec2(inner_x, badge_y),
                ImVec2(inner_x + badge_w, badge_y + badge_h),
                aida::ui::with_alpha(type_col_full, row_alpha * 0.45f), 4.f, 0, 1.f);
            fdl->AddText(body_strong_font, badge_font_size,
                ImVec2(inner_x + 8.f, badge_y + (badge_h - tsz.y) * 0.5f),
                aida::ui::with_alpha(type_col_full, row_alpha), type_str);

            float addr_x = inner_x + badge_w + 10.f;
            char addr_buf[20];
            int first_nz = 0;
            xref_address_split(e.addr, addr_buf, sizeof(addr_buf), first_nz);
            ImU32 addr_dim_col = aida::ui::with_alpha(tk.text_dim, row_alpha * 0.75f);
            ImU32 addr_strong_col = aida::ui::with_alpha(tk.text_address, row_alpha);
            char dim_part[20] = {};
            for (int k = 0; k < first_nz; ++k) dim_part[k] = addr_buf[k];
            dim_part[first_nz] = 0;
            ImVec2 addr_text_sz_probe = code_font->CalcTextSizeA(addr_font_size, FLT_MAX, 0.f, "0");
            float addr_y = top_y + (badge_h - addr_text_sz_probe.y) * 0.5f;
            if (first_nz > 0) {
                fdl->AddText(code_font, addr_font_size,
                    ImVec2(addr_x, addr_y),
                    addr_dim_col, dim_part);
                ImVec2 dim_sz = code_font->CalcTextSizeA(addr_font_size, FLT_MAX, 0.f, dim_part);
                addr_x += dim_sz.x;
            }
            fdl->AddText(code_font, addr_font_size,
                ImVec2(addr_x, addr_y),
                addr_strong_col, addr_buf + first_nz);
            ImVec2 strong_sz = code_font->CalcTextSizeA(addr_font_size, FLT_MAX, 0.f, addr_buf + first_nz);
            float addr_end_x = addr_x + strong_sz.x;

            float sep_x = addr_end_x + 10.f;
            fdl->AddLine(ImVec2(sep_x, top_y + 3.f),
                ImVec2(sep_x, top_y + badge_h - 3.f),
                aida::ui::with_alpha(tk.border_subtle, row_alpha * 1.5f), 1.f);

            float fn_x = sep_x + 10.f;
            float right_zone_x = rmax.x - 12.f;
            float module_pill_w = 0.f;
            ImVec2 module_sz(0.f, 0.f);
            bool has_module = !e.module_name.empty();
            if (has_module) {
                module_sz = caption_font->CalcTextSizeA(module_font_size, FLT_MAX, 0.f, e.module_name.c_str());
                module_pill_w = module_sz.x + 16.f;
                float mp_h = 20.f;
                float mp_x = right_zone_x - module_pill_w;
                float mp_y = top_y + (badge_h - mp_h) * 0.5f;
                fdl->AddRectFilled(ImVec2(mp_x, mp_y),
                    ImVec2(mp_x + module_pill_w, mp_y + mp_h),
                    aida::ui::with_alpha(tk.panel_header, row_alpha * 0.80f), mp_h * 0.5f);
                fdl->AddRect(ImVec2(mp_x, mp_y),
                    ImVec2(mp_x + module_pill_w, mp_y + mp_h),
                    aida::ui::with_alpha(tk.border_subtle, row_alpha * 1.8f), mp_h * 0.5f, 0, 1.f);
                fdl->AddText(caption_font, module_font_size,
                    ImVec2(mp_x + 8.f, mp_y + (mp_h - module_sz.y) * 0.5f),
                    aida::ui::with_alpha(tk.text_secondary, row_alpha * 1.0f),
                    e.module_name.c_str());
            }

            float fn_avail = (right_zone_x - (has_module ? module_pill_w + 10.f : 0.f)) - fn_x;
            if (fn_avail < 12.f) fn_avail = 12.f;
            ImVec2 fn_text_sz_probe = body_strong_font->CalcTextSizeA(fn_font_size, FLT_MAX, 0.f, "Mg");
            float fn_y = top_y + (badge_h - fn_text_sz_probe.y) * 0.5f;
            if (!e.function_name.empty()) {
                const char* fn_clean = xref_strip_module_prefix(e.function_name);
                std::string fn_str(fn_clean);
                std::string fn_render = xref_truncate_to_width(fn_str, body_strong_font, fn_font_size, fn_avail);
                fdl->AddText(body_strong_font, fn_font_size,
                    ImVec2(fn_x, fn_y),
                    aida::ui::with_alpha(tk.text_primary, row_alpha),
                    fn_render.c_str());
            } else {
                fdl->AddText(body_font, fn_font_size,
                    ImVec2(fn_x, fn_y),
                    aida::ui::with_alpha(tk.text_dim, row_alpha * 0.75f),
                    "(no enclosing function)");
            }

            float disasm_x = inner_x;
            float disasm_y = bot_y;
            float disasm_avail = rmax.x - 12.f - disasm_x;
            if (disasm_avail < 12.f) disasm_avail = 12.f;
            std::string disasm_render = xref_truncate_to_width(e.disasm_text, code_font, code_font_size, disasm_avail);
            ImU32 disasm_col = row_sel
                ? aida::ui::with_alpha(tk.text_primary, row_alpha)
                : aida::ui::with_alpha(tk.text_secondary, row_alpha * 1.05f);
            fdl->AddText(code_font, code_font_size,
                ImVec2(disasm_x, disasm_y),
                disasm_col, disasm_render.c_str());

            (void)inner_bottom;
        }

        s_xref_hover_anim = ui_anim::smooth_lerp(s_xref_hover_anim, hovered_now >= 0 ? 1.f : 0.f, 16.f, dt);
        s_xref_hover_row = hovered_now;

        fdl->PopClipRect();

        if (hovered_now >= 0 && hovered_now < n_results) {
            const auto& he = results_copy[static_cast<size_t>(hovered_now)];
            const std::string& full_disasm = he.disasm_text;
            char tip_addr[40];
            snprintf(tip_addr, sizeof(tip_addr), "0x%016llX", static_cast<unsigned long long>(he.addr));
            ImFont* tip_code_font = aida::ui::fonts::code();
            if (!tip_code_font) tip_code_font = ImGui::GetFont();
            ImFont* tip_body_font = aida::ui::fonts::body();
            if (!tip_body_font) tip_body_font = ImGui::GetFont();
            ImFont* tip_caption = aida::ui::fonts::caption();
            if (!tip_caption) tip_caption = tip_body_font;

            ImVec2 ms = ImGui::GetIO().MousePos;
            float tip_pad = 12.f;
            const float tip_addr_size = 13.f;
            const float tip_disasm_size = 14.f;
            const float tip_module_size = 13.5f;
            ImVec2 addr_sz = tip_code_font->CalcTextSizeA(tip_addr_size, FLT_MAX, 0.f, tip_addr);
            ImVec2 disasm_sz = tip_code_font->CalcTextSizeA(tip_disasm_size, FLT_MAX, 0.f, full_disasm.c_str());
            ImVec2 mod_sz_tip(0.f, 0.f);
            if (!he.module_name.empty())
                mod_sz_tip = tip_caption->CalcTextSizeA(tip_module_size, FLT_MAX, 0.f, he.module_name.c_str());

            float content_w = std::max(addr_sz.x, disasm_sz.x);
            content_w = std::max(content_w, mod_sz_tip.x);
            float min_w = 240.f;
            float max_tip_w = std::min(vp_pw * 0.6f, 760.f);
            float tip_w = std::max(min_w, content_w + tip_pad * 2.f);
            if (tip_w > max_tip_w) tip_w = max_tip_w;

            float line_gap = 6.f;
            float tip_h = tip_pad * 2.f + addr_sz.y + line_gap + disasm_sz.y;
            if (!he.module_name.empty()) tip_h += line_gap + mod_sz_tip.y;

            float tip_x = ms.x + 14.f;
            float tip_y = ms.y + 18.f;
            if (tip_x + tip_w > vp_px + vp_pw - 6.f) tip_x = vp_px + vp_pw - 6.f - tip_w;
            if (tip_y + tip_h > vp_py + vp_ph - 6.f) tip_y = ms.y - 12.f - tip_h;
            if (tip_x < vp_px + 6.f) tip_x = vp_px + 6.f;
            if (tip_y < vp_py + 6.f) tip_y = vp_py + 6.f;

            float tip_alpha = fa * s_xref_hover_anim;
            for (int g = 3; g >= 1; --g) {
                float ex = static_cast<float>(g) * 2.f;
                int ga = static_cast<int>(36 * tip_alpha / static_cast<float>(g));
                fdl->AddRect(ImVec2(tip_x - ex, tip_y - ex),
                    ImVec2(tip_x + tip_w + ex, tip_y + tip_h + ex),
                    IM_COL32(0, 0, 0, ga), 8.f + ex, 0, 1.f);
            }
            fdl->AddRectFilled(ImVec2(tip_x, tip_y),
                ImVec2(tip_x + tip_w, tip_y + tip_h),
                aida::ui::with_alpha(tk.panel_header, tip_alpha * 0.97f), 7.f);
            fdl->AddRect(ImVec2(tip_x, tip_y),
                ImVec2(tip_x + tip_w, tip_y + tip_h),
                aida::ui::with_alpha(tk.accent_dim, tip_alpha * 0.85f), 7.f, 0, 1.f);

            fdl->PushClipRect(ImVec2(tip_x, tip_y),
                ImVec2(tip_x + tip_w, tip_y + tip_h), true);
            float ty = tip_y + tip_pad;
            fdl->AddText(tip_code_font, tip_addr_size,
                ImVec2(tip_x + tip_pad, ty),
                aida::ui::with_alpha(tk.text_address, tip_alpha), tip_addr);
            ty += addr_sz.y + line_gap;
            fdl->AddText(tip_code_font, tip_disasm_size,
                ImVec2(tip_x + tip_pad, ty),
                aida::ui::with_alpha(tk.text_primary, tip_alpha),
                full_disasm.c_str());
            ty += disasm_sz.y + line_gap;
            if (!he.module_name.empty()) {
                fdl->AddText(tip_caption, tip_module_size,
                    ImVec2(tip_x + tip_pad, ty),
                    aida::ui::with_alpha(tk.text_secondary, tip_alpha * 0.95f),
                    he.module_name.c_str());
            }
            fdl->PopClipRect();
        }

        if (content_h > list_h && list_h > 0.f) {
            float sb_x = px + pw - 10.f;
            float sb_track_h = list_h;
            float ratio = list_h / content_h;
            float thumb_h = std::max(20.f, sb_track_h * ratio);
            float scroll_range = content_h - list_h;
            float thumb_y = list_y + (scroll_range > 0.f
                ? (st.xref_popup_scroll / scroll_range) * (sb_track_h - thumb_h) : 0.f);

            bool sb_hov = ImGui::IsMouseHoveringRect(
                ImVec2(sb_x - 4.f, list_y), ImVec2(sb_x + 8.f, list_y + sb_track_h));

            if (sb_hov || st.xref_popup_sb_dragging) {
                fdl->AddRectFilled(ImVec2(sb_x, list_y), ImVec2(sb_x + 6.f, list_y + sb_track_h),
                    aida::ui::with_alpha(tk.hover_wash, fa), 3.f);
                fdl->AddRectFilled(ImVec2(sb_x, thumb_y), ImVec2(sb_x + 6.f, thumb_y + thumb_h),
                    aida::ui::with_alpha(st.xref_popup_sb_dragging ? tk.accent_u32 : tk.accent_dim, fa), 3.f);
            }

            if (sb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                st.xref_popup_sb_dragging = true;
                st.xref_popup_sb_drag_offset = ImGui::GetIO().MousePos.y - thumb_y;
            }
            if (st.xref_popup_sb_dragging) {
                if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                    float my = ImGui::GetIO().MousePos.y - st.xref_popup_sb_drag_offset;
                    float drag_ratio = (my - list_y) / (sb_track_h - thumb_h);
                    drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                    st.xref_popup_target_scroll = drag_ratio * scroll_range;
                    st.xref_popup_scroll = st.xref_popup_target_scroll;
                } else {
                    st.xref_popup_sb_dragging = false;
                }
            }
        }
    } else if (show_scanning_state) {
        s_xref_anim_t += dt * 5.f;
        float region_top = toolbar_end + 2.f;
        float region_bottom = py + ph - footer_h;
        float region_cx = px + pw * 0.5f;
        const char* scan_text = "Scanning for cross-references...";
        ImVec2 stsz = ImGui::CalcTextSize(scan_text);
        float content_h = 12.f + 6.f + stsz.y;
        float content_top = region_top + ((region_bottom - region_top) - content_h) * 0.5f;
        float spinner_cy = content_top + 12.f;
        ImU32 spin_col = aida::ui::with_alpha(tk.accent_u32, fa);
        ui_anim::render_spinner(fdl, region_cx, spinner_cy, 12.f, 2.5f, spin_col, s_xref_anim_t);
        float label_y = spinner_cy + 12.f + 6.f;
        fdl->AddText(ImVec2(region_cx - stsz.x * 0.5f, label_y),
            _ta(tk.text_secondary), scan_text);
    } else {
        float region_top = toolbar_end + 2.f;
        float region_bottom = py + ph - footer_h;
        float region_h = region_bottom - region_top;
        float region_cx = px + pw * 0.5f;

        float circle_r = 22.f;
        float circle_cy = region_top + 16.f + circle_r;
        if (region_h < circle_r * 2.f + 90.f) {
            circle_cy = region_top + 10.f + circle_r;
        }

        ImU32 bg_col = aida::ui::with_alpha(tk.accent_glow, fa * 0.6f);
        ImU32 border_col = aida::ui::with_alpha(tk.accent_dim, fa);
        fdl->AddCircleFilled(ImVec2(region_cx, circle_cy), circle_r, bg_col, 32);
        fdl->AddCircle(ImVec2(region_cx, circle_cy), circle_r, border_col, 32, 1.5f);

        ImU32 glyph_col = aida::ui::with_alpha(tk.accent_u32, fa);
        fdl->AddCircleFilled(ImVec2(region_cx, circle_cy - 7.f), 2.2f, glyph_col, 12);
        fdl->AddLine(ImVec2(region_cx, circle_cy - 1.f),
                     ImVec2(region_cx, circle_cy + 9.f),
                     glyph_col, 2.5f);

        ImFont* title_font = aida::ui::fonts::body_strong();
        if (!title_font) title_font = ImGui::GetFont();
        float title_size = 15.f;
        const char* title_text = "No cross-references";
        ImVec2 title_sz = title_font->CalcTextSizeA(title_size, FLT_MAX, 0.f, title_text);
        float title_y = circle_cy + circle_r + 10.f;
        fdl->AddText(title_font, title_size,
            ImVec2(region_cx - title_sz.x * 0.5f, title_y),
            _ta(tk.text_primary), title_text);

        char sub_buf[160];
        snprintf(sub_buf, sizeof(sub_buf),
                 "Nothing in this module calls or references 0x%llX.",
                 static_cast<unsigned long long>(st.xref_popup_addr));
        ImVec2 sub_sz = ImGui::CalcTextSize(sub_buf);
        float sub_y = title_y + title_sz.y + 4.f;
        fdl->AddText(ImVec2(region_cx - sub_sz.x * 0.5f, sub_y),
            _ta(tk.text_secondary), sub_buf);
    }

    {
        struct chip_part_t {
            const char* chip;
            const char* label;
        };
        const chip_part_t parts[] = {
            { "Up/Dn",    "navigate" },
            { "Enter",    "jump"     },
            { "Esc",      "close"    },
            { "Dbl-click","goto"     },
        };
        const int part_count = static_cast<int>(sizeof(parts) / sizeof(parts[0]));

        const float gap_chip_label = 10.f;
        const float gap_pair_pair = 20.f;
        const float chip_pad_x = 6.f;
        const float divider_h = 14.f;
        const float verb_font_size = 15.5f;

        ImFont* footer_body = aida::ui::fonts::body();
        if (!footer_body) footer_body = ImGui::GetFont();
        ImFont* footer_verb = aida::ui::fonts::body_strong();
        if (!footer_verb) footer_verb = footer_body;

        float total_w = 0.f;
        float chip_w_arr[4];
        float lbl_w_arr[4];
        float chip_h_arr[4];
        float lbl_h = 0.f;
        for (int i = 0; i < part_count; ++i) {
            ImVec2 cts = ImGui::CalcTextSize(parts[i].chip);
            chip_w_arr[i] = cts.x + chip_pad_x * 2.f;
            chip_h_arr[i] = cts.y + 4.f;
            ImVec2 lts = footer_verb->CalcTextSizeA(verb_font_size, FLT_MAX, 0.f, parts[i].label);
            lbl_w_arr[i] = lts.x;
            if (lts.y > lbl_h) lbl_h = lts.y;
            total_w += chip_w_arr[i] + gap_chip_label + lbl_w_arr[i];
            if (i < part_count - 1)
                total_w += gap_pair_pair;
        }

        float row_h = std::max(lbl_h, chip_h_arr[0]);
        float fx = px + pw - 14.f - total_w;
        if (fx < px + 12.f) fx = px + 12.f;
        float fy = py + ph - footer_h + (footer_h - row_h) * 0.5f - 1.f;

        for (int i = 0; i < part_count; ++i) {
            float chip_y = fy + (row_h - chip_h_arr[i]) * 0.5f;
            ui_anim::render_kbd_chip(fdl, fx, chip_y, parts[i].chip, fa);
            fx += chip_w_arr[i] + gap_chip_label;
            float verb_y = fy + (row_h - lbl_h) * 0.5f;
            fdl->AddText(footer_verb, verb_font_size,
                ImVec2(fx, verb_y),
                aida::ui::with_alpha(tk.text_secondary, fa),
                parts[i].label);
            fx += lbl_w_arr[i];
            if (i < part_count - 1) {
                float div_x = fx + gap_pair_pair * 0.5f;
                float div_y0 = fy + (row_h - divider_h) * 0.5f;
                fdl->AddLine(ImVec2(div_x, div_y0),
                             ImVec2(div_x, div_y0 + divider_h),
                             _ta(tk.text_dim), 1.f);
                fx += gap_pair_pair;
            }
        }
    }

    bool body_hover = ImGui::IsMouseHoveringRect(ImVec2(px, py), ImVec2(px + pw, py + ph));
    if (st.xref_popup_open && !body_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        st.xref_popup_open = false;
    }
}


struct modal_input_block_scope_t {
    bool active = false;
    float saved_mouse_dur[5] = {};
    bool saved_mouse_down[5] = {};
    modal_input_block_scope_t() {
        if (source_reconstruct_view::is_open()) {
            active = true;
            ImGuiIO& io = ImGui::GetIO();
            for (int i = 0; i < 5; ++i) {
                saved_mouse_dur[i] = io.MouseDownDuration[i];
                saved_mouse_down[i] = io.MouseDown[i];
                if (io.MouseDownDuration[i] == 0.0f)
                    io.MouseDownDuration[i] = 0.0001f;
                io.MouseDown[i] = false;
            }
        }
    }
    ~modal_input_block_scope_t() {
        if (active) {
            ImGuiIO& io = ImGui::GetIO();
            for (int i = 0; i < 5; ++i) {
                io.MouseDownDuration[i] = saved_mouse_dur[i];
                io.MouseDown[i] = saved_mouse_down[i];
            }
        }
    }
};

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            DisasmState& disasm, float dt) {

    modal_input_block_scope_t input_block_scope;

    const uint64_t frame_t0_ns = now_ns();

    {
        static uint32_t s_render_call_count = 0;
        if (s_render_call_count < 10 || (s_render_call_count & 0x3FF) == 0) {
            diag::log_tagged_fmt("disasm_view", "render_enter call=%u instrs=%zu live_mode=%d selected_row=%d",
                s_render_call_count, disasm.file.instrs.size(),
                disasm.live_mode ? 1 : 0, g_state.selected_row);
        }
        ++s_render_call_count;
    }

    ensure_pdb_event_subscriptions();

    auto& st    = g_state;

    {
        static uint32_t s_last_theme_gen = 0u;
        const uint32_t cur_theme_gen = aida::ui::theme_generation();
        if (cur_theme_gen != s_last_theme_gen) {
            s_last_theme_gen = cur_theme_gen;
            bump_format_generation();
        }
    }

    {
        const uint32_t cur_pid = driver_bridge::attached_pid();
        const uint32_t prev_pid = s_last_attached_pid.load(std::memory_order_acquire);
        const uint64_t cur_img = disasm.file.image_base;
        const uint64_t prev_img = s_last_loaded_image_base.load(std::memory_order_acquire);
        if (cur_pid != prev_pid || cur_img != prev_img) {
            diag::log_tagged_critical_fmt("disasm_view",
                "attach_state_changed cur_pid=%u prev_pid=%u cur_img=0x%llX prev_img=0x%llX",
                cur_pid, prev_pid,
                (unsigned long long)cur_img, (unsigned long long)prev_img);
            s_last_attached_pid.store(cur_pid, std::memory_order_release);
            s_last_loaded_image_base.store(cur_img, std::memory_order_release);
            diag::log_tagged_critical("disasm_view", "pre_on_attach_state_changed");
            on_attach_state_changed();
            diag::log_tagged_critical("disasm_view", "post_on_attach_state_changed");
        }
    }

    instr_cache_bound_size();

    const bool throttled = throttle_active();

    auto sweep_row_keyed_map = [](std::unordered_map<int, aida::ui::hover_state_t>& m,
                                  int lo, int hi) {
        if (m.empty()) return;
        if (m.size() < 256u && (hi - lo) > 0 && static_cast<int>(m.size()) <= (hi - lo) * 2) return;
        auto it = m.begin();
        while (it != m.end()) {
            if (it->first < lo || it->first > hi) it = m.erase(it);
            else ++it;
        }
    };

    auto sweep_row_entrance_map = [](std::unordered_map<int, float>& m,
                                     int lo, int hi) {
        if (m.empty()) return;
        if (m.size() < 256u && (hi - lo) > 0 && static_cast<int>(m.size()) <= (hi - lo) * 2) return;
        auto it = m.begin();
        while (it != m.end()) {
            if (it->first < lo || it->first > hi) it = m.erase(it);
            else ++it;
        }
    };


    if (disasm.live_mode && disasm.live_pending_ready.load(std::memory_order_acquire)) {

        driver_bridge::debug_log("disasm_view: live_pending_ready=TRUE, moving %llu instrs to display\n",
            static_cast<unsigned long long>(disasm.live_pending_instrs.size()));

        uint64_t scroll_addr = 0;
        if (st.selected_row >= 0 && st.selected_row < static_cast<int>(disasm.file.instrs.size()))
            scroll_addr = disasm.file.instrs[st.selected_row].addr;

        disasm.file.instrs = std::move(disasm.live_pending_instrs);
        if (disasm.live_base != 0) {
            disasm.file.image_base = disasm.live_base;
        } else {
            disasm.file.image_base = disasm.live_pending_va;
        }
        disasm.file.text_va    = disasm.live_pending_va;
        disasm.live_pending_ready.store(false, std::memory_order_release);
        disasm.last_swap_was_live = true;


        if (scroll_addr != 0 && !disasm.file.instrs.empty()) {
            int lo = 0, hi = static_cast<int>(disasm.file.instrs.size()) - 1;
            int best = 0;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                if (disasm.file.instrs[mid].addr == scroll_addr) { best = mid; break; }
                if (disasm.file.instrs[mid].addr < scroll_addr) { best = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            bool had_multi_selection = (st.sel_anchor >= 0 && st.sel_extent >= 0
                && st.sel_anchor != st.sel_extent);
            st.selected_row = best;
            if (!had_multi_selection) {
                st.sel_anchor = best;
                st.sel_extent = best;
                st.sel_dragging = false;
                st.sel_anchor_sub = INT_MIN;
                st.sel_extent_sub = INT_MIN;
                st.sel_anchor_px  = -1.f;
                st.sel_extent_px  = -1.f;
            }
        }
    }


    if (disasm.live_mode && !disasm.live_paused) {
        disasm.live_refresh_timer += dt;
        if (disasm.live_refresh_timer >= disasm.live_refresh_interval || disasm.live_needs_refresh) {
            disasm.live_refresh_timer = 0.f;
            disasm.live_needs_refresh = false;

            if (driver_bridge::attached_pid() != disasm.live_pid) {
                driver_bridge::debug_log("disasm_view: pid mismatch (attached=%u live=%u), stopping live\n",
                    driver_bridge::attached_pid(), disasm.live_pid);
                disasm::stop_live(disasm);
            } else if (disasm.live_fail_count.load(std::memory_order_acquire) < 5) {
                static int s_req_log = 0;
                if (s_req_log++ < 20)
                    driver_bridge::debug_log("disasm_view: triggering request_live_decode (fail_count=%d, decoding=%d)\n",
                        disasm.live_fail_count.load(std::memory_order_acquire),
                        disasm.live_decoding.load(std::memory_order_acquire) ? 1 : 0);
                disasm::request_live_decode(disasm);
            }
        }
    }

    auto& file  = disasm.file;
    auto& instrs = file.instrs;
    const float a = alpha;
    const auto& tk = aida::ui::resolved();
    const auto _ta = [a](ImU32 c) -> ImU32 { return aida::ui::with_alpha(c, a); };
    const int n = static_cast<int>(instrs.size());

    if (n == 0) {

        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 wpos = ImGui::GetWindowPos();
        float ox = wpos.x + pos_x;
        float oy = wpos.y + pos_y;

        if (disasm.live_mode || disasm.file.decoding) {
            bool failed = disasm.live_mode
                && disasm.live_decode_failed.load(std::memory_order_acquire)
                && disasm.live_fail_count.load(std::memory_order_acquire) >= 3;

            {
                static int s_spinner_log = 0;
                if (s_spinner_log++ < 10)
                    driver_bridge::debug_log("disasm_view SPINNER: n=%d live_mode=%d decoding=%d failed=%d fail_count=%d pending_ready=%d paused=%d\n",
                        n, disasm.live_mode ? 1 : 0,
                        disasm.live_decoding.load(std::memory_order_acquire) ? 1 : 0,
                        disasm.live_decode_failed.load(std::memory_order_acquire) ? 1 : 0,
                        disasm.live_fail_count.load(std::memory_order_acquire),
                        disasm.live_pending_ready.load() ? 1 : 0, disasm.live_paused ? 1 : 0);
            }

            if (failed) {
                float cx = ox + width * 0.5f;
                float cy = oy + height * 0.5f;
                const char* err_msg = "Failed to read process memory";
                ImVec2 es = ImGui::CalcTextSize(err_msg);
                dl->AddText(ImVec2(cx - es.x * 0.5f, cy - 20.f),
                    aida::ui::with_alpha(tk.error, a), err_msg);

                const char* hint_msg = "Verify driver connection and process attachment";
                ImVec2 hs = ImGui::CalcTextSize(hint_msg);
                dl->AddText(ImVec2(cx - hs.x * 0.5f, cy + 4.f),
                    _ta(tk.text_secondary), hint_msg);

                ImGui::SetCursorScreenPos(ImVec2(cx - 38.f, cy + 30.f));
                if (aida::ui::components::button("Retry", aida::ui::components::button_kind_t::primary,
                                                  aida::ui::components::size_t_::sm)) {
                    disasm.live_fail_count.store(0, std::memory_order_release);
                    disasm.live_decode_failed.store(false, std::memory_order_release);
                    disasm.live_needs_refresh = true;
                }
            } else {
                float panel_w = std::min(420.f, width * 0.6f);
                float panel_h = 180.f;
                float px2 = ox + (width - panel_w) * 0.5f;
                float py2 = oy + (height - panel_h) * 0.5f;
                ImVec2 ga(px2, py2);
                ImVec2 gb(px2 + panel_w, py2 + panel_h);
                aida::ui::blur::render_drop_shadow(dl, ga, gb, 12.f, 4, 0.30f * a);
                aida::ui::blur::render_glass_fill(dl, ga, gb, 12.f, a);
                aida::ui::blur::render_glass_border(dl, ga, gb, 12.f, a);

                const char* msg = disasm.live_mode
                    ? "Loading live disassembly..."
                    : "Decoding instructions...";
                dl->AddText(ImVec2(px2 + 20.f, py2 + 18.f),
                    _ta(tk.text_primary), msg);

                aida::ui::skeleton::render_table_rows(dl,
                    ImVec2(px2 + 20.f, py2 + 50.f),
                    ImVec2(px2 + panel_w - 20.f, py2 + panel_h - 36.f),
                    4, 5, 18.f);

                aida::ui::components::render_progress_bar(ImVec2(px2 + 20.f, py2 + panel_h - 24.f),
                                                          panel_w - 40.f, 4.f, 0.f, true, true);

                if (disasm.live_mode && disasm.live_fail_count.load(std::memory_order_acquire) > 0) {
                    char attempt_buf[48];
                    snprintf(attempt_buf, sizeof(attempt_buf), "Retry %d/5...",
                        disasm.live_fail_count.load(std::memory_order_acquire));
                    dl->AddText(ImVec2(px2 + panel_w - 80.f, py2 + 18.f),
                        aida::ui::with_alpha(tk.warning, a), attempt_buf);
                }

                const std::string& label = disasm.live_mode
                    ? disasm.live_module : disasm.file.filename;
                if (!label.empty()) {
                    ImVec2 ms = ImGui::CalcTextSize(label.c_str());
                    dl->AddText(ImVec2(px2 + (panel_w - ms.x) * 0.5f, py2 + panel_h - 44.f),
                        _ta(tk.text_dim), label.c_str());
                }
            }
        } else {
            aida::ui::empty_state::config_t cfg;
            cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
            cfg.title = "No buffer loaded";
            cfg.body  = "Open a binary file or attach a process to begin disassembly.";
            cfg.hints = { { "Ctrl+O" }, { "Ctrl+P" } };
            aida::ui::empty_state::render(ImVec2(ox, oy), ImVec2(width, height), cfg);
        }
        s_first_load_anim = 0.f;
        s_last_known_n = 0;
        return;
    }

    if (s_last_known_n != n) {
        if (disasm.last_swap_was_live) {
            diag::log_tagged_fmt("disasm_view", "instr_count_changed_live prev=%d new=%d image_base=0x%llX",
                s_last_known_n, n, static_cast<unsigned long long>(disasm.file.image_base));
            s_last_known_n = n;
        } else {
            diag::log_tagged_fmt("disasm_view", "instr_count_changed_static prev=%d new=%d filename=%s image_base=0x%llX",
                s_last_known_n, n, disasm.file.filename.c_str(),
                static_cast<unsigned long long>(disasm.file.image_base));
            s_first_load_anim = 0.f;
            s_row_entrance.clear();
            s_row_hover.clear();
            s_banner_row_hover.clear();
            s_last_known_n = n;
        }
    }
    disasm.last_swap_was_live = false;
    if (s_first_load_anim < 1.f)
        s_first_load_anim += dt * 1.6f;
    if (s_first_load_anim > 1.f) s_first_load_anim = 1.f;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + pos_y;

    const float nav_band_h = 6.f;
    const float line_h = 18.f;

    dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
        aida::ui::with_alpha(disasm_theme::panel_bg(), a));

    {
        float bx0 = ox;
        float by0 = oy;
        float bx1 = ox + width;
        float by1 = oy + nav_band_h;

        dl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1),
            _ta(tk.bg_base));

        if (n > 0) {
            uint64_t range_start = instrs[0].addr;
            uint64_t range_end   = instrs[n - 1].addr + instrs[n - 1].len;
            uint64_t range       = range_end > range_start ? range_end - range_start : 1;

            float band_w = bx1 - bx0 - 2.f;
            float band_x = bx0 + 1.f;

            for (int i = 0; i < n; i += std::max(1, n / static_cast<int>(band_w))) {
                auto& ins = instrs[i];
                float t = static_cast<float>(ins.addr - range_start) / static_cast<float>(range);
                float px = band_x + t * band_w;

                ImU32 c;
                if (ins.is_call)
                    c = aida::ui::with_alpha(tk.accent_u32, a * 0.78f);
                else if (ins.is_branch)
                    c = aida::ui::with_alpha(tk.success, a * 0.7f);
                else if (ins.is_ret)
                    c = aida::ui::with_alpha(tk.error, a * 0.78f);
                else if (ins.is_nop)
                    c = aida::ui::with_alpha(tk.text_dim, a * 0.4f);
                else
                    c = aida::ui::with_alpha(tk.text_address, a * 0.6f);

                dl->AddRectFilled(ImVec2(px, by0 + 1.f),
                                  ImVec2(px + std::max(1.f, band_w / static_cast<float>(n) * 2.f), by1 - 1.f),
                                  c);
            }

            if (st.selected_row >= 0 && st.selected_row < n) {
                float sel_t = static_cast<float>(instrs[st.selected_row].addr - range_start) / static_cast<float>(range);
                float sel_x = band_x + sel_t * band_w;
                float cursor_w = std::max(3.f, band_w / static_cast<float>(n) * 8.f);
                dl->AddRectFilled(ImVec2(sel_x - cursor_w * 0.5f, by0),
                                  ImVec2(sel_x + cursor_w * 0.5f, by1),
                                  aida::ui::with_alpha(tk.text_primary, a * 0.78f));
                dl->AddRectFilled(ImVec2(sel_x - 1.f, by0), ImVec2(sel_x + 1.f, by1),
                                  aida::ui::with_alpha(tk.accent_u32, a));
            }

            if (ImGui::IsMouseHoveringRect(ImVec2(bx0, by0), ImVec2(bx1, by1), false) &&
                ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                float mx = ImGui::GetIO().MousePos.x - band_x;
                float click_t = mx / band_w;
                click_t = std::max(0.f, std::min(1.f, click_t));
                uint64_t target_addr = range_start + static_cast<uint64_t>(click_t * static_cast<float>(range));
                goto_address(target_addr, disasm);
            }
        }

        dl->AddLine(ImVec2(bx0, by1), ImVec2(bx1, by1),
            aida::ui::with_alpha(tk.border_subtle, a));
    }

    float oy_content = oy + nav_band_h;
    float content_height = height - nav_band_h;

    {
        uint64_t fmb_state = static_cast<uint64_t>(
            file_metadata_banner::detail::cache().state.load(std::memory_order_acquire));
        uint64_t img_sig = file.image_base ^ (static_cast<uint64_t>(s_format_gen.load(std::memory_order_acquire)) << 32);
        uint64_t sig = (fmb_state << 1) ^ img_sig;
        uint64_t cur = s_banner_cache_signature.load(std::memory_order_acquire);
        if (sig != cur || s_banner_cache.empty()) {
            rebuild_banner_lines(file);
            s_banner_line_count = static_cast<int>(s_banner_cache.size());
            s_banner_cache_signature.store(sig, std::memory_order_release);
            s_banner_row_hover.clear();
            const int total_b = s_banner_line_count;
            if (st.banner_selected_row >= total_b) st.banner_selected_row = -1;
            if (st.banner_sel_anchor >= total_b)   st.banner_sel_anchor = -1;
            if (st.banner_sel_extent >= total_b)   st.banner_sel_extent = -1;
        }
    }
    const int banner_lines = s_banner_line_count;

    {
        const uint32_t cur_gen_for_layout = s_format_gen.load(std::memory_order_acquire);
        const uint64_t fi_sig = function_index_state_signature();
        const uint64_t first_addr = (n > 0) ? instrs.front().addr : 0;
        const uint64_t last_addr  = (n > 0) ? instrs.back().addr  : 0;
        const bool hard_invalid = !s_layout.ready
            || s_layout.built_n != n
            || s_layout.built_addr_first != first_addr
            || s_layout.built_addr_last  != last_addr
            || s_layout.built_gen != cur_gen_for_layout
            || s_layout.banner_rows != banner_lines;
        const bool soft_invalid = s_layout.built_fi_state_sig != fi_sig;
        bool need_rebuild = hard_invalid;
        if (!hard_invalid && soft_invalid) {
            const uint64_t now = now_ns();
            const bool bulk_active = function_index::static_bulk_in_progress();
            const uint64_t debounce_ns = bulk_active ? 16000000ull : 120000000ull;
            if (s_layout.built_at_ns == 0
                || now - s_layout.built_at_ns >= debounce_ns)
            {
                need_rebuild = true;
            }
        }
        if (need_rebuild) {
            diag::log_tagged_fmt("disasm_view", "rebuild_layout n=%d banner_lines=%d gen=%u fi_sig=0x%llX",
                static_cast<int>(instrs.size()), banner_lines, cur_gen_for_layout,
                static_cast<unsigned long long>(fi_sig));
            rebuild_layout(instrs, banner_lines, cur_gen_for_layout, fi_sig);
            diag::log_tagged_fmt("disasm_view", "rebuild_layout_done total_rows=%d virtual_flat=%d",
                s_layout.total_rows, s_layout.virtual_flat ? 1 : 0);
        }
    }

    ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 60.f, dt);
    float max_scroll = std::max(0.f,
        static_cast<float>(s_layout.total_rows) * line_h - content_height + line_h);
    st.target_scroll_y = std::max(0.f, std::min(st.target_scroll_y, max_scroll));
    st.scroll_y = std::max(0.f, std::min(st.scroll_y, max_scroll));
    if (st.goto_flash_t > 0.f) {
        st.goto_flash_t -= dt * 1.4f;
        if (st.goto_flash_t <= 0.f) {
            st.goto_flash_t = 0.f;
            st.goto_flash_row = -1;
        }
    }


    static bool s_ctx_popup_was_open_prev = false;
    const bool ctx_popup_open_now = ImGui::IsPopupOpen("##disasm_view_ctx")
        || ImGui::IsPopupOpen("##disasm_view_banner_ctx");
    const bool ctx_input_locked = ctx_popup_open_now || s_ctx_popup_was_open_prev;
    s_ctx_popup_was_open_prev = ctx_popup_open_now;

    bool hovered = !ctx_input_locked && ImGui::IsMouseHoveringRect(ImVec2(ox, oy_content), ImVec2(ox + width, oy_content + content_height));
    if (hovered) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            st.target_scroll_y -= wheel * line_h * 3.f;
    }


    ImFont* code_font = aida::ui::fonts::code();
    if (!code_font) code_font = ImGui::GetFont();
    const float code_size = code_font->FontSize > 0.f ? code_font->FontSize : ImGui::GetFontSize();
    const float ch_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, "0").x;
    const float ch_w_safe = ch_w > 0.f ? ch_w : 7.f;

    const float gutter_w = 20.f;
    const uint32_t cur_gen = s_format_gen.load(std::memory_order_acquire);

    dl->AddRectFilled(ImVec2(ox, oy_content), ImVec2(ox + width, oy_content + content_height),
        aida::ui::with_alpha(disasm_theme::panel_bg(), a));
    dl->AddRectFilled(ImVec2(ox, oy_content), ImVec2(ox + gutter_w, oy_content + content_height),
        aida::ui::with_alpha(disasm_theme::gutter_bg(), a));

    int first_vrow = std::max(0, static_cast<int>(st.scroll_y / line_h) - 1);
    int last_vrow  = static_cast<int>((st.scroll_y + content_height) / line_h) + 1;
    int first_row = -1;
    int last_row  = -1;
    if (n > 0 && s_layout.ready) {
        first_row = layout_first_visible_instr(first_vrow, banner_lines);
        last_row  = layout_last_visible_instr(last_vrow);
        if (first_row < 0 || last_row < 0 || first_row > last_row) {
            first_row = 0;
            last_row = -1;
        } else {
            if (first_row >= n) first_row = n - 1;
            if (last_row  >= n) last_row  = n - 1;
        }
    } else if (n > 0) {
        first_row = std::max(0, first_vrow - banner_lines);
        last_row  = std::min(n - 1, last_vrow - banner_lines);
        if (last_row < first_row) {
            first_row = 0;
            last_row = -1;
        }
    }

    if (n > 0 && first_row <= last_row && !throttled) {
        uint64_t now_w = now_ns();
        uint64_t last_w = s_visible_warm_last_ns.load(std::memory_order_acquire);
        const bool live_warm = (driver_bridge::attached_pid() != 0);
        const uint64_t warm_gate_ns = live_warm ? 150000000ull : 16000000ull;
        if (now_w - last_w >= warm_gate_ns) {
            s_visible_warm_last_ns.store(now_w, std::memory_order_release);
            uint64_t lo_va = instrs[first_row].addr;
            uint64_t hi_va = instrs[last_row].addr + static_cast<uint64_t>(instrs[last_row].len);
            xref_index::warm_range(lo_va, hi_va);
            function_index::warm_range(lo_va, hi_va);
            symbol_classifier::warm_range(lo_va, hi_va);
        }
    }

    if (n > 0 && first_row <= last_row) {
        int sweep_lo = first_row - 20;
        int sweep_hi = last_row + 20;
        if (sweep_lo < 0) sweep_lo = 0;
        if (sweep_hi >= n) sweep_hi = n - 1;
        sweep_row_keyed_map(s_row_hover, sweep_lo, sweep_hi);
        sweep_row_entrance_map(s_row_entrance, sweep_lo, sweep_hi);
    }
    if (banner_lines > 0) {
        int b_lo = std::max(0, first_vrow - 20);
        int b_hi = std::min(banner_lines - 1, last_vrow + 20);
        if (b_hi >= b_lo) {
            sweep_row_keyed_map(s_banner_row_hover, b_lo, b_hi);
        } else if (!s_banner_row_hover.empty()) {
            s_banner_row_hover.clear();
        }
    } else if (!s_banner_row_hover.empty()) {
        s_banner_row_hover.clear();
    }

    const float x_seg_addr = ox + gutter_w + 4.f;
    const float content_right = std::max(x_seg_addr + ch_w_safe, ox + width - 24.f);
    const float min_addr_prefix_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f,
        (g_state.addr_format == addr_format_t::rva) ? ".text:+00000000" : ".text:0000000000000000").x;
    float addr_prefix_w = min_addr_prefix_w;
    auto measure_prefix = [&](uint64_t va, const std::string& seg_override) {
        std::string seg = seg_override.empty() ? ida_section_name_for_va(file, va) : seg_override;
        if (seg.empty()) seg = ".text";
        char sample[96];
        if (g_state.addr_format == addr_format_t::rva && file.image_base != 0 && va >= file.image_base) {
            std::snprintf(sample, sizeof(sample), "%s:+%08llX",
                seg.c_str(), static_cast<unsigned long long>(va - file.image_base));
        } else {
            char addr_part[32];
            std::snprintf(addr_part, sizeof(addr_part), "%016llX",
                static_cast<unsigned long long>(va));
            std::snprintf(sample, sizeof(sample), "%s:%s", seg.c_str(), addr_part);
        }
        addr_prefix_w = std::max(addr_prefix_w,
            code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, sample).x);
    };
    if (banner_lines > 0) {
        const uint64_t banner_addr = instrs.empty() ? file.image_base : instrs.front().addr;
        const std::string banner_seg = instrs.empty()
            ? std::string(".text")
            : ida_export::section_for(banner_addr);
        measure_prefix(banner_addr, banner_seg.empty() ? std::string(".text") : banner_seg);
    }
    if (first_row >= 0 && last_row >= first_row) {
        const int sample_hi = std::min(last_row, first_row + 256);
        for (int si = first_row; si <= sample_hi; ++si)
            measure_prefix(instrs[si].addr, std::string());
    }
    const std::string bytes_probe = byte_width_probe(10, "...");
    const float bytes_pixel_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, bytes_probe.c_str()).x;
    const float mnem_chars = 7.f;
    const float operand_chars = 28.f;
    const float default_comment_x = x_seg_addr + static_cast<float>(ida_export::kColComment) * ch_w_safe;
    const float min_tail_w = (mnem_chars + 12.f) * ch_w_safe;
    const float max_prefix_w = std::max(min_addr_prefix_w,
        content_right - x_seg_addr - min_tail_w - (st.show_bytes ? bytes_pixel_w + 3.f * ch_w_safe : 0.f));
    addr_prefix_w = std::max(min_addr_prefix_w, std::min(addr_prefix_w, max_prefix_w));
    const bool draw_bytes_column = st.show_bytes
        && content_right - (x_seg_addr + addr_prefix_w + 3.f * ch_w_safe + bytes_pixel_w) > min_tail_w;
    const float x_bytes = x_seg_addr + addr_prefix_w + 2.f * ch_w_safe;
    const float x_mnem = draw_bytes_column
        ? (x_bytes + bytes_pixel_w + 1.f * ch_w_safe)
        : (x_seg_addr + addr_prefix_w + 2.f * ch_w_safe);
    const float x_operand = x_mnem + mnem_chars * ch_w_safe;
    const float x_comment = std::max(default_comment_x, x_operand + operand_chars * ch_w_safe);
    const float prefix_clip_right = std::max(x_seg_addr + ch_w_safe,
        std::min(x_seg_addr + addr_prefix_w, content_right));

    const int banner_sel_lo = (st.banner_sel_anchor < 0 || st.banner_sel_extent < 0)
        ? -1 : std::min(st.banner_sel_anchor, st.banner_sel_extent);
    const int banner_sel_hi = (st.banner_sel_anchor < 0 || st.banner_sel_extent < 0)
        ? -1 : std::max(st.banner_sel_anchor, st.banner_sel_extent);

    if (banner_lines > 0 && first_vrow < banner_lines) {
        int b_first = std::max(0, first_vrow);
        int b_last = std::min(banner_lines - 1, last_vrow);
        if (b_first <= b_last) {
            const float x_banner_text = x_bytes;
            const float disasm_text_oy = (line_h - code_size) * 0.5f;
            const uint64_t banner_addr = instrs.empty() ? file.image_base : instrs.front().addr;
            const std::string banner_seg = instrs.empty()
                ? std::string(".text")
                : ida_export::section_for(banner_addr);
            const std::string seg_part = banner_seg.empty() ? std::string(".text") : banner_seg;
            char addr_buf[24];
            if (g_state.addr_format == addr_format_t::rva && file.image_base != 0 && banner_addr >= file.image_base) {
                std::snprintf(addr_buf, sizeof(addr_buf), "+%08llX",
                    static_cast<unsigned long long>(banner_addr - file.image_base));
            } else {
                std::snprintf(addr_buf, sizeof(addr_buf), "%016llX",
                    static_cast<unsigned long long>(banner_addr));
            }
            const float banner_colon_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, ":").x;
            const float banner_addr_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, addr_buf).x;
            const float banner_seg_max_w = prefix_clip_right - x_seg_addr - banner_addr_w - banner_colon_w - ch_w_safe;
            const std::string seg_draw = banner_seg_max_w > ch_w_safe
                ? trim_middle_to_width(code_font, code_size, seg_part, banner_seg_max_w)
                : std::string();
            const float seg_w = seg_draw.empty() ? 0.f
                : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, seg_draw.c_str()).x;
            ImVec4 prefix_clip(x_seg_addr, oy_content, prefix_clip_right, oy_content + content_height);

            for (int bi = b_first; bi <= b_last; ++bi) {
                if (bi >= static_cast<int>(s_banner_cache.size())) break;
                float y = oy_content + bi * line_h - st.scroll_y;
                if (y + line_h < oy_content || y > oy_content + content_height) continue;
                const auto& bl = s_banner_cache[bi];

                bool banner_row_hovered = !ctx_input_locked && ImGui::IsMouseHoveringRect(
                    ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f), false);

                auto& bhov_st = s_banner_row_hover[bi];
                float brh = bhov_st.tick(banner_row_hovered, dt, aida::motion::spring::snappy);

                if (brh > 0.002f) {
                    dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                        aida::ui::with_alpha(tk.hover_wash, a * brh));
                }

                bool banner_in_sel = (banner_sel_lo >= 0 && bi >= banner_sel_lo && bi <= banner_sel_hi);
                bool banner_is_cursor = (bi == st.banner_selected_row);

                if (banner_in_sel) {
                    dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                        aida::ui::with_alpha(tk.selection, a));
                }
                if (banner_is_cursor) {
                    dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                        aida::ui::with_alpha(disasm_theme::cursor_line_bg(), a * 0.5f));
                    dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + 3.f, y + line_h - 1.f),
                        aida::ui::with_alpha(tk.accent_u32, a));
                }

                if (!seg_draw.empty()) {
                    dl->AddText(code_font, code_size, ImVec2(x_seg_addr, y + disasm_text_oy),
                        aida::ui::with_alpha(disasm_theme::segment(), a * 0.85f),
                        seg_draw.c_str(), nullptr, 0.f, &prefix_clip);
                    dl->AddText(code_font, code_size, ImVec2(x_seg_addr + seg_w, y + disasm_text_oy),
                        aida::ui::with_alpha(disasm_theme::separator(), a * 0.85f), ":",
                        nullptr, 0.f, &prefix_clip);
                    dl->AddText(code_font, code_size, ImVec2(x_seg_addr + seg_w + banner_colon_w, y + disasm_text_oy),
                        aida::ui::with_alpha(disasm_theme::address(), a * 0.85f), addr_buf,
                        nullptr, 0.f, &prefix_clip);
                } else {
                    dl->AddText(code_font, code_size, ImVec2(x_seg_addr, y + disasm_text_oy),
                        aida::ui::with_alpha(disasm_theme::address(), a * 0.85f), addr_buf,
                        nullptr, 0.f, &prefix_clip);
                }

                if (!bl.text.empty()) {
                    ImU32 col = aida::ui::with_alpha(bl.color, a);
                    ImVec4 text_clip(x_banner_text, oy_content, content_right, oy_content + content_height);
                    dl->AddText(code_font, code_size, ImVec2(x_banner_text, y + disasm_text_oy),
                        col, bl.text.c_str(), nullptr, 0.f, &text_clip);
                }

                if (banner_row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                    if (ImGui::GetIO().KeyShift) {
                        if (st.banner_sel_anchor < 0) st.banner_sel_anchor = bi;
                        st.banner_sel_extent = bi;
                        st.banner_selected_row = bi;
                        st.banner_sel_dragging = false;
                    } else {
                        st.banner_sel_anchor = bi;
                        st.banner_sel_extent = bi;
                        st.banner_selected_row = bi;
                        st.banner_sel_dragging = true;
                    }
                    st.sel_anchor = -1;
                    st.sel_extent = -1;
                    st.selected_row = -1;
                    st.sel_dragging = false;
                    st.sel_anchor_sub = INT_MIN;
                    st.sel_extent_sub = INT_MIN;
                    st.sel_anchor_px  = -1.f;
                    st.sel_extent_px  = -1.f;
                }

                if (banner_row_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    if (banner_addr != 0) {
                        goto_address(banner_addr, disasm);
                    }
                }

                if (banner_row_hovered && st.banner_sel_dragging
                    && ImGui::IsMouseDown(ImGuiMouseButton_Left)
                    && st.banner_sel_extent != bi)
                {
                    st.banner_sel_extent = bi;
                    st.banner_selected_row = bi;
                }

                if (banner_row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                    st.banner_ctx_row = bi;
                    if (bi < banner_sel_lo || bi > banner_sel_hi) {
                        st.banner_sel_anchor = bi;
                        st.banner_sel_extent = bi;
                        st.banner_selected_row = bi;
                    }
                    st.banner_popup_anchor = st.banner_sel_anchor;
                    st.banner_popup_extent = st.banner_sel_extent;
                    st.sel_anchor = -1;
                    st.sel_extent = -1;
                    st.selected_row = -1;
                    st.sel_dragging = false;
                    st.sel_anchor_sub = INT_MIN;
                    st.sel_extent_sub = INT_MIN;
                    st.sel_anchor_px  = -1.f;
                    st.sel_extent_px  = -1.f;
                    ImGui::OpenPopup("##disasm_view_banner_ctx");
                }
            }
        }
    }

    if (st.banner_sel_dragging && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
        st.banner_sel_dragging = false;
    }

    if (disasm.live_mode && n > 0) {
        int mid_row = (first_row + last_row) / 2;
        if (mid_row >= 0 && mid_row < n)
            disasm.live_view_addr = instrs[mid_row].addr;
    }

    auto& vc = var_cache_slot();
    vc.func_start = 0;
    vc.resolved = false;

    struct sec_resolver_t {
        bool                                   resolved = false;
        uint64_t                               module_base = 0;
        uint32_t                               module_size = 0;
        std::vector<pe_parser::section_info_t> sections;
        std::string                            fallback;
    };
    sec_resolver_t sec_resolver;

    auto draw_addr_prefix_cached = [&](float yy, instr_cache_entry_t* cache_ptr,
                                       uint64_t va, const std::string& seg_override,
                                       float row_alpha, float yoff)
    {
        const std::string* seg_part_ptr = nullptr;
        const std::string* addr_part_ptr = nullptr;
        float seg_part_w = 0.f;
        std::string fallback_seg;
        std::string fallback_addr;
        const bool can_cache = (cache_ptr != nullptr) && (sec_resolver.module_base != 0);

        if (can_cache && cache_ptr->seg_addr_valid) {
            seg_part_ptr = &cache_ptr->seg_part_str;
            addr_part_ptr = &cache_ptr->addr_part_str;
            seg_part_w = cache_ptr->seg_part_width;
        } else {
            std::string seg_addr = format_segment_address(file, va, seg_override);
            size_t colon = seg_addr.find(':');
            if (colon != std::string::npos) {
                fallback_seg = seg_addr.substr(0, colon);
                fallback_addr = seg_addr.substr(colon + 1);
            } else {
                fallback_addr = seg_addr;
            }
            seg_part_w = fallback_seg.empty() ? 0.f
                : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, fallback_seg.c_str()).x;
            if (can_cache) {
                cache_ptr->seg_addr_str = std::move(seg_addr);
                cache_ptr->seg_part_str = fallback_seg;
                cache_ptr->addr_part_str = fallback_addr;
                cache_ptr->seg_part_width = seg_part_w;
                cache_ptr->seg_addr_valid = true;
                seg_part_ptr = &cache_ptr->seg_part_str;
                addr_part_ptr = &cache_ptr->addr_part_str;
            } else {
                seg_part_ptr = &fallback_seg;
                addr_part_ptr = &fallback_addr;
            }
        }

        const std::string& seg_part = *seg_part_ptr;
        const std::string& addr_part = *addr_part_ptr;
        const float addr_text_oy = (line_h - code_size) * 0.5f;
        const float colon_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, ":").x;
        const float addr_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, addr_part.c_str()).x;
        std::string seg_draw = seg_part;
        float seg_draw_w = seg_part_w;
        if (!seg_draw.empty()) {
            const float seg_max_w = prefix_clip_right - x_seg_addr - addr_w - colon_w - ch_w_safe;
            if (seg_max_w <= ch_w_safe) {
                seg_draw.clear();
                seg_draw_w = 0.f;
            } else if (seg_draw_w > seg_max_w) {
                seg_draw = trim_middle_to_width(code_font, code_size, seg_draw, seg_max_w);
                seg_draw_w = seg_draw.empty() ? 0.f
                    : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, seg_draw.c_str()).x;
            }
        }
        ImVec4 prefix_clip(x_seg_addr, oy_content, prefix_clip_right, oy_content + content_height);
        ImVec2 sp(x_seg_addr, yy + addr_text_oy - yoff);
        if (!seg_draw.empty()) {
            dl->AddText(code_font, code_size, sp,
                aida::ui::with_alpha(disasm_theme::segment(), row_alpha), seg_draw.c_str(),
                nullptr, 0.f, &prefix_clip);
            ImVec2 cp(x_seg_addr + seg_draw_w, yy + addr_text_oy - yoff);
            dl->AddText(code_font, code_size, cp,
                aida::ui::with_alpha(disasm_theme::separator(), row_alpha), ":",
                nullptr, 0.f, &prefix_clip);
            ImVec2 ap(x_seg_addr + seg_draw_w + colon_w, yy + addr_text_oy - yoff);
            dl->AddText(code_font, code_size, ap,
                aida::ui::with_alpha(disasm_theme::address(), row_alpha), addr_part.c_str(),
                nullptr, 0.f, &prefix_clip);
        } else {
            dl->AddText(code_font, code_size, sp,
                aida::ui::with_alpha(disasm_theme::address(), row_alpha), addr_part.c_str(),
                nullptr, 0.f, &prefix_clip);
        }
    };

    auto draw_addr_prefix = [&](float yy, uint64_t va, const std::string& seg_override,
                                float row_alpha, float yoff)
    {
        draw_addr_prefix_cached(yy, nullptr, va, seg_override, row_alpha, yoff);
    };

    const float disasm_text_oy = (line_h - code_size) * 0.5f;
    auto draw_text_at = [&](float xx, float yy, ImU32 col, const char* str, float yoff) {
        if (!str || !*str || xx >= content_right) return;
        ImVec4 clip(ox, oy_content, content_right, oy_content + content_height);
        dl->AddText(code_font, code_size, ImVec2(xx, yy + disasm_text_oy - yoff), col,
            str, nullptr, 0.f, &clip);
    };

    auto fill_row_bg = [&](float yy, ImU32 col) {
        dl->AddRectFilled(ImVec2(ox, yy), ImVec2(ox + width, yy + line_h - 1.f), col);
    };

    auto fill_row_bg_range = [&](float yy, float x0_abs, float x1_abs, ImU32 col) {
        if (x1_abs < x0_abs) {
            float t = x0_abs;
            x0_abs = x1_abs;
            x1_abs = t;
        }
        float lo = x0_abs < ox ? ox : x0_abs;
        float hi = x1_abs > ox + width ? ox + width : x1_abs;
        if (hi <= lo) return;
        dl->AddRectFilled(ImVec2(lo, yy), ImVec2(hi, yy + line_h - 1.f), col);
    };

    const bool s_full_line_select_mode = editor_config::disasm_full_line_select;

    auto mouse_x_abs_clamped = [&]() -> float {
        float mx = ImGui::GetIO().MousePos.x;
        if (mx < ox) mx = ox;
        if (mx > ox + width) mx = ox + width;
        return mx;
    };

    auto fill_subrow_selection = [&](float yy, int i_row, int sub, ImU32 sel_col) {
        if (st.sel_anchor < 0 || st.sel_extent < 0) return;
        const int lo_row = std::min(st.sel_anchor, st.sel_extent);
        const int hi_row = std::max(st.sel_anchor, st.sel_extent);
        if (i_row < lo_row || i_row > hi_row) return;

        const bool char_active = !s_full_line_select_mode
            && st.sel_anchor_px >= 0.f && st.sel_extent_px >= 0.f
            && st.sel_anchor_sub != INT_MIN && st.sel_extent_sub != INT_MIN;

        if (!char_active) {
            fill_row_bg(yy, sel_col);
            return;
        }

        const int anchor_row = st.sel_anchor;
        const int extent_row = st.sel_extent;
        const int anchor_sub = st.sel_anchor_sub;
        const int extent_sub = st.sel_extent_sub;
        const float anchor_x = st.sel_anchor_px;
        const float extent_x = st.sel_extent_px;

        int lead_row, tail_row, lead_sub, tail_sub;
        float lead_x, tail_x;
        if (anchor_row < extent_row
            || (anchor_row == extent_row && anchor_sub < extent_sub)
            || (anchor_row == extent_row && anchor_sub == extent_sub && anchor_x <= extent_x))
        {
            lead_row = anchor_row;
            lead_sub = anchor_sub;
            lead_x   = anchor_x;
            tail_row = extent_row;
            tail_sub = extent_sub;
            tail_x   = extent_x;
        } else {
            lead_row = extent_row;
            lead_sub = extent_sub;
            lead_x   = extent_x;
            tail_row = anchor_row;
            tail_sub = anchor_sub;
            tail_x   = anchor_x;
        }

        const bool same_row = (lead_row == tail_row);
        const bool same_sub = same_row && (lead_sub == tail_sub);

        if (same_sub) {
            if (i_row == lead_row && sub == lead_sub) {
                fill_row_bg_range(yy, lead_x, tail_x, sel_col);
            }
            return;
        }

        const bool is_lead_row_sub = (i_row == lead_row && sub == lead_sub);
        const bool is_tail_row_sub = (i_row == tail_row && sub == tail_sub);

        if (is_lead_row_sub) {
            fill_row_bg_range(yy, lead_x, ox + width, sel_col);
            return;
        }
        if (is_tail_row_sub) {
            fill_row_bg_range(yy, ox, tail_x, sel_col);
            return;
        }

        if (i_row > lead_row && i_row < tail_row) {
            fill_row_bg(yy, sel_col);
            return;
        }

        if (i_row == lead_row && sub > lead_sub) {
            fill_row_bg(yy, sel_col);
            return;
        }

        if (i_row == tail_row && sub < tail_sub) {
            fill_row_bg(yy, sel_col);
            return;
        }
    };

    auto reset_char_selection = [&]() {
        st.sel_anchor_px = -1.f;
        st.sel_extent_px = -1.f;
        st.sel_anchor_sub = INT_MIN;
        st.sel_extent_sub = INT_MIN;
    };

    auto begin_char_selection = [&](int sub, bool shift_extend) {
        if (s_full_line_select_mode) {
            reset_char_selection();
            return;
        }
        float mx = mouse_x_abs_clamped() - ox;
        if (shift_extend) {
            if (st.sel_anchor_sub == INT_MIN || st.sel_anchor_px < 0.f) {
                st.sel_anchor_sub = sub;
                st.sel_anchor_px  = mx;
            }
            st.sel_extent_sub = sub;
            st.sel_extent_px  = mx;
        } else {
            st.sel_anchor_sub = sub;
            st.sel_extent_sub = sub;
            st.sel_anchor_px  = mx;
            st.sel_extent_px  = mx;
        }
    };

    auto update_char_drag = [&](int sub) {
        if (s_full_line_select_mode) return;
        float mx = mouse_x_abs_clamped() - ox;
        st.sel_extent_sub = sub;
        st.sel_extent_px  = mx;
    };

    auto log_disasm_sel_click = [&](int i_row, int sub, uint64_t addr) {
        float mx = mouse_x_abs_clamped() - ox;
        driver_bridge::debug_log(
            "[disasm_sel] click row=%d sub=%d col_px=%.1f addr=0x%llX full_line=%d\n",
            i_row, sub, mx,
            static_cast<unsigned long long>(addr),
            s_full_line_select_mode ? 1 : 0);
    };

    auto sec_resolver_init = [&]() {
        if (sec_resolver.resolved) return;
        sec_resolver.resolved = true;
        sec_resolver.fallback = ".text";
        if (file.image_base == 0 || n == 0) return;

        uint64_t probe_va = instrs[std::max(0, std::min(n - 1, first_row))].addr;
        if (auto cached = xref_index::detail::lookup_cached_module(probe_va)) {
            if (cached->base != 0 && !cached->sections.empty()) {
                sec_resolver.module_base = cached->base;
                sec_resolver.module_size = cached->size;
                sec_resolver.sections = cached->sections;
                return;
            }
        }
    };

    auto get_visible_section = [&](uint64_t va) -> std::string {
        if (!sec_resolver.resolved) sec_resolver_init();
        if (sec_resolver.module_base == 0) return sec_resolver.fallback;
        if (va < sec_resolver.module_base) return sec_resolver.fallback;
        uint32_t rva = static_cast<uint32_t>(va - sec_resolver.module_base);
        for (const auto& s : sec_resolver.sections) {
            if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
                return s.name;
        }
        return sec_resolver.fallback;
    };

    const int sel_lo = (st.sel_anchor < 0 || st.sel_extent < 0)
        ? -1 : std::min(st.sel_anchor, st.sel_extent);
    const int sel_hi = (st.sel_anchor < 0 || st.sel_extent < 0)
        ? -1 : std::max(st.sel_anchor, st.sel_extent);

    uint64_t align_skip_end = 0;
    const bool virtual_flat_layout = layout_uses_virtual_flat();
    for (int i = first_row; i <= last_row; i++) {
        if (s_layout.ready && layout_instr_hidden(i)) {
            continue;
        }
        const float instr_row_f = static_cast<float>(layout_instr_start_row(i, banner_lines));
        float y = oy_content + instr_row_f * line_h - st.scroll_y;
        const AsmInstr& ins = instrs[i];

        if (align_skip_end != 0 && ins.addr < align_skip_end) {
            continue;
        }
        if (align_skip_end != 0 && ins.addr >= align_skip_end) {
            align_skip_end = 0;
        }

        if (!throttled && !virtual_flat_layout) {
            function_index::detail::align_run_t arun;
            if (function_index::is_align_row_start(ins.addr)
                && function_index::align_run_at(ins.addr, &arun)) {
                float row_entrance_a = 1.f;
                if (s_first_load_anim < 1.f) {
                    float& re_a = s_row_entrance[i];
                    float per_item_a = 0.012f;
                    float local_a = s_first_load_anim - (float)(i - first_row) * per_item_a;
                    if (local_a < 0.f) local_a = 0.f;
                    re_a = aida::motion::ease::out_back(local_a);
                    row_entrance_a = re_a;
                }
                float row_y_off_a = (1.f - row_entrance_a) * 6.f;
                float row_a_inner_a = a * row_entrance_a;
                std::string sec_name_a = get_visible_section(ins.addr);

                float y_label = y;
                float y_directive = y + line_h;

                auto paint_align_row_bg = [&](float yy) {
                    bool al_in_sel = (sel_lo >= 0 && i >= sel_lo && i <= sel_hi);
                    bool al_is_cursor = (i == st.selected_row);
                    if (al_in_sel) {
                        fill_row_bg(yy, aida::ui::with_alpha(tk.selection, row_a_inner_a));
                    }
                    if (al_is_cursor) {
                        fill_row_bg(yy, aida::ui::with_alpha(disasm_theme::cursor_line_bg(), row_a_inner_a * 0.5f));
                        dl->AddRectFilled(ImVec2(ox, yy), ImVec2(ox + 3.f, yy + line_h - 1.f),
                            aida::ui::with_alpha(tk.accent_u32, row_a_inner_a));
                    }
                    bool al_hovered = !ctx_input_locked && ImGui::IsMouseHoveringRect(
                        ImVec2(ox, yy), ImVec2(ox + width, yy + line_h - 1.f), false);
                    if (al_hovered) {
                        fill_row_bg(yy, aida::ui::with_alpha(tk.hover_wash, row_a_inner_a * 0.85f));
                    }
                };
                paint_align_row_bg(y_label);
                paint_align_row_bg(y_directive);

                draw_addr_prefix(y_label, arun.addr, sec_name_a,
                    row_a_inner_a * 0.95f, row_y_off_a);
                char label_buf[40];
                std::snprintf(label_buf, sizeof(label_buf), "algn_%llX:",
                    static_cast<unsigned long long>(arun.addr));
                ImU32 label_col = aida::ui::with_alpha(disasm_theme::loc_label(),
                    row_a_inner_a);
                draw_text_at(x_mnem, y_label, label_col, label_buf, row_y_off_a);

                draw_addr_prefix(y_directive, arun.addr, sec_name_a,
                    row_a_inner_a * 0.95f, row_y_off_a);

                if (draw_bytes_column) {
                    uint64_t run_len = (arun.end > arun.addr) ? (arun.end - arun.addr) : 0;
                    const int max_pairs = 10;
                    std::string bytes_buf = format_repeated_byte_preview(
                        arun.fill_byte, run_len, max_pairs, "...");
                    ImU32 bytes_col = aida::ui::with_alpha(disasm_theme::bytes(),
                        row_a_inner_a);
                    draw_text_at(x_bytes, y_directive, bytes_col, bytes_buf.c_str(), row_y_off_a);
                }

                char align_buf[40];
                std::snprintf(align_buf, sizeof(align_buf), "align %s",
                    ida_export::format_unsigned_hex(static_cast<uint64_t>(arun.alignment)).c_str());
                ImU32 align_col = aida::ui::with_alpha(disasm_theme::keyword(),
                    row_a_inner_a);
                draw_text_at(x_mnem, y_directive, align_col, align_buf, row_y_off_a);

                auto align_hit_test = [&](float yy) {
                    bool inj_hovered = !ctx_input_locked && ImGui::IsMouseHoveringRect(
                        ImVec2(ox, yy), ImVec2(ox + width, yy + line_h - 1.f), false);
                    if (!inj_hovered) return;
                    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                        if (ImGui::GetIO().KeyShift) {
                            if (st.sel_anchor < 0) st.sel_anchor = i;
                            st.sel_extent = i;
                        } else {
                            st.sel_anchor = i;
                            st.sel_extent = i;
                        }
                        st.selected_row = i;
                        st.sel_dragging = false;
                        reset_char_selection();
                        st.banner_sel_anchor = -1;
                        st.banner_sel_extent = -1;
                        st.banner_selected_row = -1;
                        st.banner_sel_dragging = false;
                    }
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        goto_address(arun.addr, disasm);
                    }
                    if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                        st.ctx_row = i;
                        if (i < sel_lo || i > sel_hi) {
                            st.sel_anchor = i;
                            st.sel_extent = i;
                            st.selected_row = i;
                            reset_char_selection();
                        }
                        st.popup_sel_anchor = st.sel_anchor;
                        st.popup_sel_extent = st.sel_extent;
                        st.popup_sel_row    = st.selected_row;
                        st.banner_sel_anchor = -1;
                        st.banner_sel_extent = -1;
                        st.banner_selected_row = -1;
                        st.banner_sel_dragging = false;
                        ImGui::OpenPopup("##disasm_view_ctx");
                    }
                };
                align_hit_test(y_label);
                align_hit_test(y_directive);

                align_skip_end = arun.end;
                continue;
            }
        }

        float row_entrance = 1.f;
        if (s_first_load_anim < 1.f) {
            float& re = s_row_entrance[i];
            float per_item = 0.012f;
            float local = s_first_load_anim - (float)(i - first_row) * per_item;
            if (local < 0.f) local = 0.f;
            re = aida::motion::ease::out_back(local);
            row_entrance = re;
        }
        float row_y_off = (1.f - row_entrance) * 6.f;
        float row_a_inner = a * row_entrance;

        bool row_hovered = !ctx_input_locked && ImGui::IsMouseHoveringRect(
            ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f), false);

        auto& hov_st = s_row_hover[i];
        float rh = hov_st.tick(row_hovered, dt, aida::motion::spring::snappy);

        if (rh > 0.002f)
            fill_row_bg(y, aida::ui::with_alpha(tk.hover_wash, row_a_inner * rh));

        bool in_sel    = (sel_lo >= 0 && i >= sel_lo && i <= sel_hi);
        bool is_cursor = (i == st.selected_row);

        const int before_extent_total = layout_before_extent_for(i);
        const int main_subrow_id = before_extent_total;

        if (in_sel) {
            fill_subrow_selection(y, i, main_subrow_id,
                aida::ui::with_alpha(tk.selection, row_a_inner));
        }
        if (i == st.goto_flash_row && st.goto_flash_t > 0.001f) {
            float ft = st.goto_flash_t;
            ImU32 flash_fill = aida::ui::with_alpha(tk.accent_glow, row_a_inner * ft * 0.85f);
            fill_row_bg(y, flash_fill);
            ImU32 flash_border = aida::ui::with_alpha(tk.accent_u32, row_a_inner * ft);
            dl->AddRect(ImVec2(ox + 2.f, y + 1.f),
                ImVec2(ox + width - 2.f, y + line_h - 2.f),
                flash_border, 3.f, 0, 1.8f);
        }
        if (is_cursor) {
            const bool main_char_cursor = !s_full_line_select_mode
                && st.sel_anchor_sub != INT_MIN
                && st.sel_extent_sub != INT_MIN;
            const bool main_sub_matches = main_char_cursor
                ? (main_subrow_id == st.sel_anchor_sub
                   || main_subrow_id == st.sel_extent_sub)
                : true;
            if (main_sub_matches) {
                fill_row_bg(y, aida::ui::with_alpha(disasm_theme::cursor_line_bg(), row_a_inner * 0.5f));
                dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + 3.f, y + line_h - 1.f),
                    aida::ui::with_alpha(tk.accent_u32, row_a_inner));
            }
        }

        for (auto& bm : st.bookmarks) {
            if (bm.addr == ins.addr) {
                dl->AddRectFilled(ImVec2(ox + 4.f, y), ImVec2(ox + 7.f, y + line_h - 1.f),
                    aida::ui::with_alpha(tk.warning, row_a_inner));
                break;
            }
        }

        std::string sec_name = throttled ? std::string(".text") : get_visible_section(ins.addr);

        instr_cache_entry_t& cache = instr_cache_slot(ins.addr, cur_gen, ins.raw, ins.len);

        const std::vector<function_index::injection_row_t>* before_rows_ptr = nullptr;
        const std::vector<function_index::injection_row_t>* after_rows_ptr = nullptr;
        const std::string* inline_label_ptr = nullptr;
        static const std::vector<function_index::injection_row_t> s_empty_inj;
        static const std::string s_empty_str;
        if (!throttled && !virtual_flat_layout) {
            if (!cache.inj_valid) {
                cache.before_rows = function_index::rows_before(ins.addr);
                cache.after_rows = function_index::rows_after(ins.addr);
                cache.inline_label = function_index::inline_label_at(ins.addr);
                if (cache.inline_label.empty()) {
                    std::vector<xref_index::annotation_t> probe = xref_index::query_to(ins.addr, 1);
                    bool jump_xref = false;
                    for (const auto& a : probe) {
                        if (a.kind == xref_index::kind_t::code && a.edge == xref_index::edge_t::jump) {
                            jump_xref = true;
                            break;
                        }
                    }
                    if (jump_xref && function_index::is_inside_known_function(ins.addr)) {
                        std::string loc = function_index::loc_label_for(ins.addr);
                        if (!loc.empty()) cache.inline_label = loc + ":";
                    }
                }
                cache.inj_valid = true;
            }
            before_rows_ptr = &cache.before_rows;
            after_rows_ptr = &cache.after_rows;
            inline_label_ptr = &cache.inline_label;
        } else {
            before_rows_ptr = &s_empty_inj;
            after_rows_ptr = &s_empty_inj;
            inline_label_ptr = &s_empty_str;
        }

        if (!before_rows_ptr->empty()) {
            uint64_t fstart = ins.addr;
            for (const auto& br : *before_rows_ptr) {
                if (br.kind == function_index::injection_t::var_decl) {
                    fstart = br.addr;
                    break;
                }
            }
            prime_var_cache(fstart);
        } else if (!throttled) {
            uint64_t enclosing = function_index::detail::lookup_function_start_for_addr(ins.addr);
            if (enclosing != 0) prime_var_cache(enclosing);
        }

        const std::vector<xref_index::annotation_t>* xrefs_at_func_ptr = nullptr;
        bool xrefs_more = false;
        bool is_proc_start = false;
        static const std::vector<xref_index::annotation_t> s_empty_xref;
        if (!throttled) {
            for (const auto& br : *before_rows_ptr) {
                if (br.kind == function_index::injection_t::proc_header) {
                    is_proc_start = true;
                    if (!cache.xref_valid) {
                        cache.xref_at_func = xref_index::query_to(ins.addr, 6);
                        cache.xref_more_at_func = xref_index::has_more(ins.addr, 6);
                        cache.xref_valid = true;
                    }
                    xrefs_at_func_ptr = &cache.xref_at_func;
                    xrefs_more = cache.xref_more_at_func;
                    break;
                }
            }
        }
        if (!xrefs_at_func_ptr) xrefs_at_func_ptr = &s_empty_xref;
        const std::vector<xref_index::annotation_t>& xrefs_at_func = *xrefs_at_func_ptr;

        auto draw_injection_row = [&](float yy, const function_index::injection_row_t& r,
                                      const std::string& addr_seg)
        {
            draw_addr_prefix_cached(yy, &cache, ins.addr, addr_seg, row_a_inner * 0.7f, row_y_off);
            if (r.kind == function_index::injection_t::spacer_line) return;
            if (r.text.empty()) return;

            if (r.kind == function_index::injection_t::proc_header
                || r.kind == function_index::injection_t::proc_endp)
            {
                ImU32 name_col = disasm_theme::sub_label();
                if (!throttled) {
                    symbol_classifier::kind_t k = symbol_classifier::classify(r.addr);
                    if (k != symbol_classifier::kind_t::unknown) {
                        name_col = disasm_theme::color_for_kind(static_cast<int>(k));
                    }
                }
                size_t name_end = 0;
                const std::string& t = r.text;
                while (name_end < t.size() && t[name_end] != ' ' && t[name_end] != '\t') ++name_end;
                std::string name_part = t.substr(0, name_end);
                std::string tail_part = t.substr(name_end);
                ImU32 name_alpha = aida::ui::with_alpha(name_col, row_a_inner);
                draw_text_at(x_mnem, yy, name_alpha, name_part.c_str(), row_y_off);
                if (!tail_part.empty()) {
                    float name_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, name_part.c_str()).x;
                    ImU32 tail_alpha = aida::ui::with_alpha(disasm_theme::keyword(), row_a_inner);
                    draw_text_at(x_mnem + name_w, yy, tail_alpha, tail_part.c_str(), row_y_off);
                }
                return;
            }

            if (r.kind == function_index::injection_t::function_banner && !throttled) {
                bool is_entry = false;
                bool is_user_main = false;
                std::string user_main_kind;
                {
                    auto& fc = function_index::detail::cache();
                    std::shared_lock<std::shared_mutex> lk(fc.mutex);
                    auto fit = fc.by_start.find(r.addr);
                    if (fit != fc.by_start.end()) {
                        is_entry = fit->second.is_entry_stub;
                        is_user_main = fit->second.is_user_main;
                        user_main_kind = fit->second.user_main_kind;
                    }
                }
                if (is_entry) {
                    std::string text = "; =============== S U B R O U T I N E (start) =============================";
                    ImU32 text_col = aida::ui::with_alpha(disasm_theme::banner(), row_a_inner);
                    draw_text_at(x_mnem, yy, text_col, text.c_str(), row_y_off);
                    return;
                }
                if (is_user_main) {
                    std::string label = !user_main_kind.empty() ? user_main_kind : std::string("main");
                    std::string text = "; =============== S U B R O U T I N E (" + label + ") ============================";
                    ImU32 text_col = aida::ui::with_alpha(disasm_theme::banner(), row_a_inner);
                    draw_text_at(x_mnem, yy, text_col, text.c_str(), row_y_off);
                    return;
                }
            }

            ImU32 text_col;
            switch (r.kind) {
                case function_index::injection_t::function_banner:
                case function_index::injection_t::endp_separator:
                    text_col = aida::ui::with_alpha(disasm_theme::banner(), row_a_inner);
                    break;
                case function_index::injection_t::attributes_line:
                case function_index::injection_t::prototype_line:
                    text_col = aida::ui::with_alpha(disasm_theme::comment(), row_a_inner);
                    break;
                case function_index::injection_t::var_decl:
                    text_col = aida::ui::with_alpha(disasm_theme::var_decl(), row_a_inner);
                    break;
                case function_index::injection_t::label_line:
                    text_col = aida::ui::with_alpha(disasm_theme::loc_label(), row_a_inner);
                    break;
                case function_index::injection_t::proc_header:
                case function_index::injection_t::proc_endp:
                case function_index::injection_t::spacer_line:
                    return;
            }
            draw_text_at(x_mnem, yy, text_col, r.text.c_str(), row_y_off);
        };

        auto paint_injection_row_bg = [&](float yy, int sub_id) {
            bool injr_in_sel = (sel_lo >= 0 && i >= sel_lo && i <= sel_hi);
            bool injr_is_cursor = (i == st.selected_row);
            if (injr_in_sel) {
                fill_subrow_selection(yy, i, sub_id,
                    aida::ui::with_alpha(tk.selection, row_a_inner));
            }
            if (injr_is_cursor) {
                const bool char_cursor = !s_full_line_select_mode
                    && st.sel_anchor_sub != INT_MIN
                    && st.sel_extent_sub != INT_MIN;
                const bool sub_matches_cursor = char_cursor
                    ? (sub_id == st.sel_anchor_sub || sub_id == st.sel_extent_sub)
                    : true;
                if (sub_matches_cursor) {
                    fill_row_bg(yy, aida::ui::with_alpha(disasm_theme::cursor_line_bg(), row_a_inner * 0.5f));
                    dl->AddRectFilled(ImVec2(ox, yy), ImVec2(ox + 3.f, yy + line_h - 1.f),
                        aida::ui::with_alpha(tk.accent_u32, row_a_inner));
                }
            }
            bool injr_hovered = !ctx_input_locked && ImGui::IsMouseHoveringRect(
                ImVec2(ox, yy), ImVec2(ox + width, yy + line_h - 1.f), false);
            if (injr_hovered) {
                fill_row_bg(yy, aida::ui::with_alpha(tk.hover_wash, row_a_inner * 0.85f));
            }
        };

        auto handle_injection_row_input = [&](float yy, uint64_t row_addr, int sub_id) {
            bool inj_hovered = !ctx_input_locked && ImGui::IsMouseHoveringRect(
                ImVec2(ox, yy), ImVec2(ox + width, yy + line_h - 1.f), false);
            if (!inj_hovered) return;
            if (st.sel_dragging
                && ImGui::IsMouseDown(ImGuiMouseButton_Left)
                && !ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            {
                if (st.sel_extent != i) {
                    st.sel_extent = i;
                    st.selected_row = i;
                }
                update_char_drag(sub_id);
                return;
            }
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                const bool shift_held = ImGui::GetIO().KeyShift;
                if (shift_held) {
                    if (st.sel_anchor < 0) st.sel_anchor = i;
                    st.sel_extent = i;
                    st.selected_row = i;
                    st.sel_dragging = false;
                    begin_char_selection(sub_id, true);
                } else {
                    st.sel_anchor = i;
                    st.sel_extent = i;
                    st.selected_row = i;
                    st.sel_dragging = false;
                    begin_char_selection(sub_id, false);
                }
                log_disasm_sel_click(i, sub_id, row_addr);
                st.banner_sel_anchor = -1;
                st.banner_sel_extent = -1;
                st.banner_selected_row = -1;
                st.banner_sel_dragging = false;
            }
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                if (row_addr != 0) {
                    goto_address(row_addr, disasm);
                }
            }
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                st.ctx_row = i;
                if (i < sel_lo || i > sel_hi) {
                    st.sel_anchor = i;
                    st.sel_extent = i;
                    st.selected_row = i;
                    reset_char_selection();
                    begin_char_selection(sub_id, false);
                }
                st.popup_sel_anchor = st.sel_anchor;
                st.popup_sel_extent = st.sel_extent;
                st.popup_sel_row    = st.selected_row;
                st.banner_sel_anchor = -1;
                st.banner_sel_extent = -1;
                st.banner_selected_row = -1;
                st.banner_sel_dragging = false;
                ImGui::OpenPopup("##disasm_view_ctx");
            }
        };

        const auto& before_rows_ref = *before_rows_ptr;
        const int before_row_cap = layout_before_row_count_for(
            i, static_cast<int>(before_rows_ref.size()));
        int slot_idx = 0;

        auto slot_y = [&](int slot) -> float {
            return y - static_cast<float>(before_extent_total - slot) * line_h;
        };

        const size_t before_iter_n = std::min(before_rows_ref.size(), static_cast<size_t>(before_row_cap));
        for (size_t bi = 0; bi < before_iter_n; ++bi) {
            const int this_slot = slot_idx++;
            float yy = slot_y(this_slot);
            const auto& br = before_rows_ref[bi];
            bool visible = (yy + line_h >= oy_content) && (yy <= oy_content + content_height);
            if (visible) {
                paint_injection_row_bg(yy, this_slot);
                if (br.kind == function_index::injection_t::spacer_line) {
                    draw_addr_prefix_cached(yy, &cache, ins.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                } else {
                    draw_injection_row(yy, br, sec_name);
                }
                if (br.kind == function_index::injection_t::proc_header && !xrefs_at_func.empty()) {
                    std::string xref_text = ida_format_xref_comment(xrefs_at_func[0],
                        xrefs_more && xrefs_at_func.size() == 1);
                    size_t hn_end = 0;
                    const std::string& ht = br.text;
                    while (hn_end < ht.size() && ht[hn_end] != ' ' && ht[hn_end] != '\t') ++hn_end;
                    std::string hn_name = ht.substr(0, hn_end);
                    std::string hn_tail = ht.substr(hn_end);
                    float hn_name_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f,
                        hn_name.c_str()).x;
                    float hn_tail_w = hn_tail.empty()
                        ? 0.f
                        : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, hn_tail.c_str()).x;
                    float header_w = hn_name_w + hn_tail_w;
                    float xref_x = std::max(x_comment, x_mnem + header_w + 4.f * ch_w_safe);
                    draw_text_at(xref_x, yy,
                        aida::ui::with_alpha(disasm_theme::xref(), row_a_inner * 0.95f),
                        xref_text.c_str(), row_y_off);
                }
                handle_injection_row_input(yy, br.addr, this_slot);
            }
            if (br.kind == function_index::injection_t::proc_header && xrefs_at_func.size() > 1) {
                const int reserved_proc_xref = layout_proc_xref_extra_for(
                    i, static_cast<int>(xrefs_at_func.size()) - 1);
                int drawn_xref = 0;
                for (size_t xi = 1; xi < xrefs_at_func.size() && drawn_xref < reserved_proc_xref; ++xi, ++drawn_xref) {
                    const int x_slot = slot_idx++;
                    float xy = slot_y(x_slot);
                    if (xy + line_h < oy_content || xy > oy_content + content_height) continue;
                    paint_injection_row_bg(xy, x_slot);
                    draw_addr_prefix_cached(xy, &cache, ins.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                    bool last_more = (xi + 1 == xrefs_at_func.size()) && xrefs_more;
                    std::string xt = ida_format_xref_comment(xrefs_at_func[xi], last_more);
                    draw_text_at(x_comment, xy,
                        aida::ui::with_alpha(disasm_theme::xref(), row_a_inner * 0.9f),
                        xt.c_str(), row_y_off);
                    handle_injection_row_input(xy, br.addr, x_slot);
                }
            }
        }

        if (!inline_label_ptr->empty() && !throttled) {
            const int prefix_slot = slot_idx++;
            float prefix_y = slot_y(prefix_slot);
            if (prefix_y + line_h >= oy_content && prefix_y <= oy_content + content_height) {
                paint_injection_row_bg(prefix_y, prefix_slot);
                draw_addr_prefix_cached(prefix_y, &cache, ins.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                handle_injection_row_input(prefix_y, ins.addr, prefix_slot);
            }
            const int label_slot = slot_idx++;
            float label_y = slot_y(label_slot);
            if (label_y + line_h >= oy_content && label_y <= oy_content + content_height) {
                paint_injection_row_bg(label_y, label_slot);
                draw_addr_prefix_cached(label_y, &cache, ins.addr, sec_name, row_a_inner * 0.7f, row_y_off);
                std::string lbl_text = *inline_label_ptr;
                if (lbl_text.empty() || lbl_text.back() != ':') lbl_text += ":";
                draw_text_at(x_mnem, label_y,
                    aida::ui::with_alpha(disasm_theme::loc_label(), row_a_inner),
                    lbl_text.c_str(), row_y_off);
                if (!cache.xref_inline_valid) {
                    cache.xref_inline = xref_index::query_to(ins.addr, 6);
                    cache.xref_inline_more = xref_index::has_more(ins.addr, 6);
                    cache.xref_inline_valid = true;
                }
                if (!cache.xref_inline.empty()) {
                    bool head_more = cache.xref_inline_more && cache.xref_inline.size() == 1;
                    std::string xt = ida_format_xref_comment(cache.xref_inline[0], head_more);
                    float lbl_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f,
                        lbl_text.c_str()).x;
                    float xref_x = std::max(x_comment, x_mnem + lbl_w + 4.f * ch_w_safe);
                    draw_text_at(xref_x, label_y,
                        aida::ui::with_alpha(disasm_theme::xref(), row_a_inner * 0.9f),
                        xt.c_str(), row_y_off);
                }
                handle_injection_row_input(label_y, ins.addr, label_slot);
            }
            if (cache.xref_inline_valid && cache.xref_inline.size() > 1) {
                const int reserved_inline_xref = layout_inline_xref_extra_for(
                    i, static_cast<int>(cache.xref_inline.size()) - 1);
                int drawn_inline = 0;
                for (size_t xi = 1; xi < cache.xref_inline.size() && drawn_inline < reserved_inline_xref; ++xi, ++drawn_inline) {
                    const int x_slot = slot_idx++;
                    float xy = slot_y(x_slot);
                    if (xy + line_h < oy_content || xy > oy_content + content_height) continue;
                    paint_injection_row_bg(xy, x_slot);
                    draw_addr_prefix_cached(xy, &cache, ins.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                    bool last_more = (xi + 1 == cache.xref_inline.size()) && cache.xref_inline_more;
                    std::string xt = ida_format_xref_comment(cache.xref_inline[xi], last_more);
                    draw_text_at(x_comment, xy,
                        aida::ui::with_alpha(disasm_theme::xref(), row_a_inner * 0.9f),
                        xt.c_str(), row_y_off);
                    handle_injection_row_input(xy, ins.addr, x_slot);
                }
            }
        }

        draw_addr_prefix_cached(y, &cache, ins.addr, sec_name, row_a_inner * 0.95f, row_y_off);

        if (draw_bytes_column) {
            if (!cache.bytes_valid) {
                int max_pairs = 7;
                std::string bytes_buf = format_byte_preview(
                    ins.raw, ins.len, max_pairs, "..");
                if (ins.len > max_pairs) {
                    s_bytes_overflow_log_seen.fetch_add(1, std::memory_order_relaxed);
                    uint32_t prev_max = s_bytes_overflow_log_max_len.load(std::memory_order_relaxed);
                    while (static_cast<uint32_t>(ins.len) > prev_max
                        && !s_bytes_overflow_log_max_len.compare_exchange_weak(
                            prev_max, static_cast<uint32_t>(ins.len),
                            std::memory_order_relaxed, std::memory_order_relaxed)) {
                    }
                    const uint64_t now_ns_v = now_ns();
                    uint64_t prev_log = s_bytes_overflow_log_last_ns.load(std::memory_order_relaxed);
                    if (prev_log == 0
                        || now_ns_v - prev_log >= 5000000000ull)
                    {
                        if (s_bytes_overflow_log_last_ns.compare_exchange_strong(
                            prev_log, now_ns_v,
                            std::memory_order_acq_rel, std::memory_order_relaxed))
                        {
                            uint64_t total = s_bytes_overflow_log_seen.exchange(0, std::memory_order_acq_rel);
                            uint32_t mx = s_bytes_overflow_log_max_len.exchange(0, std::memory_order_acq_rel);
                            driver_bridge::debug_log(
                                "[disasm_bytes] truncated len=%d addr=0x%llX cap=%d window_count=%llu window_max_len=%u\n",
                                ins.len,
                                static_cast<unsigned long long>(ins.addr),
                                max_pairs,
                                static_cast<unsigned long long>(total),
                                mx);
                        }
                    }
                }
                cache.bytes_str.assign(bytes_buf);
                cache.bytes_valid = true;
            }
            draw_text_at(x_bytes, y,
                aida::ui::with_alpha(disasm_theme::bytes(), row_a_inner),
                cache.bytes_str.c_str(), row_y_off);
        }

        std::string mnem_override_token;
        bool has_mnem_override = !throttled
            && lookup_mnem_override_at(ins.addr, mnem_override_token)
            && !mnem_override_token.empty();

        function_index::directive_override_t dir_ov_live;
        bool has_dir_override_live = !throttled
            && function_index::directive_override_at(ins.addr, &dir_ov_live);

        ImU32 mc = mnemonic_color(ins, row_a_inner);
        if (has_mnem_override) {
            const std::string& tok = mnem_override_token;
            int override_kind = -1;
            if (tok.size() >= 2 && tok[0] == 'r' && tok[1] == '_') {
                override_kind = disasm_theme::kind_restored_reg;
            } else if (tok.size() >= 2 && tok[0] == 's' && tok[1] == '_') {
                override_kind = disasm_theme::kind_saved_reg;
            }
            if (override_kind >= 0) {
                mc = aida::ui::with_alpha(
                    disasm_theme::color_for_kind(override_kind), row_a_inner);
            }
        }
        if (has_dir_override_live) {
            mc = aida::ui::with_alpha(disasm_theme::keyword(), row_a_inner);
        }
        if (!cache.mnem_valid) {
            cache.mnem_str = ida_export::ida_mnemonic(std::string(ins.mnem));
            cache.mnem_valid = true;
        }
        std::string dir_mnem_text;
        const char* mnem_render = cache.mnem_str.empty() ? ins.mnem : cache.mnem_str.c_str();
        if (has_dir_override_live) {
            if (dir_ov_live.kind == function_index::directive_kind_t::align) {
                dir_mnem_text = "align";
            }
            else if (dir_ov_live.kind == function_index::directive_kind_t::db) {
                dir_mnem_text = "db";
            }
            if (!dir_mnem_text.empty()) {
                mnem_render = dir_mnem_text.c_str();
            }
        }
        draw_text_at(x_mnem, y, mc, mnem_render, row_y_off);

        const std::string* operand_text_ptr = nullptr;
        std::string dir_ops_text;
        if (throttled) {
            operand_text_ptr = nullptr;
        } else if (has_dir_override_live) {
            if (dir_ov_live.kind == function_index::directive_kind_t::align) {
                dir_ops_text = ida_export::format_unsigned_hex(static_cast<uint64_t>(dir_ov_live.value));
            }
            else if (dir_ov_live.kind == function_index::directive_kind_t::db) {
                char hb[16];
                std::snprintf(hb, sizeof(hb), "0%02Xh", static_cast<unsigned int>(dir_ov_live.value));
                dir_ops_text = hb;
            }
            operand_text_ptr = &dir_ops_text;
        } else {
            if (!cache.ops_valid) {
                std::string ops_subst = substitute_operand_text(ins, file);
                if ((ins.is_branch || ins.is_call) && ins.branch_target != 0) {
                    uint64_t target = ins.branch_target;
                    std::string ida_label = ida_export::resolve_branch_symbol(target);
                    symbol_classifier::kind_t kbr = symbol_classifier::classify(target);
                    if (kbr == symbol_classifier::kind_t::external_import) {
                        if (!ida_label.empty() && ida_label.compare(0, 6, "__imp_") != 0)
                            ida_label = "__imp_" + ida_label;
                    }
                    if (!ida_label.empty()) {
                        bool is_short = false;
                        if (ins.is_branch && !ins.is_call) {
                            int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(ins.addr);
                            if (diff >= -128 && diff <= 127) is_short = true;
                        }
                        ops_subst = is_short ? (std::string("short ") + ida_label) : ida_label;
                    }
                }
                cache.ops_subst = ida_export::convert_operands_to_ida(ops_subst);
                build_operand_colored_runs(ins, cache.ops_subst, cache.ops_runs);
                cache.ops_run_widths.clear();
                cache.ops_run_widths.reserve(cache.ops_runs.size());
                cache.ops_total_width = 0.f;
                for (const auto& run : cache.ops_runs) {
                    float w = run.text.empty() ? 0.f
                        : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, run.text.c_str()).x;
                    cache.ops_run_widths.push_back(w);
                    cache.ops_total_width += w;
                }
                cache.ops_valid = true;

                if (ins.has_imm && builtin_typelib::looks_like_status(ins.imm_unsigned)) {
                    std::string label;
                    if (builtin_typelib::lookup_auto(ins.imm_unsigned, label) && !label.empty()) {
                        std::string existing = auto_comment_store::get(ins.addr);
                        if (existing.empty()) {
                            auto_comment_store::set(ins.addr, label);
                        } else if (existing.find(label) == std::string::npos) {
                            auto_comment_store::set(ins.addr, existing + "; " + label);
                        }
                    }
                }
            }
            operand_text_ptr = &cache.ops_subst;
        }
        const char* operand_render_cstr = throttled ? ins.ops : operand_text_ptr->c_str();
        if (has_dir_override_live && !dir_ops_text.empty()) {
            ImU32 oc = aida::ui::with_alpha(disasm_theme::bytes(), row_a_inner * 0.85f);
            draw_text_at(x_operand, y, oc, dir_ops_text.c_str(), row_y_off);
        } else if (throttled) {
            if (operand_render_cstr && operand_render_cstr[0]) {
                ImU32 oc;
                if (ins.is_branch || ins.is_call)
                    oc = aida::ui::with_alpha(disasm_theme::sub_label(), row_a_inner);
                else if (ins.is_nop)
                    oc = aida::ui::with_alpha(disasm_theme::bytes(), row_a_inner * 0.7f);
                else
                    oc = aida::ui::with_alpha(disasm_theme::reg(), row_a_inner);
                draw_text_at(x_operand, y, oc, operand_render_cstr, row_y_off);
            }
        } else if (!cache.ops_runs.empty()) {
            float run_x = x_operand;
            const float run_alpha = ins.is_nop ? row_a_inner * 0.7f : row_a_inner;
            const size_t run_count = cache.ops_runs.size();
            for (size_t ri = 0; ri < run_count; ++ri) {
                const auto& run = cache.ops_runs[ri];
                if (run.text.empty()) continue;
                ImU32 col = aida::ui::with_alpha(run.color, run_alpha);
                draw_text_at(run_x, y, col, run.text.c_str(), row_y_off);
                float run_w = (ri < cache.ops_run_widths.size())
                    ? cache.ops_run_widths[ri]
                    : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, run.text.c_str()).x;
                run_x += run_w;
            }
        }

        if ((ins.is_branch || ins.is_call) && ins.branch_target != 0) {
            uint64_t target = ins.branch_target;
            if (!instrs.empty() && target >= instrs.front().addr
                && target <= instrs.back().addr)
            {
                float arrow_x = ox + width - 18.f;
                bool row_selected = (i == st.selected_row);
                float arrow_a = row_selected
                    ? row_a_inner * aida::ui::clock::pulse(1.6f, 0.6f, 1.f)
                    : row_a_inner * 0.55f;
                ImU32 arrow_col = aida::ui::with_alpha(
                    target < ins.addr ? disasm_theme::arrow_up() : disasm_theme::arrow_down(),
                    arrow_a);
                if (target < ins.addr) {
                    dl->AddTriangleFilled(
                        ImVec2(arrow_x + 4.f, y + 4.f),
                        ImVec2(arrow_x, y + line_h - 4.f),
                        ImVec2(arrow_x + 8.f, y + line_h - 4.f),
                        arrow_col);
                } else {
                    dl->AddTriangleFilled(
                        ImVec2(arrow_x, y + 4.f),
                        ImVec2(arrow_x + 8.f, y + 4.f),
                        ImVec2(arrow_x + 4.f, y + line_h - 4.f),
                        arrow_col);
                }
            }
        }

        std::string composed_cmt;
        std::string composed_tooltip;
        bool composed_multiline = false;
        if (!throttled) {
            bool compose_inputs_match = cache.composed_valid
                && cache.composed_branch_target == ins.branch_target
                && cache.composed_has_imm == ins.has_imm
                && cache.composed_imm == ins.imm_unsigned
                && cache.composed_has_mnem_override == has_mnem_override
                && cache.composed_mnem_override_token == mnem_override_token;
            if (compose_inputs_match) {
                composed_cmt = cache.composed_cmt_str;
                composed_tooltip = cache.composed_tooltip_str;
                composed_multiline = cache.composed_multiline;
            } else {
                std::string typelib_auto_cmt = auto_comment_store::get(ins.addr);
                std::string user_cmt = comment_store::has(ins.addr)
                    ? comment_store::get(ins.addr) : std::string();
                std::string auto_cmt = function_index::inline_comment_at(ins.addr);

                std::string merged_user_cmt;
                if (!user_cmt.empty() && !typelib_auto_cmt.empty()) {
                    merged_user_cmt = user_cmt + "; " + typelib_auto_cmt;
                } else if (!user_cmt.empty()) {
                    merged_user_cmt = user_cmt;
                } else if (!typelib_auto_cmt.empty()) {
                    merged_user_cmt = typelib_auto_cmt;
                }

                std::string thunk_annotation;
                std::string demangle_annotation;
                if ((ins.is_branch || ins.is_call) && ins.branch_target != 0) {
                    if (function_index::is_thunk(ins.branch_target)) {
                        std::string tgt_name = function_index::synthetic_name(ins.branch_target);
                        if (!tgt_name.empty()) {
                            if (tgt_name.size() >= 2 && tgt_name[0] == 'j' && tgt_name[1] == '_') {
                                thunk_annotation = "tail-call to " + tgt_name.substr(2);
                            } else {
                                thunk_annotation = "tail-call to " + tgt_name;
                            }
                        }
                    }
                    std::string resolved = ida_export::resolve_branch_symbol(ins.branch_target);
                    std::string demangled = demangle_tail_comment(resolved);
                    if (demangled.empty()) {
                        std::string exact = symbol_store::resolve_symbol_exact(ins.branch_target);
                        exact = strip_module_prefix_fast(exact);
                        if (!exact.empty() && exact != resolved) {
                            demangled = demangle_tail_comment(exact);
                        }
                    }
                    if (!demangled.empty()) demangle_annotation = demangled;
                }

                std::string parts;
                std::string full_for_tooltip;
                if (!merged_user_cmt.empty()) {
                    size_t nl = merged_user_cmt.find('\n');
                    std::string first_line = (nl == std::string::npos) ? merged_user_cmt : merged_user_cmt.substr(0, nl);
                    parts = first_line;
                    if (nl != std::string::npos) composed_multiline = true;
                    full_for_tooltip = merged_user_cmt;
                }
                auto append_part = [&](const std::string& s) {
                    if (s.empty()) return;
                    if (!parts.empty()) parts += " | ";
                    parts += s;
                    if (!full_for_tooltip.empty()) full_for_tooltip += "\n";
                    full_for_tooltip += s;
                };
                append_part(auto_cmt);
                append_part(thunk_annotation);
                append_part(demangle_annotation);
                if (has_mnem_override) {
                    append_part(mnem_override_token);
                }
                if (parts.empty() && ins.has_imm) {
                    uint64_t imm_a = ins.imm_unsigned;
                    if (imm_a >= 0x20 && imm_a <= 0x7E && imm_a != 0x60) {
                        char ch_a = static_cast<char>(imm_a);
                        char ascii_buf[8];
                        std::snprintf(ascii_buf, sizeof(ascii_buf), "'%c'", ch_a);
                        append_part(std::string(ascii_buf));
                    }
                }
                if (!parts.empty()) {
                    composed_cmt = parts;
                    composed_tooltip = full_for_tooltip;
                }
                cache.composed_cmt_str = composed_cmt;
                cache.composed_tooltip_str = composed_tooltip;
                cache.composed_multiline = composed_multiline;
                cache.composed_branch_target = ins.branch_target;
                cache.composed_imm = ins.imm_unsigned;
                cache.composed_has_imm = ins.has_imm;
                cache.composed_has_mnem_override = has_mnem_override;
                cache.composed_mnem_override_token = mnem_override_token;
                cache.composed_valid = true;
            }
        }

        if (!throttled && !composed_cmt.empty()) {
            float operand_w = (!throttled && cache.ops_valid)
                ? cache.ops_total_width
                : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f,
                    operand_render_cstr ? operand_render_cstr : "").x;
            float cmt_x = std::max(x_comment, x_operand + operand_w + 4.f * ch_w_safe);
            float cmt_max_w = (ox + width - 24.f) - cmt_x;
            if (cmt_max_w > 24.f) {
                if (cache.cmt_trimmed_for_width != cmt_max_w
                    || cache.cmt_source != composed_cmt) {
                    std::string cmt_render = "; " + composed_cmt;
                    bool cmt_truncated = composed_multiline;
                    float cmt_full_w = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, cmt_render.c_str()).x;
                    if (cmt_full_w > cmt_max_w) {
                        size_t lo = 0;
                        size_t hi = cmt_render.size();
                        while (lo < hi) {
                            size_t mid = (lo + hi + 1) / 2;
                            std::string trial = cmt_render.substr(0, mid) + "...";
                            if (code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f, trial.c_str()).x <= cmt_max_w)
                                lo = mid;
                            else
                                hi = mid - 1;
                        }
                        if (lo < cmt_render.size())
                            cmt_render = cmt_render.substr(0, lo) + "...";
                        cmt_truncated = true;
                    }
                    cache.cmt_trimmed = std::move(cmt_render);
                    cache.cmt_truncated = cmt_truncated;
                    cache.cmt_drawn_width = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f,
                        cache.cmt_trimmed.c_str()).x;
                    cache.cmt_trimmed_for_width = cmt_max_w;
                    cache.cmt_source = composed_cmt;
                }
                ImU32 cmt_col = aida::ui::with_alpha(disasm_theme::comment(), row_a_inner * 0.95f);
                draw_text_at(cmt_x, y, cmt_col, cache.cmt_trimmed.c_str(), row_y_off);
                if (cache.cmt_truncated) {
                    if (ImGui::IsMouseHoveringRect(ImVec2(cmt_x, y),
                        ImVec2(cmt_x + cache.cmt_drawn_width, y + line_h - 1.f), false))
                        ImGui::SetTooltip("%s", composed_tooltip.empty()
                            ? composed_cmt.c_str() : composed_tooltip.c_str());
                }
            }
        }

        const int after_sub_base = before_extent_total + 1;
        size_t after_row_offset = 0;
        if (!throttled && function_index::is_noreturn_call_at(ins.addr)) {
            float yy = y + line_h;
            if (yy + line_h >= oy_content && yy <= oy_content + content_height) {
                const int noreturn_sub = after_sub_base + static_cast<int>(after_row_offset);
                paint_injection_row_bg(yy, noreturn_sub);
                draw_addr_prefix(yy, ins.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                function_index::injection_row_t sep;
                sep.kind = function_index::injection_t::endp_separator;
                sep.addr = ins.addr;
                sep.text = "; ---------------------------------------------------------------------------";
                draw_injection_row(yy, sep, sec_name);
                handle_injection_row_input(yy, ins.addr, noreturn_sub);
            }
            ++after_row_offset;
        }

        const auto& after_rows_ref = *after_rows_ptr;
        if (!after_rows_ref.empty()) {
            for (size_t ai = 0; ai < after_rows_ref.size(); ++ai) {
                float yy = y + static_cast<float>(ai + 1 + after_row_offset) * line_h;
                if (yy + line_h < oy_content || yy > oy_content + content_height) continue;
                const auto& ar = after_rows_ref[ai];
                const int after_sub = after_sub_base + static_cast<int>(after_row_offset + ai);
                paint_injection_row_bg(yy, after_sub);
                if (ar.kind == function_index::injection_t::spacer_line) {
                    draw_addr_prefix(yy, ar.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                } else {
                    function_index::injection_row_t copy = ar;
                    draw_injection_row(yy, copy, sec_name);
                }
                handle_injection_row_input(yy, ar.addr, after_sub);
            }
        }

        if (row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            const bool shift_held = ImGui::GetIO().KeyShift;
            if (shift_held) {
                if (st.sel_anchor < 0) st.sel_anchor = i;
                st.sel_extent = i;
                st.selected_row = i;
                st.sel_dragging = false;
                begin_char_selection(main_subrow_id, true);
            } else {
                st.sel_anchor = i;
                st.sel_extent = i;
                st.selected_row = i;
                st.sel_dragging = true;
                begin_char_selection(main_subrow_id, false);
            }
            log_disasm_sel_click(i, main_subrow_id, ins.addr);
            st.banner_sel_anchor = -1;
            st.banner_sel_extent = -1;
            st.banner_selected_row = -1;
            st.banner_sel_dragging = false;
        }

        if (row_hovered && st.sel_dragging
            && ImGui::IsMouseDown(ImGuiMouseButton_Left))
        {
            if (st.sel_extent != i) {
                st.sel_extent = i;
                st.selected_row = i;
            }
            update_char_drag(main_subrow_id);
        }

        if (row_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            if ((ins.is_branch || ins.is_call) && ins.branch_target != 0) {
                goto_address(ins.branch_target, disasm);
            }
        }

        if (row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            st.ctx_row = i;
            if (i < sel_lo || i > sel_hi) {
                st.sel_anchor = i;
                st.sel_extent = i;
                st.selected_row = i;
                reset_char_selection();
                begin_char_selection(main_subrow_id, false);
            }
            st.popup_sel_anchor = st.sel_anchor;
            st.popup_sel_extent = st.sel_extent;
            st.popup_sel_row    = st.selected_row;
            st.banner_sel_anchor = -1;
            st.banner_sel_extent = -1;
            st.banner_selected_row = -1;
            st.banner_sel_dragging = false;
            ImGui::OpenPopup("##disasm_view_ctx");
        }
    }

    if (st.sel_dragging && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        const float kAutoScrollMarginSmall = 8.f;
        const float kAutoScrollMarginFar   = 32.f;
        const float kAutoScrollSpeedSlow   = 8.f  * line_h;
        const float kAutoScrollSpeedFast   = 24.f * line_h;
        float mouse_y = ImGui::GetMousePos().y;
        float top_y    = oy_content + kAutoScrollMarginSmall;
        float bottom_y = oy_content + content_height - kAutoScrollMarginSmall;
        if (mouse_y < top_y) {
            float depth = top_y - mouse_y;
            float speed = (depth > kAutoScrollMarginFar) ? kAutoScrollSpeedFast : kAutoScrollSpeedSlow;
            st.target_scroll_y -= speed * dt;
            if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
            int top_row;
            if (s_layout.ready) {
                int top_vrow = static_cast<int>(st.target_scroll_y / line_h);
                top_row = layout_first_visible_instr(top_vrow, banner_lines);
                if (top_row < 0) top_row = 0;
            } else {
                top_row = std::max(0, static_cast<int>(st.target_scroll_y / line_h) - s_banner_line_count);
            }
            if (top_row >= n) top_row = n - 1;
            if (top_row >= 0 && top_row != st.sel_extent) {
                st.sel_extent = top_row;
                st.selected_row = top_row;
                if (!s_full_line_select_mode
                    && st.sel_anchor_px >= 0.f
                    && st.sel_extent_px >= 0.f)
                {
                    st.sel_extent_sub = 0;
                    st.sel_extent_px  = 0.f;
                }
            }
        } else if (mouse_y > bottom_y) {
            float depth = mouse_y - bottom_y;
            float speed = (depth > kAutoScrollMarginFar) ? kAutoScrollSpeedFast : kAutoScrollSpeedSlow;
            st.target_scroll_y += speed * dt;
            if (st.target_scroll_y > max_scroll) st.target_scroll_y = max_scroll;
            int bottom_row;
            if (s_layout.ready) {
                int bot_vrow = static_cast<int>((st.target_scroll_y + content_height) / line_h);
                bottom_row = layout_last_visible_instr(bot_vrow);
                if (bottom_row < 0) bottom_row = 0;
            } else {
                bottom_row = static_cast<int>((st.target_scroll_y + content_height) / line_h) - s_banner_line_count;
            }
            if (bottom_row >= n) bottom_row = n - 1;
            if (bottom_row >= 0 && bottom_row != st.sel_extent) {
                st.sel_extent = bottom_row;
                st.selected_row = bottom_row;
                if (!s_full_line_select_mode
                    && st.sel_anchor_px >= 0.f
                    && st.sel_extent_px >= 0.f)
                {
                    st.sel_extent_sub = INT_MAX;
                    st.sel_extent_px  = width;
                }
            }
        }
    }

    if (st.sel_dragging && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
        st.sel_dragging = false;
    }

    {
        const uint64_t now_end = now_ns();
        const uint64_t elapsed_ns = now_end - frame_t0_ns;
        if (elapsed_ns > 24000000ull && !throttled) {
            throttle_arm(250);
        }
        s_render_ms_accum_us.fetch_add(elapsed_ns / 1000ull, std::memory_order_relaxed);
        s_render_log_frames.fetch_add(1u, std::memory_order_relaxed);
        s_render_log_rows_accum.fetch_add(
            static_cast<uint64_t>((last_row >= first_row) ? (last_row - first_row + 1) : 0),
            std::memory_order_relaxed);
        uint64_t prev_log = s_render_log_last_ns.load(std::memory_order_acquire);
        if (prev_log == 0) {
            s_render_log_last_ns.store(now_end, std::memory_order_release);
        } else if (now_end - prev_log >= 1000000000ull) {
            uint64_t total_us = s_render_ms_accum_us.exchange(0, std::memory_order_acq_rel);
            uint32_t frames = s_render_log_frames.exchange(0, std::memory_order_acq_rel);
            uint64_t rows_sum = s_render_log_rows_accum.exchange(0, std::memory_order_acq_rel);
            s_render_log_last_ns.store(now_end, std::memory_order_release);
            if (frames > 0) {
                double avg_ms = static_cast<double>(total_us) / 1000.0 / static_cast<double>(frames);
                double avg_rows = static_cast<double>(rows_sum) / static_cast<double>(frames);
                driver_bridge::debug_log("[disasm] render_ms=%.2f rows=%.0f frames=%u\n",
                    avg_ms, avg_rows, frames);
            }
        }
    }

    if (throttled) {
        float panel_w = 220.f;
        float panel_h = 32.f;
        float lx = ox + width - panel_w - 14.f;
        float ly = oy_content + 6.f;
        ImVec2 la(lx, ly);
        ImVec2 lb(lx + panel_w, ly + panel_h);
        aida::ui::blur::render_drop_shadow(dl, la, lb, panel_h * 0.5f, 4, 0.30f * a);
        aida::ui::blur::render_glass_fill(dl, la, lb, panel_h * 0.5f, a);
        aida::ui::blur::render_glass_border(dl, la, lb, panel_h * 0.5f, a);
        const char* lmsg = "Loading symbols...";
        ImVec2 ms = ImGui::CalcTextSize(lmsg);
        dl->AddText(ImVec2(lx + (panel_w - ms.x) * 0.5f,
                           ly + (panel_h - ImGui::GetFontSize()) * 0.5f),
                    aida::ui::with_alpha(tk.text_secondary, a), lmsg);
    }

    {
        struct branch_vis_t { float from_y; float to_y; ImU32 color; bool is_selected_pair; };
        std::vector<branch_vis_t> bv;
        for (int bi = first_row; bi <= last_row; ++bi) {
            const AsmInstr& bins = instrs[bi];
            if (!bins.is_branch && !bins.is_call) continue;
            uint64_t btarget = bins.branch_target;
            if (btarget == 0) continue;
            int tidx = find_instr_at(btarget, file);
            if (tidx < first_row || tidx > last_row) continue;
            const float bi_row = static_cast<float>(layout_instr_start_row(bi, banner_lines));
            const float tidx_row = static_cast<float>(layout_instr_start_row(tidx, banner_lines));
            float fy = oy_content + bi_row * line_h - st.scroll_y + line_h * 0.5f;
            float ty = oy_content + tidx_row * line_h - st.scroll_y + line_h * 0.5f;
            ImU32 bcol;
            if (bins.is_call)
                bcol = aida::ui::with_alpha(tk.accent_u32, a * 0.7f);
            else if (strcmp(bins.mnem, "jmp") == 0)
                bcol = aida::ui::with_alpha(tk.accent_u32, a * 0.7f);
            else
                bcol = aida::ui::with_alpha(tk.success, a * 0.7f);
            bool sel_pair = (bi == st.selected_row || tidx == st.selected_row);
            if (sel_pair) {
                float pulse = aida::ui::clock::pulse(1.4f, 0.7f, 1.f);
                bcol = aida::ui::with_alpha(tk.accent_u32, a * pulse);
            }
            bv.push_back({fy, ty, bcol, sel_pair});
        }
        float gx = ox + 2.f;
        for (auto& ba : bv) {
            float arrow_a = ba.is_selected_pair ? 1.f : s_first_load_anim;
            ui_anim::render_branch_arrow(dl, gx, ba.from_y, ba.to_y, gutter_w, ba.color, arrow_a);
        }
    }


    auto copy_range_to_clipboard = [&](int lo, int hi) {
        if (lo < 0 || hi < 0 || lo >= n || hi >= n || lo > hi) return;
        std::string out = ida_export::build_listing(disasm.file, instrs, lo, hi);
        copy_text_to_clipboard(out);
    };

    auto copy_selection_to_clipboard = [&]() {
        int lo = (st.sel_anchor < 0 || st.sel_extent < 0)
            ? -1 : std::min(st.sel_anchor, st.sel_extent);
        int hi = (st.sel_anchor < 0 || st.sel_extent < 0)
            ? -1 : std::max(st.sel_anchor, st.sel_extent);
        if (lo < 0 && st.selected_row >= 0) {
            lo = hi = st.selected_row;
        }
        copy_range_to_clipboard(lo, hi);
    };

    auto dump_full_listing_to_file = [&]() -> bool {
        if (n <= 0) return false;
        std::string out = ida_export::build_listing(disasm.file, instrs, 0, n - 1);
        if (out.empty()) return false;
        char path[MAX_PATH];
        _snprintf_s(path, sizeof(path), _TRUNCATE,
            "%saida_disasm_dump.txt", diag::resolve_log_dir());
        HANDLE hf = CreateFileA(path, GENERIC_WRITE,
            FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            diag::log_tagged_fmt("disasm_dump",
                "create_failed path=%s err=%lu", path, GetLastError());
            return false;
        }
        const char* data = out.data();
        size_t remaining = out.size();
        bool ok = true;
        while (remaining > 0) {
            DWORD chunk = static_cast<DWORD>(remaining > (1u << 20) ? (1u << 20) : remaining);
            DWORD written = 0;
            if (!WriteFile(hf, data, chunk, &written, nullptr) || written == 0) {
                ok = false;
                break;
            }
            data += written;
            remaining -= written;
        }
        CloseHandle(hf);
        if (ok) {
            diag::log_tagged_fmt("disasm_dump",
                "wrote path=%s bytes=%zu lines=%d",
                path, out.size(), n);
        } else {
            diag::log_tagged_fmt("disasm_dump",
                "write_failed path=%s err=%lu", path, GetLastError());
        }
        return ok;
    };

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 6.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tk.bg_overlay));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImGui::ColorConvertU32ToFloat4(tk.hover_wash));

    if (ImGui::BeginPopup("##disasm_view_ctx")) {
        if (st.ctx_row >= 0 && st.ctx_row < n) {
            const AsmInstr& ci = instrs[st.ctx_row];


            if (ImGui::MenuItem("Copy", "Ctrl+C")) {
                int snap_anchor = st.popup_sel_anchor;
                int snap_extent = st.popup_sel_extent;
                int snap_row    = st.popup_sel_row;
                int lo = (snap_anchor < 0 || snap_extent < 0)
                    ? -1 : std::min(snap_anchor, snap_extent);
                int hi = (snap_anchor < 0 || snap_extent < 0)
                    ? -1 : std::max(snap_anchor, snap_extent);
                if (lo < 0 && snap_row >= 0) { lo = hi = snap_row; }
                copy_range_to_clipboard(lo, hi);
            }


            if (ImGui::MenuItem("Copy Address")) {
                char buf[20];
                snprintf(buf, sizeof(buf), "%08llX", static_cast<unsigned long long>(ci.addr));
                copy_text_to_clipboard(std::string(buf));
            }


            if (ImGui::MenuItem("Copy Bytes")) {
                char buf[64] = {};
                int boff2 = 0;
                for (int b = 0; b < ci.len && boff2 + 3 < 64; b++)
                    boff2 += snprintf(buf + boff2, 64 - boff2, b ? " %02X" : "%02X", ci.raw[b]);
                copy_text_to_clipboard(std::string(buf));
            }


            if (ImGui::MenuItem("Copy Instruction")) {
                char buf[256];
                if (ci.ops[0])
                    snprintf(buf, sizeof(buf), "%08llX  %-8s %s",
                             static_cast<unsigned long long>(ci.addr), ci.mnem, ci.ops);
                else
                    snprintf(buf, sizeof(buf), "%08llX  %s",
                             static_cast<unsigned long long>(ci.addr), ci.mnem);
                copy_text_to_clipboard(std::string(buf));
            }

            ImGui::Separator();

            if (ImGui::MenuItem("Dump full listing to aida_disasm_dump.txt", "Ctrl+Shift+D")) {
                dump_full_listing_to_file();
            }

            ImGui::Separator();


            bool has_bm = false;
            int bm_idx = -1;
            for (int bi = 0; bi < static_cast<int>(st.bookmarks.size()); bi++) {
                if (st.bookmarks[bi].addr == ci.addr) { has_bm = true; bm_idx = bi; break; }
            }
            if (has_bm) {
                if (ImGui::MenuItem("Remove Bookmark")) {
                    diag::log_tagged_fmt("disasm_view", "ctx_remove_bookmark addr=0x%llX",
                        static_cast<unsigned long long>(ci.addr));
                    st.bookmarks.erase(st.bookmarks.begin() + bm_idx);
                }
            } else {
                if (ImGui::MenuItem("Add Bookmark")) {
                    bookmark_t bm;
                    bm.addr = ci.addr;
                    char lbl[32];
                    snprintf(lbl, sizeof(lbl), "0x%llX", static_cast<unsigned long long>(ci.addr));
                    bm.label = lbl;
                    st.bookmarks.push_back(bm);
                    diag::log_tagged_fmt("disasm_view", "ctx_add_bookmark addr=0x%llX total=%zu",
                        static_cast<unsigned long long>(ci.addr), st.bookmarks.size());
                }
            }


            if (ci.is_branch || ci.is_call) {
                if (ImGui::MenuItem("Follow Target")) {
                    diag::log_tagged_fmt("disasm_view", "ctx_follow_target from=0x%llX to=0x%llX is_call=%d",
                        static_cast<unsigned long long>(ci.addr),
                        static_cast<unsigned long long>(ci.branch_target), ci.is_call ? 1 : 0);
                    if (ci.branch_target != 0)
                        goto_address(ci.branch_target, disasm);
                }
            }

            ImGui::Separator();


            if (ImGui::MenuItem("VA Format", nullptr, st.addr_format == addr_format_t::va)) {
                if (st.addr_format != addr_format_t::va) {
                    diag::log_tagged_fmt("disasm_view", "ctx_addr_format_va");
                    st.addr_format = addr_format_t::va;
                    bump_format_generation();
                }
            }
            if (ImGui::MenuItem("RVA Format", nullptr, st.addr_format == addr_format_t::rva)) {
                if (st.addr_format != addr_format_t::rva) {
                    diag::log_tagged_fmt("disasm_view", "ctx_addr_format_rva");
                    st.addr_format = addr_format_t::rva;
                    bump_format_generation();
                }
            }

            if (ImGui::MenuItem("Show Bytes", nullptr, st.show_bytes))
                st.show_bytes = !st.show_bytes;

            if (ImGui::MenuItem("Full-Line Selection", nullptr,
                editor_config::disasm_full_line_select))
            {
                editor_config::disasm_full_line_select =
                    !editor_config::disasm_full_line_select;
                st.sel_anchor_sub = INT_MIN;
                st.sel_extent_sub = INT_MIN;
                st.sel_anchor_px  = -1.f;
                st.sel_extent_px  = -1.f;
            }

            ImGui::Separator();

            if (ImGui::MenuItem("Decompile Function")) {
                uint64_t rc_entry = find_enclosing_function_start(ci.addr, disasm.file);
                if (rc_entry == 0) rc_entry = ci.addr;
                pseudocode_view::request_decompile(rc_entry, &disasm.file);
                diag::log_tagged_critical_fmt("dec_ui", "right_click_native_dispatched addr=0x%llX",
                    static_cast<unsigned long long>(rc_entry));
            }
            if (ImGui::MenuItem("Reconstruct Source")) {
                diag::log_tagged_fmt("disasm_view", "ctx_reconstruct_source addr=0x%llX",
                    static_cast<unsigned long long>(ci.addr));
                source_reconstruct_view::open();
            }
            if (ImGui::MenuItem("Generate AOB Signature")) {
                bool driver_ok = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
                bool static_ok = disasm.file.loaded && !disasm.file.sections.empty();
                if (ci.addr == 0 || (!driver_ok && !static_ok)) {
                    aob_generator::g_state.show_no_address_modal = true;
                    {
                        std::lock_guard<std::mutex> lk(aob_generator::g_state.mutex);
                        aob_generator::g_state.last_error = (ci.addr == 0)
                            ? "No address selected - click an instruction first."
                            : "No data source available. Attach a process or open a PE file.";
                    }
                    diag::log_tagged_fmt("aob", "menu_refused addr=0x%llX driver=%d static=%d",
                        static_cast<unsigned long long>(ci.addr),
                        static_cast<int>(driver_ok), static_cast<int>(static_ok));
                    scan_hub_view::set_sub_tab(scan_hub_view::sub_tab_t::aob);
                    globals::ui::active_center_view = center_view_t::scan_hub;
                } else {
                    char addr_buf[32];
                    snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(ci.addr));
                    strncpy(aob_generator::g_state.address_input, addr_buf, sizeof(aob_generator::g_state.address_input) - 1);
                    aob_generator::generate_from_address(ci.addr, aob_generator::g_state.instruction_count, aob_generator::g_state.auto_wildcard);
                    scan_hub_view::set_sub_tab(scan_hub_view::sub_tab_t::aob);
                    globals::ui::active_center_view = center_view_t::scan_hub;
                }
            }
        }
        ImGui::EndPopup();
    }

    auto build_banner_range_text = [&](int lo, int hi) -> std::string {
        std::string out;
        if (lo < 0 || hi < 0 || lo > hi) return out;
        const int total = static_cast<int>(s_banner_cache.size());
        if (lo >= total) return out;
        if (hi >= total) hi = total - 1;
        uint64_t banner_addr2 = instrs.empty() ? file.image_base : instrs.front().addr;
        std::string banner_seg2 = instrs.empty()
            ? std::string(".text")
            : ida_export::section_for(banner_addr2);
        if (banner_seg2.empty()) banner_seg2 = ".text";
        char line_buf[640];
        for (int bi = lo; bi <= hi; ++bi) {
            const auto& bl = s_banner_cache[bi];
            std::snprintf(line_buf, sizeof(line_buf), "%s:%016llX %s",
                banner_seg2.c_str(),
                static_cast<unsigned long long>(banner_addr2),
                bl.text.c_str());
            out += line_buf;
            out += "\r\n";
        }
        return out;
    };

    auto copy_banner_range_to_clipboard = [&](int lo, int hi) {
        std::string out = build_banner_range_text(lo, hi);
        if (!out.empty()) copy_text_to_clipboard(out);
    };

    if (ImGui::BeginPopup("##disasm_view_banner_ctx")) {
        const int snap_anchor = st.banner_popup_anchor;
        const int snap_extent = st.banner_popup_extent;
        const int snap_ctx = st.banner_ctx_row;
        int lo_b = (snap_anchor < 0 || snap_extent < 0)
            ? -1 : std::min(snap_anchor, snap_extent);
        int hi_b = (snap_anchor < 0 || snap_extent < 0)
            ? -1 : std::max(snap_anchor, snap_extent);
        if (lo_b < 0 && snap_ctx >= 0) { lo_b = hi_b = snap_ctx; }

        if (ImGui::MenuItem("Copy", "Ctrl+C")) {
            copy_banner_range_to_clipboard(lo_b, hi_b);
        }
        if (ImGui::MenuItem("Copy Line Text")) {
            if (snap_ctx >= 0 && snap_ctx < static_cast<int>(s_banner_cache.size())) {
                copy_text_to_clipboard(s_banner_cache[snap_ctx].text);
            }
        }
        if (ImGui::MenuItem("Copy Address")) {
            uint64_t banner_addr2 = instrs.empty() ? file.image_base : instrs.front().addr;
            char addr_buf[24];
            std::snprintf(addr_buf, sizeof(addr_buf), "%08llX",
                static_cast<unsigned long long>(banner_addr2));
            copy_text_to_clipboard(std::string(addr_buf));
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Select All Banner")) {
            const int total_b = static_cast<int>(s_banner_cache.size());
            if (total_b > 0) {
                st.banner_sel_anchor = 0;
                st.banner_sel_extent = total_b - 1;
                st.banner_selected_row = 0;
                st.banner_sel_dragging = false;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::PopStyleColor(3);
    ImGui::PopStyleVar(3);


    if (hovered || st.goto_visible) {
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false))
            st.goto_visible = !st.goto_visible;


        if (ImGui::GetIO().KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false))
            navigate_back();
        if (ImGui::GetIO().KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false))
            navigate_forward();

        ImGuiIO& disasm_hk_io = ImGui::GetIO();
        bool disasm_hk_text_lock = disasm_hk_io.WantTextInput
            || ImGui::IsAnyItemActive();

        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            if (st.xref_popup_open) {
                st.xref_popup_open = false;
            } else if (st.goto_visible) {
                st.goto_visible = false;
            } else if (!comment_dialog::is_open()
                       && !rename_dialog::is_open()
                       && !disasm_hk_io.KeyCtrl
                       && !disasm_hk_io.KeyAlt
                       && !disasm_hk_text_lock) {
                uint64_t prev_addr = 0;
                if (nav_history::pop(&prev_addr)) {
                    s_nav_history_suppress_push = true;
                    goto_address(prev_addr, disasm);
                    s_nav_history_suppress_push = false;
                }
            }
        }

        if (!st.xref_popup_open && !st.goto_visible && !disasm_hk_io.KeyCtrl && !disasm_hk_io.KeyAlt
            && !disasm_hk_text_lock) {
            if (ImGui::IsKeyPressed(ImGuiKey_X, false)) {
                int row = st.selected_row;
                if (row >= 0 && row < n) {
                    uint64_t addr = instrs[row].addr;
                    if (addr == 0) {
                        diag::log_tagged_critical_fmt("xref",
                            "x_key_skipped_zero_addr row=%d n=%d", row, n);
                    } else {
                        uint64_t func_start = find_enclosing_function_start(addr, disasm.file);
                        uint64_t display_addr = (func_start != 0 && func_start != addr) ? func_start : addr;
                        st.xref_popup_addr = display_addr;
                        {
                            std::string rn = rename_store::get(display_addr);
                            std::string sym = !rn.empty() ? rn : symbol_store::resolve_symbol(display_addr);
                            if (sym.empty() && func_start != 0 && func_start != addr) {
                                char fbuf[40];
                                snprintf(fbuf, sizeof(fbuf), "sub_%llX",
                                    static_cast<unsigned long long>(func_start));
                                sym = fbuf;
                            }
                            st.xref_popup_target_name = sym;
                        }
                        st.xref_popup_open = true;
                        st.xref_popup_fade = 0.f;
                        st.xref_popup_scroll = 0.f;
                        st.xref_popup_target_scroll = 0.f;
                        st.xref_popup_selected = -1;
                        {
                            std::lock_guard<std::mutex> lk(st.xref_mutex);
                            st.xref_results.clear();
                        }
                        if (!try_instant_xref_lookup(addr, func_start)) {
                            launch_xref_scan(addr, func_start);
                        }
                    }
                } else {
                    diag::log_tagged_critical_fmt("xref",
                        "x_key_skipped_no_row selected=%d n=%d", row, n);
                }
            }

            if (!comment_dialog::is_open() && ImGui::IsKeyPressed(ImGuiKey_Semicolon, false)) {
                uint64_t cmt_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < n)
                    cmt_addr = instrs[st.selected_row].addr;
                else if (n > 0)
                    cmt_addr = instrs[0].addr;
                diag::log_tagged_fmt("disasm_view", "key_semicolon_comment addr=0x%llX",
                    static_cast<unsigned long long>(cmt_addr));
                if (cmt_addr != 0)
                    comment_dialog::open(cmt_addr);
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) {
                uint64_t cursor_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < n)
                    cursor_addr = instrs[st.selected_row].addr;
                else if (n > 0)
                    cursor_addr = instrs[0].addr;
                diag::log_tagged_fmt("disasm_view", "key_space_cfg cursor=0x%llX",
                    static_cast<unsigned long long>(cursor_addr));
                if (cursor_addr != 0) {
                    uint64_t entry = find_enclosing_function_start(cursor_addr, disasm.file);
                    if (entry == 0) entry = cursor_addr;
                    diag::log_tagged_fmt("disasm_view", "key_space_cfg_build entry=0x%llX",
                        static_cast<unsigned long long>(entry));
                    cfg_view::g_state.current_rip = cursor_addr;
                    cfg_view::g_state.last_cursor_addr = cursor_addr;
                    if (cfg_view::g_state.entry_addr != entry || !cfg_view::g_state.built)
                        cfg_view::build_cfg(entry);
                    cfg_view::g_state.fit_request = true;
                    globals::ui::active_center_view = center_view_t::graph_view;
                }
            }

            if (ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
                uint64_t f5_cursor_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < n)
                    f5_cursor_addr = instrs[st.selected_row].addr;
                else if (n > 0)
                    f5_cursor_addr = instrs[0].addr;
                if (f5_cursor_addr == 0) {
                    output_log::push(bottom_tab_t::output,
                        "[disasm] F5: no cursor address available; aborting decompile.");
                    diag::log_tagged_critical("f5", "disasm_f5_no_cursor");
                } else if (st.selected_row >= 0 && st.selected_row < n &&
                           instrs[st.selected_row].raw[0] == 0 &&
                           instrs[st.selected_row].raw[1] == 0 &&
                           std::strcmp(instrs[st.selected_row].mnem, "add") == 0) {
                    output_log::push(bottom_tab_t::output,
                        "[disasm] F5: selected row is zero-filled padding, not a function.");
                    diag::log_tagged_critical_fmt("f5",
                        "disasm_f5_rejected_zero_padding cursor=0x%llX row=%d",
                        static_cast<unsigned long long>(f5_cursor_addr),
                        st.selected_row);
                } else {
                    uint64_t f5_entry = find_enclosing_function_start(f5_cursor_addr, disasm.file);
                    if (f5_entry == 0) f5_entry = f5_cursor_addr;
                    uint64_t f5_resolved = follow_thunk_chain(f5_entry);
                    uint64_t f5_active = pseudocode_view::active_tab_address();
                    bool f5_same = (f5_resolved != 0 && f5_resolved == f5_active);
                    diag::log_tagged_critical_fmt("f5",
                        "disasm_f5_resolved cursor=0x%llX entry=0x%llX resolved=0x%llX active=0x%llX same=%d",
                        static_cast<unsigned long long>(f5_cursor_addr),
                        static_cast<unsigned long long>(f5_entry),
                        static_cast<unsigned long long>(f5_resolved),
                        static_cast<unsigned long long>(f5_active),
                        f5_same ? 1 : 0);
                    pseudocode_view::request_decompile(f5_resolved, &disasm.file, f5_same);
                    diag::log_tagged_critical_fmt("dec_ui", "f5_native_dispatched addr=0x%llX force=%d",
                        static_cast<unsigned long long>(f5_resolved),
                        f5_same ? 1 : 0);
                }
            }

            if (ImGui::IsKeyPressed(ImGuiKey_G, false) && !ImGui::GetIO().KeyCtrl) {
                st.goto_visible = true;
                st.goto_buf[0] = '\0';
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
                uint64_t tab_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < n)
                    tab_addr = instrs[st.selected_row].addr;
                else if (n > 0)
                    tab_addr = instrs[0].addr;
                if (tab_addr != 0) {
                    uint64_t tab_entry = find_enclosing_function_start(tab_addr, disasm.file);
                    if (tab_entry == 0) tab_entry = tab_addr;
                    pseudocode_view::request_decompile(tab_entry, &disasm.file);
                    diag::log_tagged_critical_fmt("dec_ui", "tab_native_dispatched addr=0x%llX",
                        static_cast<unsigned long long>(tab_entry));
                }
            }

            if (!rename_dialog::is_open() && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
                int row = st.selected_row;
                uint64_t rename_addr = 0;
                if (row >= 0 && row < n)
                    rename_addr = instrs[row].addr;
                else if (n > 0)
                    rename_addr = instrs[0].addr;
                diag::log_tagged_fmt("disasm_view", "key_n_rename addr=0x%llX",
                    static_cast<unsigned long long>(rename_addr));
                if (rename_addr != 0)
                    rename_dialog::open(rename_addr);
            }
        }
    }

    {
        ImGuiIO& copy_hk_io = ImGui::GetIO();
        bool copy_hk_text_lock = copy_hk_io.WantTextInput
            || ImGui::IsAnyItemActive();
        bool copy_hk_has_selection = (st.sel_anchor >= 0 && st.sel_extent >= 0)
            || st.selected_row >= 0;
        bool copy_hk_has_banner = (st.banner_sel_anchor >= 0 && st.banner_sel_extent >= 0)
            || st.banner_selected_row >= 0;
        if (!st.xref_popup_open && !st.goto_visible
            && !copy_hk_text_lock
            && copy_hk_io.KeyCtrl && !copy_hk_io.KeyAlt) {
            if (ImGui::IsKeyPressed(ImGuiKey_A, false)) {
                if (copy_hk_has_banner && !copy_hk_has_selection) {
                    const int total_b = static_cast<int>(s_banner_cache.size());
                    if (total_b > 0) {
                        st.banner_sel_anchor = 0;
                        st.banner_sel_extent = total_b - 1;
                        st.banner_selected_row = 0;
                        st.banner_sel_dragging = false;
                    }
                } else if (n > 0) {
                    st.sel_anchor = 0;
                    st.sel_extent = n - 1;
                    st.selected_row = 0;
                    st.sel_dragging = false;
                    st.sel_anchor_sub = INT_MIN;
                    st.sel_extent_sub = INT_MIN;
                    st.sel_anchor_px  = -1.f;
                    st.sel_extent_px  = -1.f;
                }
            }
            if (ImGui::IsKeyPressed(ImGuiKey_C, false)
                || ImGui::IsKeyPressed(ImGuiKey_Insert, false)) {
                if (copy_hk_has_banner) {
                    int lo_b = (st.banner_sel_anchor < 0 || st.banner_sel_extent < 0)
                        ? -1 : std::min(st.banner_sel_anchor, st.banner_sel_extent);
                    int hi_b = (st.banner_sel_anchor < 0 || st.banner_sel_extent < 0)
                        ? -1 : std::max(st.banner_sel_anchor, st.banner_sel_extent);
                    if (lo_b < 0 && st.banner_selected_row >= 0) {
                        lo_b = hi_b = st.banner_selected_row;
                    }
                    copy_banner_range_to_clipboard(lo_b, hi_b);
                } else if (copy_hk_has_selection) {
                    copy_selection_to_clipboard();
                }
            }
            if (copy_hk_io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_D, false)) {
                dump_full_listing_to_file();
            }
        }
    }


    if (st.goto_visible) {
        float gpanel_w = 360.f;
        float gpanel_h = 44.f;
        float gpanel_x = ox + 10.f;
        float gpanel_y = oy_content + 4.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 ga(gpanel_x, gpanel_y);
        ImVec2 gb(gpanel_x + gpanel_w, gpanel_y + gpanel_h);
        aida::ui::blur::render_drop_shadow(fdl, ga, gb, 10.f, 4, 0.30f * a);
        aida::ui::blur::render_glass_fill(fdl, ga, gb, 10.f, a);
        aida::ui::blur::render_glass_border(fdl, ga, gb, 10.f, a);

        ImGui::SetCursorScreenPos(ImVec2(gpanel_x + 8.f, gpanel_y + 6.f));
        bool go = false;
        ImGui::PushID("##disasm_goto_blk");
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(tk.panel_header));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertU32ToFloat4(tk.panel_header));
        ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImGui::ColorConvertU32ToFloat4(tk.selection));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
        ImGui::PushItemWidth(220.f);
        if (ImGui::InputTextWithHint("##in", "0x140001000 or CreateFileW",
            st.goto_buf, sizeof(st.goto_buf),
            ImGuiInputTextFlags_EnterReturnsTrue))
            go = true;
        ImGui::PopItemWidth();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor(3);
        ImGui::PopID();

        ImGui::SameLine();
        if (aida::ui::components::button("Go", aida::ui::components::button_kind_t::primary,
                                          aida::ui::components::size_t_::sm) || go) {
            std::string raw_input(st.goto_buf);
            std::string trimmed_input = raw_input;
            while (!trimmed_input.empty() && (trimmed_input.front() == ' ' || trimmed_input.front() == '\t'))
                trimmed_input.erase(trimmed_input.begin());
            while (!trimmed_input.empty() && (trimmed_input.back() == ' ' || trimmed_input.back() == '\t'))
                trimmed_input.pop_back();

            uint64_t resolved_addr = 0;
            bool resolved_ok = false;

            if (!trimmed_input.empty()) {
                std::string hex_view_str = trimmed_input;
                if (hex_view_str.size() > 2 && hex_view_str[0] == '0'
                    && (hex_view_str[1] == 'x' || hex_view_str[1] == 'X'))
                    hex_view_str = hex_view_str.substr(2);

                bool all_hex = !hex_view_str.empty();
                for (char c : hex_view_str) {
                    bool is_hex = (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'f')
                        || (c >= 'A' && c <= 'F');
                    if (!is_hex) { all_hex = false; break; }
                }

                if (all_hex) {
                    char* end = nullptr;
                    uint64_t parsed = std::strtoull(hex_view_str.c_str(), &end, 16);
                    if (end && *end == '\0' && parsed != 0) {
                        resolved_addr = parsed;
                        resolved_ok = true;
                    }
                }

                if (!resolved_ok) {
                    uint64_t sym_addr = symbol_store::resolve_name_to_addr(trimmed_input);
                    if (sym_addr != 0) {
                        resolved_addr = sym_addr;
                        resolved_ok = true;
                    }
                }
            }

            if (resolved_ok) {
                diag::log_tagged_fmt("disasm_view", "goto_bar_navigate input=%s resolved=0x%llX",
                    trimmed_input.c_str(), static_cast<unsigned long long>(resolved_addr));
                goto_address(resolved_addr, disasm);
                st.goto_visible = false;
                st.goto_buf[0] = '\0';
            } else if (!trimmed_input.empty()) {
                diag::log_tagged_fmt("disasm_view", "goto_bar_unresolved input=%s",
                    trimmed_input.c_str());
            }
        }
        ImGui::SameLine();
        if (aida::ui::components::button("<", aida::ui::components::button_kind_t::secondary,
                                          aida::ui::components::size_t_::sm))
            navigate_back();
        ImGui::SameLine();
        if (aida::ui::components::button(">", aida::ui::components::button_kind_t::secondary,
                                          aida::ui::components::size_t_::sm))
            navigate_forward();
    }


    if (!st.bookmarks.empty()) {
        float bm_h = 28.f;
        float bm_y = oy_content + content_height - bm_h - 2.f;

        const auto& th_bm = aida::ui::resolved();
        ImU32 backdrop_top = aida::ui::with_alpha(th_bm.bg_overlay, a * 0.92f);
        ImU32 backdrop_bot = aida::ui::with_alpha(th_bm.panel_header, a * 0.96f);
        dl->AddRectFilledMultiColor(
            ImVec2(ox, bm_y - 1.f), ImVec2(ox + width, bm_y + bm_h),
            backdrop_top, backdrop_top, backdrop_bot, backdrop_bot);
        dl->AddRectFilled(ImVec2(ox, bm_y - 1.f), ImVec2(ox + width, bm_y),
                          aida::ui::with_alpha(th_bm.border_strong, a * 0.65f));
        dl->AddLine(ImVec2(ox + 6.f, bm_y - 0.5f), ImVec2(ox + width - 6.f, bm_y - 0.5f),
                    aida::ui::with_alpha(tk.warning, a * 0.45f), 1.f);

        float total_bm_w = 8.f;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            total_bm_w += ts.x + 18.f + 6.f;
        }
        float max_scroll = std::max(0.f, total_bm_w - width + 8.f);

        bool bm_bar_hov = ImGui::IsMouseHoveringRect(
            ImVec2(ox, bm_y), ImVec2(ox + width, bm_y + bm_h));
        if (bm_bar_hov && max_scroll > 0.f) {
            float wheel = ImGui::GetIO().MouseWheel;
            if (wheel != 0.f)
                st.bm_scroll_x = std::max(0.f, std::min(max_scroll, st.bm_scroll_x - wheel * 40.f));
        }
        if (st.bm_scroll_x > max_scroll) st.bm_scroll_x = max_scroll;

        ImU32 gold_r = tk.warning;
        ImU32 gold_fill_top = aida::ui::with_alpha(aida::ui::lighten(gold_r, 28), a * 0.22f);
        ImU32 gold_fill_bot = aida::ui::with_alpha(gold_r, a * 0.14f);
        ImU32 gold_fill_top_hv = aida::ui::with_alpha(aida::ui::lighten(gold_r, 36), a * 0.38f);
        ImU32 gold_fill_bot_hv = aida::ui::with_alpha(gold_r, a * 0.26f);
        ImU32 gold_border = aida::ui::with_alpha(gold_r, a * 0.55f);
        ImU32 gold_border_hv = aida::ui::with_alpha(aida::ui::lighten(gold_r, 18), a * 0.85f);
        ImU32 gold_text = aida::ui::with_alpha(aida::ui::lighten(gold_r, 24), a * 0.98f);

        float bm_x = ox + 8.f - st.bm_scroll_x;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            float btn_w = ts.x + 18.f;
            float btn_h = bm_h - 6.f;
            float btn_y = bm_y + 3.f;

            if (bm_x + btn_w >= ox && bm_x <= ox + width) {
                bool bm_hv = ImGui::IsMouseHoveringRect(
                    ImVec2(std::max(bm_x, ox), btn_y),
                    ImVec2(std::min(bm_x + btn_w, ox + width), btn_y + btn_h));
                ImVec2 pa(bm_x, btn_y);
                ImVec2 pb(bm_x + btn_w, btn_y + btn_h);
                float radius = btn_h * 0.5f;
                ImU32 top_c = bm_hv ? gold_fill_top_hv : gold_fill_top;
                ImU32 bot_c = bm_hv ? gold_fill_bot_hv : gold_fill_bot;
                ImU32 flat = aida::ui::mix(top_c, bot_c, 0.5f);
                dl->AddRectFilled(pa, pb, flat, radius);
                dl->AddRect(pa, pb, bm_hv ? gold_border_hv : gold_border, radius, 0, 1.0f);
                dl->AddText(ImVec2(bm_x + 9.f, btn_y + (btn_h - ts.y) * 0.5f),
                            gold_text, bm.label.c_str());
                if (bm_hv && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                    goto_address(bm.addr, disasm);
            }
            bm_x += btn_w + 6.f;
        }

        if (st.bm_scroll_x > 0.f) {
            for (int gi = 0; gi < 24; gi++) {
                float ga = (1.f - gi / 24.f) * a * 0.5f;
                dl->AddLine(ImVec2(ox + static_cast<float>(gi), bm_y),
                            ImVec2(ox + static_cast<float>(gi), bm_y + bm_h),
                            aida::ui::with_alpha(tk.panel_bg, ga));
            }
        }
        if (st.bm_scroll_x < max_scroll) {
            for (int gi = 0; gi < 24; gi++) {
                float ga = (1.f - gi / 24.f) * a * 0.5f;
                dl->AddLine(ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y),
                            ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y + bm_h),
                            aida::ui::with_alpha(tk.panel_bg, ga));
            }
        }
    }


    if (disasm.live_mode) {
        float ind_w = 320.f, ind_h = 30.f;
        float ix = ox + width - ind_w - 14.f;
        float iy = oy_content + 6.f;
        ImVec2 ia(ix, iy);
        ImVec2 ib(ix + ind_w, iy + ind_h);

        aida::ui::blur::render_drop_shadow(dl, ia, ib, ind_h * 0.5f, 4, 0.30f * a);
        aida::ui::blur::render_glass_fill(dl, ia, ib, ind_h * 0.5f, a);
        aida::ui::blur::render_glass_border(dl, ia, ib, ind_h * 0.5f, a);

        float dot_x = ix + 14.f, dot_y = iy + ind_h * 0.5f;
        ImU32 dot_col = disasm.live_paused
            ? aida::ui::with_alpha(tk.warning, a)
            : aida::ui::with_alpha(tk.success, a);
        aida::ui::components::status_dot(ImVec2(dot_x, dot_y), 4.f, dot_col, !disasm.live_paused, 1.4f);

        const char* status_txt = disasm.live_paused ? "PAUSED" : "LIVE";
        dl->AddText(ImVec2(dot_x + 10.f, iy + (ind_h - ImGui::GetFontSize()) * 0.5f),
            dot_col, status_txt);

        float label_x = dot_x + 10.f + ImGui::CalcTextSize(status_txt).x + 8.f;
        std::string mod_short = disasm.live_module;
        if (mod_short.size() > 18) mod_short = mod_short.substr(0, 15) + "...";
        dl->AddText(ImVec2(label_x, iy + (ind_h - ImGui::GetFontSize()) * 0.5f),
            _ta(tk.text_secondary), mod_short.c_str());

        float btn_w2 = 70.f;
        float btn_x = ix + ind_w - btn_w2 - 4.f;
        float btn_y = iy + 3.f;
        ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
        const char* btn_lbl = disasm.live_paused ? "Play" : "Pause";
        if (aida::ui::components::button(btn_lbl,
                                          aida::ui::components::button_kind_t::secondary,
                                          aida::ui::components::size_t_::sm,
                                          ImVec2(btn_w2, ind_h - 6.f))) {
            disasm.live_paused = !disasm.live_paused;
            if (!disasm.live_paused)
                disasm.live_needs_refresh = true;
        }
    }


    {
        float total_content = s_layout.ready
            ? static_cast<float>(s_layout.total_rows) * line_h
            : static_cast<float>(n + s_banner_line_count) * line_h;
        if (total_content > content_height) {
            const float sb_w = 10.f;
            const float sb_pad = 2.f;
            float track_x = ox + width - sb_w - sb_pad;
            float track_y0 = oy_content + sb_pad;
            float track_h  = content_height - sb_pad * 2.f;

            float ratio = content_height / total_content;
            float thumb_h = std::max(20.f, track_h * ratio);
            float scroll_range = total_content - content_height;
            float thumb_y = track_y0 + (scroll_range > 0.f ? (st.scroll_y / scroll_range) * (track_h - thumb_h) : 0.f);

            bool sb_hov = ImGui::IsMouseHoveringRect(
                ImVec2(track_x - 4.f, track_y0), ImVec2(track_x + sb_w + 4.f, track_y0 + track_h));

            ImGuiID sb_hov_id = ImGui::GetID("##disasm_sb_hov");
            float sb_a = ImGui::GetStateStorage()->GetFloat(sb_hov_id, 0.f);
            sb_a += ((sb_hov || st.sb_dragging ? 1.f : 0.f) - sb_a) * std::min(14.f * dt, 1.f);
            ImGui::GetStateStorage()->SetFloat(sb_hov_id, sb_a);

            if (sb_a > 0.01f) {
                dl->AddRectFilled(ImVec2(track_x, track_y0), ImVec2(track_x + sb_w, track_y0 + track_h),
                    aida::ui::with_alpha(tk.hover_wash, sb_a * a), 3.f);

                bool thumb_hov = ImGui::IsMouseHoveringRect(
                    ImVec2(track_x - 2.f, thumb_y), ImVec2(track_x + sb_w + 2.f, thumb_y + thumb_h));
                ImU32 thumb_col = thumb_hov || st.sb_dragging
                    ? aida::ui::with_alpha(tk.accent_u32, sb_a * a)
                    : aida::ui::with_alpha(tk.accent_dim, sb_a * a);
                dl->AddRectFilled(ImVec2(track_x, thumb_y), ImVec2(track_x + sb_w, thumb_y + thumb_h),
                    thumb_col, 3.f);
            }

            if (sb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                float my = ImGui::GetIO().MousePos.y;
                if (my < thumb_y || my > thumb_y + thumb_h) {
                    float click_ratio = (my - track_y0 - thumb_h * 0.5f) / (track_h - thumb_h);
                    click_ratio = std::max(0.f, std::min(1.f, click_ratio));
                    st.target_scroll_y = click_ratio * scroll_range;
                }
                st.sb_dragging = true;
                st.sb_drag_offset = ImGui::GetIO().MousePos.y - thumb_y;
            }

            if (st.sb_dragging) {
                if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                    float my = ImGui::GetIO().MousePos.y - st.sb_drag_offset;
                    float drag_ratio = (my - track_y0) / (track_h - thumb_h);
                    drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                    st.target_scroll_y = drag_ratio * scroll_range;
                    st.scroll_y = st.target_scroll_y;
                } else {
                    st.sb_dragging = false;
                }
            }
        }
    }

    render_xref_popup(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b, disasm, dt);

    comment_dialog::render();
    rename_dialog::render();
}

std::unique_ptr<snapshot_t> detach_snapshot()
{
    std::lock_guard<std::mutex> lk(g_state.xref_mutex);
    auto out = std::make_unique<snapshot_t>();
    out->nav_history = std::move(g_state.nav_history);
    out->nav_pos = g_state.nav_pos;
    out->goto_visible = g_state.goto_visible;
    std::memcpy(out->goto_buf, g_state.goto_buf, sizeof(out->goto_buf));
    out->addr_format = g_state.addr_format;
    out->active_section = g_state.active_section;
    out->show_bytes = g_state.show_bytes;
    out->bookmarks = std::move(g_state.bookmarks);
    out->scroll_y = g_state.scroll_y;
    out->target_scroll_y = g_state.target_scroll_y;
    out->sb_dragging = g_state.sb_dragging;
    out->sb_drag_offset = g_state.sb_drag_offset;
    out->bm_scroll_x = g_state.bm_scroll_x;
    out->selected_row = g_state.selected_row;
    out->sel_anchor = g_state.sel_anchor;
    out->sel_extent = g_state.sel_extent;
    out->sel_dragging = g_state.sel_dragging;
    out->sel_anchor_sub = g_state.sel_anchor_sub;
    out->sel_extent_sub = g_state.sel_extent_sub;
    out->sel_anchor_px = g_state.sel_anchor_px;
    out->sel_extent_px = g_state.sel_extent_px;
    out->banner_selected_row = g_state.banner_selected_row;
    out->banner_sel_anchor = g_state.banner_sel_anchor;
    out->banner_sel_extent = g_state.banner_sel_extent;
    out->banner_sel_dragging = g_state.banner_sel_dragging;
    out->banner_ctx_row = g_state.banner_ctx_row;
    out->banner_popup_anchor = g_state.banner_popup_anchor;
    out->banner_popup_extent = g_state.banner_popup_extent;
    out->popup_sel_anchor = g_state.popup_sel_anchor;
    out->popup_sel_extent = g_state.popup_sel_extent;
    out->popup_sel_row = g_state.popup_sel_row;
    out->ctx_row = g_state.ctx_row;
    out->xref_popup_open = g_state.xref_popup_open;
    out->xref_popup_addr = g_state.xref_popup_addr;
    out->xref_popup_fade = g_state.xref_popup_fade;
    out->xref_popup_scroll = g_state.xref_popup_scroll;
    out->xref_popup_target_scroll = g_state.xref_popup_target_scroll;
    out->xref_popup_selected = g_state.xref_popup_selected;
    out->xref_popup_sb_dragging = g_state.xref_popup_sb_dragging;
    out->xref_popup_sb_drag_offset = g_state.xref_popup_sb_drag_offset;
    std::memcpy(out->xref_popup_filter, g_state.xref_popup_filter, sizeof(out->xref_popup_filter));
    out->xref_popup_target_name = std::move(g_state.xref_popup_target_name);
    out->xref_results = std::move(g_state.xref_results);
    out->xref_scanning = g_state.xref_scanning.load(std::memory_order_acquire);
    out->layout_signature = g_state.layout_signature;
    out->layout_n = g_state.layout_n;
    g_state.nav_history.clear();
    g_state.nav_pos = -1;
    g_state.goto_visible = false;
    std::memset(g_state.goto_buf, 0, sizeof(g_state.goto_buf));
    g_state.addr_format = addr_format_t::va;
    g_state.active_section = 0;
    g_state.show_bytes = true;
    g_state.bookmarks.clear();
    g_state.scroll_y = 0.f;
    g_state.target_scroll_y = 0.f;
    g_state.sb_dragging = false;
    g_state.sb_drag_offset = 0.f;
    g_state.bm_scroll_x = 0.f;
    g_state.selected_row = -1;
    g_state.sel_anchor = -1;
    g_state.sel_extent = -1;
    g_state.sel_dragging = false;
    g_state.sel_anchor_sub = -1;
    g_state.sel_extent_sub = -1;
    g_state.sel_anchor_px = -1.f;
    g_state.sel_extent_px = -1.f;
    g_state.banner_selected_row = -1;
    g_state.banner_sel_anchor = -1;
    g_state.banner_sel_extent = -1;
    g_state.banner_sel_dragging = false;
    g_state.banner_ctx_row = -1;
    g_state.banner_popup_anchor = -1;
    g_state.banner_popup_extent = -1;
    g_state.popup_sel_anchor = -1;
    g_state.popup_sel_extent = -1;
    g_state.popup_sel_row = -1;
    g_state.ctx_row = -1;
    g_state.xref_popup_open = false;
    g_state.xref_popup_addr = 0;
    g_state.xref_popup_fade = 0.f;
    g_state.xref_popup_scroll = 0.f;
    g_state.xref_popup_target_scroll = 0.f;
    g_state.xref_popup_selected = -1;
    g_state.xref_popup_sb_dragging = false;
    g_state.xref_popup_sb_drag_offset = 0.f;
    std::memset(g_state.xref_popup_filter, 0, sizeof(g_state.xref_popup_filter));
    g_state.xref_popup_target_name.clear();
    g_state.xref_results.clear();
    g_state.xref_scanning.store(false, std::memory_order_release);
    g_state.layout_signature = 0;
    g_state.layout_n = 0;
    return out;
}

void attach_snapshot(std::unique_ptr<snapshot_t> snap)
{
    diag::log_tagged_fmt("disasm", "attach_snapshot enter has_snap=%d",
        snap ? 1 : 0);
    std::lock_guard<std::mutex> lk(g_state.xref_mutex);
    if (!snap) snap = std::make_unique<snapshot_t>();
    g_state.nav_history = std::move(snap->nav_history);
    g_state.nav_pos = snap->nav_pos;
    g_state.goto_visible = snap->goto_visible;
    std::memcpy(g_state.goto_buf, snap->goto_buf, sizeof(g_state.goto_buf));
    g_state.addr_format = snap->addr_format;
    g_state.active_section = snap->active_section;
    g_state.show_bytes = snap->show_bytes;
    g_state.bookmarks = std::move(snap->bookmarks);
    g_state.scroll_y = snap->scroll_y;
    g_state.target_scroll_y = snap->target_scroll_y;
    g_state.sb_dragging = snap->sb_dragging;
    g_state.sb_drag_offset = snap->sb_drag_offset;
    g_state.bm_scroll_x = snap->bm_scroll_x;
    g_state.selected_row = snap->selected_row;
    g_state.sel_anchor = snap->sel_anchor;
    g_state.sel_extent = snap->sel_extent;
    g_state.sel_dragging = snap->sel_dragging;
    g_state.sel_anchor_sub = snap->sel_anchor_sub;
    g_state.sel_extent_sub = snap->sel_extent_sub;
    g_state.sel_anchor_px = snap->sel_anchor_px;
    g_state.sel_extent_px = snap->sel_extent_px;
    g_state.banner_selected_row = snap->banner_selected_row;
    g_state.banner_sel_anchor = snap->banner_sel_anchor;
    g_state.banner_sel_extent = snap->banner_sel_extent;
    g_state.banner_sel_dragging = snap->banner_sel_dragging;
    g_state.banner_ctx_row = snap->banner_ctx_row;
    g_state.banner_popup_anchor = snap->banner_popup_anchor;
    g_state.banner_popup_extent = snap->banner_popup_extent;
    g_state.popup_sel_anchor = snap->popup_sel_anchor;
    g_state.popup_sel_extent = snap->popup_sel_extent;
    g_state.popup_sel_row = snap->popup_sel_row;
    g_state.ctx_row = snap->ctx_row;
    g_state.xref_popup_open = snap->xref_popup_open;
    g_state.xref_popup_addr = snap->xref_popup_addr;
    g_state.xref_popup_fade = snap->xref_popup_fade;
    g_state.xref_popup_scroll = snap->xref_popup_scroll;
    g_state.xref_popup_target_scroll = snap->xref_popup_target_scroll;
    g_state.xref_popup_selected = snap->xref_popup_selected;
    g_state.xref_popup_sb_dragging = snap->xref_popup_sb_dragging;
    g_state.xref_popup_sb_drag_offset = snap->xref_popup_sb_drag_offset;
    std::memcpy(g_state.xref_popup_filter, snap->xref_popup_filter, sizeof(g_state.xref_popup_filter));
    g_state.xref_popup_target_name = std::move(snap->xref_popup_target_name);
    g_state.xref_results = std::move(snap->xref_results);
    g_state.xref_scanning.store(snap->xref_scanning, std::memory_order_release);
    g_state.layout_signature = snap->layout_signature;
    g_state.layout_n = snap->layout_n;
}

}
