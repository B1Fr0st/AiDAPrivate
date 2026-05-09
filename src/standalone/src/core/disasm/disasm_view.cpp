#include "disasm_view.hpp"
#include "nav_history.hpp"
#include "zydis_disasm.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <thread>
#include <unordered_map>
#include "ui_anim.hpp"
#include "decompiler_engine.hpp"
#include "aob_generator.hpp"
#include "scan_hub_view.hpp"
#include "standalone_settings.hpp"
#include "symbol_store.hpp"
#include "xref_engine.hpp"
#include "cfg_view.hpp"
#include "comment_dialog.hpp"
#include "comment_store.hpp"
#include "rename_dialog.hpp"
#include "rename_store.hpp"
#include "source_reconstruct_view.hpp"
#include "disasm_theme.hpp"
#include "file_metadata_banner.hpp"
#include "xref_index.hpp"
#include "function_index.hpp"
#include "symbol_classifier.hpp"
#include "../ui/theme.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/fonts.hpp"

namespace disasm_view {

static float s_xref_anim_t = 0.f;
static float s_first_load_anim = 0.f;
static int   s_last_known_n = 0;
static std::unordered_map<int, aida::ui::hover_state_t> s_row_hover;
static std::unordered_map<int, float> s_row_entrance;
static aida::ui::flash_t s_branch_flash;

static std::atomic<uint64_t> s_throttle_until_ns{0};
static std::atomic<uint32_t> s_last_attached_pid{0xFFFFFFFFu};
static std::atomic<uint64_t> s_last_loaded_image_base{0xFFFFFFFFFFFFFFFFull};
static std::atomic<uint64_t> s_visible_warm_last_ns{0};
static std::atomic<uint32_t> s_format_gen{1};
static std::atomic<uint64_t> s_render_log_last_ns{0};
static std::atomic<uint64_t> s_render_ms_accum_us{0};
static std::atomic<uint32_t> s_render_log_frames{0};
static std::atomic<uint64_t> s_render_log_rows_accum{0};

static inline uint64_t now_ns() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

static inline bool throttle_active() {
    uint64_t until = s_throttle_until_ns.load(std::memory_order_acquire);
    if (until == 0) return false;
    return now_ns() < until;
}

static inline void throttle_arm(uint64_t window_ms) {
    s_throttle_until_ns.store(now_ns() + window_ms * 1000000ull, std::memory_order_release);
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
};

static std::unordered_map<uint64_t, instr_cache_entry_t> s_instr_cache_hot;
static std::unordered_map<uint64_t, instr_cache_entry_t> s_instr_cache_cold;

static inline void instr_cache_clear_all() {
    s_instr_cache_hot.clear();
    s_instr_cache_cold.clear();
}

static inline void instr_cache_bound_size() {
    constexpr size_t kCap = 65536;
    if (s_instr_cache_hot.size() > kCap) {
        s_instr_cache_cold = std::move(s_instr_cache_hot);
        s_instr_cache_hot.clear();
        s_instr_cache_hot.reserve(kCap / 2);
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
    }
    return e;
}

void bump_format_generation() {
    s_format_gen.fetch_add(1u, std::memory_order_release);
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
    std::snprintf(buf, sizeof(buf), "%s:%08llX",
        seg.c_str(), static_cast<unsigned long long>(addr));
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
    return up ? "\xe2\x86\x91" : "\xe2\x86\x93";
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
    c.resolved = true;
    if (func_start == 0) return;

    auto& fc = function_index::detail::cache();
    std::shared_lock<std::shared_mutex> lk(fc.mutex);
    auto it = fc.by_start.find(func_start);
    if (it == fc.by_start.end()) return;
    for (const auto& v : it->second.vars) {
        c.offset_to_name[v.offset] = v.name;
        c.offset_to_size[v.offset] = v.size;
    }
}

static bool lookup_named_offset(int64_t offset, std::string& out_name) {
    auto& c = var_cache_slot();
    auto it = c.offset_to_name.find(offset);
    if (it == c.offset_to_name.end()) return false;
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
        size_t ds_pos = base.find("ds:0x");
        if (ds_pos != std::string::npos) {
            size_t hex_start = ds_pos + 5;
            uint64_t target = 0;
            if (sscanf_s(base.c_str() + hex_start - 2, "%llx", &target) == 1
                && target != 0)
            {
                std::string sym = symbol_store::resolve_symbol_exact(target);
                if (sym.empty()) sym = symbol_store::resolve_symbol(target);
                if (!sym.empty()) {
                    auto bang = sym.find('!');
                    if (bang != std::string::npos) sym = sym.substr(bang + 1);
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

    (void)file;
    return base;
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

static inline ImU32 default_operand_color(const AsmInstr& ins) {
    if (ins.is_branch || ins.is_call) return disasm_theme::sub_label();
    if (ins.is_nop) return disasm_theme::bytes();
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

            ImU32 color = default_color;
            if (tok_is_hex_h) {
                color = disasm_theme::immediate_num();
            } else {
                symbol_classifier::kind_t k = symbol_classifier::classify_name(tok);
                if (k != symbol_classifier::kind_t::unknown) {
                    color = disasm_theme::color_for_kind(static_cast<int>(k));
                }
            }

            append_colored_run(out, color, tok.data(), tok.size());
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

static ImU32 mnemonic_color(const AsmInstr& ins, float a) {
    if (ins.is_call || ins.is_branch || ins.is_ret)
        return aida::ui::with_alpha(disasm_theme::mnemonic(), a);
    if (ins.is_nop)
        return aida::ui::with_alpha(disasm_theme::bytes(), a * 0.85f);
    if (ins.is_priv)
        return aida::ui::with_alpha(disasm_theme::keyword(), a);
    return aida::ui::with_alpha(disasm_theme::mnemonic(), a);
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
    if (file.instrs.empty()) return addr;
    int idx = find_instr_at(addr, file);
    if (idx < 0) return addr;

    const int max_scan = 4096;
    int last_terminator = -1;
    for (int i = idx; i >= 0 && (idx - i) < max_scan; --i) {
        if (i < idx && file.instrs[i].is_ret) {
            last_terminator = i;
            break;
        }
    }

    if (last_terminator >= 0 && last_terminator + 1 < static_cast<int>(file.instrs.size())) {
        int candidate = last_terminator + 1;
        while (candidate < static_cast<int>(file.instrs.size())
               && file.instrs[candidate].is_nop)
            ++candidate;
        if (candidate <= idx)
            return file.instrs[candidate].addr;
    }

    return file.instrs[0].addr;
}

static thread_local bool s_nav_history_suppress_push = false;

void goto_address(uint64_t addr, DisasmState& disasm) {
    auto& st = g_state;
    int idx = find_instr_at(addr, disasm.file);
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
    st.target_scroll_y = idx * 18.f;
}

void navigate_back() {
    auto& st = g_state;
    if (st.nav_pos <= 0 || st.nav_history.empty()) return;
    st.nav_pos--;
    st.selected_row = st.nav_history[st.nav_pos];
    st.target_scroll_y = st.selected_row * 18.f;
}

void navigate_forward() {
    auto& st = g_state;
    if (st.nav_pos + 1 >= static_cast<int>(st.nav_history.size())) return;
    st.nav_pos++;
    st.selected_row = st.nav_history[st.nav_pos];
    st.target_scroll_y = st.selected_row * 18.f;
}

static void launch_xref_scan(uint64_t addr)
{
    auto& st = g_state;
    st.xref_scanning.store(true);
    st.xref_popup_selected = -1;
    st.xref_popup_scroll = 0.f;
    st.xref_popup_target_scroll = 0.f;

    try {
    std::thread([addr]() {
        auto modules = driver_bridge::enumerate_modules();

        uint64_t search_base = 0;
        uint64_t search_size = 0;
        std::string mod_name;

        bool use_static = false;

        for (auto& m : modules) {
            if (addr >= m.base && addr < m.base + m.size) {
                search_base = m.base;
                search_size = m.size;
                mod_name = m.name;
                break;
            }
        }

        if (search_size == 0 && !modules.empty()) {
            search_base = modules[0].base;
            search_size = modules[0].size;
            mod_name = modules[0].name;
        }

        if (search_size == 0 && g_disasm.file.loaded && !g_disasm.file.sections.empty()) {
            use_static = true;
            search_base = g_disasm.file.image_base;
            search_size = static_analysis::total_image_size(g_disasm.file);
            mod_name = g_disasm.file.filename;
        }

        if (search_size == 0) {
            g_state.xref_scanning.store(false);
            return;
        }

        const size_t page_size = 4096;
        std::vector<xref_popup_entry_t> found;

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

            if (!got_page || page_data.empty())
                continue;

            const uint8_t* data = page_data.data();
            int sz = static_cast<int>(page_data.size());
            int pos = 0;

            while (pos < sz) {
                int avail = sz - pos;
                if (avail > 15) avail = 15;

                uint64_t ins_addr = search_base + offset + pos;
                AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);

                uint64_t resolved = 0;
                if (xref_engine::detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved)) {
                    if (resolved == addr) {
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
        }

        {
            std::lock_guard<std::mutex> lk(g_state.xref_mutex);
            g_state.xref_results = std::move(found);
        }
        g_state.xref_scanning.store(false);
    }).detach();
    } catch (...) {
        g_state.xref_scanning.store(false);
        driver_bridge::debug_log("[disasm] xref scan thread creation failed\n");
    }
}

static float s_close_btn_anim = 0.f;
static float s_copy_addr_anim = 0.f;
static float s_copy_all_anim = 0.f;

static void render_xref_popup(float pos_x, float pos_y, float width, float height,
                               float alpha, float accent_r, float accent_g, float accent_b,
                               DisasmState& disasm, float dt)
{
    auto& st = g_state;

    float target_fade = st.xref_popup_open ? 1.f : 0.f;
    st.xref_popup_fade = ui_anim::smooth_lerp(st.xref_popup_fade, target_fade, 14.f, dt);

    if (st.xref_popup_fade < 0.01f && !st.xref_popup_open)
        return;

    float fa = alpha * st.xref_popup_fade;
    const auto& tk = aida::ui::resolved();
    const auto _ta = [fa](ImU32 c) -> ImU32 { return aida::ui::with_alpha(c, fa); };
    ImDrawList* fdl = ImGui::GetForegroundDrawList();

    float popup_w = std::min(760.f, width * 0.88f);
    float popup_h = std::min(460.f, height * 0.8f);
    float cx = pos_x + width * 0.5f;
    float cy = pos_y + height * 0.5f;

    ui_anim::render_popup_frame(fdl, cx, cy, popup_w, popup_h, st.xref_popup_fade,
                                accent_r, accent_g, accent_b, alpha,
                                pos_x, pos_y, width, height);

    float t_back = ui_anim::ease_out_back(std::clamp(st.xref_popup_fade * 1.2f, 0.f, 1.f));
    float scale = 0.92f + 0.08f * t_back;
    float pw = popup_w * scale;
    float ph = popup_h * scale;
    float px = cx - pw * 0.5f;
    float py = cy - ph * 0.5f + (1.f - t_back) * 12.f;

    char title_buf[256];
    if (!st.xref_popup_target_name.empty()) {
        snprintf(title_buf, sizeof(title_buf), "Xrefs to %s  (0x%llX)",
                 st.xref_popup_target_name.c_str(),
                 static_cast<unsigned long long>(st.xref_popup_addr));
    } else {
        snprintf(title_buf, sizeof(title_buf), "Xrefs to 0x%llX",
                 static_cast<unsigned long long>(st.xref_popup_addr));
    }

    std::vector<xref_popup_entry_t> results_copy;
    {
        std::lock_guard<std::mutex> lk(st.xref_mutex);
        results_copy = st.xref_results;
    }

    float header_h = 38.f;
    ui_anim::render_popup_header(fdl, px, py, pw, header_h,
                                  title_buf, accent_r, accent_g, accent_b, fa);

    if (ui_anim::render_popup_close_button(fdl, px, py, pw, header_h, fa, s_close_btn_anim, dt))
        st.xref_popup_open = false;

    float toolbar_y = py + header_h;
    float toolbar_h = 30.f;
    fdl->AddRectFilled(ImVec2(px, toolbar_y), ImVec2(px + pw, toolbar_y + toolbar_h),
        _ta(tk.panel_header));
    fdl->AddLine(ImVec2(px, toolbar_y + toolbar_h - 1.f), ImVec2(px + pw, toolbar_y + toolbar_h - 1.f),
        _ta(tk.border_subtle));

    float btn_x = px + 10.f;
    float btn_y = toolbar_y + 4.f;
    if (ui_anim::render_toolbar_button(fdl, "Copy Address", btn_x, btn_y,
                                        accent_r, accent_g, accent_b, fa, s_copy_addr_anim, dt,
                                        false, results_copy.empty())) {
        if (st.xref_popup_selected >= 0 && st.xref_popup_selected < static_cast<int>(results_copy.size())) {
            char addr_buf_copy[20];
            snprintf(addr_buf_copy, sizeof(addr_buf_copy), "%llX",
                     static_cast<unsigned long long>(results_copy[static_cast<size_t>(st.xref_popup_selected)].addr));
            ImGui::SetClipboardText(addr_buf_copy);
        }
    }
    btn_x += ui_anim::toolbar_button_width("Copy Address") + 4.f;
    if (ui_anim::render_toolbar_button(fdl, "Copy All", btn_x, btn_y,
                                        accent_r, accent_g, accent_b, fa, s_copy_all_anim, dt,
                                        false, results_copy.empty())) {
        std::string all_text;
        for (auto& e : results_copy) {
            char line_buf[256];
            snprintf(line_buf, sizeof(line_buf), "%016llX  %s\n",
                     static_cast<unsigned long long>(e.addr), e.disasm_text.c_str());
            all_text += line_buf;
        }
        if (!all_text.empty())
            ImGui::SetClipboardText(all_text.c_str());
    }

    bool scanning = st.xref_scanning.load();

    if (scanning) {
        s_xref_anim_t += dt * 5.f;
        float spinner_x = px + pw - 28.f;
        float spinner_y = py + header_h * 0.5f;
        ImU32 spin_col = aida::ui::with_alpha(tk.accent_u32, fa);
        ui_anim::render_spinner(fdl, spinner_x, spinner_y, 6.f, 2.f, spin_col, s_xref_anim_t);
    }

    char count_buf[32];
    snprintf(count_buf, sizeof(count_buf), "%zu result%s",
             results_copy.size(), results_copy.size() == 1 ? "" : "s");
    ImVec2 cs = ImGui::CalcTextSize(count_buf);
    fdl->AddText(ImVec2(px + pw - cs.x - (scanning ? 42.f : 14.f), py + 11.f),
        _ta(tk.text_secondary), count_buf);

    float toolbar_end = toolbar_y + toolbar_h;
    const float footer_h = 26.f;
    float table_y = toolbar_end + 2.f;
    float table_h = ph - header_h - toolbar_h - 4.f - footer_h;
    const float row_h = 24.f;

    float col_type_w = 54.f;
    float col_addr_w = 145.f;
    float col_func_w = 200.f;
    float col_disasm_w = pw - col_type_w - col_addr_w - col_func_w - 30.f;
    if (col_disasm_w < 100.f) col_disasm_w = 100.f;

    ui_anim::table_col_t xref_cols[] = {
        { "Type", col_type_w }, { "Address", col_addr_w },
        { "Function", col_func_w }, { "Disassembly", col_disasm_w }
    };
    ui_anim::render_table_header(fdl, px, table_y, pw, row_h, xref_cols, 4,
                                  accent_r, accent_g, accent_b, fa);

    float list_y = table_y + row_h;
    float list_h = table_h - row_h;
    if (list_h < 1.f) list_h = 1.f;

    float content_h = static_cast<float>(results_copy.size()) * row_h;
    int n_results = static_cast<int>(results_copy.size());

    bool popup_hovered = ImGui::IsMouseHoveringRect(ImVec2(px, list_y), ImVec2(px + pw, list_y + list_h));
    if (popup_hovered) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            st.xref_popup_target_scroll -= wheel * row_h * 3.f;
    }

    if (st.xref_popup_open) {
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
            st.xref_popup_selected = std::min(st.xref_popup_selected + 1, n_results - 1);
            if (st.xref_popup_selected < 0) st.xref_popup_selected = 0;
            float sel_y = static_cast<float>(st.xref_popup_selected) * row_h;
            if (sel_y < st.xref_popup_target_scroll)
                st.xref_popup_target_scroll = sel_y;
            if (sel_y + row_h > st.xref_popup_target_scroll + list_h)
                st.xref_popup_target_scroll = sel_y + row_h - list_h;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
            st.xref_popup_selected = std::max(st.xref_popup_selected - 1, 0);
            float sel_y = static_cast<float>(st.xref_popup_selected) * row_h;
            if (sel_y < st.xref_popup_target_scroll)
                st.xref_popup_target_scroll = sel_y;
            if (sel_y + row_h > st.xref_popup_target_scroll + list_h)
                st.xref_popup_target_scroll = sel_y + row_h - list_h;
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

    fdl->PushClipRect(ImVec2(px + 1.f, list_y), ImVec2(px + pw - 12.f, list_y + list_h), true);

    int first_vis = static_cast<int>(st.xref_popup_scroll / row_h);
    int last_vis = first_vis + static_cast<int>(list_h / row_h) + 2;
    if (first_vis < 0) first_vis = 0;
    if (last_vis > n_results) last_vis = n_results;

    for (int i = first_vis; i < last_vis; ++i) {
        float ry = list_y + static_cast<float>(i) * row_h - st.xref_popup_scroll;
        if (ry + row_h < list_y || ry > list_y + list_h) continue;

        auto& e = results_copy[static_cast<size_t>(i)];

        ImVec2 rmin(px + 4.f, ry);
        ImVec2 rmax(px + pw - 14.f, ry + row_h);

        bool row_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
        bool row_sel = (st.xref_popup_selected == i);

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

        if (row_sel) {
            fdl->AddRectFilled(rmin, rmax,
                aida::ui::with_alpha(tk.selection, row_alpha));
            fdl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
                aida::ui::with_alpha(tk.accent_u32, row_alpha));
        } else if (row_hov) {
            fdl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(tk.hover_wash, row_alpha));
        } else if (i & 1) {
            fdl->AddRectFilled(rmin, rmax,
                aida::ui::with_alpha(IM_COL32(255, 255, 255, 6), row_alpha));
        }

        float rx = px + 10.f;

        ImU32 type_col;
        const char* type_str;
        switch (e.type) {
        case 0:  type_str = "CALL"; type_col = aida::ui::with_alpha(tk.info,    row_alpha); break;
        case 1:  type_str = "JMP";  type_col = aida::ui::with_alpha(tk.warning, row_alpha); break;
        case 2:  type_str = "Jcc";  type_col = aida::ui::with_alpha(tk.warning, row_alpha * 0.85f); break;
        case 3:  type_str = "LEA";  type_col = aida::ui::with_alpha(tk.success, row_alpha); break;
        default: type_str = "DATA"; type_col = aida::ui::with_alpha(tk.text_secondary, row_alpha); break;
        }

        ImVec2 tsz = ImGui::CalcTextSize(type_str);
        float badge_w = tsz.x + 10.f;
        fdl->AddRectFilled(ImVec2(rx, ry + 3.f), ImVec2(rx + badge_w, ry + row_h - 3.f),
            aida::ui::with_alpha(type_col, 0.18f), 3.f);
        fdl->AddText(ImVec2(rx + 5.f, ry + 4.f), type_col, type_str);
        rx += col_type_w;

        char addr_buf[20];
        snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(e.addr));
        fdl->AddText(ImVec2(rx, ry + 4.f),
            aida::ui::with_alpha(tk.text_address, row_alpha), addr_buf);
        rx += col_addr_w;

        const std::string& fn_text = !e.function_name.empty() ? e.function_name : e.module_name;
        if (!fn_text.empty()) {
            size_t max_fn = 28;
            std::string fn_short = fn_text.size() > max_fn
                ? fn_text.substr(0, max_fn - 2) + ".." : fn_text;
            ImU32 fn_col = !e.function_name.empty()
                ? aida::ui::with_alpha(tk.text_primary, row_alpha)
                : aida::ui::with_alpha(tk.text_secondary, row_alpha);
            fdl->AddText(ImVec2(rx, ry + 4.f), fn_col, fn_short.c_str());
        } else {
            fdl->AddText(ImVec2(rx, ry + 4.f),
                aida::ui::with_alpha(tk.text_dim, row_alpha), "-");
        }
        rx += col_func_w;

        const char* disasm_end = e.disasm_text.c_str() + std::min(e.disasm_text.size(), static_cast<size_t>(60));
        fdl->AddText(ImVec2(rx, ry + 4.f),
            aida::ui::with_alpha(tk.text_primary, row_alpha),
            e.disasm_text.c_str(), disasm_end);

    }

    fdl->PopClipRect();

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

    if (results_copy.empty() && !scanning) {
        float cw = std::min(pw - 32.f, 460.f);
        if (cw < 140.f) cw = std::max(140.f, pw - 20.f);
        float ccx = px + (pw - cw) * 0.5f;
        float ccy = list_y + list_h * 0.5f - 26.f;
        char empty_buf[160];
        snprintf(empty_buf, sizeof(empty_buf),
                 "No cross-references found for 0x%llX.",
                 static_cast<unsigned long long>(st.xref_popup_addr));
        ui_anim::render_inline_callout(fdl, ccx, ccy, cw, 52.f,
            empty_buf,
            ui_anim::callout_kind_t::info, accent_r, accent_g, accent_b, fa);
    }

    {
        float fx = px + 12.f;
        float fy = py + ph - footer_h + 4.f;
        float cw;
        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "\xe2\x86\x91", fa);
        fx += cw + 4.f;
        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "\xe2\x86\x93", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(tk.text_dim), "navigate");
        fx += ImGui::CalcTextSize("navigate").x + 14.f;

        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "Enter", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(tk.text_dim), "jump");
        fx += ImGui::CalcTextSize("jump").x + 14.f;

        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "Esc", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(tk.text_dim), "close");
        fx += ImGui::CalcTextSize("close").x + 14.f;

        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "Dbl-click", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(tk.text_dim), "goto");
    }

    if (!st.xref_popup_open && !popup_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        st.xref_popup_fade = 0.f;
    }
}


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            DisasmState& disasm, float dt) {

    const uint64_t frame_t0_ns = now_ns();

    auto& st    = g_state;

    {
        const uint32_t cur_pid = driver_bridge::attached_pid();
        const uint32_t prev_pid = s_last_attached_pid.load(std::memory_order_acquire);
        const uint64_t cur_img = disasm.file.image_base;
        const uint64_t prev_img = s_last_loaded_image_base.load(std::memory_order_acquire);
        if (cur_pid != prev_pid || cur_img != prev_img) {
            s_last_attached_pid.store(cur_pid, std::memory_order_release);
            s_last_loaded_image_base.store(cur_img, std::memory_order_release);
            on_attach_state_changed();
        }
    }

    instr_cache_bound_size();

    const bool throttled = throttle_active();


    if (disasm.live_mode && disasm.live_pending_ready.load(std::memory_order_acquire)) {

        driver_bridge::debug_log("disasm_view: live_pending_ready=TRUE, moving %llu instrs to display\n",
            static_cast<unsigned long long>(disasm.live_pending_instrs.size()));

        uint64_t scroll_addr = 0;
        if (st.selected_row >= 0 && st.selected_row < static_cast<int>(disasm.file.instrs.size()))
            scroll_addr = disasm.file.instrs[st.selected_row].addr;

        disasm.file.instrs = std::move(disasm.live_pending_instrs);
        disasm.file.image_base = disasm.live_pending_va;
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
            st.selected_row = best;
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
            s_last_known_n = n;
        } else {
            s_first_load_anim = 0.f;
            s_row_entrance.clear();
            s_row_hover.clear();
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


    ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 20.f, dt);
    float max_scroll = std::max(0.f, n * line_h - content_height + line_h);
    st.target_scroll_y = std::max(0.f, std::min(st.target_scroll_y, max_scroll));
    st.scroll_y = std::max(0.f, std::min(st.scroll_y, max_scroll));


    bool hovered = ImGui::IsMouseHoveringRect(ImVec2(ox, oy_content), ImVec2(ox + width, oy_content + content_height));
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
    const float seg_addr_chars = 22.f;
    const float bytes_chars = 35.f;
    const float mnem_chars = 6.f;
    const float operand_chars = 28.f;
    const float comment_indent_chars = 78.f;

    const float x_seg_addr = ox + gutter_w + 4.f;
    const float x_bytes = x_seg_addr + seg_addr_chars * ch_w_safe + 2.f * ch_w_safe;
    const float x_mnem = st.show_bytes
        ? (x_bytes + bytes_chars * ch_w_safe + 1.f * ch_w_safe)
        : (x_seg_addr + seg_addr_chars * ch_w_safe + 2.f * ch_w_safe);
    const float x_operand = x_mnem + mnem_chars * ch_w_safe;
    const float x_comment = x_seg_addr + comment_indent_chars * ch_w_safe;
    const uint32_t cur_gen = s_format_gen.load(std::memory_order_acquire);

    dl->AddRectFilled(ImVec2(ox, oy_content), ImVec2(ox + width, oy_content + content_height),
        aida::ui::with_alpha(disasm_theme::panel_bg(), a));
    dl->AddRectFilled(ImVec2(ox, oy_content), ImVec2(ox + gutter_w, oy_content + content_height),
        aida::ui::with_alpha(disasm_theme::gutter_bg(), a));

    int first_row = std::max(0, static_cast<int>(st.scroll_y / line_h) - 1);
    int last_row  = std::min(n - 1, static_cast<int>((st.scroll_y + content_height) / line_h) + 1);

    if (n > 0 && first_row <= last_row && !throttled) {
        uint64_t now_w = now_ns();
        uint64_t last_w = s_visible_warm_last_ns.load(std::memory_order_acquire);
        if (now_w - last_w >= 150000000ull) {
            s_visible_warm_last_ns.store(now_w, std::memory_order_release);
            uint64_t lo_va = instrs[first_row].addr;
            uint64_t hi_va = instrs[last_row].addr + static_cast<uint64_t>(instrs[last_row].len);
            xref_index::warm_range(lo_va, hi_va);
            function_index::warm_range(lo_va, hi_va);
            symbol_classifier::warm_range(lo_va, hi_va);
        }
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
        ImVec2 sp(x_seg_addr, yy + 1.f - yoff);
        dl->AddText(code_font, code_size, sp,
            aida::ui::with_alpha(disasm_theme::segment(), row_alpha), seg_part.c_str());
        if (!seg_part.empty()) {
            ImVec2 cp(x_seg_addr + seg_part_w, yy + 1.f - yoff);
            dl->AddText(code_font, code_size, cp,
                aida::ui::with_alpha(disasm_theme::separator(), row_alpha), ":");
            ImVec2 ap(x_seg_addr + seg_part_w + ch_w_safe, yy + 1.f - yoff);
            dl->AddText(code_font, code_size, ap,
                aida::ui::with_alpha(disasm_theme::address(), row_alpha), addr_part.c_str());
        } else {
            dl->AddText(code_font, code_size, sp,
                aida::ui::with_alpha(disasm_theme::address(), row_alpha), addr_part.c_str());
        }
    };

    auto draw_addr_prefix = [&](float yy, uint64_t va, const std::string& seg_override,
                                float row_alpha, float yoff)
    {
        draw_addr_prefix_cached(yy, nullptr, va, seg_override, row_alpha, yoff);
    };

    auto draw_text_at = [&](float xx, float yy, ImU32 col, const char* str, float yoff) {
        dl->AddText(code_font, code_size, ImVec2(xx, yy + 1.f - yoff), col, str);
    };

    auto fill_row_bg = [&](float yy, ImU32 col) {
        dl->AddRectFilled(ImVec2(ox, yy), ImVec2(ox + width, yy + line_h - 1.f), col);
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

    for (int i = first_row; i <= last_row; i++) {
        float y = oy_content + i * line_h - st.scroll_y;
        const AsmInstr& ins = instrs[i];

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

        bool row_hovered = ImGui::IsMouseHoveringRect(
            ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f), false);

        auto& hov_st = s_row_hover[i];
        float rh = hov_st.tick(row_hovered, dt, aida::motion::spring::snappy);

        if (rh > 0.002f)
            fill_row_bg(y, aida::ui::with_alpha(tk.hover_wash, row_a_inner * rh));

        if (i == st.selected_row) {
            fill_row_bg(y, aida::ui::with_alpha(disasm_theme::cursor_line_bg(), row_a_inner));
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + 3.f, y + line_h - 1.f),
                aida::ui::with_alpha(tk.accent_u32, row_a_inner));
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
        if (!throttled) {
            if (!cache.inj_valid) {
                cache.before_rows = function_index::rows_before(ins.addr);
                cache.after_rows = function_index::rows_after(ins.addr);
                cache.inline_label = function_index::inline_label_at(ins.addr);
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

        float anchor_y = y;
        int row_local = 0;

        const auto& before_rows_ref = *before_rows_ptr;
        for (size_t bi = 0; bi < before_rows_ref.size(); ++bi) {
            float yy = y - static_cast<float>(before_rows_ref.size() - bi) * line_h;
            if (yy + line_h < oy_content || yy > oy_content + content_height) continue;
            const auto& br = before_rows_ref[bi];
            if (br.kind == function_index::injection_t::spacer_line) {
                draw_addr_prefix_cached(yy, &cache, ins.addr, sec_name, row_a_inner * 0.55f, row_y_off);
            } else {
                draw_injection_row(yy, br, sec_name);
            }
            if (br.kind == function_index::injection_t::proc_header && !xrefs_at_func.empty()) {
                std::string xref_text = ida_format_xref_comment(xrefs_at_func[0],
                    xrefs_more && xrefs_at_func.size() == 1);
                draw_text_at(x_comment, yy,
                    aida::ui::with_alpha(disasm_theme::xref(), row_a_inner * 0.95f),
                    xref_text.c_str(), row_y_off);
            }
            (void)row_local;
        }

        if (is_proc_start && xrefs_at_func.size() > 1) {
            for (size_t xi = 1; xi < xrefs_at_func.size(); ++xi) {
                float yy = y - static_cast<float>(xi) * line_h;
                if (yy + line_h < oy_content || yy > oy_content + content_height) continue;
                draw_addr_prefix_cached(yy, &cache, ins.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                bool last_more = (xi + 1 == xrefs_at_func.size()) && xrefs_more;
                std::string xt = ida_format_xref_comment(xrefs_at_func[xi], last_more);
                draw_text_at(x_comment, yy,
                    aida::ui::with_alpha(disasm_theme::xref(), row_a_inner * 0.9f),
                    xt.c_str(), row_y_off);
            }
        }

        if (!inline_label_ptr->empty() && !throttled) {
            float yy = y - line_h;
            if (yy + line_h >= oy_content && yy <= oy_content + content_height) {
                draw_addr_prefix_cached(yy, &cache, ins.addr, sec_name, row_a_inner * 0.7f, row_y_off);
                std::string lbl_text = *inline_label_ptr + ":";
                draw_text_at(x_mnem, yy,
                    aida::ui::with_alpha(disasm_theme::loc_label(), row_a_inner),
                    lbl_text.c_str(), row_y_off);
                if (!cache.xref_inline_valid) {
                    cache.xref_inline = xref_index::query_to(ins.addr, 1);
                    cache.xref_inline_more = xref_index::has_more(ins.addr, 1);
                    cache.xref_inline_valid = true;
                }
                if (!cache.xref_inline.empty()) {
                    std::string xt = ida_format_xref_comment(cache.xref_inline[0], cache.xref_inline_more);
                    draw_text_at(x_comment, yy,
                        aida::ui::with_alpha(disasm_theme::xref(), row_a_inner * 0.9f),
                        xt.c_str(), row_y_off);
                }
            }
        }

        draw_addr_prefix_cached(y, &cache, ins.addr, sec_name, row_a_inner * 0.95f, row_y_off);

        if (st.show_bytes) {
            if (!cache.bytes_valid) {
                char bytes_buf[96] = {};
                int boff = 0;
                int max_pairs = 12;
                int show_n = ins.len < max_pairs ? ins.len : max_pairs;
                for (int b = 0; b < show_n && boff + 4 < static_cast<int>(sizeof(bytes_buf)); b++)
                    boff += std::snprintf(bytes_buf + boff, sizeof(bytes_buf) - boff,
                        b ? " %02X" : "%02X", ins.raw[b]);
                if (ins.len > max_pairs && boff + 4 < static_cast<int>(sizeof(bytes_buf)))
                    std::snprintf(bytes_buf + boff, sizeof(bytes_buf) - boff, "...");
                cache.bytes_str.assign(bytes_buf);
                cache.bytes_valid = true;
            }
            draw_text_at(x_bytes, y,
                aida::ui::with_alpha(disasm_theme::bytes(), row_a_inner),
                cache.bytes_str.c_str(), row_y_off);
        }

        ImU32 mc = mnemonic_color(ins, row_a_inner);
        draw_text_at(x_mnem, y, mc, ins.mnem, row_y_off);

        const std::string* operand_text_ptr = nullptr;
        if (throttled) {
            operand_text_ptr = nullptr;
        } else {
            if (!cache.ops_valid) {
                cache.ops_subst = substitute_operand_text(ins, file);
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
            }
            operand_text_ptr = &cache.ops_subst;
        }
        const char* operand_render_cstr = throttled ? ins.ops : operand_text_ptr->c_str();
        if (throttled) {
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

        if (!throttled && comment_store::has(ins.addr)) {
            std::string cmt_text = comment_store::get(ins.addr);
            if (!cmt_text.empty()) {
                float operand_w = (!throttled && cache.ops_valid)
                    ? cache.ops_total_width
                    : code_font->CalcTextSizeA(code_size, FLT_MAX, 0.f,
                        operand_render_cstr ? operand_render_cstr : "").x;
                float cmt_x = std::max(x_comment, x_operand + operand_w + 4.f * ch_w_safe);
                float cmt_max_w = (ox + width - 24.f) - cmt_x;
                if (cmt_max_w > 24.f) {
                    if (cache.cmt_trimmed_for_width != cmt_max_w
                        || cache.cmt_source != cmt_text) {
                        size_t cmt_nl = cmt_text.find('\n');
                        std::string cmt_first = (cmt_nl == std::string::npos) ? cmt_text : cmt_text.substr(0, cmt_nl);
                        bool cmt_multiline = (cmt_nl != std::string::npos);
                        std::string cmt_render = "; " + cmt_first;
                        bool cmt_truncated = cmt_multiline;
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
                        cache.cmt_source = cmt_text;
                    }
                    ImU32 cmt_col = aida::ui::with_alpha(disasm_theme::comment(), row_a_inner * 0.95f);
                    draw_text_at(cmt_x, y, cmt_col, cache.cmt_trimmed.c_str(), row_y_off);
                    if (cache.cmt_truncated) {
                        if (ImGui::IsMouseHoveringRect(ImVec2(cmt_x, y),
                            ImVec2(cmt_x + cache.cmt_drawn_width, y + line_h - 1.f), false))
                            ImGui::SetTooltip("%s", cmt_text.c_str());
                    }
                }
            }
        }

        const auto& after_rows_ref = *after_rows_ptr;
        if (!after_rows_ref.empty()) {
            for (size_t ai = 0; ai < after_rows_ref.size(); ++ai) {
                float yy = y + static_cast<float>(ai + 1) * line_h;
                if (yy + line_h < oy_content || yy > oy_content + content_height) continue;
                const auto& ar = after_rows_ref[ai];
                if (ar.kind == function_index::injection_t::spacer_line) {
                    draw_addr_prefix(yy, ar.addr, sec_name, row_a_inner * 0.55f, row_y_off);
                } else {
                    function_index::injection_row_t copy = ar;
                    draw_injection_row(yy, copy, sec_name);
                }
            }
        }

        if (row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            st.selected_row = i;
        }

        if (row_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            if ((ins.is_branch || ins.is_call) && ins.branch_target != 0) {
                goto_address(ins.branch_target, disasm);
            }
        }

        if (row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            st.ctx_row = i;
            ImGui::OpenPopup("##disasm_view_ctx");
        }

        (void)anchor_y;
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
            float fy = oy_content + static_cast<float>(bi) * line_h - st.scroll_y + line_h * 0.5f;
            float ty = oy_content + static_cast<float>(tidx) * line_h - st.scroll_y + line_h * 0.5f;
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


    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 6.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tk.bg_overlay));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImGui::ColorConvertU32ToFloat4(tk.hover_wash));

    if (ImGui::BeginPopup("##disasm_view_ctx")) {
        if (st.ctx_row >= 0 && st.ctx_row < n) {
            const AsmInstr& ci = instrs[st.ctx_row];


            if (ImGui::MenuItem("Copy Address")) {
                char buf[20];
                snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(ci.addr));
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), buf, strlen(buf) + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }


            if (ImGui::MenuItem("Copy Bytes")) {
                char buf[64] = {};
                int boff2 = 0;
                for (int b = 0; b < ci.len && boff2 + 3 < 64; b++)
                    boff2 += snprintf(buf + boff2, 64 - boff2, b ? " %02X" : "%02X", ci.raw[b]);
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), buf, strlen(buf) + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }


            if (ImGui::MenuItem("Copy Instruction")) {
                char buf[256];
                if (ci.ops[0])
                    snprintf(buf, sizeof(buf), "%016llX  %-8s %s",
                             static_cast<unsigned long long>(ci.addr), ci.mnem, ci.ops);
                else
                    snprintf(buf, sizeof(buf), "%016llX  %s",
                             static_cast<unsigned long long>(ci.addr), ci.mnem);
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), buf, strlen(buf) + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }

            ImGui::Separator();


            bool has_bm = false;
            int bm_idx = -1;
            for (int bi = 0; bi < static_cast<int>(st.bookmarks.size()); bi++) {
                if (st.bookmarks[bi].addr == ci.addr) { has_bm = true; bm_idx = bi; break; }
            }
            if (has_bm) {
                if (ImGui::MenuItem("Remove Bookmark")) {
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
                }
            }


            if (ci.is_branch || ci.is_call) {
                if (ImGui::MenuItem("Follow Target")) {
                    if (ci.branch_target != 0)
                        goto_address(ci.branch_target, disasm);
                }
            }

            ImGui::Separator();


            if (ImGui::MenuItem("VA Format", nullptr, st.addr_format == addr_format_t::va))
                st.addr_format = addr_format_t::va;
            if (ImGui::MenuItem("RVA Format", nullptr, st.addr_format == addr_format_t::rva))
                st.addr_format = addr_format_t::rva;

            if (ImGui::MenuItem("Show Bytes", nullptr, st.show_bytes))
                st.show_bytes = !st.show_bytes;

            ImGui::Separator();

            if (ImGui::MenuItem("Decompile Function")) {
                globals::ui::decompile_popup_addr = ci.addr;
                if (globals::ui::decompile_default_mode == 0) {
                    decompiler_engine::decompile_function(ci.addr, g_sa_settings);
                    globals::ui::active_center_view = center_view_t::decompiler;
                } else if (globals::ui::decompile_default_mode == 1) {
                    decompiler_engine::decompile_function_native(ci.addr);
                    globals::ui::active_center_view = center_view_t::decompiler;
                } else if (globals::ui::decompile_default_mode == 2) {
                    decompiler_engine::decompile_function_hybrid(ci.addr, g_sa_settings);
                    globals::ui::active_center_view = center_view_t::decompiler;
                } else {
                    globals::ui::show_decompile_popup = true;
                }
            }
            if (ImGui::MenuItem("Reconstruct Source")) {
                source_reconstruct_view::open();
            }
            if (ImGui::MenuItem("Generate AOB Signature")) {
                char addr_buf[32];
                snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(ci.addr));
                strncpy(aob_generator::g_state.address_input, addr_buf, sizeof(aob_generator::g_state.address_input) - 1);
                aob_generator::generate_from_address(ci.addr, aob_generator::g_state.instruction_count, aob_generator::g_state.auto_wildcard);
                scan_hub_view::set_sub_tab(scan_hub_view::sub_tab_t::aob);
                globals::ui::active_center_view = center_view_t::scan_hub;
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
            || disasm_hk_io.WantCaptureKeyboard
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
                    st.xref_popup_addr = addr;
                    {
                        std::string rn = rename_store::get(addr);
                        st.xref_popup_target_name = !rn.empty() ? rn : symbol_store::resolve_symbol(addr);
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
                    launch_xref_scan(addr);
                }
            }

            if (!comment_dialog::is_open() && ImGui::IsKeyPressed(ImGuiKey_Semicolon, false)) {
                uint64_t cmt_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < n)
                    cmt_addr = instrs[st.selected_row].addr;
                else if (n > 0)
                    cmt_addr = instrs[0].addr;
                if (cmt_addr != 0)
                    comment_dialog::open(cmt_addr);
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) {
                uint64_t cursor_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < n)
                    cursor_addr = instrs[st.selected_row].addr;
                else if (n > 0)
                    cursor_addr = instrs[0].addr;
                if (cursor_addr != 0) {
                    uint64_t entry = find_enclosing_function_start(cursor_addr, disasm.file);
                    if (entry == 0) entry = cursor_addr;
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
                } else {
                    uint64_t f5_entry = find_enclosing_function_start(f5_cursor_addr, disasm.file);
                    if (f5_entry == 0) {
                        output_log::push(bottom_tab_t::output,
                            "[disasm] F5: enclosing function not found; aborting decompile.");
                    } else {
                        globals::ui::decompile_popup_addr = f5_entry;
                        if (globals::ui::decompile_default_mode == 0) {
                            decompiler_engine::decompile_function(f5_entry, g_sa_settings);
                            globals::ui::active_center_view = center_view_t::decompiler;
                        } else if (globals::ui::decompile_default_mode == 1) {
                            decompiler_engine::decompile_function_native(f5_entry);
                            globals::ui::active_center_view = center_view_t::decompiler;
                        } else if (globals::ui::decompile_default_mode == 2) {
                            decompiler_engine::decompile_function_hybrid(f5_entry, g_sa_settings);
                            globals::ui::active_center_view = center_view_t::decompiler;
                        } else {
                            globals::ui::show_decompile_popup = true;
                        }
                    }
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
                    globals::ui::decompile_popup_addr = tab_addr;
                    if (globals::ui::decompile_default_mode == 0)
                        decompiler_engine::decompile_function(tab_addr, g_sa_settings);
                    else if (globals::ui::decompile_default_mode == 1)
                        decompiler_engine::decompile_function_native(tab_addr);
                    else
                        decompiler_engine::decompile_function_hybrid(tab_addr, g_sa_settings);
                    globals::ui::active_center_view = center_view_t::decompiler;
                }
            }

            if (!rename_dialog::is_open() && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
                int row = st.selected_row;
                uint64_t rename_addr = 0;
                if (row >= 0 && row < n)
                    rename_addr = instrs[row].addr;
                else if (n > 0)
                    rename_addr = instrs[0].addr;
                if (rename_addr != 0)
                    rename_dialog::open(rename_addr);
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
                goto_address(resolved_addr, disasm);
                st.goto_visible = false;
                st.goto_buf[0] = '\0';
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
        float bm_y = oy_content + content_height - 22.f;
        dl->AddRectFilled(ImVec2(ox, bm_y), ImVec2(ox + width, bm_y + 20.f),
                          _ta(tk.bg_base));


        float total_bm_w = 6.f;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            total_bm_w += ts.x + 12.f + 4.f;
        }
        float max_scroll = std::max(0.f, total_bm_w - width + 6.f);


        bool bm_bar_hov = ImGui::IsMouseHoveringRect(
            ImVec2(ox, bm_y), ImVec2(ox + width, bm_y + 20.f));
        if (bm_bar_hov && max_scroll > 0.f) {
            float wheel = ImGui::GetIO().MouseWheel;
            if (wheel != 0.f)
                st.bm_scroll_x = std::max(0.f, std::min(max_scroll, st.bm_scroll_x - wheel * 40.f));
        }
        if (st.bm_scroll_x > max_scroll) st.bm_scroll_x = max_scroll;

        float bm_x = ox + 6.f - st.bm_scroll_x;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            float btn_w = ts.x + 12.f;

            if (bm_x + btn_w >= ox && bm_x <= ox + width) {
                bool bm_hv = ImGui::IsMouseHoveringRect(
                    ImVec2(std::max(bm_x, ox), bm_y + 1.f),
                    ImVec2(std::min(bm_x + btn_w, ox + width), bm_y + 19.f));
                if (bm_hv)
                    dl->AddRectFilled(ImVec2(bm_x, bm_y + 1.f), ImVec2(bm_x + btn_w, bm_y + 19.f),
                                      aida::ui::with_alpha(tk.hover_wash, a), 3.f);
                dl->AddText(ImVec2(bm_x + 6.f, bm_y + 3.f),
                            aida::ui::with_alpha(tk.warning, a), bm.label.c_str());
                if (bm_hv && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                    goto_address(bm.addr, disasm);
            }
            bm_x += btn_w + 4.f;
        }


        if (st.bm_scroll_x > 0.f) {
            for (int gi = 0; gi < 20; gi++) {
                float ga = (1.f - gi / 20.f) * a;
                dl->AddLine(ImVec2(ox + static_cast<float>(gi), bm_y),
                            ImVec2(ox + static_cast<float>(gi), bm_y + 20.f),
                            aida::ui::with_alpha(tk.bg_base, ga));
            }
        }
        if (st.bm_scroll_x < max_scroll) {
            for (int gi = 0; gi < 20; gi++) {
                float ga = (1.f - gi / 20.f) * a;
                dl->AddLine(ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y),
                            ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y + 20.f),
                            aida::ui::with_alpha(tk.bg_base, ga));
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
        float total_content = n * line_h;
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

}
