#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "comparer.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida {
namespace burp {
namespace comparer {

namespace {

struct registry_t
{
    std::mutex                                              mtx;
    std::atomic<uint64_t>                                   next_id{1};
    std::unordered_map<uint64_t, slot_t>                    slots;
    std::mutex                                              err_mtx;
    std::string                                             last_err;
};

static registry_t g_reg;

static void set_last_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_reg.err_mtx);
    g_reg.last_err = msg;
}

static uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

template <typename Token>
struct token_view_t
{
    const std::vector<Token>* tokens = nullptr;
    bool                      reverse = false;
    size_t                    size_v = 0;

    size_t size() const { return size_v; }
    const Token& at(size_t i) const { return (*tokens)[i]; }
};

template <typename Token>
static std::vector<diff_block_t> myers_diff_tokens(
    const std::vector<Token>& a, const std::vector<Token>& b,
    const std::vector<size_t>& a_byte_offsets,
    const std::vector<size_t>& a_byte_lengths,
    const std::vector<size_t>& b_byte_offsets,
    const std::vector<size_t>& b_byte_lengths)
{
    std::vector<diff_block_t> out;
    size_t N = a.size();
    size_t M = b.size();
    if (N == 0 && M == 0) return out;

    if (N == 0) {
        diff_block_t bk;
        bk.kind = diff_block_t::kind_t::insert;
        bk.a_start = 0; bk.a_end = 0;
        bk.b_start = b_byte_offsets.empty() ? 0 : b_byte_offsets.front();
        size_t last = b.size() - 1;
        bk.b_end = b_byte_offsets[last] + b_byte_lengths[last];
        out.push_back(bk);
        return out;
    }
    if (M == 0) {
        diff_block_t bk;
        bk.kind = diff_block_t::kind_t::delete_;
        bk.a_start = a_byte_offsets.empty() ? 0 : a_byte_offsets.front();
        size_t last = a.size() - 1;
        bk.a_end = a_byte_offsets[last] + a_byte_lengths[last];
        bk.b_start = 0; bk.b_end = 0;
        out.push_back(bk);
        return out;
    }

    constexpr size_t kHardTokenCap = 4000;
    constexpr size_t kHardDCap = 1500;
    if (N > kHardTokenCap || M > kHardTokenCap) {
        diff_block_t bk;
        bk.kind = diff_block_t::kind_t::replace;
        bk.a_start = a_byte_offsets.front();
        bk.a_end   = a_byte_offsets.back() + a_byte_lengths.back();
        bk.b_start = b_byte_offsets.front();
        bk.b_end   = b_byte_offsets.back() + b_byte_lengths.back();
        out.push_back(bk);
        return out;
    }
    size_t max_d_total = N + M;
    size_t max_d = (max_d_total > kHardDCap) ? kHardDCap : max_d_total;

    size_t offset = max_d_total;
    size_t v_size = 2 * max_d_total + 1;
    std::vector<int64_t> V(v_size, -1);
    std::vector<std::vector<int64_t>> trace;
    trace.reserve(max_d + 1);

    V[offset + 1] = 0;
    int64_t final_d = -1;
    for (size_t d = 0; d <= max_d; ++d) {
        size_t snap_half = d;
        std::vector<int64_t> V_snap(2 * snap_half + 1, -1);
        for (size_t i = 0; i < V_snap.size(); ++i) {
            size_t src_idx = offset - snap_half + i;
            if (src_idx < V.size()) V_snap[i] = V[src_idx];
        }
        for (int64_t k = -static_cast<int64_t>(d); k <= static_cast<int64_t>(d); k += 2) {
            int64_t x;
            int64_t down = V[offset + k + 1];
            int64_t up   = (k - 1 >= -static_cast<int64_t>(d)) ? V[offset + k - 1] : -1;
            if (k == -static_cast<int64_t>(d) || (k != static_cast<int64_t>(d) && up < down)) {
                x = down;
            } else {
                x = up + 1;
            }
            int64_t y = x - k;
            while (x >= 0 && y >= 0 &&
                   static_cast<size_t>(x) < N && static_cast<size_t>(y) < M &&
                   a[static_cast<size_t>(x)] == b[static_cast<size_t>(y)]) {
                x++; y++;
            }
            V[offset + k] = x;
            if (static_cast<size_t>(x) >= N && static_cast<size_t>(y) >= M) {
                trace.push_back(std::move(V_snap));
                final_d = static_cast<int64_t>(d);
                d = max_d + 1;
                break;
            }
        }
        if (final_d >= 0) break;
        trace.push_back(std::move(V_snap));
    }

    if (final_d < 0) {
        diff_block_t bk;
        bk.kind = diff_block_t::kind_t::replace;
        bk.a_start = a_byte_offsets.front();
        bk.a_end   = a_byte_offsets.back() + a_byte_lengths.back();
        bk.b_start = b_byte_offsets.front();
        bk.b_end   = b_byte_offsets.back() + b_byte_lengths.back();
        out.push_back(bk);
        return out;
    }

    struct edit_t { int64_t prev_x; int64_t prev_y; int64_t x; int64_t y; bool snake; };
    std::vector<edit_t> edits;

    int64_t x = static_cast<int64_t>(N);
    int64_t y = static_cast<int64_t>(M);
    for (int64_t d = final_d; d > 0; --d) {
        const auto& Vd = trace[static_cast<size_t>(d)];
        int64_t snap_half = static_cast<int64_t>(d);
        int64_t snap_offset = snap_half;
        int64_t k = x - y;
        int64_t down_k = k + 1;
        int64_t up_k   = k - 1;
        int64_t prev_d = d - 1;
        bool down_in_range = (down_k >= -prev_d) && (down_k <= prev_d);
        bool up_in_range   = (up_k   >= -prev_d) && (up_k   <= prev_d);
        int64_t down_v = down_in_range ? Vd[static_cast<size_t>(snap_offset + down_k)] : -1;
        int64_t up_v   = up_in_range   ? Vd[static_cast<size_t>(snap_offset + up_k)]   : -1;
        bool down_choice;
        if (!up_in_range) {
            down_choice = true;
        } else if (!down_in_range) {
            down_choice = false;
        } else {
            down_choice = (down_v >= up_v);
        }
        int64_t prev_k = down_choice ? down_k : up_k;
        int64_t prev_x = Vd[static_cast<size_t>(snap_offset + prev_k)];
        if (prev_x < 0) prev_x = 0;
        int64_t prev_y = prev_x - prev_k;
        while (x > prev_x && y > prev_y) {
            edit_t e{x - 1, y - 1, x, y, true};
            edits.push_back(e);
            x--; y--;
        }
        if (d > 0) {
            edit_t e{prev_x, prev_y, x, y, false};
            edits.push_back(e);
            x = prev_x; y = prev_y;
        }
    }
    while (x > 0 && y > 0) {
        edit_t e{x - 1, y - 1, x, y, true};
        edits.push_back(e);
        x--; y--;
    }
    std::reverse(edits.begin(), edits.end());

    auto flush_block = [&](diff_block_t::kind_t kind, size_t a0, size_t a1, size_t b0, size_t b1) {
        diff_block_t bk;
        bk.kind = kind;
        bk.a_start = a0; bk.a_end = a1;
        bk.b_start = b0; bk.b_end = b1;
        out.push_back(bk);
    };

    diff_block_t::kind_t cur_kind = diff_block_t::kind_t::equal;
    size_t cur_a0 = 0, cur_a1 = 0, cur_b0 = 0, cur_b1 = 0;
    bool have_block = false;

    auto tok_a_byte_start = [&](int64_t idx) -> size_t {
        if (idx < 0 || static_cast<size_t>(idx) >= a_byte_offsets.size()) return 0;
        return a_byte_offsets[static_cast<size_t>(idx)];
    };
    auto tok_a_byte_end = [&](int64_t idx) -> size_t {
        if (idx < 0 || static_cast<size_t>(idx) >= a_byte_offsets.size()) return 0;
        return a_byte_offsets[static_cast<size_t>(idx)] + a_byte_lengths[static_cast<size_t>(idx)];
    };
    auto tok_b_byte_start = [&](int64_t idx) -> size_t {
        if (idx < 0 || static_cast<size_t>(idx) >= b_byte_offsets.size()) return 0;
        return b_byte_offsets[static_cast<size_t>(idx)];
    };
    auto tok_b_byte_end = [&](int64_t idx) -> size_t {
        if (idx < 0 || static_cast<size_t>(idx) >= b_byte_offsets.size()) return 0;
        return b_byte_offsets[static_cast<size_t>(idx)] + b_byte_lengths[static_cast<size_t>(idx)];
    };

    auto append_step = [&](diff_block_t::kind_t kind, size_t a0, size_t a1, size_t b0, size_t b1) {
        if (have_block && kind == cur_kind && cur_a1 == a0 && cur_b1 == b0) {
            cur_a1 = a1;
            cur_b1 = b1;
        } else {
            if (have_block) {
                flush_block(cur_kind, cur_a0, cur_a1, cur_b0, cur_b1);
            }
            cur_kind = kind;
            cur_a0 = a0; cur_a1 = a1;
            cur_b0 = b0; cur_b1 = b1;
            have_block = true;
        }
    };

    for (const auto& e : edits) {
        if (e.snake) {
            size_t a_start = tok_a_byte_start(e.prev_x);
            size_t a_end   = tok_a_byte_end(e.x - 1);
            size_t b_start = tok_b_byte_start(e.prev_y);
            size_t b_end   = tok_b_byte_end(e.y - 1);
            append_step(diff_block_t::kind_t::equal, a_start, a_end, b_start, b_end);
        } else {
            if (e.x > e.prev_x && e.y == e.prev_y) {
                size_t a_start = tok_a_byte_start(e.prev_x);
                size_t a_end   = tok_a_byte_end(e.x - 1);
                size_t b_pos   = (e.prev_y >= 0 && static_cast<size_t>(e.prev_y) < b_byte_offsets.size())
                                     ? tok_b_byte_start(e.prev_y)
                                     : (b_byte_offsets.empty() ? 0 : (b_byte_offsets.back() + b_byte_lengths.back()));
                append_step(diff_block_t::kind_t::delete_, a_start, a_end, b_pos, b_pos);
            } else if (e.y > e.prev_y && e.x == e.prev_x) {
                size_t b_start = tok_b_byte_start(e.prev_y);
                size_t b_end   = tok_b_byte_end(e.y - 1);
                size_t a_pos   = (e.prev_x >= 0 && static_cast<size_t>(e.prev_x) < a_byte_offsets.size())
                                     ? tok_a_byte_start(e.prev_x)
                                     : (a_byte_offsets.empty() ? 0 : (a_byte_offsets.back() + a_byte_lengths.back()));
                append_step(diff_block_t::kind_t::insert, a_pos, a_pos, b_start, b_end);
            }
        }
    }
    if (have_block) flush_block(cur_kind, cur_a0, cur_a1, cur_b0, cur_b1);

    std::vector<diff_block_t> collapsed;
    collapsed.reserve(out.size());
    for (const auto& bk : out) {
        if (!collapsed.empty()) {
            auto& last = collapsed.back();
            bool replace_pair = false;
            if ((last.kind == diff_block_t::kind_t::delete_ && bk.kind == diff_block_t::kind_t::insert) ||
                (last.kind == diff_block_t::kind_t::insert  && bk.kind == diff_block_t::kind_t::delete_)) {
                replace_pair = true;
            }
            if (replace_pair) {
                diff_block_t rep;
                rep.kind = diff_block_t::kind_t::replace;
                rep.a_start = std::min(last.a_start, bk.a_start);
                rep.a_end   = std::max(last.a_end,   bk.a_end);
                rep.b_start = std::min(last.b_start, bk.b_start);
                rep.b_end   = std::max(last.b_end,   bk.b_end);
                collapsed.pop_back();
                collapsed.push_back(rep);
                continue;
            }
        }
        collapsed.push_back(bk);
    }

    return collapsed;
}

static void tokenize_bytes(const std::vector<uint8_t>& data,
    std::vector<uint64_t>& tokens,
    std::vector<size_t>& offsets,
    std::vector<size_t>& lengths)
{
    tokens.reserve(data.size());
    offsets.reserve(data.size());
    lengths.reserve(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        tokens.push_back(static_cast<uint64_t>(data[i]));
        offsets.push_back(i);
        lengths.push_back(1);
    }
}

static size_t utf8_decode(const uint8_t* p, size_t avail, uint32_t& cp_out)
{
    if (avail == 0) { cp_out = 0; return 0; }
    uint8_t c0 = p[0];
    if (c0 < 0x80) { cp_out = c0; return 1; }
    if ((c0 & 0xE0) == 0xC0 && avail >= 2 && (p[1] & 0xC0) == 0x80) {
        cp_out = (static_cast<uint32_t>(c0 & 0x1F) << 6) | static_cast<uint32_t>(p[1] & 0x3F);
        return 2;
    }
    if ((c0 & 0xF0) == 0xE0 && avail >= 3 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
        cp_out = (static_cast<uint32_t>(c0 & 0x0F) << 12) |
                 (static_cast<uint32_t>(p[1] & 0x3F) << 6) |
                 static_cast<uint32_t>(p[2] & 0x3F);
        return 3;
    }
    if ((c0 & 0xF8) == 0xF0 && avail >= 4 &&
        (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
        cp_out = (static_cast<uint32_t>(c0 & 0x07) << 18) |
                 (static_cast<uint32_t>(p[1] & 0x3F) << 12) |
                 (static_cast<uint32_t>(p[2] & 0x3F) << 6) |
                 static_cast<uint32_t>(p[3] & 0x3F);
        return 4;
    }
    cp_out = c0;
    return 1;
}

static void tokenize_chars(const std::vector<uint8_t>& data,
    std::vector<uint32_t>& tokens,
    std::vector<size_t>& offsets,
    std::vector<size_t>& lengths)
{
    size_t i = 0;
    while (i < data.size()) {
        uint32_t cp = 0;
        size_t n = utf8_decode(data.data() + i, data.size() - i, cp);
        if (n == 0) break;
        tokens.push_back(cp);
        offsets.push_back(i);
        lengths.push_back(n);
        i += n;
    }
}

static void tokenize_lines(const std::vector<uint8_t>& data,
    std::vector<std::string>& tokens,
    std::vector<size_t>& offsets,
    std::vector<size_t>& lengths)
{
    size_t i = 0;
    while (i < data.size()) {
        size_t start = i;
        while (i < data.size() && data[i] != '\n') i++;
        size_t end = i;
        if (i < data.size() && data[i] == '\n') { i++; end = i; }
        offsets.push_back(start);
        lengths.push_back(end - start);
        tokens.emplace_back(reinterpret_cast<const char*>(data.data() + start), end - start);
    }
}

static void tokenize_words(const std::vector<uint8_t>& data,
    std::vector<std::string>& tokens,
    std::vector<size_t>& offsets,
    std::vector<size_t>& lengths)
{
    auto is_word = [](uint8_t c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
    };
    size_t i = 0;
    while (i < data.size()) {
        size_t start = i;
        if (is_word(data[i])) {
            while (i < data.size() && is_word(data[i])) i++;
        } else {
            while (i < data.size() && !is_word(data[i])) i++;
        }
        offsets.push_back(start);
        lengths.push_back(i - start);
        tokens.emplace_back(reinterpret_cast<const char*>(data.data() + start), i - start);
    }
}

constexpr size_t kMyersWindow = 32 * 1024;

static std::vector<uint8_t> trim_to_window(const std::vector<uint8_t>& data, bool& truncated)
{
    if (data.size() <= kMyersWindow) {
        truncated = false;
        return data;
    }
    truncated = true;
    return std::vector<uint8_t>(data.begin(), data.begin() + static_cast<ptrdiff_t>(kMyersWindow));
}

static std::vector<diff_block_t> compute_diff_impl(const std::vector<uint8_t>& a_full, const std::vector<uint8_t>& b_full,
                                                   diff_mode_t mode, diff_stats_t& stats)
{
    diag::log_tagged_fmt("comparer", "compute_diff_impl entry a_full=%zu b_full=%zu mode=%d",
        a_full.size(), b_full.size(), (int)mode);
    bool ta = false, tb = false;
    std::vector<uint8_t> a = trim_to_window(a_full, ta);
    std::vector<uint8_t> b = trim_to_window(b_full, tb);
    stats.truncated = ta || tb;
    stats.window_used = std::max(a.size(), b.size());
    stats.a_size = a.size();
    stats.b_size = b.size();
    if (ta || tb) {
        diag::log_tagged_fmt("comparer", "compute_diff_impl truncated a_orig=%zu b_orig=%zu window=%zu",
            a_full.size(), b_full.size(), kMyersWindow);
    }

    std::vector<diff_block_t> blocks;
    switch (mode) {
        case diff_mode_t::bytes: {
            std::vector<uint64_t> ta_tok, tb_tok;
            std::vector<size_t> ao, al, bo, bl;
            tokenize_bytes(a, ta_tok, ao, al);
            tokenize_bytes(b, tb_tok, bo, bl);
            blocks = myers_diff_tokens<uint64_t>(ta_tok, tb_tok, ao, al, bo, bl);
            break;
        }
        case diff_mode_t::chars: {
            std::vector<uint32_t> ta_tok, tb_tok;
            std::vector<size_t> ao, al, bo, bl;
            tokenize_chars(a, ta_tok, ao, al);
            tokenize_chars(b, tb_tok, bo, bl);
            blocks = myers_diff_tokens<uint32_t>(ta_tok, tb_tok, ao, al, bo, bl);
            break;
        }
        case diff_mode_t::words: {
            std::vector<std::string> ta_tok, tb_tok;
            std::vector<size_t> ao, al, bo, bl;
            tokenize_words(a, ta_tok, ao, al);
            tokenize_words(b, tb_tok, bo, bl);
            blocks = myers_diff_tokens<std::string>(ta_tok, tb_tok, ao, al, bo, bl);
            break;
        }
        case diff_mode_t::lines: {
            std::vector<std::string> ta_tok, tb_tok;
            std::vector<size_t> ao, al, bo, bl;
            tokenize_lines(a, ta_tok, ao, al);
            tokenize_lines(b, tb_tok, bo, bl);
            blocks = myers_diff_tokens<std::string>(ta_tok, tb_tok, ao, al, bo, bl);
            break;
        }
    }

    stats.equal_runs = stats.insert_runs = stats.delete_runs = stats.replace_runs = 0;
    stats.bytes_equal = stats.bytes_inserted = stats.bytes_deleted = stats.bytes_replaced = 0;
    for (const auto& bk : blocks) {
        switch (bk.kind) {
            case diff_block_t::kind_t::equal:
                stats.equal_runs++;
                stats.bytes_equal += (bk.a_end - bk.a_start);
                break;
            case diff_block_t::kind_t::insert:
                stats.insert_runs++;
                stats.bytes_inserted += (bk.b_end - bk.b_start);
                break;
            case diff_block_t::kind_t::delete_:
                stats.delete_runs++;
                stats.bytes_deleted += (bk.a_end - bk.a_start);
                break;
            case diff_block_t::kind_t::replace:
                stats.replace_runs++;
                stats.bytes_replaced += std::max((bk.a_end - bk.a_start), (bk.b_end - bk.b_start));
                break;
        }
    }
    return blocks;
}

}

uint64_t add_slot(const slot_t& s)
{
    slot_t copy = s;
    if (copy.id == 0) copy.id = g_reg.next_id.fetch_add(1);
    if (copy.created_ms == 0) copy.created_ms = now_ms();
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        g_reg.slots[copy.id] = copy;
    }
    ::diag::log_tagged_fmt("comparer", "slot_added id=%llu label='%s' size=%zu",
        static_cast<unsigned long long>(copy.id), copy.label.c_str(), copy.data.size());
    return copy.id;
}

uint64_t add_slot_from_bytes(const std::string& label, const std::vector<uint8_t>& data, const std::string& source_hint)
{
    diag::log_tagged_fmt("comparer", "add_slot_from_bytes entry label='%s' data_len=%zu source='%s'",
        label.c_str(), data.size(), source_hint.c_str());
    slot_t s;
    s.label = label.empty() ? ("Slot " + std::to_string(g_reg.next_id.load())) : label;
    s.data = data;
    s.source_hint = source_hint;
    uint64_t id = add_slot(s);
    diag::log_tagged_fmt("comparer", "add_slot_from_bytes ok id=%llu", static_cast<unsigned long long>(id));
    return id;
}

bool add_slot_from_file(const std::string& label, const std::string& path)
{
    diag::log_tagged_fmt("comparer", "add_slot_from_file entry label='%s' path='%s'", label.c_str(), path.c_str());
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        diag::log_tagged_fmt("comparer", "add_slot_from_file error open_failed path='%s'", path.c_str());
        set_last_error("file_open_failed");
        return false;
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    diag::log_tagged_fmt("comparer", "add_slot_from_file read_ok bytes=%zu path='%s'", buf.size(), path.c_str());
    add_slot_from_bytes(label.empty() ? path : label, buf, std::string("file:") + path);
    return true;
}

std::vector<slot_t> list_slots()
{
    diag::log_tagged_fmt("comparer", "list_slots entry");
    std::vector<slot_t> out;
    std::lock_guard<std::mutex> lk(g_reg.mtx);
    out.reserve(g_reg.slots.size());
    for (const auto& kv : g_reg.slots) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const slot_t& a, const slot_t& b) { return a.id < b.id; });
    diag::log_tagged_fmt("comparer", "list_slots result count=%zu", out.size());
    return out;
}

bool get_slot(uint64_t id, slot_t& out)
{
    diag::log_tagged_fmt("comparer", "get_slot entry id=%llu", static_cast<unsigned long long>(id));
    std::lock_guard<std::mutex> lk(g_reg.mtx);
    auto it = g_reg.slots.find(id);
    if (it == g_reg.slots.end()) {
        diag::log_tagged_fmt("comparer", "get_slot not_found id=%llu", static_cast<unsigned long long>(id));
        return false;
    }
    out = it->second;
    diag::log_tagged_fmt("comparer", "get_slot found id=%llu label='%s' size=%zu",
        static_cast<unsigned long long>(id), out.label.c_str(), out.data.size());
    return true;
}

void clear_slots()
{
    diag::log_tagged_fmt("comparer", "clear_slots entry");
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        count = g_reg.slots.size();
        g_reg.slots.clear();
    }
    diag::log_tagged_fmt("comparer", "clear_slots done cleared=%zu", count);
}

bool remove_slot(uint64_t id)
{
    diag::log_tagged_fmt("comparer", "remove_slot entry id=%llu", static_cast<unsigned long long>(id));
    std::lock_guard<std::mutex> lk(g_reg.mtx);
    auto it = g_reg.slots.find(id);
    if (it == g_reg.slots.end()) {
        diag::log_tagged_fmt("comparer", "remove_slot not_found id=%llu", static_cast<unsigned long long>(id));
        return false;
    }
    g_reg.slots.erase(it);
    diag::log_tagged_fmt("comparer", "remove_slot ok id=%llu", static_cast<unsigned long long>(id));
    return true;
}

std::vector<diff_block_t> compute_diff(uint64_t slot_a, uint64_t slot_b, diff_mode_t mode)
{
    diag::log_tagged_fmt("comparer", "compute_diff entry slot_a=%llu slot_b=%llu",
        static_cast<unsigned long long>(slot_a), static_cast<unsigned long long>(slot_b));
    diff_stats_t stats;
    auto result = compute_diff_with_stats(slot_a, slot_b, mode, stats);
    diag::log_tagged_fmt("comparer", "compute_diff result blocks=%zu", result.size());
    return result;
}

std::vector<diff_block_t> compute_diff_with_stats(uint64_t slot_a, uint64_t slot_b, diff_mode_t mode, diff_stats_t& stats)
{
    diag::log_tagged_fmt("comparer", "compute_diff_with_stats entry slot_a=%llu slot_b=%llu mode=%d",
        static_cast<unsigned long long>(slot_a), static_cast<unsigned long long>(slot_b), (int)mode);
    slot_t a;
    slot_t b;
    if (!get_slot(slot_a, a)) {
        diag::log_tagged_fmt("comparer", "compute_diff_with_stats error slot_a_not_found id=%llu", static_cast<unsigned long long>(slot_a));
        set_last_error("slot_a_not_found");
        return {};
    }
    if (!get_slot(slot_b, b)) {
        diag::log_tagged_fmt("comparer", "compute_diff_with_stats error slot_b_not_found id=%llu", static_cast<unsigned long long>(slot_b));
        set_last_error("slot_b_not_found");
        return {};
    }
    diag::log_tagged_fmt("comparer", "compute_diff_with_stats a_size=%zu b_size=%zu", a.data.size(), b.data.size());
    auto result = compute_diff_impl(a.data, b.data, mode, stats);
    diag::log_tagged_fmt("comparer", "compute_diff_with_stats done blocks=%zu equal=%zu insert=%zu delete=%zu replace=%zu",
        result.size(), stats.equal_runs, stats.insert_runs, stats.delete_runs, stats.replace_runs);
    return result;
}

std::string last_error()
{
    diag::log_tagged_fmt("comparer", "last_error queried");
    std::lock_guard<std::mutex> lk(g_reg.err_mtx);
    return g_reg.last_err;
}

}
}
}
