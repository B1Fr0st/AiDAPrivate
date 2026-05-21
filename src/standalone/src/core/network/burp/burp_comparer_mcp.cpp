#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_comparer_mcp.hpp"
#include "comparer.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace comparer_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

std::vector<uint8_t> b64_decode(const std::string& s)
{
    std::vector<uint8_t> out;
    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    int val = 0;
    int valb = -8;
    for (uint8_t c : s) {
        int v = table[c];
        if (v < 0) {
            if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
            return {};
        }
        val = (val << 6) | v;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

static const char* kind_name(aida::burp::comparer::diff_block_t::kind_t k)
{
    switch (k) {
        case aida::burp::comparer::diff_block_t::kind_t::equal:   return "equal";
        case aida::burp::comparer::diff_block_t::kind_t::insert:  return "insert";
        case aida::burp::comparer::diff_block_t::kind_t::delete_: return "delete";
        case aida::burp::comparer::diff_block_t::kind_t::replace: return "replace";
    }
    return "?";
}

static aida::burp::comparer::diff_mode_t parse_mode(const std::string& s)
{
    if (s == "bytes") return aida::burp::comparer::diff_mode_t::bytes;
    if (s == "chars" || s == "raw_chars") return aida::burp::comparer::diff_mode_t::chars;
    if (s == "words") return aida::burp::comparer::diff_mode_t::words;
    return aida::burp::comparer::diff_mode_t::lines;
}

tool_result_t handle_add_slot(const json& p)
{
    std::string label = (p.contains("label") && p["label"].is_string()) ? p["label"].get<std::string>() : "Slot";
    std::string hint  = (p.contains("source_hint") && p["source_hint"].is_string()) ? p["source_hint"].get<std::string>() : "mcp";
    diag::log_tagged_fmt("mcp_burp", "comparer_add_slot label=%s hint=%s", label.c_str(), hint.c_str());

    std::vector<uint8_t> data;
    if (p.contains("data_b64") && p["data_b64"].is_string()) {
        data = b64_decode(p["data_b64"].get<std::string>());
    } else if (p.contains("data_text") && p["data_text"].is_string()) {
        const std::string& s = p["data_text"].get_ref<const std::string&>();
        data.assign(s.begin(), s.end());
    } else {
        diag::log_tagged_fmt("mcp_burp", "comparer_add_slot missing data");
        return tool_result_t::error("data_b64 or data_text required");
    }
    uint64_t id = aida::burp::comparer::add_slot_from_bytes(label, data, hint);
    diag::log_tagged_fmt("mcp_burp", "comparer_add_slot ok slot_id=%llu bytes=%zu", static_cast<unsigned long long>(id), data.size());
    json out;
    out["slot_id"] = id;
    return tool_result_t::ok("slot added", out);
}

tool_result_t handle_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "comparer_list entry");
    auto v = aida::burp::comparer::list_slots();
    json arr = json::array();
    for (const auto& s : v) {
        json e;
        e["id"]         = s.id;
        e["label"]      = s.label;
        e["size"]       = static_cast<uint64_t>(s.data.size());
        e["source_hint"] = s.source_hint;
        e["created_ms"] = static_cast<uint64_t>(s.created_ms);
        arr.push_back(std::move(e));
    }
    diag::log_tagged_fmt("mcp_burp", "comparer_list ok count=%zu", v.size());
    json out;
    out["slots"] = std::move(arr);
    return tool_result_t::ok("slots", out);
}

tool_result_t handle_remove(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "comparer_remove entry");
    if (!p.contains("slot_id") || !p["slot_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "comparer_remove missing slot_id");
        return tool_result_t::error("slot_id required");
    }
    const uint64_t sid = p["slot_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "comparer_remove slot_id=%llu", static_cast<unsigned long long>(sid));
    bool ok = aida::burp::comparer::remove_slot(sid);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "comparer_remove not_found id=%llu", static_cast<unsigned long long>(sid));
        return tool_result_t::error("slot not found");
    }
    diag::log_tagged_fmt("mcp_burp", "comparer_remove ok slot_id=%llu", static_cast<unsigned long long>(sid));
    return tool_result_t::ok("slot removed");
}

tool_result_t handle_clear(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "comparer_clear entry");
    aida::burp::comparer::clear_slots();
    diag::log_tagged_fmt("mcp_burp", "comparer_clear ok");
    return tool_result_t::ok("cleared");
}

tool_result_t handle_diff(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "comparer_diff entry");
    if (!p.contains("slot_a") || !p["slot_a"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "comparer_diff missing slot_a");
        return tool_result_t::error("slot_a required");
    }
    if (!p.contains("slot_b") || !p["slot_b"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "comparer_diff missing slot_b");
        return tool_result_t::error("slot_b required");
    }

    const uint64_t sa = p["slot_a"].get<uint64_t>();
    const uint64_t sb = p["slot_b"].get<uint64_t>();
    aida::burp::comparer::diff_mode_t mode = aida::burp::comparer::diff_mode_t::lines;
    if (p.contains("mode") && p["mode"].is_string()) mode = parse_mode(p["mode"].get<std::string>());
    diag::log_tagged_fmt("mcp_burp", "comparer_diff slot_a=%llu slot_b=%llu mode=%s", static_cast<unsigned long long>(sa), static_cast<unsigned long long>(sb), p.value("mode", std::string("lines")).c_str());

    aida::burp::comparer::diff_stats_t stats;
    auto blocks = aida::burp::comparer::compute_diff_with_stats(sa, sb, mode, stats);
    diag::log_tagged_fmt("mcp_burp", "comparer_diff ok blocks=%zu truncated=%d", blocks.size(), (int)stats.truncated);

    json arr = json::array();
    for (const auto& b : blocks) {
        json e;
        e["kind"]    = kind_name(b.kind);
        e["a_start"] = static_cast<uint64_t>(b.a_start);
        e["a_end"]   = static_cast<uint64_t>(b.a_end);
        e["b_start"] = static_cast<uint64_t>(b.b_start);
        e["b_end"]   = static_cast<uint64_t>(b.b_end);
        arr.push_back(std::move(e));
    }
    json st;
    st["equal_runs"]     = static_cast<uint64_t>(stats.equal_runs);
    st["insert_runs"]    = static_cast<uint64_t>(stats.insert_runs);
    st["delete_runs"]    = static_cast<uint64_t>(stats.delete_runs);
    st["replace_runs"]   = static_cast<uint64_t>(stats.replace_runs);
    st["bytes_equal"]    = static_cast<uint64_t>(stats.bytes_equal);
    st["bytes_inserted"] = static_cast<uint64_t>(stats.bytes_inserted);
    st["bytes_deleted"]  = static_cast<uint64_t>(stats.bytes_deleted);
    st["bytes_replaced"] = static_cast<uint64_t>(stats.bytes_replaced);
    st["a_size"]         = static_cast<uint64_t>(stats.a_size);
    st["b_size"]         = static_cast<uint64_t>(stats.b_size);
    st["truncated"]      = stats.truncated;
    st["window_used"]    = static_cast<uint64_t>(stats.window_used);

    json out;
    out["blocks"] = std::move(arr);
    out["stats"]  = std::move(st);
    return tool_result_t::ok("diff computed", out);
}

}

void register_comparer_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_comparer_add_slot", "burp",
        "Add a slot to the Comparer pool. Provide either base64-encoded bytes (for binary), or plain text. "
        "Slots can later be diffed against each other using bytes / chars / words / lines tokenisation.",
        {{"label",       "string", "Human label for the slot", false},
         {"data_b64",    "string", "Base64-encoded raw bytes (preferred for binary payloads)", false},
         {"data_text",   "string", "UTF-8 plain text", false},
         {"source_hint", "string", "Where the data came from (e.g. 'repeater', 'sitemap_response')", false}},
        handle_add_slot, false
    });

    register_compat(srv, {
        "burp_comparer_list_slots", "burp",
        "List all slots currently held by the Comparer (id, label, size, source hint, creation time).",
        {},
        handle_list, true
    });

    register_compat(srv, {
        "burp_comparer_remove_slot", "burp",
        "Remove a single slot by id.",
        {{"slot_id", "number", "Slot id to delete", true}},
        handle_remove, false
    });

    register_compat(srv, {
        "burp_comparer_clear", "burp",
        "Delete every slot.",
        {},
        handle_clear, false
    });

    register_compat(srv, {
        "burp_comparer_diff", "burp",
        "Compute a Myers shortest-edit-script diff between slot_a and slot_b. Returns blocks { kind, a_start, a_end, b_start, b_end } "
        "with byte offsets into the original slot data. Modes: 'bytes' (per-byte), 'chars' (UTF-8 code point), "
        "'words' (alnum-or-underscore runs), 'lines' (newline-separated). Inputs above ~32 KiB are clamped to a window with "
        "'truncated' set in stats.",
        {{"slot_a", "number", "First slot id", true},
         {"slot_b", "number", "Second slot id", true},
         {"mode",   "string", "'bytes' | 'chars' | 'words' | 'lines' (default 'lines')", false}},
        handle_diff, true
    });
}

}
}
}
