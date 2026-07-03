#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "site_map.hpp"
#include "burp_logger.hpp"
#include "scope.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../infra/event_bus.hpp"
#include "../../infra/work_queue.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>

namespace aida {
namespace burp {
namespace sitemap {

namespace {

struct host_key_t
{
    std::string host;
    uint16_t    port = 0;
    bool        tls = false;
    bool operator<(const host_key_t& o) const noexcept
    {
        if (host != o.host) return host < o.host;
        if (port != o.port) return port < o.port;
        return tls < o.tls;
    }
};

struct state_t
{
    std::mutex                                       mtx;
    std::map<host_key_t, std::shared_ptr<host_node_t>> hosts;
    std::map<uint64_t, exchange_observed_t>          by_id;
    std::atomic<uint64_t>                            next_id{1};
    std::atomic<uint64_t>                            selected_exchange_id{0};
    std::atomic<bool>                                initialized{false};
    aida::events::subscription_handle_t              exchange_sub;
    std::mutex                                       err_mtx;
    std::string                                      last_err;

    char                                             tree_filter[256] = {};
    std::string                                      selected_host;
    uint16_t                                         selected_port = 0;
    bool                                             selected_tls = false;
    std::string                                      selected_path;
    int                                              right_tab = 0;
    int                                              detail_tab = 0;
    float                                            split_left = 0.32f;
    std::set<std::string>                            expanded_paths;
};

state_t& s()
{
    static state_t st;
    return st;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

void split_path_segments(const std::string& path, std::vector<std::string>& out)
{
    out.clear();
    size_t i = 0;
    if (path.empty() || path[0] != '/') { out.emplace_back("/"); return; }
    while (i < path.size()) {
        if (path[i] == '/') { ++i; continue; }
        size_t end = path.find('/', i);
        if (end == std::string::npos) { out.emplace_back(path.substr(i)); break; }
        out.emplace_back(path.substr(i, end - i));
        i = end + 1;
    }
}

std::string find_resp_header(const exchange_observed_t& e, const std::string& name)
{
    for (const auto& kv : e.resp_headers) {
        if (kv.first.size() != name.size()) continue;
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i) {
            const char a = static_cast<char>(kv.first[i] | 0x20);
            const char b = static_cast<char>(name[i] | 0x20);
            if (a != b) { match = false; break; }
        }
        if (match) return kv.second;
    }
    return {};
}

void insert_into_tree(state_t& st, const exchange_observed_t& e)
{
    host_key_t key{e.host, e.port, e.scheme == "https" || e.scheme == "wss"};
    auto it = st.hosts.find(key);
    if (it == st.hosts.end()) {
        auto h = std::make_shared<host_node_t>();
        h->host = e.host;
        h->port = e.port;
        h->tls  = key.tls;
        h->root = std::make_shared<path_node_t>();
        h->root->segment = "/";
        h->in_scope = scope::in_scope_components(e.scheme, e.host, e.port, e.path);
        h->total_requests = 0;
        h->issue_count = 0;
        it = st.hosts.emplace(key, h).first;
    }
    auto host = it->second;
    host->last_seen_ms = e.timestamp_ms != 0 ? e.timestamp_ms : now_ms();
    host->total_requests++;
    if (e.status_code >= 500) host->issue_count++;

    std::vector<std::string> segs;
    split_path_segments(e.path, segs);

    auto cur = host->root;
    cur->total_requests++;
    cur->last_seen_ms = host->last_seen_ms;
    cur->in_scope = scope::in_scope_components(e.scheme, e.host, e.port, e.path);

    for (const auto& seg : segs) {
        auto sit = cur->children.find(seg);
        if (sit == cur->children.end()) {
            auto n = std::make_shared<path_node_t>();
            n->segment = seg;
            sit = cur->children.emplace(seg, n).first;
        }
        cur = sit->second;
        cur->total_requests++;
        cur->last_seen_ms = host->last_seen_ms;
        cur->in_scope = scope::in_scope_components(e.scheme, e.host, e.port, e.path);
        cur->last_status = e.status_code;
    }

    cur->exchanges.push_back(e);
    if (cur->exchanges.size() > 512) {
        cur->exchanges.erase(cur->exchanges.begin(), cur->exchanges.begin() + (cur->exchanges.size() - 512));
    }
    st.by_id[e.id] = e;
    if (st.by_id.size() > 65536) {
        st.by_id.erase(st.by_id.begin());
    }
}

std::string normalized_source(const exchange_observed_t& e);
std::string source_label_for(const exchange_observed_t& e);

void store_exchange(exchange_observed_t e)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    if (e.id == 0) e.id = st.next_id.fetch_add(1);
    if (e.timestamp_ms == 0) e.timestamp_ms = now_ms();
    const std::string source = normalized_source(e);
    const std::string label = source_label_for(e);
    diag::log_tagged_fmt("burp", "site_map_store_exchange id=%llu source=%s source_label=%s host=%s path=%s status=%d",
        static_cast<unsigned long long>(e.id),
        source.c_str(),
        label.c_str(),
        e.host.c_str(),
        e.path.c_str(),
        e.status_code);
    insert_into_tree(st, e);
}

void handle_exchange(const exchange_observed_t& evt)
{
    if (!work_queue::post([evt]() { store_exchange(evt); })) {
        diag::log_tagged("burp", "site_map_async_post_failed_sync_store");
        store_exchange(evt);
    }
}

std::string path_join(const std::string& parent, const std::string& seg)
{
    if (parent.empty() || parent == "/") return std::string("/") + (seg == "/" ? std::string() : seg);
    if (seg == "/") return parent;
    return parent + "/" + seg;
}

std::string normalized_source(const exchange_observed_t& e)
{
    return e.source.empty() ? std::string("proxy") : e.source;
}

std::string source_label_for(const exchange_observed_t& e)
{
    const std::string source = normalized_source(e);
    logger::source_t src = logger::source_t::proxy;
    if (logger::parse_source(source, src)) return logger::source_label(src);
    return source;
}

}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    st.exchange_sub = aida::events::subscribe(kExchangeObservedEvent,
        [](const exchange_observed_t& e) { handle_exchange(e); });
    diag::log_tagged("burp", "site_map_initialized");
    return true;
}

void shutdown()
{
    auto& st = s();
    if (!st.initialized.exchange(false)) return;
    if (st.exchange_sub.valid()) aida::events::unsubscribe(st.exchange_sub);
}

void ingest_exchange(const exchange_observed_t& e)
{
    store_exchange(e);
}

uint64_t get_selected_exchange_id()
{
    return s().selected_exchange_id.load();
}

void set_selected_exchange_id(uint64_t id)
{
    s().selected_exchange_id.store(id);
}

void clear_selection()
{
    auto& st = s();
    st.selected_exchange_id.store(0);
    std::lock_guard<std::mutex> lk(st.mtx);
    st.selected_host.clear();
    st.selected_port = 0;
    st.selected_tls = false;
    st.selected_path.clear();
}

bool find_exchange(uint64_t id, exchange_observed_t& out)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    const auto it = st.by_id.find(id);
    if (it == st.by_id.end()) return false;
    out = it->second;
    return true;
}

std::vector<exchange_observed_t> list_exchanges_for(const std::string& host, uint16_t port, const std::string& path)
{
    auto& st = s();
    std::vector<exchange_observed_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& kv : st.hosts) {
        if (kv.first.host != host || (port != 0 && kv.first.port != port)) continue;
        std::vector<std::string> segs;
        split_path_segments(path, segs);
        auto cur = kv.second->root;
        bool ok = true;
        for (const auto& seg : segs) {
            auto sit = cur->children.find(seg);
            if (sit == cur->children.end()) { ok = false; break; }
            cur = sit->second;
        }
        if (ok && cur) out.insert(out.end(), cur->exchanges.begin(), cur->exchanges.end());
    }
    return out;
}

std::vector<exchange_observed_t> list_all_exchanges()
{
    auto& st = s();
    std::vector<exchange_observed_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    out.reserve(st.by_id.size());
    for (const auto& kv : st.by_id)
        out.push_back(kv.second);
    return out;
}

bool import_exchanges(const std::vector<exchange_observed_t>& exchanges, bool replace_existing)
{
    if (replace_existing)
        clear_all();
    for (const auto& exchange : exchanges)
        ingest_exchange(exchange);
    return true;
}

std::vector<host_summary_t> list_hosts(bool scope_only)
{
    auto& st = s();
    std::vector<host_summary_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& kv : st.hosts) {
        const auto& h = *kv.second;
        if (scope_only && !h.in_scope) continue;
        host_summary_t hs;
        hs.host = h.host;
        hs.port = h.port;
        hs.tls  = h.tls;
        hs.in_scope = h.in_scope;
        hs.total_requests = h.total_requests;
        hs.issue_count = h.issue_count;
        out.push_back(hs);
    }
    return out;
}

namespace {
void collect_paths_rec(const std::shared_ptr<path_node_t>& n, const std::string& prefix, std::vector<std::string>& out)
{
    if (!n) return;
    const std::string here = (prefix.empty() && n->segment == "/") ? std::string("/") : path_join(prefix, n->segment);
    if (!n->exchanges.empty()) out.push_back(here);
    for (const auto& c : n->children) collect_paths_rec(c.second, here, out);
}
}

std::vector<std::string> list_paths(const std::string& host, uint16_t port)
{
    auto& st = s();
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& kv : st.hosts) {
        if (kv.first.host != host || (port != 0 && kv.first.port != port)) continue;
        collect_paths_rec(kv.second->root, std::string(), out);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

void send_to(uint64_t exchange_id, const std::string& target, const std::string& source_view)
{
    send_to_action_t evt;
    evt.exchange_id = exchange_id;
    evt.target = target;
    evt.source_view = source_view;
    aida::events::publish(kSendToActionEvent, evt);
    diag::log_tagged_fmt("burp", "site_map_send_to id=%llu target=%s",
        static_cast<unsigned long long>(exchange_id), target.c_str());
}

namespace {

std::string base64_encode(const std::vector<uint8_t>& data)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < data.size()) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) |
                            static_cast<uint32_t>(data[i + 2]);
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back(tbl[(v >> 6) & 0x3F]);
        out.push_back(tbl[v & 0x3F]);
        i += 3;
    }
    if (i < data.size()) {
        const size_t rem = data.size() - i;
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (rem > 1) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back(rem > 1 ? tbl[(v >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

}

nlohmann::json exchange_to_json(const exchange_observed_t& e, bool include_bodies)
{
    nlohmann::json j;
    j["id"]            = e.id;
    j["timestamp_ms"]  = e.timestamp_ms;
    j["method"]        = e.method;
    j["scheme"]        = e.scheme;
    j["host"]          = e.host;
    j["port"]          = e.port;
    j["path"]          = e.path;
    j["query"]         = e.query;
    j["status_code"]   = e.status_code;
    j["reason"]        = e.reason_phrase;
    j["latency_ms"]    = e.latency_ms;
    j["is_websocket"]  = e.is_websocket;
    j["is_h2"]         = e.is_h2;
    j["tls_version"]   = e.tls_version;
    j["alpn"]          = e.alpn;
    j["client_addr"]   = e.client_addr;
    j["client_port"]   = e.client_port;
    j["source"]        = normalized_source(e);
    j["source_label"]  = source_label_for(e);

    nlohmann::json rh = nlohmann::json::array();
    for (const auto& kv : e.req_headers) {
        nlohmann::json h;
        h["name"]  = kv.first;
        h["value"] = kv.second;
        rh.push_back(h);
    }
    j["request_headers"] = rh;

    nlohmann::json sh = nlohmann::json::array();
    for (const auto& kv : e.resp_headers) {
        nlohmann::json h;
        h["name"]  = kv.first;
        h["value"] = kv.second;
        sh.push_back(h);
    }
    j["response_headers"] = sh;

    j["request_size"]  = e.req_body.size();
    j["response_size"] = e.resp_body.size();
    if (include_bodies) {
        j["request_body_base64"]  = base64_encode(e.req_body);
        j["response_body_base64"] = base64_encode(e.resp_body);
    }
    return j;
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    return st.last_err;
}

size_t total_exchanges()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    return st.by_id.size();
}

void clear_all()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    st.hosts.clear();
    st.by_id.clear();
    st.selected_host.clear();
    st.selected_path.clear();
    st.selected_port = 0;
    st.selected_tls = false;
    st.selected_exchange_id.store(0);
}

namespace {

void render_tree_node(state_t& st, const std::shared_ptr<path_node_t>& node, const std::string& host,
                      uint16_t port, bool tls, const std::string& cur_path,
                      int depth, float alpha, int& visible_counter, float anim_time)
{
    const auto& th = aida::ui::resolved();
    if (!node) return;

    const std::string label_full = cur_path;
    const std::string& seg = node->segment;
    const std::string display_seg = seg.empty() ? std::string("/") : seg;

    const std::string filter = st.tree_filter;
    bool matches_filter = true;
    if (!filter.empty()) {
        matches_filter = (label_full.find(filter) != std::string::npos) || (host.find(filter) != std::string::npos);
    }

    const bool has_children = !node->children.empty();
    const bool expanded = st.expanded_paths.count(host + "|" + label_full) > 0;
    const bool selected = (st.selected_host == host && st.selected_port == port && st.selected_path == label_full);

    if (matches_filter) {
        const float row_alpha_anim = ui_anim::render_row_entrance(visible_counter, anim_time, 0.010f);
        const float r_alpha = alpha * row_alpha_anim;

        ImGui::PushID(visible_counter);
        const ImVec2 cursor_screen = ImGui::GetCursorScreenPos();
        const float row_h = 22.f;
        const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const float win_w = ImGui::GetContentRegionAvail().x;

        if (visible_counter & 1) {
            dl->AddRectFilled(cursor_screen, ImVec2(cursor_screen.x + win_w, cursor_screen.y + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
        }
        if (selected) {
            dl->AddRectFilled(cursor_screen, ImVec2(cursor_screen.x + win_w, cursor_screen.y + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
        }

        const float indent = depth * 14.f;
        const float caret_x = cursor_screen.x + indent + 4.f;
        const float text_x = caret_x + 14.f;

        ImU32 caret_col = aida::ui::with_alpha(th.text_secondary, r_alpha);
        if (has_children) {
            const ImVec2 a(caret_x, cursor_screen.y + 6.f);
            const ImVec2 b(caret_x + 8.f, cursor_screen.y + 6.f);
            const ImVec2 c(caret_x + 4.f, cursor_screen.y + 14.f);
            if (expanded) {
                dl->AddTriangleFilled(a, b, c, caret_col);
            } else {
                const ImVec2 a2(caret_x, cursor_screen.y + 4.f);
                const ImVec2 b2(caret_x + 8.f, cursor_screen.y + 10.f);
                const ImVec2 c2(caret_x, cursor_screen.y + 16.f);
                dl->AddTriangleFilled(a2, b2, c2, caret_col);
            }
        }

        ImU32 txt_col = aida::ui::with_alpha(node->in_scope ? th.text_primary : th.text_dim, r_alpha);
        dl->AddText(ImVec2(text_x, cursor_screen.y + text_oy), txt_col, display_seg.c_str());

        if (node->total_requests > 0) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%zu", node->total_requests);
            const float bw = ImGui::CalcTextSize(buf).x + 12.f;
            dl->AddRectFilled(ImVec2(cursor_screen.x + win_w - bw - 4.f, cursor_screen.y + 3.f),
                              ImVec2(cursor_screen.x + win_w - 4.f, cursor_screen.y + row_h - 3.f),
                              aida::ui::with_alpha(th.accent_dim, r_alpha * 0.6f), 4.f);
            dl->AddText(ImVec2(cursor_screen.x + win_w - bw + 2.f, cursor_screen.y + text_oy),
                        aida::ui::with_alpha(th.text_secondary, r_alpha), buf);
        }

        ImGui::InvisibleButton("##tree_row", ImVec2(win_w, row_h));
        const bool item_clicked = ImGui::IsItemClicked();
        const bool item_right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);

        if (item_clicked) {
            if (has_children) {
                const std::string ek = host + "|" + label_full;
                if (expanded) st.expanded_paths.erase(ek);
                else          st.expanded_paths.insert(ek);
            }
            st.selected_host = host;
            st.selected_port = port;
            st.selected_tls  = tls;
            st.selected_path = label_full;
        }

        if (item_right_clicked) ImGui::OpenPopup("##sitemap_node_ctx");

        if (ImGui::BeginPopup("##sitemap_node_ctx")) {
            char url_buf[1024];
            std::snprintf(url_buf, sizeof(url_buf), "%s://%s:%u%s", tls ? "https" : "http",
                          host.c_str(), port, label_full.c_str());
            ImGui::TextDisabled("%s", url_buf);
            ImGui::Separator();
            if (ImGui::MenuItem("Add to scope")) {
                scope::add_include_rule(tls ? "https" : "http", host, port, label_full);
            }
            if (ImGui::MenuItem("Exclude from scope")) {
                scope::add_exclude_rule(tls ? "https" : "http", host, port, label_full);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Copy URL")) ImGui::SetClipboardText(url_buf);
            ImGui::EndPopup();
        }

        ImGui::PopID();
        ++visible_counter;
    }

    if (has_children && expanded) {
        for (const auto& c : node->children) {
            const std::string child_path = path_join(label_full, c.first);
            render_tree_node(st, c.second, host, port, tls, child_path, depth + 1, alpha, visible_counter, anim_time);
        }
    }
}

void render_tree(state_t& st, float width, float height, float alpha)
{
    const auto& th = aida::ui::resolved();
    (void)th;

    ImGui::PushID("##burp_sitemap_tree");

    ImGui::SetNextItemWidth(width - 12.f);
    ImGui::InputTextWithHint("##sitemap_filter", "Filter host or path...", st.tree_filter, sizeof(st.tree_filter));

    ImGui::BeginChild("##sitemap_tree_scroll", ImVec2(width - 8.f, height - 36.f), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> tree_lk(st.mtx);
    std::vector<std::pair<host_key_t, std::shared_ptr<host_node_t>>> snapshot;
    snapshot.reserve(st.hosts.size());
    for (const auto& kv : st.hosts) snapshot.emplace_back(kv.first, kv.second);

    static float s_anim_time = 0.f;
    s_anim_time += ImGui::GetIO().DeltaTime;
    int visible = 0;

    for (const auto& kv : snapshot) {
        const auto& h = *kv.second;
        char header_buf[512];
        std::snprintf(header_buf, sizeof(header_buf), "%s://%s:%u  [%zu]",
                      h.tls ? "https" : "http", h.host.c_str(), h.port, h.total_requests);

        const std::string ek = h.host + "|HOST|" + std::to_string(h.port);
        const bool expanded = st.expanded_paths.count(ek) > 0;

        ImGui::PushID(visible);
        const ImVec2 cs = ImGui::GetCursorScreenPos();
        const float row_h = 22.f;
        const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const float win_w = ImGui::GetContentRegionAvail().x;

        const float row_alpha_anim = ui_anim::render_row_entrance(visible, s_anim_time, 0.010f);
        const float r_alpha = alpha * row_alpha_anim;

        if (visible & 1) {
            dl->AddRectFilled(cs, ImVec2(cs.x + win_w, cs.y + row_h),
                              aida::ui::with_alpha(aida::ui::resolved().hover_wash, r_alpha * 0.30f));
        }
        const bool host_selected = (st.selected_host == h.host && st.selected_port == h.port && st.selected_path.empty());
        if (host_selected) {
            dl->AddRectFilled(cs, ImVec2(cs.x + win_w, cs.y + row_h),
                              aida::ui::with_alpha(aida::ui::resolved().selection, r_alpha), 4.f);
        }

        ImU32 caret_col = aida::ui::with_alpha(aida::ui::resolved().text_secondary, r_alpha);
        const float caret_x = cs.x + 4.f;
        if (expanded) {
            const ImVec2 a(caret_x, cs.y + 6.f);
            const ImVec2 b(caret_x + 8.f, cs.y + 6.f);
            const ImVec2 c(caret_x + 4.f, cs.y + 14.f);
            dl->AddTriangleFilled(a, b, c, caret_col);
        } else {
            const ImVec2 a(caret_x, cs.y + 4.f);
            const ImVec2 b(caret_x + 8.f, cs.y + 10.f);
            const ImVec2 c(caret_x, cs.y + 16.f);
            dl->AddTriangleFilled(a, b, c, caret_col);
        }

        ImU32 host_col = aida::ui::with_alpha(h.in_scope ? aida::ui::resolved().text_primary : aida::ui::resolved().text_dim, r_alpha);
        dl->AddText(ImVec2(cs.x + 20.f, cs.y + text_oy), host_col, header_buf);

        ImGui::InvisibleButton("##sitemap_host_row", ImVec2(win_w, row_h));
        if (ImGui::IsItemClicked()) {
            if (expanded) st.expanded_paths.erase(ek);
            else          st.expanded_paths.insert(ek);
            st.selected_host = h.host;
            st.selected_port = h.port;
            st.selected_tls  = h.tls;
            st.selected_path.clear();
        }
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) ImGui::OpenPopup("##sitemap_host_ctx");
        if (ImGui::BeginPopup("##sitemap_host_ctx")) {
            ImGui::TextDisabled("%s://%s:%u", h.tls ? "https" : "http", h.host.c_str(), h.port);
            ImGui::Separator();
            if (ImGui::MenuItem("Add host to scope")) {
                scope::add_include_rule(h.tls ? "https" : "http", h.host, h.port, std::string());
            }
            if (ImGui::MenuItem("Exclude host")) {
                scope::add_exclude_rule(h.tls ? "https" : "http", h.host, h.port, std::string());
            }
            ImGui::EndPopup();
        }

        ImGui::PopID();
        ++visible;

        if (expanded) {
            for (const auto& c : h.root->children) {
                const std::string child_path = path_join(std::string(), c.first);
                render_tree_node(st, c.second, h.host, h.port, h.tls, child_path, 1, alpha, visible, s_anim_time);
            }
        }
    }

    if (visible == 0) {
        const ImVec2 c_org = ImGui::GetWindowPos();
        const ImVec2 c_sz  = ImGui::GetWindowSize();
        const char* msg = "No traffic captured yet.";
        const ImVec2 sz = ImGui::CalcTextSize(msg);
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(c_org.x + (c_sz.x - sz.x) * 0.5f, c_org.y + (c_sz.y - sz.y) * 0.5f),
            aida::ui::with_alpha(aida::ui::resolved().text_dim, alpha * 0.85f), msg);
    }

    ImGui::EndChild();
    ImGui::PopID();
}

void render_request_block(const exchange_observed_t& e, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::PushID("##req_block");
    if (ImGui::BeginTabBar("##req_tabs")) {
        if (ImGui::BeginTabItem("Raw")) {
            std::string raw;
            char first[1024];
            std::snprintf(first, sizeof(first), "%s %s%s%s HTTP/1.1\n",
                          e.method.empty() ? "GET" : e.method.c_str(),
                          e.path.c_str(),
                          e.query.empty() ? "" : "?",
                          e.query.c_str());
            raw.append(first);
            for (const auto& h : e.req_headers) { raw.append(h.first); raw.append(": "); raw.append(h.second); raw.append("\n"); }
            raw.append("\n");
            if (!e.req_body.empty()) {
                size_t shown = std::min<size_t>(e.req_body.size(), 65536);
                raw.append(reinterpret_cast<const char*>(e.req_body.data()), shown);
                if (shown < e.req_body.size()) raw.append("\n... (truncated)");
            }
            ImGui::InputTextMultiline("##req_raw", raw.data(), raw.size() + 1,
                                       ImVec2(-1.f, -1.f), ImGuiInputTextFlags_ReadOnly);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Headers")) {
            for (const auto& h : e.req_headers) {
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "%s:", h.first.c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                                   "%s", h.second.c_str());
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Body")) {
            if (e.req_body.empty()) {
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)), "(empty)");
            } else {
                std::string body(reinterpret_cast<const char*>(e.req_body.data()),
                                 std::min<size_t>(e.req_body.size(), 65536));
                ImGui::InputTextMultiline("##req_body", body.data(), body.size() + 1,
                                           ImVec2(-1.f, -1.f), ImGuiInputTextFlags_ReadOnly);
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::PopID();
}

void render_response_block(const exchange_observed_t& e, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::PushID("##resp_block");
    if (ImGui::BeginTabBar("##resp_tabs")) {
        if (ImGui::BeginTabItem("Raw")) {
            std::string raw;
            char first[256];
            std::snprintf(first, sizeof(first), "HTTP/1.1 %d %s\n", e.status_code, e.reason_phrase.c_str());
            raw.append(first);
            for (const auto& h : e.resp_headers) { raw.append(h.first); raw.append(": "); raw.append(h.second); raw.append("\n"); }
            raw.append("\n");
            if (!e.resp_body.empty()) {
                size_t shown = std::min<size_t>(e.resp_body.size(), 65536);
                raw.append(reinterpret_cast<const char*>(e.resp_body.data()), shown);
                if (shown < e.resp_body.size()) raw.append("\n... (truncated)");
            }
            ImGui::InputTextMultiline("##resp_raw", raw.data(), raw.size() + 1,
                                       ImVec2(-1.f, -1.f), ImGuiInputTextFlags_ReadOnly);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Headers")) {
            for (const auto& h : e.resp_headers) {
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "%s:", h.first.c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                                   "%s", h.second.c_str());
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Body")) {
            if (e.resp_body.empty()) {
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)), "(empty)");
            } else {
                std::string body(reinterpret_cast<const char*>(e.resp_body.data()),
                                 std::min<size_t>(e.resp_body.size(), 65536));
                ImGui::InputTextMultiline("##resp_body", body.data(), body.size() + 1,
                                           ImVec2(-1.f, -1.f), ImGuiInputTextFlags_ReadOnly);
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::PopID();
}

std::string build_curl_command(const exchange_observed_t& e)
{
    std::string out = "curl -i -k -X ";
    out.append(e.method.empty() ? "GET" : e.method);
    out.append(" \"");
    out.append(e.scheme.empty() ? "https" : e.scheme);
    out.append("://");
    out.append(e.host);
    if (e.port != 0 && e.port != 80 && e.port != 443) {
        out.append(":");
        out.append(std::to_string(e.port));
    }
    out.append(e.path);
    if (!e.query.empty()) { out.append("?"); out.append(e.query); }
    out.append("\"");
    for (const auto& h : e.req_headers) {
        const std::string lk = [&]{ std::string r; for (char c : h.first) r.push_back(static_cast<char>(c | 0x20)); return r; }();
        if (lk == "host" || lk == "content-length") continue;
        out.append(" -H \"");
        out.append(h.first);
        out.append(": ");
        out.append(h.second);
        out.append("\"");
    }
    if (!e.req_body.empty()) {
        out.append(" --data-binary \"");
        for (uint8_t b : e.req_body) {
            if (b == '"' || b == '\\') out.push_back('\\');
            if (b >= 0x20 && b < 0x7F) out.push_back(static_cast<char>(b));
            else                       out.push_back('?');
        }
        out.append("\"");
    }
    return out;
}

void render_right_pane(state_t& st, float width, float height, float alpha)
{
    const auto& th = aida::ui::resolved();

    char header_buf[1024];
    if (st.selected_host.empty()) {
        std::snprintf(header_buf, sizeof(header_buf), "Select a host or path on the left");
    } else if (st.selected_path.empty()) {
        std::snprintf(header_buf, sizeof(header_buf), "%s://%s:%u",
                      st.selected_tls ? "https" : "http", st.selected_host.c_str(), st.selected_port);
    } else {
        std::snprintf(header_buf, sizeof(header_buf), "%s://%s:%u%s",
                      st.selected_tls ? "https" : "http", st.selected_host.c_str(),
                      st.selected_port, st.selected_path.c_str());
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetCursorScreenPos();
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 26.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 5.f), aida::ui::with_alpha(th.text_primary, alpha), header_buf);
    ImGui::Dummy(ImVec2(width, 30.f));

    if (st.selected_host.empty()) return;

    std::vector<exchange_observed_t> exchanges;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (const auto& kv : st.hosts) {
            if (kv.first.host != st.selected_host || kv.first.port != st.selected_port) continue;
            if (st.selected_path.empty()) {
                std::vector<std::string> all_paths;
                collect_paths_rec(kv.second->root, std::string(), all_paths);
                for (const auto& p : all_paths) {
                    std::vector<std::string> segs;
                    split_path_segments(p, segs);
                    auto cur = kv.second->root;
                    bool ok = true;
                    for (const auto& seg : segs) {
                        auto sit = cur->children.find(seg);
                        if (sit == cur->children.end()) { ok = false; break; }
                        cur = sit->second;
                    }
                    if (ok && cur) exchanges.insert(exchanges.end(), cur->exchanges.begin(), cur->exchanges.end());
                }
            } else {
                std::vector<std::string> segs;
                split_path_segments(st.selected_path, segs);
                auto cur = kv.second->root;
                bool ok = true;
                for (const auto& seg : segs) {
                    auto sit = cur->children.find(seg);
                    if (sit == cur->children.end()) { ok = false; break; }
                    cur = sit->second;
                }
                if (ok && cur) exchanges = cur->exchanges;
            }
        }
    }
    std::sort(exchanges.begin(), exchanges.end(), [](const exchange_observed_t& a, const exchange_observed_t& b) {
        return a.timestamp_ms < b.timestamp_ms;
    });

    const float list_h = height * 0.45f;
    ImGui::BeginChild("##sitemap_list", ImVec2(width, list_h), false, ImGuiWindowFlags_NoBackground);
    ImDrawList* ldl = ImGui::GetWindowDrawList();
    ImVec2 lorg = ImGui::GetWindowPos();

    const float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    const float col_id     = 60.f;
    const float col_method = 60.f;
    const float col_status = 60.f;
    const float col_size   = 80.f;
    const float col_lat    = 64.f;
    const float col_path   = std::max(160.f, width - col_id - col_method - col_status - col_size - col_lat - 24.f);

    ldl->AddRectFilled(ImVec2(lorg.x, lorg.y), ImVec2(lorg.x + width, lorg.y + row_h),
                       aida::ui::with_alpha(th.panel_header, alpha));
    float cx = lorg.x + 6.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    ldl->AddText(ImVec2(cx, lorg.y + text_oy), hdr_col, "#");       cx += col_id;
    ldl->AddText(ImVec2(cx, lorg.y + text_oy), hdr_col, "Method");  cx += col_method;
    ldl->AddText(ImVec2(cx, lorg.y + text_oy), hdr_col, "Path");    cx += col_path;
    ldl->AddText(ImVec2(cx, lorg.y + text_oy), hdr_col, "Status");  cx += col_status;
    ldl->AddText(ImVec2(cx, lorg.y + text_oy), hdr_col, "Size");    cx += col_size;
    ldl->AddText(ImVec2(cx, lorg.y + text_oy), hdr_col, "Time");

    ImGui::SetCursorPosY(row_h + 4.f);
    const uint64_t sel_id = st.selected_exchange_id.load();
    static float s_anim_time = 0.f;
    s_anim_time += ImGui::GetIO().DeltaTime;

    int visible = 0;
    for (int i = 0; i < static_cast<int>(exchanges.size()); ++i) {
        const auto& e = exchanges[static_cast<size_t>(i)];
        const float row_alpha_anim = ui_anim::render_row_entrance(visible, s_anim_time, 0.010f);
        const float r_alpha = alpha * row_alpha_anim;
        const float abs_ry = ImGui::GetCursorScreenPos().y;

        if (visible & 1) {
            ldl->AddRectFilled(ImVec2(lorg.x, abs_ry), ImVec2(lorg.x + width, abs_ry + row_h),
                               aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
        }
        const bool selected = (sel_id == e.id);
        if (selected) {
            ldl->AddRectFilled(ImVec2(lorg.x, abs_ry), ImVec2(lorg.x + width, abs_ry + row_h),
                               aida::ui::with_alpha(th.selection, r_alpha), 4.f);
            ldl->AddRectFilled(ImVec2(lorg.x, abs_ry), ImVec2(lorg.x + 3.f, abs_ry + row_h),
                               aida::ui::with_alpha(th.accent_u32, r_alpha));
        }

        ImGui::PushID(static_cast<int>(e.id));
        ImGui::InvisibleButton("##sm_row", ImVec2(width, row_h));
        if (ImGui::IsItemClicked()) st.selected_exchange_id.store(e.id);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) ImGui::OpenPopup("##sm_row_ctx");
        if (ImGui::BeginPopup("##sm_row_ctx")) {
            if (ImGui::MenuItem("Send to Repeater"))  send_to(e.id, "repeater",  "sitemap");
            if (ImGui::MenuItem("Send to Intruder"))  send_to(e.id, "intruder",  "sitemap");
            if (ImGui::MenuItem("Send to Comparer"))  send_to(e.id, "comparer",  "sitemap");
            if (ImGui::MenuItem("Send to Scanner"))   send_to(e.id, "scanner",   "sitemap");
            if (ImGui::MenuItem("Send to Decoder"))   send_to(e.id, "decoder",   "sitemap");
            ImGui::Separator();
            if (ImGui::MenuItem("Copy as cURL")) {
                const std::string c = build_curl_command(e);
                ImGui::SetClipboardText(c.c_str());
            }
            if (ImGui::MenuItem("Add path to scope")) {
                scope::add_include_rule(e.scheme, e.host, e.port, e.path);
            }
            ImGui::EndPopup();
        }

        ImU32 txt = aida::ui::with_alpha(th.text_primary, r_alpha);
        ImU32 dim = aida::ui::with_alpha(th.text_dim, r_alpha);
        float lx = lorg.x + 6.f;
        const float ty = abs_ry + text_oy;
        char buf[64];

        std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(e.id));
        ldl->AddText(ImVec2(lx, ty), dim, buf); lx += col_id;

        ldl->AddText(ImVec2(lx, ty), txt, e.method.empty() ? "GET" : e.method.c_str());
        lx += col_method;

        std::string p_disp = e.path;
        if (!e.query.empty()) { p_disp.push_back('?'); p_disp.append(e.query); }
        ldl->AddText(ImVec2(lx, ty), txt, p_disp.c_str());
        lx += col_path;

        std::snprintf(buf, sizeof(buf), "%d", e.status_code);
        ImU32 sc_col = txt;
        if (e.status_code >= 500)      sc_col = aida::ui::with_alpha(th.error, r_alpha);
        else if (e.status_code >= 400) sc_col = aida::ui::with_alpha(th.warning, r_alpha);
        else if (e.status_code >= 200 && e.status_code < 300) sc_col = aida::ui::with_alpha(th.success, r_alpha);
        ldl->AddText(ImVec2(lx, ty), sc_col, buf);
        lx += col_status;

        std::snprintf(buf, sizeof(buf), "%zu", e.resp_body.size());
        ldl->AddText(ImVec2(lx, ty), dim, buf);
        lx += col_size;

        std::snprintf(buf, sizeof(buf), "%llu ms", static_cast<unsigned long long>(e.latency_ms));
        ldl->AddText(ImVec2(lx, ty), dim, buf);

        ImGui::PopID();
        ++visible;
    }

    ImGui::EndChild();

    exchange_observed_t cur;
    bool have_cur = false;
    if (sel_id != 0) have_cur = find_exchange(sel_id, cur);

    ImGui::BeginChild("##sitemap_detail", ImVec2(width, height - list_h - 38.f), false, ImGuiWindowFlags_NoBackground);
    if (!have_cur) {
        const ImVec2 dorg = ImGui::GetWindowPos();
        const ImVec2 dsz  = ImGui::GetWindowSize();
        const char* msg = "Select an exchange above";
        const ImVec2 sz = ImGui::CalcTextSize(msg);
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(dorg.x + (dsz.x - sz.x) * 0.5f, dorg.y + (dsz.y - sz.y) * 0.5f),
            aida::ui::with_alpha(th.text_dim, alpha * 0.85f), msg);
    } else {
        if (ImGui::BeginTabBar("##sitemap_detail_tabs")) {
            if (ImGui::BeginTabItem("Request")) {
                render_request_block(cur, alpha);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Response")) {
                render_response_block(cur, alpha);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Meta")) {
                ImGui::Text("ID: %llu", static_cast<unsigned long long>(cur.id));
                ImGui::Text("Host: %s", cur.host.c_str());
                ImGui::Text("Port: %u", cur.port);
                ImGui::Text("Scheme: %s", cur.scheme.c_str());
                ImGui::Text("Status: %d %s", cur.status_code, cur.reason_phrase.c_str());
                ImGui::Text("Latency: %llu ms", static_cast<unsigned long long>(cur.latency_ms));
                ImGui::Text("TLS: %s  ALPN: %s", cur.tls_version.c_str(), cur.alpn.c_str());
                ImGui::Text("WebSocket: %s  HTTP/2: %s", cur.is_websocket ? "yes" : "no", cur.is_h2 ? "yes" : "no");
                ImGui::Text("Request size: %zu  Response size: %zu", cur.req_body.size(), cur.resp_body.size());
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::EndChild();
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = s();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_sitemap_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Site map");

    const size_t total = total_exchanges();
    char tot[96];
    std::snprintf(tot, sizeof(tot), "%zu exchanges", total);
    const ImVec2 ts = ImGui::CalcTextSize(tot);
    dl->AddText(ImVec2(org.x + width - ts.x - 12.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_dim, alpha), tot);

    const float content_y = pos_y + 34.f;
    const float content_h = height - 38.f;
    const float split_w = std::clamp(st.split_left, 0.20f, 0.65f);
    const float left_w  = width * split_w;
    const float gap     = 6.f;
    const float right_w = width - left_w - gap;

    ImGui::SetCursorPos(ImVec2(pos_x + 2.f, content_y));
    ImGui::BeginChild("##sitemap_left", ImVec2(left_w - 4.f, content_h), false, ImGuiWindowFlags_NoBackground);
    render_tree(st, left_w - 4.f, content_h, alpha);
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(pos_x + left_w + gap, content_y));
    ImGui::BeginChild("##sitemap_right", ImVec2(right_w, content_h), false, ImGuiWindowFlags_NoBackground);
    render_right_pane(st, right_w, content_h, alpha);
    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
