#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#include "../../../preview/studio_semantics.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifdef small
#undef small
#endif

#include "site_map.hpp"
#include "../network_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_burp_core.hpp"
#else
#include "burp_logger.hpp"
#endif
#include "scope.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/design_system.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/application_ui_runtime.hpp"
#include "../../infra/event_bus.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_executor.hpp"
#else
#include "../../infra/executor.hpp"
#endif
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

namespace aida {
namespace burp {
namespace sitemap {

namespace {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
std::string semantic_artifact_id(
    std::string_view kind, const network_view::artifact_identity_t& identity)
{
    const std::string retained = identity.id + ":" +
        std::to_string(identity.timestamp) + ":" +
        std::to_string(identity.revision) + ":" +
        std::to_string(identity.content_hash) + ":" +
        std::to_string(identity.content_size);
    return aida::preview::semantics::stable_id(
        "aida.network", std::string(kind) + "-" +
            aida::preview::semantics::entity_token(retained));
}

std::string semantic_site_node_id(std::string retained)
{
    return aida::preview::semantics::stable_id(
        "aida.network", "site-map-node-" +
            aida::preview::semantics::entity_token(retained));
}
#endif

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

struct tree_row_t
{
    enum class kind_t { host, path } kind = kind_t::path;
    std::string host;
    std::string path;
    std::string display;
    uint16_t port = 0;
    bool tls = false;
    bool in_scope = true;
    bool has_children = false;
    bool expanded = false;
    int depth = 0;
    size_t total_requests = 0;
    uint64_t last_seen_ms = 0;
    std::weak_ptr<host_node_t> host_node;
    std::weak_ptr<path_node_t> path_node;
};

struct exchange_row_t
{
    uint64_t id = 0;
    uint64_t timestamp_ms = 0;
    std::string method;
    std::string path;
    int status_code = 0;
    size_t response_size = 0;
    uint64_t latency_ms = 0;
};

constexpr size_t kMaxCachedTreeRows = 65536;
constexpr size_t kMaxCachedTreeTextBytes = 16u * 1024u * 1024u;
constexpr size_t kMaxCachedExchangeRows = 65536;

struct state_t
{
    std::mutex                                       mtx;
    std::map<host_key_t, std::shared_ptr<host_node_t>> hosts;
    std::map<uint64_t, exchange_observed_t>          by_id;
    std::atomic<uint64_t>                            next_id{1};
    std::atomic<uint64_t>                            selected_exchange_id{0};
    std::atomic<size_t>                              exchange_count{0};
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
    std::map<host_key_t, std::deque<exchange_row_t>> exchange_index;
    std::mutex                                       cache_mtx;
    std::shared_ptr<const std::vector<tree_row_t>>   tree_rows =
        std::make_shared<const std::vector<tree_row_t>>();
    bool                                             tree_cache_limited = false;
    std::string                                      tree_cache_filter;
    std::set<std::string>                            tree_cache_expanded;
    uint64_t                                         tree_query_revision = 1;
    std::atomic<bool>                                tree_rebuild_dirty{true};
    std::atomic<bool>                                tree_rebuild_inflight{false};
    std::atomic<uint64_t>                            topology_revision{1};
    std::atomic<bool>                                shutting_down{false};
    std::atomic<uint64_t>                            tree_retry_after_ms{0};
    std::atomic<uint32_t>                            tree_retry_attempt{0};
    uint64_t                                         detail_cache_id = 0;
    exchange_observed_t                              detail_cache;
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

std::string bounded_display(std::string value, size_t limit)
{
    if (value.size() <= limit) return value;
    value.resize(limit - 3);
    value.append("...");
    return value;
}

uint64_t monotonic_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

exchange_row_t make_exchange_row(const exchange_observed_t& e)
{
    exchange_row_t row;
    row.id = e.id;
    row.timestamp_ms = e.timestamp_ms;
    row.method = bounded_display(e.method.empty() ? "GET" : e.method, 32);
    row.path = e.path;
    if (!e.query.empty()) {
        row.path.push_back('?');
        row.path.append(e.query);
    }
    row.path = bounded_display(std::move(row.path), 1024);
    row.status_code = e.status_code;
    row.response_size = e.resp_body.size();
    row.latency_ms = e.latency_ms;
    return row;
}

void insert_exchange_index(state_t& st, const host_key_t& key, const exchange_observed_t& e)
{
    auto& rows = st.exchange_index[key];
    exchange_row_t row = make_exchange_row(e);
    const auto pos = std::upper_bound(rows.begin(), rows.end(), row,
        [](const exchange_row_t& lhs, const exchange_row_t& rhs) {
            if (lhs.timestamp_ms != rhs.timestamp_ms)
                return lhs.timestamp_ms < rhs.timestamp_ms;
            return lhs.id < rhs.id;
        });
    rows.insert(pos, std::move(row));
}

void remove_exchange_index(state_t& st, const exchange_observed_t& e)
{
    const host_key_t key{e.host, e.port, e.scheme == "https" || e.scheme == "wss"};
    const auto index_it = st.exchange_index.find(key);
    if (index_it == st.exchange_index.end()) return;
    auto& rows = index_it->second;
    if (!rows.empty() && rows.front().id == e.id) {
        rows.pop_front();
    } else if (!rows.empty() && rows.back().id == e.id) {
        rows.pop_back();
    } else {
        const auto row_it = std::find_if(rows.begin(), rows.end(),
            [&e](const exchange_row_t& row) { return row.id == e.id; });
        if (row_it != rows.end()) rows.erase(row_it);
    }
    if (rows.empty()) st.exchange_index.erase(index_it);
}

void remove_exchange_from_leaf(state_t& st, const exchange_observed_t& e)
{
    const host_key_t key{e.host, e.port, e.scheme == "https" || e.scheme == "wss"};
    const auto host = st.hosts.find(key);
    if (host == st.hosts.end() || !host->second || !host->second->root) return;
    std::vector<std::string> segments;
    split_path_segments(e.path, segments);
    auto node = host->second->root;
    for (const auto& segment : segments) {
        const auto child = node->children.find(segment);
        if (child == node->children.end()) return;
        node = child->second;
    }
    const auto exchange = std::find_if(node->exchanges.begin(), node->exchanges.end(),
        [&e](const exchange_observed_t& candidate) { return candidate.id == e.id; });
    if (exchange != node->exchanges.end()) node->exchanges.erase(exchange);
}

bool insert_into_tree(state_t& st, const exchange_observed_t& e)
{
    host_key_t key{e.host, e.port, e.scheme == "https" || e.scheme == "wss"};
    bool topology_changed = false;
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
        topology_changed = true;
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
            topology_changed = true;
        }
        cur = sit->second;
        cur->total_requests++;
        cur->last_seen_ms = host->last_seen_ms;
        cur->in_scope = scope::in_scope_components(e.scheme, e.host, e.port, e.path);
        cur->last_status = e.status_code;
    }

    const auto exchange_pos = std::upper_bound(cur->exchanges.begin(), cur->exchanges.end(), e,
        [](const exchange_observed_t& lhs, const exchange_observed_t& rhs) {
            if (lhs.timestamp_ms != rhs.timestamp_ms)
                return lhs.timestamp_ms < rhs.timestamp_ms;
            return lhs.id < rhs.id;
        });
    cur->exchanges.insert(exchange_pos, e);
    if (cur->exchanges.size() > 512) {
        const auto erase_count = static_cast<decltype(cur->exchanges)::difference_type>(cur->exchanges.size() - 512);
        cur->exchanges.erase(cur->exchanges.begin(), cur->exchanges.begin() + erase_count);
    }
    const auto existing = st.by_id.find(e.id);
    if (existing != st.by_id.end()) {
        remove_exchange_index(st, existing->second);
        remove_exchange_from_leaf(st, existing->second);
    }
    st.by_id[e.id] = e;
    insert_exchange_index(st, key, e);
    if (st.by_id.size() > kMaxCachedExchangeRows) {
        const auto oldest = st.by_id.begin();
        remove_exchange_index(st, oldest->second);
        remove_exchange_from_leaf(st, oldest->second);
        st.by_id.erase(oldest);
    }
    st.exchange_count.store(st.by_id.size());
    return topology_changed;
}

std::string normalized_source(const exchange_observed_t& e);
std::string source_label_for(const exchange_observed_t& e);
void request_tree_cache_rebuild();

void store_exchange(exchange_observed_t e)
{
    auto& st = s();
    bool topology_changed = false;
    {
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
        topology_changed = insert_into_tree(st, e);
    }
    if (topology_changed) {
        st.topology_revision.fetch_add(1);
        request_tree_cache_rebuild();
    }
}

void handle_exchange(const exchange_observed_t& evt)
{
    if (![&]() {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.site_map";
        sub.label = "site_map.store_exchange";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::feature_worker;
        sub.priority = 3;
        sub.body = [evt]() { store_exchange(evt); };
        return ::aida::infra::executor::submit(std::move(sub)).submitted;
    }())
        diag::log_tagged("burp", "site_map_executor_post_failed");
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
    st.shutting_down.store(false);
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
    st.shutting_down.store(true);
    st.tree_rebuild_dirty.store(false);
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

bool exchange_exists(uint64_t id)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    return st.by_id.find(id) != st.by_id.end();
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
    return s().exchange_count.load();
}

void clear_all()
{
    auto& st = s();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.hosts.clear();
        st.by_id.clear();
        st.exchange_index.clear();
        st.exchange_count.store(0);
        st.selected_host.clear();
        st.selected_path.clear();
        st.selected_port = 0;
        st.selected_tls = false;
        st.selected_exchange_id.store(0);
        st.topology_revision.fetch_add(1);
    }
    request_tree_cache_rebuild();
}

namespace {

void build_tree_cache(state_t& st)
{
    std::string filter;
    std::set<std::string> expanded;
    uint64_t query_revision = 0;
    const uint64_t topology_revision = st.topology_revision.load();
    {
        std::lock_guard<std::mutex> cache_lk(st.cache_mtx);
        filter = st.tree_cache_filter;
        expanded = st.tree_cache_expanded;
        query_revision = st.tree_query_revision;
    }

    auto rows = std::make_shared<std::vector<tree_row_t>>();
    bool limited = false;
    size_t retained_bytes = 0;
    const auto append = [&](tree_row_t&& row) {
        const size_t bytes = row.host.size() + row.path.size() + row.display.size();
        if (rows->size() >= kMaxCachedTreeRows ||
            bytes > kMaxCachedTreeTextBytes - retained_bytes) {
            limited = true;
            return false;
        }
        retained_bytes += bytes;
        rows->push_back(std::move(row));
        return true;
    };

    struct pending_path_t
    {
        std::shared_ptr<path_node_t> node;
        std::string path;
        int depth = 0;
    };

    std::vector<std::pair<host_key_t, std::shared_ptr<host_node_t>>> hosts;
    {
        std::lock_guard<std::mutex> model_lk(st.mtx);
        hosts.reserve(std::min(kMaxCachedTreeRows, st.hosts.size()));
        for (const auto& host : st.hosts) {
            if (hosts.size() >= kMaxCachedTreeRows) {
                limited = true;
                break;
            }
            hosts.push_back(host);
        }
    }
    rows->reserve(hosts.size() >= kMaxCachedTreeRows / 8
        ? kMaxCachedTreeRows : hosts.size() * 8);
    for (const auto& kv : hosts) {
        const std::string host_key = kv.first.host + "|HOST|" + std::to_string(kv.first.port);
        const bool host_expanded = expanded.count(host_key) > 0;
        std::string host_name;
        uint16_t host_port = 0;
        bool host_tls = false;
        bool host_in_scope = true;
        size_t host_requests = 0;
        uint64_t host_last_seen = 0;
        bool host_has_children = false;
        std::shared_ptr<path_node_t> root;
        std::vector<pending_path_t> first_children;
        size_t pending_text_bytes = 0;
        {
            std::lock_guard<std::mutex> model_lk(st.mtx);
            if (!kv.second) continue;
            host_name = kv.second->host;
            host_port = kv.second->port;
            host_tls = kv.second->tls;
            host_in_scope = kv.second->in_scope;
            host_requests = kv.second->total_requests;
            host_last_seen = kv.second->last_seen_ms;
            root = kv.second->root;
            if (root) {
                host_has_children = !root->children.empty();
                if (host_expanded) {
                    first_children.reserve(std::min(kMaxCachedTreeRows, root->children.size()));
                    for (auto it = root->children.begin(); it != root->children.end(); ++it) {
                        if (first_children.size() >= kMaxCachedTreeRows) {
                            limited = true;
                            break;
                        }
                        if (it->first.size() + 1 > kMaxCachedTreeTextBytes) {
                            limited = true;
                            continue;
                        }
                        std::string child_path = path_join(std::string(), it->first);
                        if (child_path.size() > kMaxCachedTreeTextBytes - pending_text_bytes) {
                            limited = true;
                            continue;
                        }
                        pending_text_bytes += child_path.size();
                        first_children.push_back({it->second, std::move(child_path), 1});
                    }
                }
            }
        }
        if (host_name.size() > kMaxCachedTreeTextBytes) {
            limited = true;
            break;
        }
        char header[512];
        std::snprintf(header, sizeof(header), "%s://%s:%u  [%zu]",
            host_tls ? "https" : "http", host_name.c_str(), host_port, host_requests);
        tree_row_t host_row;
        host_row.kind = tree_row_t::kind_t::host;
        host_row.host = host_name;
        host_row.display = header;
        host_row.port = host_port;
        host_row.tls = host_tls;
        host_row.in_scope = host_in_scope;
        host_row.has_children = host_has_children;
        host_row.expanded = host_expanded;
        host_row.total_requests = host_requests;
        host_row.last_seen_ms = host_last_seen;
        host_row.host_node = kv.second;
        if (!append(std::move(host_row))) break;
        if (!host_expanded || !root) continue;

        std::vector<pending_path_t> pending;
        for (auto it = first_children.rbegin(); it != first_children.rend(); ++it)
            pending.push_back(std::move(*it));

        while (!pending.empty() && rows->size() < kMaxCachedTreeRows) {
            pending_path_t current = std::move(pending.back());
            pending.pop_back();
            pending_text_bytes -= std::min(pending_text_bytes, current.path.size());
            if (!current.node) continue;
            const bool row_expanded = expanded.count(host_name + "|" + current.path) > 0;
            std::string segment;
            bool path_in_scope = true;
            bool path_has_children = false;
            size_t path_requests = 0;
            uint64_t path_last_seen = 0;
            std::vector<std::pair<std::string, std::shared_ptr<path_node_t>>> node_children;
            const size_t occupied = std::min(kMaxCachedTreeRows,
                rows->size() + pending.size());
            const size_t child_capacity = kMaxCachedTreeRows - occupied;
            {
                std::lock_guard<std::mutex> model_lk(st.mtx);
                segment = current.node->segment;
                path_in_scope = current.node->in_scope;
                path_requests = current.node->total_requests;
                path_last_seen = current.node->last_seen_ms;
                path_has_children = !current.node->children.empty();
                if (row_expanded) {
                    node_children.reserve(std::min(child_capacity, current.node->children.size()));
                    for (const auto& child : current.node->children) {
                        if (node_children.size() >= child_capacity) {
                            limited = true;
                            break;
                        }
                        node_children.push_back(child);
                    }
                }
            }
            const bool matches = filter.empty() || current.path.find(filter) != std::string::npos ||
                host_name.find(filter) != std::string::npos;
            if (matches) {
                tree_row_t path_row;
                path_row.kind = tree_row_t::kind_t::path;
                path_row.host = host_name;
                path_row.path = current.path;
                path_row.display = segment.empty() ? "/" : segment;
                path_row.port = host_port;
                path_row.tls = host_tls;
                path_row.in_scope = path_in_scope;
                path_row.has_children = path_has_children;
                path_row.expanded = row_expanded;
                path_row.depth = current.depth;
                path_row.total_requests = path_requests;
                path_row.last_seen_ms = path_last_seen;
                path_row.path_node = current.node;
                if (!append(std::move(path_row))) break;
            }
            if (row_expanded) {
                std::vector<pending_path_t> children;
                const size_t available = kMaxCachedTreeRows - occupied;
                children.reserve(std::min(available, node_children.size()));
                for (const auto& child : node_children) {
                    if (children.size() >= available) {
                        limited = true;
                        break;
                    }
                    if (child.first.size() + 1 >
                        kMaxCachedTreeTextBytes - std::min(current.path.size(), kMaxCachedTreeTextBytes)) {
                        limited = true;
                        continue;
                    }
                    std::string child_path = path_join(current.path, child.first);
                    if (child_path.size() > kMaxCachedTreeTextBytes - pending_text_bytes) {
                        limited = true;
                        continue;
                    }
                    pending_text_bytes += child_path.size();
                    children.push_back({child.second, std::move(child_path), current.depth + 1});
                }
                for (auto it = children.rbegin(); it != children.rend(); ++it)
                    pending.push_back(std::move(*it));
            }
        }
        if (limited) break;
    }
    std::lock_guard<std::mutex> cache_lk(st.cache_mtx);
    if (query_revision == st.tree_query_revision &&
        topology_revision == st.topology_revision.load()) {
        st.tree_rows = std::move(rows);
        st.tree_cache_limited = limited;
        st.tree_retry_attempt.store(0);
        st.tree_retry_after_ms.store(0);
        std::lock_guard<std::mutex> err_lk(st.err_mtx);
        st.last_err.clear();
    } else {
        st.tree_rebuild_dirty.store(true);
    }
}

void request_tree_cache_rebuild()
{
    auto& st = s();
    if (st.shutting_down.load()) return;
    st.tree_rebuild_dirty.store(true);
    const uint64_t now = monotonic_ms();
    if (now < st.tree_retry_after_ms.load()) return;
    bool expected = false;
    if (!st.tree_rebuild_inflight.compare_exchange_strong(expected, true)) return;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "burp.site_map";
    submission.label = "site_map.rebuild_tree_cache";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 2;
    submission.body = [] {
        auto& state = s();
        state.tree_rebuild_dirty.store(false);
        try {
            build_tree_cache(state);
        } catch (const std::exception& ex) {
            state.tree_rebuild_dirty.store(true);
            const uint32_t attempt = std::min<uint32_t>(
                state.tree_retry_attempt.fetch_add(1), 5);
            state.tree_retry_after_ms.store(monotonic_ms() +
                std::min<uint64_t>(10000, 250ull << attempt));
            {
                std::lock_guard<std::mutex> err_lk(state.err_mtx);
                state.last_err = std::string("Site-map index rebuild failed: ") + ex.what();
            }
        } catch (...) {
            state.tree_rebuild_dirty.store(true);
            const uint32_t attempt = std::min<uint32_t>(
                state.tree_retry_attempt.fetch_add(1), 5);
            state.tree_retry_after_ms.store(monotonic_ms() +
                std::min<uint64_t>(10000, 250ull << attempt));
            {
                std::lock_guard<std::mutex> err_lk(state.err_mtx);
                state.last_err = "Site-map index rebuild failed";
            }
        }
        state.tree_rebuild_inflight.store(false);
        if (state.tree_rebuild_dirty.load()) request_tree_cache_rebuild();
    };
    if (!aida::infra::executor::submit(std::move(submission)).submitted) {
        st.tree_rebuild_inflight.store(false);
        const uint32_t attempt = std::min<uint32_t>(st.tree_retry_attempt.fetch_add(1), 5);
        const uint64_t delay = std::min<uint64_t>(10000, 250ull << attempt);
        st.tree_retry_after_ms.store(now + delay);
        std::lock_guard<std::mutex> err_lk(st.err_mtx);
        st.last_err = "Site-map index rebuild could not be scheduled";
    }
}

void render_tree(state_t& st, float width, float height, float alpha)
{
    const auto& th = aida::ui::resolved();

    ImGui::PushID("##burp_sitemap_tree");

    ImGui::SetNextItemWidth(width - 12.f);
    if (ImGui::InputTextWithHint("##sitemap_filter", "Filter host or path...",
            st.tree_filter, sizeof(st.tree_filter))) {
        {
            std::lock_guard<std::mutex> cache_lk(st.cache_mtx);
            st.tree_cache_filter = st.tree_filter;
            st.tree_cache_expanded = st.expanded_paths;
            ++st.tree_query_revision;
        }
        request_tree_cache_rebuild();
    }

    ImGui::BeginChild("##sitemap_tree_scroll", ImVec2(width - 8.f, height - 36.f), false, ImGuiWindowFlags_NoBackground);
    std::shared_ptr<const std::vector<tree_row_t>> rows_snapshot;
    bool cache_limited = false;
    {
        std::lock_guard<std::mutex> cache_lk(st.cache_mtx);
        rows_snapshot = st.tree_rows;
        cache_limited = st.tree_cache_limited;
    }
    if (!rows_snapshot) rows_snapshot = std::make_shared<const std::vector<tree_row_t>>();
    if (st.tree_rebuild_dirty.load()) request_tree_cache_rebuild();
    if (rows_snapshot->empty() && total_exchanges() != 0)
        request_tree_cache_rebuild();
    const std::string cache_error = last_error();
    if (!cache_error.empty())
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.error), "%s",
            cache_error.c_str());
    if (cache_limited)
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.warning),
            "View limit reached; filter to narrow the site map.");

    static float s_anim_time = 0.f;
    s_anim_time += ImGui::GetIO().DeltaTime;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows_snapshot->size()), 22.f);
    while (clipper.Step()) {
        std::vector<tree_row_t> visible_rows;
        visible_rows.reserve(static_cast<size_t>(clipper.DisplayEnd - clipper.DisplayStart));
        {
            std::lock_guard<std::mutex> model_lk(st.mtx);
            for (int row_index = clipper.DisplayStart; row_index < clipper.DisplayEnd; ++row_index) {
                tree_row_t row = (*rows_snapshot)[static_cast<size_t>(row_index)];
                if (row.kind == tree_row_t::kind_t::host) {
                    if (const auto live = row.host_node.lock()) {
                        row.in_scope = live->in_scope;
                        row.total_requests = live->total_requests;
                        row.last_seen_ms = live->last_seen_ms;
                        char header[512];
                        std::snprintf(header, sizeof(header), "%s://%s:%u  [%zu]",
                            row.tls ? "https" : "http", row.host.c_str(), row.port,
                            row.total_requests);
                        row.display = header;
                    }
                } else if (const auto live = row.path_node.lock()) {
                    row.in_scope = live->in_scope;
                    row.total_requests = live->total_requests;
                    row.last_seen_ms = live->last_seen_ms;
                }
                visible_rows.push_back(std::move(row));
            }
        }
        for (int row_index = clipper.DisplayStart; row_index < clipper.DisplayEnd; ++row_index) {
            const tree_row_t& row = visible_rows[static_cast<size_t>(row_index - clipper.DisplayStart)];
            const bool is_host = row.kind == tree_row_t::kind_t::host;
            const bool selected = st.selected_host == row.host && st.selected_port == row.port &&
                st.selected_path == row.path;
            const float r_alpha = alpha * ui_anim::render_row_entrance(
                row_index, s_anim_time, 0.010f);
            const ImVec2 cs = ImGui::GetCursorScreenPos();
            const float row_h = 22.f;
            const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
            const float win_w = ImGui::GetContentRegionAvail().x;
            ImDrawList* dl = ImGui::GetWindowDrawList();

            if (row_index & 1)
                dl->AddRectFilled(cs, ImVec2(cs.x + win_w, cs.y + row_h),
                    aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
            if (selected)
                dl->AddRectFilled(cs, ImVec2(cs.x + win_w, cs.y + row_h),
                    aida::ui::with_alpha(th.selection, r_alpha), 4.f);

            const float caret_x = cs.x + static_cast<float>(row.depth) * 14.f + 4.f;
            if (row.has_children) {
                const ImU32 caret_col = aida::ui::with_alpha(th.text_secondary, r_alpha);
                if (row.expanded)
                    dl->AddTriangleFilled(ImVec2(caret_x, cs.y + 6.f),
                        ImVec2(caret_x + 8.f, cs.y + 6.f),
                        ImVec2(caret_x + 4.f, cs.y + 14.f), caret_col);
                else
                    dl->AddTriangleFilled(ImVec2(caret_x, cs.y + 4.f),
                        ImVec2(caret_x + 8.f, cs.y + 10.f),
                        ImVec2(caret_x, cs.y + 16.f), caret_col);
            }
            dl->AddText(ImVec2(caret_x + 16.f, cs.y + text_oy),
                aida::ui::with_alpha(row.in_scope ? th.text_primary : th.text_dim, r_alpha),
                row.display.c_str());
            if (!is_host && row.total_requests > 0) {
                char count[64];
                std::snprintf(count, sizeof(count), "%zu", row.total_requests);
                const float badge_w = ImGui::CalcTextSize(count).x + 12.f;
                dl->AddRectFilled(ImVec2(cs.x + win_w - badge_w - 4.f, cs.y + 3.f),
                    ImVec2(cs.x + win_w - 4.f, cs.y + row_h - 3.f),
                    aida::ui::with_alpha(th.accent_dim, r_alpha * 0.6f), 4.f);
                dl->AddText(ImVec2(cs.x + win_w - badge_w + 2.f, cs.y + text_oy),
                    aida::ui::with_alpha(th.text_secondary, r_alpha), count);
            }

            ImGui::PushID(row.tls ? 1 : 0);
            ImGui::PushID(static_cast<int>(row.port));
            ImGui::PushID(row.host.c_str());
            ImGui::PushID(row.path.c_str());
            ImGui::InvisibleButton(is_host ? "##sitemap_host_row" : "##tree_row",
                ImVec2(win_w, row_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            if (ImGui::IsItemVisible()) {
                const std::string retained = (row.tls ? "https:" : "http:") + row.host + ":" +
                    std::to_string(row.port) + (is_host ? std::string() : ":" + row.path);
                aida::preview::semantics::register_last_item(
                    semantic_site_node_id(retained), "network-site-map-node", false, false,
                    "aida.dock-window.view.network.site-map");
            }
#endif
            const bool clicked = ImGui::IsItemClicked();
            const bool pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            if (clicked) {
                if (row.has_children) {
                    const std::string key = is_host
                        ? row.host + "|HOST|" + std::to_string(row.port)
                        : row.host + "|" + row.path;
                    if (row.expanded) st.expanded_paths.erase(key);
                    else {
                        if (st.expanded_paths.size() >= kMaxCachedTreeRows)
                            st.expanded_paths.erase(st.expanded_paths.begin());
                        st.expanded_paths.insert(key);
                    }
                    {
                        std::lock_guard<std::mutex> cache_lk(st.cache_mtx);
                        st.tree_cache_filter = st.tree_filter;
                        st.tree_cache_expanded = st.expanded_paths;
                        ++st.tree_query_revision;
                    }
                    request_tree_cache_rebuild();
                }
                st.selected_host = row.host;
                st.selected_port = row.port;
                st.selected_tls = row.tls;
                st.selected_path = row.path;
            }
            const bool menu_context = selected &&
                ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
                ImGui::IsKeyPressed(ImGuiKey_Menu, false);
            const bool shift_context = !menu_context && selected &&
                ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
                ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
            if (pointer_context || menu_context || shift_context) {
                aida::ui::application_ui::retained_entity_context_t context;
                context.owner_id = is_host ? "network.site_map.host" : "network.site_map.path";
                const std::string scheme = row.tls ? "https" : "http";
                context.entity_id = scheme + "://" + row.host + ":" +
                    std::to_string(row.port) + row.path;
                context.entity_generation = row.last_seen_ms;
                context.active_view = aida::ui::stable_view_id_t("view.network.site_map");
                const auto retained_last_seen = row.last_seen_ms;
                const auto retained_requests = row.total_requests;
                if (is_host) {
                    const auto retained = row.host_node;
                    context.validate_identity = [retained, retained_last_seen, retained_requests] {
                        auto& state = s();
                        std::lock_guard<std::mutex> lk(state.mtx);
                        const auto live = retained.lock();
                        return live && live->last_seen_ms == retained_last_seen &&
                                live->total_requests == retained_requests
                            ? aida::ui::capability_state_t::available()
                            : aida::ui::capability_state_t::unavailable(
                                "The site-map host was removed or replaced; select it again");
                    };
                } else {
                    const auto retained = row.path_node;
                    context.validate_identity = [retained, retained_last_seen, retained_requests] {
                        auto& state = s();
                        std::lock_guard<std::mutex> lk(state.mtx);
                        const auto live = retained.lock();
                        return live && live->last_seen_ms == retained_last_seen &&
                                live->total_requests == retained_requests
                            ? aida::ui::capability_state_t::available()
                            : aida::ui::capability_state_t::unavailable(
                                "The site-map path was removed or replaced; select it again");
                    };
                }
                const auto add = [&context](const char* id,
                        std::function<aida::ui::action_handler_result_t()> invoke) {
                    aida::ui::application_ui::retained_entity_action_t action;
                    action.action_id = id;
                    action.capability = aida::ui::capability_state_t::available();
                    action.invoke = std::move(invoke);
                    context.actions.push_back(std::move(action));
                };
                const std::string retained_host = row.host;
                const uint16_t retained_port = row.port;
                const std::string retained_path = row.path;
                add(is_host ? "network.site_map.host.include" : "network.site_map.path.include",
                    [scheme, retained_host, retained_port, retained_path] {
                        scope::add_include_rule(scheme, retained_host, retained_port, retained_path);
                        return aida::ui::action_handler_result_t::completed();
                    });
                add(is_host ? "network.site_map.host.exclude" : "network.site_map.path.exclude",
                    [scheme, retained_host, retained_port, retained_path] {
                        scope::add_exclude_rule(scheme, retained_host, retained_port, retained_path);
                        return aida::ui::action_handler_result_t::completed();
                    });
                if (!is_host) {
                    const std::string retained_url = context.entity_id;
                    add("network.site_map.copy_url", [retained_url] {
                        ImGui::SetClipboardText(retained_url.c_str());
                        return aida::ui::action_handler_result_t::completed();
                    });
                }
                aida::ui::application_ui::open_retained_entity_context_menu(
                    std::move(context), pointer_context
                        ? aida::ui::context_menu_open_origin_t::pointer
                        : menu_context
                        ? aida::ui::context_menu_open_origin_t::menu_key
                        : aida::ui::context_menu_open_origin_t::shift_f10);
            }
            ImGui::PopID();
            ImGui::PopID();
            ImGui::PopID();
            ImGui::PopID();
        }
    }

    if (rows_snapshot->empty()) {
        const ImVec2 c_org = ImGui::GetWindowPos();
        const ImVec2 c_sz  = ImGui::GetWindowSize();
        const char* msg = "No traffic captured yet.";
        const ImVec2 sz = ImGui::CalcTextSize(msg);
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(c_org.x + (c_sz.x - sz.x) * 0.5f, c_org.y + (c_sz.y - sz.y) * 0.5f),
            aida::ui::with_alpha(aida::ui::resolved().text_dim, alpha * 0.85f), msg);
    }
    aida::ui::application_ui::render_retained_entity_context_menu(
        "network.site_map.path");
    aida::ui::application_ui::render_retained_entity_context_menu(
        "network.site_map.host");

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
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            network_view::artifact_identity_t identity;
            std::string reason;
            static_cast<void>(network_view::make_sitemap_artifact(
                e.id, network_view::artifact_kind_t::sitemap_request, identity, reason));
            if (identity.valid() && ImGui::IsItemVisible())
                aida::preview::semantics::register_last_item(
                    semantic_artifact_id("request", identity),
                    "network-request-editor", false, false,
                    semantic_artifact_id("exchange", identity));
#endif
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
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                network_view::artifact_identity_t identity;
                std::string reason;
                static_cast<void>(network_view::make_sitemap_artifact(
                    e.id, network_view::artifact_kind_t::sitemap_request, identity, reason));
                if (identity.valid() && ImGui::IsItemVisible())
                    aida::preview::semantics::register_last_item(
                        semantic_artifact_id("request", identity),
                        "network-request-editor", false, false,
                        semantic_artifact_id("exchange", identity));
#endif
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
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            network_view::artifact_identity_t identity;
            network_view::artifact_identity_t request_identity;
            std::string reason;
            static_cast<void>(network_view::make_sitemap_artifact(
                e.id, network_view::artifact_kind_t::sitemap_response, identity, reason));
            static_cast<void>(network_view::make_sitemap_artifact(
                e.id, network_view::artifact_kind_t::sitemap_request,
                request_identity, reason));
            if (identity.valid() && ImGui::IsItemVisible())
                aida::preview::semantics::register_last_item(
                    semantic_artifact_id("response", identity),
                    "network-response-editor", false, false,
                    semantic_artifact_id("exchange", request_identity));
#endif
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
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                network_view::artifact_identity_t identity;
                network_view::artifact_identity_t request_identity;
                std::string reason;
                static_cast<void>(network_view::make_sitemap_artifact(
                    e.id, network_view::artifact_kind_t::sitemap_response, identity, reason));
                static_cast<void>(network_view::make_sitemap_artifact(
                    e.id, network_view::artifact_kind_t::sitemap_request,
                    request_identity, reason));
                if (identity.valid() && ImGui::IsItemVisible())
                    aida::preview::semantics::register_last_item(
                        semantic_artifact_id("response", identity),
                        "network-response-editor", false, false,
                        semantic_artifact_id("exchange", request_identity));
#endif
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::PopID();
}

struct selected_exchange_source_t
{
    host_key_t host_key;
    std::shared_ptr<path_node_t> path_node;
    bool host_scope = true;
    size_t count = 0;
};

selected_exchange_source_t selected_exchange_source(state_t& st)
{
    selected_exchange_source_t source;
    source.host_key = {st.selected_host, st.selected_port, st.selected_tls};
    std::lock_guard<std::mutex> lk(st.mtx);
    if (st.selected_path.empty()) {
        const auto index = st.exchange_index.find(source.host_key);
        source.count = index == st.exchange_index.end() ? 0 : index->second.size();
        return source;
    }
    source.host_scope = false;
    const auto host = st.hosts.find(source.host_key);
    if (host == st.hosts.end() || !host->second || !host->second->root) return source;
    std::vector<std::string> segments;
    split_path_segments(st.selected_path, segments);
    auto node = host->second->root;
    for (const auto& segment : segments) {
        const auto child = node->children.find(segment);
        if (child == node->children.end()) return source;
        node = child->second;
    }
    source.path_node = std::move(node);
    source.count = source.path_node ? source.path_node->exchanges.size() : 0;
    return source;
}

std::vector<exchange_row_t> copy_exchange_rows(
    state_t& st, const selected_exchange_source_t& source, int begin, int end)
{
    std::vector<exchange_row_t> rows;
    if (begin < 0 || end <= begin) return rows;
    rows.reserve(static_cast<size_t>(end - begin));
    std::lock_guard<std::mutex> lk(st.mtx);
    if (source.host_scope) {
        const auto index = st.exchange_index.find(source.host_key);
        if (index == st.exchange_index.end()) return rows;
        const int bounded_end = std::min(end, static_cast<int>(index->second.size()));
        for (int i = begin; i < bounded_end; ++i)
            rows.push_back(index->second[static_cast<size_t>(i)]);
        return rows;
    }
    if (!source.path_node) return rows;
    const int bounded_end = std::min(end,
        static_cast<int>(source.path_node->exchanges.size()));
    for (int i = begin; i < bounded_end; ++i)
        rows.push_back(make_exchange_row(
            source.path_node->exchanges[static_cast<size_t>(i)]));
    return rows;
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

    const selected_exchange_source_t exchange_source = selected_exchange_source(st);

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

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(exchange_source.count), row_h);
    while (clipper.Step()) {
    const std::vector<exchange_row_t> visible_rows = copy_exchange_rows(
        st, exchange_source, clipper.DisplayStart, clipper.DisplayEnd);
    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
        const size_t local_index = static_cast<size_t>(i - clipper.DisplayStart);
        if (local_index >= visible_rows.size()) {
            ImGui::Dummy(ImVec2(width, row_h));
            continue;
        }
        const exchange_row_t& e = visible_rows[local_index];
        const float row_alpha_anim = ui_anim::render_row_entrance(i, s_anim_time, 0.010f);
        const float r_alpha = alpha * row_alpha_anim;
        const float abs_ry = ImGui::GetCursorScreenPos().y;

        if (i & 1) {
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
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        network_view::artifact_identity_t semantic_request;
        std::string semantic_reason;
        static_cast<void>(network_view::make_sitemap_artifact(
            e.id, network_view::artifact_kind_t::sitemap_request,
            semantic_request, semantic_reason));
        if (semantic_request.valid() && ImGui::IsItemVisible())
            aida::preview::semantics::register_last_item(
                semantic_artifact_id("exchange", semantic_request),
                "network-exchange-row", false, false,
                "aida.dock-window.view.network.site-map");
#endif
        if (ImGui::IsItemClicked()) st.selected_exchange_id.store(e.id);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
            st.selected_exchange_id.store(e.id);
            network_view::artifact_identity_t request;
            network_view::artifact_identity_t response;
            std::string reason;
            static_cast<void>(network_view::make_sitemap_artifact(
                e.id, network_view::artifact_kind_t::sitemap_request, request, reason));
            static_cast<void>(network_view::make_sitemap_artifact(
                e.id, network_view::artifact_kind_t::sitemap_response, response, reason));
            network_view::open_exchange_context(std::move(request), std::move(response),
                network_view::exchange_context_origin_t::pointer);
        }

        ImU32 txt = aida::ui::with_alpha(th.text_primary, r_alpha);
        ImU32 dim = aida::ui::with_alpha(th.text_dim, r_alpha);
        float lx = lorg.x + 6.f;
        const float ty = abs_ry + text_oy;
        char buf[64];

        std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(e.id));
        ldl->AddText(ImVec2(lx, ty), dim, buf); lx += col_id;

        ldl->AddText(ImVec2(lx, ty), txt, e.method.c_str());
        lx += col_method;

        ldl->AddText(ImVec2(lx, ty), txt, e.path.c_str());
        lx += col_path;

        std::snprintf(buf, sizeof(buf), "%d", e.status_code);
        ImU32 sc_col = txt;
        if (e.status_code >= 500)      sc_col = aida::ui::with_alpha(th.error, r_alpha);
        else if (e.status_code >= 400) sc_col = aida::ui::with_alpha(th.warning, r_alpha);
        else if (e.status_code >= 200 && e.status_code < 300) sc_col = aida::ui::with_alpha(th.success, r_alpha);
        ldl->AddText(ImVec2(lx, ty), sc_col, buf);
        lx += col_status;

        std::snprintf(buf, sizeof(buf), "%zu", e.response_size);
        ldl->AddText(ImVec2(lx, ty), dim, buf);
        lx += col_size;

        std::snprintf(buf, sizeof(buf), "%llu ms", static_cast<unsigned long long>(e.latency_ms));
        ldl->AddText(ImVec2(lx, ty), dim, buf);

        ImGui::PopID();
    }
    }

    const bool exchange_menu_key = sel_id != 0 &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool exchange_shift_f10 = !exchange_menu_key && sel_id != 0 &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
    if (exchange_menu_key || exchange_shift_f10) {
        network_view::artifact_identity_t request;
        network_view::artifact_identity_t response;
        std::string reason;
        static_cast<void>(network_view::make_sitemap_artifact(
            sel_id, network_view::artifact_kind_t::sitemap_request, request, reason));
        static_cast<void>(network_view::make_sitemap_artifact(
            sel_id, network_view::artifact_kind_t::sitemap_response, response, reason));
        network_view::open_exchange_context(std::move(request), std::move(response),
            exchange_menu_key
                ? network_view::exchange_context_origin_t::menu_key
                : network_view::exchange_context_origin_t::shift_f10);
    }

    ImGui::EndChild();

    bool have_cur = false;
    if (sel_id != 0) {
        if (st.detail_cache_id != sel_id) {
            have_cur = find_exchange(sel_id, st.detail_cache);
            st.detail_cache_id = have_cur ? sel_id : 0;
        } else {
            have_cur = exchange_exists(sel_id);
            if (!have_cur) st.detail_cache_id = 0;
        }
    } else if (st.detail_cache_id != 0) {
        st.detail_cache_id = 0;
        st.detail_cache = {};
    }

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
        const exchange_observed_t& cur = st.detail_cache;
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
    ImGui::BeginChild("##burp_sitemap_root", ImVec2(width, height), false,
        ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::SetScrollY(0.f);

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
    const float content_h = std::max(1.f, height - 38.f);
    if (total == 0) {
        ImGui::SetCursorPos(ImVec2(pos_x + 2.f, content_y));
        const float empty_width = std::max(1.f, width - 4.f);
        ImGui::BeginChild("##sitemap_left", ImVec2(empty_width, content_h), false,
            ImGuiWindowFlags_NoBackground);
        ImGui::PushID("##burp_sitemap_tree");
        const float state_width = std::max(1.f, ImGui::GetContentRegionAvail().x);
        ImGui::SetNextItemWidth(std::min(360.f, state_width));
        ImGui::InputTextWithHint("##sitemap_filter", "Filter host or path...",
            st.tree_filter, sizeof(st.tree_filter));
        ImGui::PopID();
        ImGui::Spacing();
        const ImVec2 empty_pos = ImGui::GetCursorScreenPos();
        const ImVec2 empty_size(
            std::max(1.f, ImGui::GetContentRegionAvail().x),
            std::max(1.f, ImGui::GetContentRegionAvail().y));
        aida::ui::empty_state::config_t empty;
        empty.glyph = aida::ui::empty_state::glyph_t::network;
        empty.title = "No captured traffic";
        empty.body = "Requests from Proxy, Repeater, Scanner, and API tools are organized here by host and path.";
        empty.footer = "Start the proxy or send a request to populate the site map.";
        empty.max_width = std::min(360.f, empty_size.x);
        aida::ui::empty_state::render_panel(empty_pos, empty_size, empty, alpha);
        aida::ui::application_ui::render_retained_entity_context_menu(
            "network.site_map.path");
        aida::ui::application_ui::render_retained_entity_context_menu(
            "network.site_map.host");
        ImGui::EndChild();
        ImGui::EndChild();
        return;
    }
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
