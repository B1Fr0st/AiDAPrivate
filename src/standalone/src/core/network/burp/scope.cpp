#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "scope.hpp"
#include "burp_events.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace aida {
namespace burp {
namespace scope {

namespace {

struct state_t
{
    std::mutex                  mtx;
    std::vector<rule_t>         rules;
    std::atomic<uint64_t>       next_id{1};
    std::atomic<bool>           initialized{false};
    std::mutex                  err_mtx;
    std::string                 last_err;

    char                        new_protocol[16] = {};
    char                        new_host[256] = {};
    char                        new_port[16] = {};
    char                        new_path[512] = {};
    int                         new_kind = 0;
    char                        test_url[512] = {};
    bool                        test_result_valid = false;
    bool                        test_result_in_scope = false;
    int                         selected_index = -1;
};

state_t& s()
{
    static state_t st;
    return st;
}

void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}

std::string ascii_lower(const std::string& v)
{
    std::string r;
    r.reserve(v.size());
    for (char c : v) {
        if (c >= 'A' && c <= 'Z') r.push_back(static_cast<char>(c + 32));
        else                      r.push_back(c);
    }
    return r;
}

bool match_host_pattern(const std::string& pattern, const std::string& host)
{
    if (pattern.empty() || pattern == "*") return true;
    if (pattern == host) return true;

    if (pattern.find_first_of("*?[\\^$+(){}|") != std::string::npos) {
        std::regex re;
        try {
            re = std::regex(pattern, std::regex::ECMAScript | std::regex::icase);
        } catch (...) {
            return false;
        }
        try {
            return std::regex_match(host, re);
        } catch (...) {
            return false;
        }
    }

    if (pattern.size() >= 2 && pattern[0] == '.' ) {
        return host.size() >= pattern.size() - 1 &&
               host.compare(host.size() - (pattern.size() - 1), pattern.size() - 1, pattern.substr(1)) == 0;
    }

    if (host.size() >= pattern.size()) {
        const size_t off = host.size() - pattern.size();
        if (host.compare(off, pattern.size(), pattern) == 0) {
            if (off == 0) return true;
            if (host[off - 1] == '.') return true;
        }
    }
    return false;
}

bool rule_matches(const rule_t& r, const std::string& scheme, const std::string& host, uint16_t port, const std::string& path)
{
    if (!r.enabled) return false;
    if (!r.protocol.empty() && ascii_lower(r.protocol) != ascii_lower(scheme)) {
        if (!(r.protocol == "*" || r.protocol == "any")) return false;
    }
    if (r.port != 0 && static_cast<uint16_t>(r.port) != port) return false;
    if (!r.host_pattern.empty() && !match_host_pattern(r.host_pattern, host)) return false;
    if (!r.path_prefix.empty()) {
        if (path.size() < r.path_prefix.size()) return false;
        if (path.compare(0, r.path_prefix.size(), r.path_prefix) != 0) return false;
    }
    return true;
}

}

parsed_url_t parse_url(const std::string& url)
{
    parsed_url_t out;
    if (url.empty()) return out;
    const size_t scheme_end = url.find("://");
    size_t cursor = 0;
    if (scheme_end != std::string::npos) {
        out.scheme = ascii_lower(url.substr(0, scheme_end));
        cursor = scheme_end + 3;
    } else {
        out.scheme = "http";
    }
    const size_t path_start = url.find('/', cursor);
    std::string authority = (path_start == std::string::npos) ? url.substr(cursor) : url.substr(cursor, path_start - cursor);

    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        out.host = ascii_lower(authority.substr(0, colon));
        const std::string port_str = authority.substr(colon + 1);
        long port_val = 0;
        for (char c : port_str) {
            if (c < '0' || c > '9') { port_val = -1; break; }
            port_val = port_val * 10 + (c - '0');
            if (port_val > 65535) { port_val = -1; break; }
        }
        if (port_val < 0) { out.host = ascii_lower(authority); out.port = 0; }
        else              out.port = static_cast<uint16_t>(port_val);
    } else {
        out.host = ascii_lower(authority);
        out.port = 0;
    }

    if (out.port == 0) {
        if (out.scheme == "https" || out.scheme == "wss") out.port = 443;
        else if (out.scheme == "http" || out.scheme == "ws") out.port = 80;
    }

    if (path_start == std::string::npos) out.path = "/";
    else                                  out.path = url.substr(path_start);

    out.valid = !out.host.empty();
    return out;
}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    load_from_disk();
    diag::log_tagged("burp", "scope_initialized");
    return true;
}

void shutdown()
{
    auto& st = s();
    if (!st.initialized.exchange(false)) return;
    save_to_disk();
}

bool in_scope_components(const std::string& scheme, const std::string& host, uint16_t port, const std::string& path)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);

    if (st.rules.empty()) return true;

    bool has_includes = false;
    bool include_matched = false;
    for (const auto& r : st.rules) {
        if (r.kind == rule_kind_t::include && r.enabled) {
            has_includes = true;
            if (rule_matches(r, scheme, host, port, path)) {
                include_matched = true;
                break;
            }
        }
    }

    if (has_includes && !include_matched) return false;

    for (const auto& r : st.rules) {
        if (r.kind == rule_kind_t::exclude && rule_matches(r, scheme, host, port, path)) return false;
    }
    return true;
}

bool in_scope(const std::string& url)
{
    parsed_url_t p = parse_url(url);
    if (!p.valid) return false;
    return in_scope_components(p.scheme, p.host, p.port, p.path);
}

uint64_t add_rule(const rule_t& src)
{
    auto& st = s();
    rule_t r = src;
    if (r.id == 0) r.id = st.next_id.fetch_add(1);
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.rules.push_back(r);
    }
    save_to_disk();
    aida::events::publish(kScopeChangedEvent, scope_changed_t{r.id, "add", r.kind == rule_kind_t::exclude});
    return r.id;
}

uint64_t add_include_rule(const std::string& protocol, const std::string& host_pattern, int port, const std::string& path_prefix)
{
    rule_t r;
    r.kind = rule_kind_t::include;
    r.protocol = protocol;
    r.host_pattern = host_pattern;
    r.port = port;
    r.path_prefix = path_prefix;
    r.enabled = true;
    return add_rule(r);
}

uint64_t add_exclude_rule(const std::string& protocol, const std::string& host_pattern, int port, const std::string& path_prefix)
{
    rule_t r;
    r.kind = rule_kind_t::exclude;
    r.protocol = protocol;
    r.host_pattern = host_pattern;
    r.port = port;
    r.path_prefix = path_prefix;
    r.enabled = true;
    return add_rule(r);
}

bool remove_rule(uint64_t rule_id)
{
    auto& st = s();
    bool removed = false;
    bool was_exclude = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto it = st.rules.begin(); it != st.rules.end(); ++it) {
            if (it->id == rule_id) {
                was_exclude = (it->kind == rule_kind_t::exclude);
                st.rules.erase(it);
                removed = true;
                break;
            }
        }
    }
    if (removed) {
        save_to_disk();
        aida::events::publish(kScopeChangedEvent, scope_changed_t{rule_id, "remove", was_exclude});
    } else {
        set_err("rule_id not found");
    }
    return removed;
}

bool set_rule_enabled(uint64_t rule_id, bool enabled)
{
    auto& st = s();
    bool changed = false;
    bool was_exclude = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto& r : st.rules) {
            if (r.id == rule_id) {
                r.enabled = enabled;
                was_exclude = (r.kind == rule_kind_t::exclude);
                changed = true;
                break;
            }
        }
    }
    if (changed) {
        save_to_disk();
        aida::events::publish(kScopeChangedEvent, scope_changed_t{rule_id, "enable", was_exclude});
    }
    return changed;
}

void clear_all()
{
    auto& st = s();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.rules.clear();
    }
    save_to_disk();
    aida::events::publish(kScopeChangedEvent, scope_changed_t{0, "clear", false});
}

std::vector<rule_t> list_rules()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    return st.rules;
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    return st.last_err;
}

std::string storage_path()
{
    PWSTR appdata = nullptr;
    std::string base;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)) && appdata) {
        const int needed = WideCharToMultiByte(CP_UTF8, 0, appdata, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            base.assign(static_cast<size_t>(needed - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, appdata, -1, base.data(), needed, nullptr, nullptr);
        }
        CoTaskMemFree(appdata);
    }
    if (base.empty()) {
        char buf[MAX_PATH] = {};
        const DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) base.assign(buf, len);
        else                            base = "C:\\Users\\Public";
        base += "\\AppData\\Roaming";
    }
    base += "\\AiDA\\Standalone\\burp";
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    base += "\\scope.json";
    return base;
}

nlohmann::json rule_to_json(const rule_t& r)
{
    nlohmann::json j;
    j["id"]            = r.id;
    j["kind"]          = (r.kind == rule_kind_t::exclude) ? "exclude" : "include";
    j["protocol"]      = r.protocol;
    j["host_pattern"]  = r.host_pattern;
    j["port"]          = r.port;
    j["path_prefix"]   = r.path_prefix;
    j["enabled"]       = r.enabled;
    return j;
}

bool rule_from_json(const nlohmann::json& j, rule_t& out)
{
    if (!j.is_object()) return false;
    out = rule_t{};
    if (j.contains("id") && j["id"].is_number_unsigned()) out.id = j["id"].get<uint64_t>();
    const std::string k = j.value("kind", std::string("include"));
    out.kind = (k == "exclude") ? rule_kind_t::exclude : rule_kind_t::include;
    out.protocol     = j.value("protocol", std::string());
    out.host_pattern = j.value("host_pattern", std::string());
    out.port         = j.value("port", 0);
    out.path_prefix  = j.value("path_prefix", std::string());
    out.enabled      = j.value("enabled", true);
    return true;
}

bool save_to_disk()
{
    auto& st = s();
    nlohmann::json arr = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (const auto& r : st.rules) arr.push_back(rule_to_json(r));
    }
    const std::string path = storage_path();
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        set_err("failed to open scope.json for write");
        return false;
    }
    const std::string dump = arr.dump(2);
    out.write(dump.data(), static_cast<std::streamsize>(dump.size()));
    return true;
}

bool load_from_disk()
{
    auto& st = s();
    const std::string path = storage_path();
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string data = ss.str();
    if (data.empty()) return false;

    nlohmann::json arr;
    try {
        arr = nlohmann::json::parse(data, nullptr, false);
    } catch (...) {
        set_err("scope.json parse failed");
        return false;
    }
    if (arr.is_discarded() || !arr.is_array()) {
        set_err("scope.json not an array");
        return false;
    }

    uint64_t max_id = 0;
    std::vector<rule_t> loaded;
    loaded.reserve(arr.size());
    for (const auto& j : arr) {
        rule_t r;
        if (!rule_from_json(j, r)) continue;
        if (r.id > max_id) max_id = r.id;
        loaded.push_back(r);
    }
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.rules = std::move(loaded);
    }
    st.next_id.store(max_id + 1);
    return true;
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = s();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_scope_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();

    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Scope rules");

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + 36.f));
    ImGui::PushID("burp_scope_form");

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Kind:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(96.f);
    const char* kinds[] = {"include", "exclude"};
    ImGui::Combo("##scope_kind", &st.new_kind, kinds, 2);

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Proto:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputTextWithHint("##scope_proto", "https/http/any", st.new_protocol, sizeof(st.new_protocol));

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Host:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.f);
    ImGui::InputTextWithHint("##scope_host", ".example.com or regex", st.new_host, sizeof(st.new_host));

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Port:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(64.f);
    ImGui::InputTextWithHint("##scope_port", "0=any", st.new_port, sizeof(st.new_port), ImGuiInputTextFlags_CharsDecimal);

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Path:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180.f);
    ImGui::InputTextWithHint("##scope_path", "/api/", st.new_path, sizeof(st.new_path));

    ImGui::SameLine();
    if (ImGui::Button("Add rule##scope_add", ImVec2(96.f, 22.f))) {
        if (st.new_host[0] != '\0') {
            int port_val = 0;
            for (const char* p = st.new_port; *p; ++p) {
                if (*p < '0' || *p > '9') { port_val = -1; break; }
                port_val = port_val * 10 + (*p - '0');
                if (port_val > 65535) { port_val = -1; break; }
            }
            if (port_val < 0) port_val = 0;
            if (st.new_kind == 0) {
                add_include_rule(st.new_protocol, st.new_host, port_val, st.new_path);
            } else {
                add_exclude_rule(st.new_protocol, st.new_host, port_val, st.new_path);
            }
            st.new_host[0] = '\0';
            st.new_path[0] = '\0';
            st.new_port[0] = '\0';
            st.new_protocol[0] = '\0';
        }
    }
    ImGui::PopID();

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + 72.f));
    ImGui::BeginChild("##burp_scope_table", ImVec2(width - 12.f, height - 150.f), false, ImGuiWindowFlags_NoBackground);

    std::vector<rule_t> snapshot;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        snapshot = st.rules;
    }

    static float s_anim_time = 0.f;
    s_anim_time += ImGui::GetIO().DeltaTime;

    ImVec2 table_org = ImGui::GetWindowPos();
    const float row_h = 24.f;
    const float col_kind = 64.f;
    const float col_proto = 64.f;
    const float col_port = 56.f;
    const float col_actions = 140.f;
    const float remain = (width - 12.f) - col_kind - col_proto - col_port - col_actions - 16.f;
    const float col_host = std::max(160.f, remain * 0.55f);
    const float col_path = std::max(80.f, remain - col_host);

    dl->AddRectFilled(ImVec2(table_org.x, table_org.y), ImVec2(table_org.x + width - 12.f, table_org.y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    float cx = table_org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, table_org.y + 4.f), hdr_col, "Kind");   cx += col_kind;
    dl->AddText(ImVec2(cx, table_org.y + 4.f), hdr_col, "Proto");  cx += col_proto;
    dl->AddText(ImVec2(cx, table_org.y + 4.f), hdr_col, "Host");   cx += col_host;
    dl->AddText(ImVec2(cx, table_org.y + 4.f), hdr_col, "Path");   cx += col_path;
    dl->AddText(ImVec2(cx, table_org.y + 4.f), hdr_col, "Port");   cx += col_port;
    dl->AddText(ImVec2(cx, table_org.y + 4.f), hdr_col, "Actions");

    ImGui::SetCursorPosY(row_h + 4.f);

    int visible_row = 0;
    for (int i = 0; i < static_cast<int>(snapshot.size()); i++) {
        const auto& r = snapshot[static_cast<size_t>(i)];

        float row_alpha = ui_anim::render_row_entrance(visible_row, s_anim_time, 0.012f);
        float r_alpha = alpha * row_alpha;

        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool selected = (st.selected_index == i);

        if (visible_row & 1) {
            dl->AddRectFilled(ImVec2(table_org.x, abs_ry), ImVec2(table_org.x + width - 12.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
        }
        if (selected) {
            dl->AddRectFilled(ImVec2(table_org.x, abs_ry), ImVec2(table_org.x + width - 12.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
        }

        ImGui::PushID(static_cast<int>(r.id));
        ImGui::InvisibleButton("##scope_row", ImVec2(width - 12.f, row_h));
        if (ImGui::IsItemClicked()) st.selected_index = i;

        ImU32 kind_col = (r.kind == rule_kind_t::include) ? aida::ui::with_alpha(th.success, r_alpha)
                                                          : aida::ui::with_alpha(th.error, r_alpha);
        ImU32 txt = aida::ui::with_alpha(r.enabled ? th.text_primary : th.text_dim, r_alpha);
        float ty = abs_ry + 4.f;
        float lx = table_org.x + 8.f;
        dl->AddText(ImVec2(lx, ty), kind_col, (r.kind == rule_kind_t::include) ? "include" : "exclude");
        lx += col_kind;
        dl->AddText(ImVec2(lx, ty), txt, r.protocol.empty() ? "*" : r.protocol.c_str());
        lx += col_proto;
        dl->AddText(ImVec2(lx, ty), txt, r.host_pattern.c_str());
        lx += col_host;
        dl->AddText(ImVec2(lx, ty), txt, r.path_prefix.empty() ? "/" : r.path_prefix.c_str());
        lx += col_path;
        char port_buf[16];
        std::snprintf(port_buf, sizeof(port_buf), "%s", r.port == 0 ? "*" : std::to_string(r.port).c_str());
        dl->AddText(ImVec2(lx, ty), txt, port_buf);
        lx += col_port;

        ImGui::SetCursorScreenPos(ImVec2(lx, abs_ry + 1.f));
        if (ImGui::SmallButton(r.enabled ? "Disable" : "Enable")) set_rule_enabled(r.id, !r.enabled);
        ImGui::SameLine();
        if (ImGui::SmallButton("Remove")) remove_rule(r.id);

        ImGui::PopID();
        ++visible_row;
    }

    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + height - 70.f));
    ImGui::PushID("burp_scope_test");
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Test URL:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(420.f);
    ImGui::InputTextWithHint("##scope_test_url", "https://example.com/path", st.test_url, sizeof(st.test_url));
    ImGui::SameLine();
    if (ImGui::Button("Check##scope_check", ImVec2(80.f, 22.f))) {
        st.test_result_valid = true;
        st.test_result_in_scope = in_scope(st.test_url);
    }
    if (st.test_result_valid) {
        ImGui::SameLine();
        ImU32 status_col = st.test_result_in_scope ? th.success : th.error;
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(status_col, alpha)),
                           st.test_result_in_scope ? "in scope" : "out of scope");
    }
    ImGui::PopID();

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + height - 38.f));
    if (ImGui::Button("Clear all##scope_clear", ImVec2(120.f, 24.f))) {
        clear_all();
        st.selected_index = -1;
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload##scope_reload", ImVec2(120.f, 24.f))) {
        load_from_disk();
    }

    ImGui::EndChild();
}

}
}
}
