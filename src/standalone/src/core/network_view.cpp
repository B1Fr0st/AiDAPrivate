#include "network_view.hpp"
#include "protocol_parser.hpp"
#include "mitm_proxy.hpp"
#include "cert_pin_bypass.hpp"
#include "ssl_keylog.hpp"
#include "comm.h"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace network_view {

// ─── Helpers ──────────────────────────────────────────────────────

static std::string format_ip(const uint8_t* addr, uint8_t af) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (af == 2) { // AF_INET
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else if (af == 23) { // AF_INET6
        inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    }
    return buf;
}

static const char* protocol_name(uint8_t proto) {
    switch (proto) {
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "???";
    }
}

static const char* tcp_state_name(uint8_t state) {
    static const char* names[] = {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
    };
    if (state < 12) return names[state];
    return "UNKNOWN";
}

static std::string format_bytes(uint64_t bytes) {
    char buf[64];
    if (bytes < 1024)
        snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
    else if (bytes < 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
    else if (bytes < 1024ULL * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    else
        snprintf(buf, sizeof(buf), "%.2f GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

static std::string format_rate(float bytes_per_sec) {
    if (bytes_per_sec < 1024.f) return format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
    return format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
}

static std::string format_timestamp(uint64_t ts) {
    uint64_t sec = ts / 1000;
    uint64_t ms = ts % 1000;
    uint64_t h = (sec / 3600) % 24;
    uint64_t m = (sec / 60) % 60;
    uint64_t s = sec % 60;
    char buf[32];
    snprintf(buf, sizeof(buf), "%02llu:%02llu:%02llu.%03llu",
        static_cast<unsigned long long>(h), static_cast<unsigned long long>(m),
        static_cast<unsigned long long>(s), static_cast<unsigned long long>(ms));
    return buf;
}

static bool filter_text_match(const char* filter, const std::string& text) {
    if (!filter || !filter[0]) return true;
    // Case-insensitive substring match
    std::string lower_filter(filter);
    std::string lower_text = text;
    for (auto& c : lower_filter) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    for (auto& c : lower_text) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lower_text.find(lower_filter) != std::string::npos;
}

// ─── Background Polling Threads ───────────────────────────────────

static void connection_poll_thread(state_t& state) {
    while (state.conn_polling.load()) {
        if (device && device->is_connected()) {
            auto raw_conns = device->enumerate_connections(
                state.conn_filter_pid, state.conn_filter_protocol);

            std::vector<connection_entry> entries;
            entries.reserve(raw_conns.size());
            for (auto& c : raw_conns) {
                connection_entry e;
                e.pid = c.pid;
                e.protocol = c.protocol;
                e.state = c.state;
                e.local_port = c.local_port;
                e.remote_port = c.remote_port;
                e.address_family = c.address_family;
                memcpy(e.local_addr, c.local_addr, 16);
                memcpy(e.remote_addr, c.remote_addr, 16);
                entries.push_back(std::move(e));
            }

            {
                std::lock_guard<std::mutex> lock(state.conn_mutex);
                state.connections = std::move(entries);
            }
        }

        // Poll every 1s
        for (int i = 0; i < 100 && state.conn_polling.load(); i++)
            Sleep(10);
    }
}

static void capture_poll_thread(state_t& state) {
    while (state.cap_polling.load()) {
        if (device && device->is_connected()) {
            auto raw_packets = device->get_captured_packets(64);

            if (!raw_packets.empty()) {
                std::lock_guard<std::mutex> lock(state.cap_mutex);
                for (auto& p : raw_packets) {
                    packet_entry entry;
                    entry.timestamp = p.timestamp;
                    entry.pid = p.pid;
                    entry.protocol = static_cast<uint8_t>(p.protocol);
                    entry.direction = static_cast<uint8_t>(p.direction);
                    entry.src_port = static_cast<uint16_t>(p.local_port);
                    entry.dst_port = static_cast<uint16_t>(p.remote_port);
                    memcpy(entry.src_addr, p.local_addr, 16);
                    memcpy(entry.dst_addr, p.remote_addr, 16);
                    entry.payload_size = p.payload_size;
                    entry.payload = p.payload;

                    // Detect protocol
                    auto det = protocol_parser::detect_protocol(
                        p.payload.data(), p.payload.size(),
                        static_cast<uint16_t>(p.local_port), static_cast<uint16_t>(p.remote_port),
                        p.protocol);
                    entry.protocol_label = det.label;
                    entry.summary = det.summary;

                    state.captured_packets.push_back(std::move(entry));
                    while (state.captured_packets.size() > state.cap_max_packets)
                        state.captured_packets.pop_front();
                }
            }
        }

        // Poll every 100ms
        for (int i = 0; i < 10 && state.cap_polling.load(); i++)
            Sleep(10);
    }
}

static void dns_poll_thread(state_t& state) {
    while (state.dns_polling.load()) {
        if (device && device->is_connected()) {
            auto raw_dns = device->get_dns_queries(state.dns_filter_pid);

            std::vector<dns_entry> entries;
            entries.reserve(raw_dns.size());
            for (auto& d : raw_dns) {
                dns_entry e;
                e.timestamp = d.timestamp;
                e.pid = d.pid;
                e.query_type = static_cast<uint16_t>(d.query_type);
                e.domain = d.domain;
                e.resolved_addr = format_ip(d.resolved_addr, 2);
                e.response_code = d.response_code;
                e.ttl = d.ttl;
                entries.push_back(std::move(e));
            }

            {
                std::lock_guard<std::mutex> lock(state.dns_mutex);
                state.dns_entries = std::move(entries);
            }
        }

        // Poll every 500ms
        for (int i = 0; i < 50 && state.dns_polling.load(); i++)
            Sleep(10);
    }
}

static void bandwidth_poll_thread(state_t& state) {
    while (state.bw_polling.load()) {
        if (device && device->is_connected()) {
            auto raw_bw = device->get_bw_per_process();

            std::vector<bw_entry> entries;
            entries.reserve(raw_bw.size());
            for (auto& b : raw_bw) {
                bw_entry e;
                e.pid = b.pid;
                e.bytes_in = b.bytes_recv;
                e.bytes_out = b.bytes_sent;
                e.rate_in = 0.f;
                e.rate_out = 0.f;
                entries.push_back(std::move(e));
            }

            {
                std::lock_guard<std::mutex> lock(state.bw_mutex);
                state.bw_entries = std::move(entries);
            }
        }

        // Poll every 500ms
        for (int i = 0; i < 50 && state.bw_polling.load(); i++)
            Sleep(10);
    }
}

// ─── Init / Shutdown ──────────────────────────────────────────────

void initialize() {
    g_state.active = true;

    // Start connection polling
    g_state.conn_polling.store(true);
    g_state.conn_thread = std::thread(connection_poll_thread, std::ref(g_state));
}

void shutdown() {
    g_state.conn_polling.store(false);
    g_state.cap_polling.store(false);
    g_state.dns_polling.store(false);
    g_state.bw_polling.store(false);

    if (g_state.conn_thread.joinable()) g_state.conn_thread.join();
    if (g_state.cap_thread.joinable()) g_state.cap_thread.join();
    if (g_state.dns_thread.joinable()) g_state.dns_thread.join();
    if (g_state.bw_thread.joinable()) g_state.bw_thread.join();

    mitm_proxy::stop();
    ssl_keylog::stop_watching();
    g_state.active = false;
}

// ─── Tab Names ────────────────────────────────────────────────────

static const char* tab_names[] = {
    "Connections", "Capture", "Intercept", "Proxy",
    "DNS", "Filters", "Bandwidth", "Repeater", "KeyLog"
};

// ─── Sub-tab Rendering ────────────────────────────────────────────

static void render_tab_bar(state_t& state, float x, float y, float w, float alpha,
                            float ar, float ag, float ab, float dt) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();

    float tab_h = 28.f;
    float tab_x = x;
    int count = static_cast<int>(sub_tab_t::COUNT);

    for (int i = 0; i < count; i++) {
        ImVec2 ts = ImGui::CalcTextSize(tab_names[i]);
        float tab_w = ts.x + 20.f;
        bool is_active = (static_cast<int>(state.active_tab) == i);

        // Animate
        float target = is_active ? 1.f : 0.f;
        state.tab_anim[i] += (target - state.tab_anim[i]) * std::min(12.f * dt, 1.f);

        float bx0 = origin.x + tab_x;
        float by0 = origin.y + y;
        float bx1 = bx0 + tab_w;
        float by1 = by0 + tab_h;

        // Hit test
        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= bx0 && mouse.x < bx1 && mouse.y >= by0 && mouse.y < by1);

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.active_tab = static_cast<sub_tab_t>(i);

        // Background
        float bg_alpha = is_active ? 0.15f : (hovered ? 0.08f : 0.f);
        if (bg_alpha > 0.01f)
            dl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1),
                IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                         static_cast<int>(ab * 255), static_cast<int>(bg_alpha * alpha * 255)),
                4.f);

        // Underline
        float ul_alpha = state.tab_anim[i];
        if (ul_alpha > 0.01f) {
            dl->AddRectFilled(ImVec2(bx0 + 4.f, by1 - 2.f), ImVec2(bx1 - 4.f, by1),
                IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                         static_cast<int>(ab * 255), static_cast<int>(ul_alpha * alpha * 255)),
                1.f);
        }

        // Text
        float text_alpha = is_active ? 0.95f : (hovered ? 0.7f : 0.5f);
        dl->AddText(ImVec2(bx0 + 10.f, by0 + (tab_h - ts.y) * 0.5f),
            IM_COL32(255, 255, 255, static_cast<int>(text_alpha * alpha * 255)),
            tab_names[i]);

        tab_x += tab_w + 2.f;
    }

    // Separator line
    dl->AddLine(
        ImVec2(origin.x + x, origin.y + y + tab_h),
        ImVec2(origin.x + x + w, origin.y + y + tab_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));
}

// ─── Connections Tab ──────────────────────────────────────────────

static void render_connections(state_t& state, float x, float y, float w, float h,
                                float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_conn", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    // Toolbar
    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));
    ImGui::SetNextItemWidth(120.f);
    ImGui::InputTextWithHint("##conn_search", "Filter...", state.conn_filter_text, sizeof(state.conn_filter_text));
    ImGui::SameLine();

    bool driver_ok = device && device->is_connected();
    if (!driver_ok) ImGui::BeginDisabled();
    if (ImGui::SmallButton(state.conn_auto_refresh ? "Auto" : "Manual")) {
        state.conn_auto_refresh = !state.conn_auto_refresh;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) {
        // trigger immediate refresh
        if (driver_ok) {
            auto raw = device->enumerate_connections(state.conn_filter_pid, state.conn_filter_protocol);
            std::lock_guard<std::mutex> lock(state.conn_mutex);
            state.connections.clear();
            for (auto& c : raw) {
                connection_entry e;
                e.pid = c.pid;
                e.protocol = c.protocol;
                e.state = c.state;
                e.local_port = c.local_port;
                e.remote_port = c.remote_port;
                e.address_family = c.address_family;
                memcpy(e.local_addr, c.local_addr, 16);
                memcpy(e.remote_addr, c.remote_addr, 16);
                state.connections.push_back(std::move(e));
            }
        }
    }
    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    {
        std::lock_guard<std::mutex> lock(state.conn_mutex);
        char count_buf[32];
        snprintf(count_buf, sizeof(count_buf), "%zu connections", state.connections.size());
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "%s", count_buf);
    }

    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Column headers
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 20.f;
    float hdr_y = org.y + cursor.y;

    // Column widths
    float col_pid = 60.f, col_proto = 45.f, col_state = 90.f;
    float col_local = (w - col_pid - col_proto - col_state - 20.f) * 0.5f;
    float col_remote = col_local;

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(180, 180, 200, static_cast<int>(0.7f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "PID");   cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Proto"); cx += col_proto;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "State"); cx += col_state;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Local"); cx += col_local;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Remote");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x + 2.f, hdr_y + row_h), ImVec2(org.x + w - 2.f, hdr_y + row_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

    // Scrollable list
    float list_h = h - (cursor.y + row_h + 8.f);
    ImGui::BeginChild("##conn_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.conn_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();

    for (int i = 0; i < static_cast<int>(state.connections.size()); i++) {
        auto& c = state.connections[static_cast<size_t>(i)];

        std::string local_str = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        std::string remote_str = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);

        // Apply text filter
        if (state.conn_filter_text[0]) {
            std::string all = std::to_string(c.pid) + " " + protocol_name(c.protocol) + " " +
                tcp_state_name(c.state) + " " + local_str + " " + remote_str;
            if (!filter_text_match(state.conn_filter_text, all)) continue;
        }

        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;
        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.conn_selected == i);

        if (hovered || selected) {
            ImU32 bg = selected
                ? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.2f * alpha * 255))
                : IM_COL32(255, 255, 255, static_cast<int>(0.04f * alpha * 255));
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg);
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.conn_selected = i;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>((selected ? 0.95f : 0.75f) * alpha * 255));

        cx = list_org.x + 4.f;
        char pid_buf[16];
        snprintf(pid_buf, sizeof(pid_buf), "%u", c.pid);
        dl->AddText(ImVec2(cx, abs_ry), txt_col, pid_buf);                            cx += col_pid;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, protocol_name(c.protocol));          cx += col_proto;

        // Color-code state
        ImU32 state_col = txt_col;
        if (c.state == 4) state_col = IM_COL32(100, 255, 100, static_cast<int>(0.85f * alpha * 255)); // ESTABLISHED
        else if (c.state == 1) state_col = IM_COL32(100, 180, 255, static_cast<int>(0.85f * alpha * 255)); // LISTEN
        dl->AddText(ImVec2(cx, abs_ry), state_col, tcp_state_name(c.state));          cx += col_state;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, local_str.c_str());                  cx += col_local;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, remote_str.c_str());

        ImGui::SetCursorPosY(ry + row_h);
    }

    ImGui::EndChild();
    ImGui::EndChild();
}

// ─── Capture Tab ──────────────────────────────────────────────────

static void render_capture(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_cap", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = device && device->is_connected();

    // Toolbar
    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));
    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.cap_running) {
        if (ImGui::SmallButton("Start Capture")) {
            if (device->start_capture(state.cap_filter_pid, state.cap_filter_port,
                                       state.cap_filter_protocol, nullptr)) {
                state.cap_running = true;
                state.cap_polling.store(true);
                state.cap_thread = std::thread(capture_poll_thread, std::ref(state));
            }
        }
    } else {
        if (ImGui::SmallButton("Stop Capture")) {
            device->stop_capture();
            state.cap_running = false;
            state.cap_polling.store(false);
            if (state.cap_thread.joinable()) state.cap_thread.join();
        }
    }

    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        state.captured_packets.clear();
        state.cap_selected = -1;
    }

    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.f);
    ImGui::InputTextWithHint("##cap_filter", "Filter...", state.cap_filter_text, sizeof(state.cap_filter_text));

    ImGui::SameLine();
    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        char count_buf[32];
        snprintf(count_buf, sizeof(count_buf), "%zu packets", state.captured_packets.size());
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "%s", count_buf);
    }

    if (state.cap_running) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(static_cast<float>(ar), static_cast<float>(ag), static_cast<float>(ab), alpha), "LIVE");
    }

    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Split: top = packet list, bottom = detail
    float split_y = h * state.detail_ratio;
    float detail_h = h - split_y - 30.f;

    // Packet list header
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 18.f;
    float hdr_y = org.y + cursor.y;

    float col_no = 50.f, col_time = 80.f, col_proto = 50.f, col_info = 50.f;
    float col_src = (w - col_no - col_time - col_proto - col_info - 20.f) * 0.5f;
    float col_dst = col_src;

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(180, 180, 200, static_cast<int>(0.7f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "#");     cx += col_no;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Time");  cx += col_time;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Src");   cx += col_src;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Dst");   cx += col_dst;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Proto"); cx += col_proto;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Info");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x + 2.f, hdr_y + row_h), ImVec2(org.x + w - 2.f, hdr_y + row_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

    float list_top = cursor.y + row_h + 4.f;
    float list_h = split_y - list_top;

    ImGui::SetCursorPosY(list_top);
    ImGui::BeginChild("##cap_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        ImVec2 list_org = ImGui::GetWindowPos();

        for (int i = 0; i < static_cast<int>(state.captured_packets.size()); i++) {
            auto& p = state.captured_packets[static_cast<size_t>(i)];

            std::string src_str = format_ip(p.src_addr, 2) + ":" + std::to_string(p.src_port);
            std::string dst_str = format_ip(p.dst_addr, 2) + ":" + std::to_string(p.dst_port);

            if (state.cap_filter_text[0]) {
                std::string all = src_str + " " + dst_str + " " + p.protocol_label + " " + p.summary;
                if (!filter_text_match(state.cap_filter_text, all)) continue;
            }

            float ry = ImGui::GetCursorPosY();
            float abs_ry = list_org.y + ry;
            ImVec2 mouse = ImGui::GetMousePos();
            bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                            mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
            bool selected = (state.cap_selected == i);

            if (hovered || selected) {
                ImU32 bg = selected
                    ? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.2f * alpha * 255))
                    : IM_COL32(255, 255, 255, static_cast<int>(0.04f * alpha * 255));
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg);
            }

            if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                state.cap_selected = i;

            ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>((selected ? 0.95f : 0.7f) * alpha * 255));

            // Color by protocol
            if (p.protocol_label == "HTTP") txt_col = IM_COL32(100, 200, 255, static_cast<int>(0.9f * alpha * 255));
            else if (p.protocol_label == "TLS") txt_col = IM_COL32(255, 200, 100, static_cast<int>(0.9f * alpha * 255));
            else if (p.protocol_label == "DNS") txt_col = IM_COL32(100, 255, 180, static_cast<int>(0.9f * alpha * 255));

            cx = list_org.x + 4.f;
            char no_buf[16]; snprintf(no_buf, sizeof(no_buf), "%d", i + 1);
            dl->AddText(ImVec2(cx, abs_ry), IM_COL32(130, 130, 150, static_cast<int>(0.6f * alpha * 255)), no_buf);
            cx += col_no;

            dl->AddText(ImVec2(cx, abs_ry), IM_COL32(150, 150, 170, static_cast<int>(0.6f * alpha * 255)),
                format_timestamp(p.timestamp).c_str());
            cx += col_time;

            dl->AddText(ImVec2(cx, abs_ry), txt_col, src_str.c_str()); cx += col_src;
            dl->AddText(ImVec2(cx, abs_ry), txt_col, dst_str.c_str()); cx += col_dst;

            dl->AddText(ImVec2(cx, abs_ry), txt_col, p.protocol_label.c_str()); cx += col_proto;

            // Truncate summary
            std::string info = p.summary;
            if (info.size() > 60) info = info.substr(0, 57) + "...";
            dl->AddText(ImVec2(cx, abs_ry), IM_COL32(200, 200, 210, static_cast<int>(0.65f * alpha * 255)), info.c_str());

            ImGui::SetCursorPosY(ry + row_h);
        }

        // Auto-scroll
        if (state.cap_auto_scroll && !state.captured_packets.empty())
            ImGui::SetScrollHereY(1.0f);
    }

    ImGui::EndChild();

    // ── Detail panel ──
    ImGui::Spacing();
    dl->AddLine(ImVec2(org.x + 2.f, org.y + ImGui::GetCursorPosY()),
                ImVec2(org.x + w - 2.f, org.y + ImGui::GetCursorPosY()),
                IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));
    ImGui::Spacing();

    if (detail_h > 30.f) {
        ImGui::BeginChild("##cap_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        std::lock_guard<std::mutex> lock2(state.cap_mutex);
        if (state.cap_selected >= 0 && state.cap_selected < static_cast<int>(state.captured_packets.size())) {
            auto& p = state.captured_packets[static_cast<size_t>(state.cap_selected)];

            ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Packet #%d - %s", state.cap_selected + 1, p.protocol_label.c_str());
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, alpha),
                "%s:%u -> %s:%u | PID: %u | %u bytes | %s",
                format_ip(p.src_addr, 2).c_str(), p.src_port,
                format_ip(p.dst_addr, 2).c_str(), p.dst_port,
                p.pid, p.payload_size,
                p.direction == 0 ? "Inbound" : "Outbound");

            if (!p.summary.empty())
                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.8f, alpha), "%s", p.summary.c_str());

            ImGui::Spacing();

            // Hex dump of payload
            if (!p.payload.empty()) {
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Payload (%u bytes):", p.payload_size);
                ImGui::BeginChild("##cap_hex", ImVec2(0, 0), false, ImGuiWindowFlags_NoBackground);

                size_t display_size = std::min(p.payload.size(), static_cast<size_t>(4096));
                for (size_t off = 0; off < display_size; off += 16) {
                    char line[128];
                    int pos = snprintf(line, sizeof(line), "%04X  ", static_cast<unsigned>(off));

                    size_t end = std::min(off + 16, display_size);
                    for (size_t j = off; j < off + 16; j++) {
                        if (j < end)
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02X ", p.payload[j]);
                        else
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
                        if (j == off + 7)
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
                    }
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " |");
                    for (size_t j = off; j < end; j++) {
                        char c = static_cast<char>(p.payload[j]);
                        line[pos++] = (c >= 32 && c < 127) ? c : '.';
                    }
                    line[pos++] = '|';
                    line[pos] = '\0';

                    ImGui::TextColored(ImVec4(0.6f, 0.65f, 0.7f, alpha), "%s", line);
                }

                if (display_size < p.payload.size()) {
                    ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha),
                        "... %zu more bytes", p.payload.size() - display_size);
                }

                ImGui::EndChild();
            }
        } else {
            ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "Select a packet to view details");
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}

// ─── DNS Tab ──────────────────────────────────────────────────────

static void render_dns(state_t& state, float x, float y, float w, float h,
                        float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_dns", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = device && device->is_connected();

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));
    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.dns_polling.load()) {
        if (ImGui::SmallButton("Start DNS Monitor")) {
            state.dns_polling.store(true);
            state.dns_thread = std::thread(dns_poll_thread, std::ref(state));
        }
    } else {
        if (ImGui::SmallButton("Stop DNS Monitor")) {
            state.dns_polling.store(false);
            if (state.dns_thread.joinable()) state.dns_thread.join();
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) {
        if (driver_ok) {
            auto raw = device->get_dns_queries(state.dns_filter_pid);
            std::lock_guard<std::mutex> lock(state.dns_mutex);
            state.dns_entries.clear();
            for (auto& d : raw) {
                dns_entry e;
                e.timestamp = d.timestamp;
                e.pid = d.pid;
                e.query_type = static_cast<uint16_t>(d.query_type);
                e.domain = d.domain;
                e.resolved_addr = format_ip(d.resolved_addr, 2);
                e.response_code = d.response_code;
                e.ttl = d.ttl;
                state.dns_entries.push_back(std::move(e));
            }
        }
    }

    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.f);
    ImGui::InputTextWithHint("##dns_filter", "Filter...", state.dns_filter_text, sizeof(state.dns_filter_text));

    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Headers
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 18.f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 60.f, col_type = 50.f, col_rcode = 55.f, col_ttl = 50.f;
    float remaining = w - col_pid - col_type - col_rcode - col_ttl - 20.f;
    float col_domain = remaining * 0.55f;
    float col_addr = remaining * 0.45f;

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(180, 180, 200, static_cast<int>(0.7f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "PID");     cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Type");    cx += col_type;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Domain");  cx += col_domain;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Address"); cx += col_addr;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "RCode");   cx += col_rcode;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "TTL");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x + 2.f, hdr_y + row_h), ImVec2(org.x + w - 2.f, hdr_y + row_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

    float list_h = h - (cursor.y + row_h + 8.f);
    ImGui::BeginChild("##dns_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.dns_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();

    for (int i = 0; i < static_cast<int>(state.dns_entries.size()); i++) {
        auto& d = state.dns_entries[static_cast<size_t>(i)];

        if (state.dns_filter_text[0]) {
            std::string all = d.domain + " " + d.resolved_addr + " " + std::to_string(d.pid);
            if (!filter_text_match(state.dns_filter_text, all)) continue;
        }

        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;
        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.dns_selected == i);

        if (hovered || selected) {
            ImU32 bg = selected
                ? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.2f * alpha * 255))
                : IM_COL32(255, 255, 255, static_cast<int>(0.04f * alpha * 255));
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg);
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.dns_selected = i;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.8f * alpha * 255));
        cx = list_org.x + 4.f;
        char buf[16];

        snprintf(buf, sizeof(buf), "%u", d.pid);
        dl->AddText(ImVec2(cx, abs_ry), txt_col, buf); cx += col_pid;

        const char* qtype = d.query_type == 1 ? "A" : d.query_type == 28 ? "AAAA" : d.query_type == 5 ? "CNAME" : "?";
        dl->AddText(ImVec2(cx, abs_ry), txt_col, qtype); cx += col_type;

        // Domain - truncate if needed
        std::string domain = d.domain;
        if (domain.size() > 40) domain = domain.substr(0, 37) + "...";
        dl->AddText(ImVec2(cx, abs_ry), IM_COL32(180, 220, 255, static_cast<int>(0.85f * alpha * 255)),
            domain.c_str()); cx += col_domain;

        dl->AddText(ImVec2(cx, abs_ry), txt_col, d.resolved_addr.c_str()); cx += col_addr;

        snprintf(buf, sizeof(buf), "%u", d.response_code);
        ImU32 rcode_col = d.response_code == 0 ? IM_COL32(100, 255, 100, static_cast<int>(0.8f * alpha * 255))
                                                : IM_COL32(255, 100, 100, static_cast<int>(0.8f * alpha * 255));
        dl->AddText(ImVec2(cx, abs_ry), rcode_col, buf); cx += col_rcode;

        snprintf(buf, sizeof(buf), "%u", d.ttl);
        dl->AddText(ImVec2(cx, abs_ry), txt_col, buf);

        ImGui::SetCursorPosY(ry + row_h);
    }

    ImGui::EndChild();
    ImGui::EndChild();
}

// ─── Proxy Tab ────────────────────────────────────────────────────

static void render_proxy(state_t& state, float x, float y, float w, float h,
                          float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_proxy", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));

    bool running = mitm_proxy::is_running();

    // Controls
    if (!running) {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Bind:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(120.f);
        ImGui::InputText("##proxy_addr", state.proxy_bind_addr, sizeof(state.proxy_bind_addr));
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Port:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(60.f);
        ImGui::InputInt("##proxy_port", &state.proxy_port, 0, 0);
        ImGui::SameLine();
        ImGui::Checkbox("TLS MITM", &state.proxy_decode_tls);
        ImGui::SameLine();

        if (ImGui::SmallButton("Start Proxy")) {
            mitm_proxy::proxy_config cfg;
            cfg.bind_addr = state.proxy_bind_addr;
            cfg.bind_port = static_cast<uint16_t>(state.proxy_port);
            cfg.decode_tls = state.proxy_decode_tls;
            mitm_proxy::start(cfg);
        }
    } else {
        auto stats = mitm_proxy::get_stats();
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "PROXY RUNNING");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha),
            " | %s:%d | %llu requests | %u active | In: %s | Out: %s",
            state.proxy_bind_addr, state.proxy_port,
            static_cast<unsigned long long>(stats.total_requests),
            stats.active_connections,
            format_bytes(stats.total_bytes_in).c_str(),
            format_bytes(stats.total_bytes_out).c_str());

        ImGui::SameLine();
        if (ImGui::SmallButton("Stop")) mitm_proxy::stop();
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear History")) mitm_proxy::clear_history();
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.f);
    ImGui::InputTextWithHint("##proxy_filter", "Filter...", state.proxy_filter_text, sizeof(state.proxy_filter_text));

    // Cert pin bypass
    ImGui::Spacing();
    if (cert_pin_bypass::is_bypass_active()) {
        ImGui::TextColored(ImVec4(0.2f, 1.f, 0.2f, alpha), "Cert pinning bypass: ACTIVE (%zu patches)",
            cert_pin_bypass::get_active_bypasses().size());
        ImGui::SameLine();
        if (ImGui::SmallButton("Revert Bypasses")) {
            cert_pin_bypass::revert_all_bypasses();
        }
    }

    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Exchange history
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 18.f;
    float hdr_y = org.y + cursor.y;

    float col_id = 40.f, col_method = 55.f, col_status = 50.f, col_lat = 55.f, col_size = 55.f, col_tls = 30.f;
    float col_host = (w - col_id - col_method - col_status - col_lat - col_size - col_tls - 20.f) * 0.35f;
    float col_path = w - col_id - col_method - col_host - col_status - col_lat - col_size - col_tls - 20.f;

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(180, 180, 200, static_cast<int>(0.7f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "#");       cx += col_id;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Method");  cx += col_method;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Host");    cx += col_host;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Path");    cx += col_path;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Status");  cx += col_status;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Time");    cx += col_lat;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Size");    cx += col_size;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "TLS");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x + 2.f, hdr_y + row_h), ImVec2(org.x + w - 2.f, hdr_y + row_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

    float split_y_proxy = (h - cursor.y - row_h - 8.f) * 0.6f;
    float list_h = split_y_proxy;

    ImGui::BeginChild("##proxy_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    auto history = mitm_proxy::get_history();
    ImVec2 list_org = ImGui::GetWindowPos();

    for (int i = 0; i < static_cast<int>(history.size()); i++) {
        auto& ex = history[static_cast<size_t>(i)];

        if (state.proxy_filter_text[0]) {
            std::string all = ex.target_host + " " + ex.request.method + " " + ex.request.uri;
            if (!filter_text_match(state.proxy_filter_text, all)) continue;
        }

        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;
        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.proxy_selected == i);

        if (hovered || selected) {
            ImU32 bg = selected
                ? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.2f * alpha * 255))
                : IM_COL32(255, 255, 255, static_cast<int>(0.04f * alpha * 255));
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg);
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.proxy_selected = i;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.8f * alpha * 255));
        cx = list_org.x + 4.f;

        char buf[32];
        snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(ex.id));
        dl->AddText(ImVec2(cx, abs_ry), IM_COL32(130, 130, 150, static_cast<int>(0.6f * alpha * 255)), buf);
        cx += col_id;

        // Color methods
        ImU32 method_col = txt_col;
        if (ex.request.method == "GET") method_col = IM_COL32(100, 200, 255, static_cast<int>(0.9f * alpha * 255));
        else if (ex.request.method == "POST") method_col = IM_COL32(255, 200, 100, static_cast<int>(0.9f * alpha * 255));
        else if (ex.request.method == "PUT") method_col = IM_COL32(255, 160, 100, static_cast<int>(0.9f * alpha * 255));
        else if (ex.request.method == "DELETE") method_col = IM_COL32(255, 100, 100, static_cast<int>(0.9f * alpha * 255));
        dl->AddText(ImVec2(cx, abs_ry), method_col, ex.request.method.c_str()); cx += col_method;

        dl->AddText(ImVec2(cx, abs_ry), txt_col, ex.target_host.c_str()); cx += col_host;

        std::string path = ex.request.uri;
        if (path.size() > 40) path = path.substr(0, 37) + "...";
        dl->AddText(ImVec2(cx, abs_ry), txt_col, path.c_str()); cx += col_path;

        // Status code coloring
        ImU32 status_col = txt_col;
        if (ex.response.status_code >= 200 && ex.response.status_code < 300)
            status_col = IM_COL32(100, 255, 100, static_cast<int>(0.9f * alpha * 255));
        else if (ex.response.status_code >= 300 && ex.response.status_code < 400)
            status_col = IM_COL32(255, 200, 100, static_cast<int>(0.9f * alpha * 255));
        else if (ex.response.status_code >= 400)
            status_col = IM_COL32(255, 100, 100, static_cast<int>(0.9f * alpha * 255));

        if (ex.response.status_code > 0) {
            snprintf(buf, sizeof(buf), "%d", ex.response.status_code);
            dl->AddText(ImVec2(cx, abs_ry), status_col, buf);
        } else {
            const char* st = "...";
            if (ex.state == mitm_proxy::http_exchange::state_t::dropped) st = "DROP";
            else if (ex.state == mitm_proxy::http_exchange::state_t::error) st = "ERR";
            dl->AddText(ImVec2(cx, abs_ry), IM_COL32(150, 150, 160, static_cast<int>(0.5f * alpha * 255)), st);
        }
        cx += col_status;

        snprintf(buf, sizeof(buf), "%llums", static_cast<unsigned long long>(ex.latency_ms));
        dl->AddText(ImVec2(cx, abs_ry), txt_col, buf); cx += col_lat;

        dl->AddText(ImVec2(cx, abs_ry), txt_col, format_bytes(ex.response_size).c_str()); cx += col_size;

        dl->AddText(ImVec2(cx, abs_ry),
            ex.is_tls ? IM_COL32(100, 255, 100, static_cast<int>(0.7f * alpha * 255))
                      : IM_COL32(150, 150, 160, static_cast<int>(0.5f * alpha * 255)),
            ex.is_tls ? "Y" : "N");

        ImGui::SetCursorPosY(ry + row_h);
    }

    ImGui::EndChild();

    // Detail pane for selected proxy exchange
    float detail_h = h - cursor.y - row_h - list_h - 16.f;
    if (detail_h > 30.f && state.proxy_selected >= 0 && state.proxy_selected < static_cast<int>(history.size())) {
        dl->AddLine(ImVec2(org.x + 2.f, org.y + ImGui::GetCursorPosY()),
                    ImVec2(org.x + w - 2.f, org.y + ImGui::GetCursorPosY()),
                    IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));
        ImGui::Spacing();
        ImGui::BeginChild("##proxy_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        auto& ex = history[static_cast<size_t>(state.proxy_selected)];
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "%s %s", ex.request.method.c_str(), ex.request.uri.c_str());
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Host: %s:%u | TLS: %s | Latency: %llums",
            ex.target_host.c_str(), ex.target_port,
            ex.is_tls ? "Yes" : "No",
            static_cast<unsigned long long>(ex.latency_ms));

        // Request headers
        if (!ex.request.headers.empty()) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, alpha), "Request Headers:");
            for (auto& h : ex.request.headers) {
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "  %s: %s", h.name.c_str(), h.value.c_str());
            }
        }

        // Response status
        if (ex.response.status_code > 0) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, alpha), "Response: %d %s",
                ex.response.status_code, ex.response.reason.c_str());
            for (auto& h : ex.response.headers) {
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "  %s: %s", h.name.c_str(), h.value.c_str());
            }
        }

        // Send to repeater button
        ImGui::Spacing();
        if (ImGui::SmallButton("Send to Repeater")) {
            repeater_entry rep;
            rep.host = ex.target_host;
            rep.port = ex.target_port;
            rep.use_tls = ex.is_tls;
            rep.raw_request = std::string(ex.raw_request.begin(), ex.raw_request.end());
            state.repeater_entries.push_back(std::move(rep));
            state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}

// ─── Filters Tab ──────────────────────────────────────────────────

static void render_filters(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_filters", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = device && device->is_connected();

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));

    // New filter form
    ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Add Filter Rule");
    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Action:");
    ImGui::SameLine();
    ImGui::RadioButton("Block", &state.nf_action, 0); ImGui::SameLine();
    ImGui::RadioButton("Allow", &state.nf_action, 1);

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Direction:");
    ImGui::SameLine();
    ImGui::RadioButton("In", &state.nf_direction, 0); ImGui::SameLine();
    ImGui::RadioButton("Out", &state.nf_direction, 1); ImGui::SameLine();
    ImGui::RadioButton("Both", &state.nf_direction, 2);

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Protocol:");
    ImGui::SameLine();
    ImGui::RadioButton("Any", &state.nf_protocol, 0); ImGui::SameLine();
    ImGui::RadioButton("TCP##f", &state.nf_protocol, 6); ImGui::SameLine();
    ImGui::RadioButton("UDP##f", &state.nf_protocol, 17);

    ImGui::SetNextItemWidth(80.f);
    ImGui::InputTextWithHint("PID##nf", "PID", state.nf_pid, sizeof(state.nf_pid));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputTextWithHint("Port##nf", "Port", state.nf_port, sizeof(state.nf_port));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.f);
    ImGui::InputTextWithHint("IP##nf", "IP Address", state.nf_ip, sizeof(state.nf_ip));
    ImGui::SameLine();

    if (!driver_ok) ImGui::BeginDisabled();
    if (ImGui::SmallButton("Add Rule")) {
        uint32_t pid = state.nf_pid[0] ? static_cast<uint32_t>(atoi(state.nf_pid)) : 0;
        uint16_t port = state.nf_port[0] ? static_cast<uint16_t>(atoi(state.nf_port)) : 0;

        uint8_t ip_bytes[16] = {};
        if (state.nf_ip[0]) {
            inet_pton(AF_INET, state.nf_ip, ip_bytes);
        }

        device->add_filter_rule(
            static_cast<uint32_t>(state.nf_action),
            static_cast<uint32_t>(state.nf_direction),
            static_cast<uint32_t>(state.nf_protocol),
            pid, port, ip_bytes, nullptr, nullptr);
    }

    ImGui::SameLine();
    if (ImGui::SmallButton("Clear All")) {
        device->clear_filter_rules();
        state.filters.clear();
    }
    if (!driver_ok) ImGui::EndDisabled();

    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Active filters list
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, alpha), "Active Rules:");
    ImGui::Spacing();

    for (int i = 0; i < static_cast<int>(state.filters.size()); i++) {
        auto& f = state.filters[static_cast<size_t>(i)];
        ImGui::TextColored(
            f.action == 0 ? ImVec4(1.f, 0.4f, 0.4f, alpha) : ImVec4(0.4f, 1.f, 0.4f, alpha),
            "[%s] %s %s PID:%u Port:%u %s",
            f.action == 0 ? "BLOCK" : "ALLOW",
            f.direction == 0 ? "IN" : f.direction == 1 ? "OUT" : "BOTH",
            f.protocol == 6 ? "TCP" : f.protocol == 17 ? "UDP" : "ANY",
            f.pid, f.port, f.ip_addr.c_str());
    }

    ImGui::EndChild();
}

// ─── Bandwidth Tab ────────────────────────────────────────────────

static void render_bandwidth(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_bw", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = device && device->is_connected();

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));
    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.bw_polling.load()) {
        if (ImGui::SmallButton("Start Monitoring")) {
            device->bw_monitor_op(0); // start
            state.bw_monitoring = true;
            state.bw_polling.store(true);
            state.bw_thread = std::thread(bandwidth_poll_thread, std::ref(state));
        }
    } else {
        if (ImGui::SmallButton("Stop Monitoring")) {
            device->bw_monitor_op(1); // stop
            state.bw_monitoring = false;
            state.bw_polling.store(false);
            if (state.bw_thread.joinable()) state.bw_thread.join();
        }
    }

    if (!driver_ok) ImGui::EndDisabled();
    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Headers
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 20.f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 60.f, col_name = 150.f;
    float col_in = (w - col_pid - col_name - 20.f) * 0.25f;
    float col_out = col_in, col_rin = col_in, col_rout = col_in;

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(180, 180, 200, static_cast<int>(0.7f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "PID");       cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Process");   cx += col_name;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "In");        cx += col_in;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Out");       cx += col_out;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "In Rate");   cx += col_rin;
    dl->AddText(ImVec2(cx, hdr_y), hdr_col, "Out Rate");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x + 2.f, hdr_y + row_h), ImVec2(org.x + w - 2.f, hdr_y + row_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

    float list_h = h - (cursor.y + row_h + 8.f);
    ImGui::BeginChild("##bw_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.bw_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();

    for (int i = 0; i < static_cast<int>(state.bw_entries.size()); i++) {
        auto& b = state.bw_entries[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.8f * alpha * 255));
        cx = list_org.x + 4.f;

        char buf[32];
        snprintf(buf, sizeof(buf), "%u", b.pid);
        dl->AddText(ImVec2(cx, abs_ry), txt_col, buf); cx += col_pid;

        std::string name = b.process_name.empty() ? "-" : b.process_name;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, name.c_str()); cx += col_name;

        dl->AddText(ImVec2(cx, abs_ry), IM_COL32(100, 200, 255, static_cast<int>(0.8f * alpha * 255)),
            format_bytes(b.bytes_in).c_str()); cx += col_in;
        dl->AddText(ImVec2(cx, abs_ry), IM_COL32(255, 200, 100, static_cast<int>(0.8f * alpha * 255)),
            format_bytes(b.bytes_out).c_str()); cx += col_out;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, format_rate(b.rate_in).c_str()); cx += col_rin;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, format_rate(b.rate_out).c_str());

        ImGui::SetCursorPosY(ry + row_h);
    }

    ImGui::EndChild();
    ImGui::EndChild();
}

// ─── Repeater Tab ─────────────────────────────────────────────────

static void render_repeater(state_t& state, float x, float y, float w, float h,
                             float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_rep", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));

    // Top bar: host, port, tls, send
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Host:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.f);
    ImGui::InputText("##rep_host", state.rep_host, sizeof(state.rep_host));
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Port:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60.f);
    ImGui::InputInt("##rep_port", &state.rep_port, 0, 0);
    ImGui::SameLine();
    ImGui::Checkbox("TLS##rep", &state.rep_use_tls);
    ImGui::SameLine();

    if (ImGui::SmallButton("New")) {
        repeater_entry rep;
        rep.host = state.rep_host;
        rep.port = static_cast<uint16_t>(state.rep_port);
        rep.use_tls = state.rep_use_tls;
        rep.raw_request = "GET / HTTP/1.1\r\nHost: " + std::string(state.rep_host) + "\r\n\r\n";
        state.repeater_entries.push_back(std::move(rep));
        state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
    }

    ImGui::PopStyleColor();

    // Tabs for each repeater entry
    if (!state.repeater_entries.empty()) {
        ImGui::Spacing();
        for (int i = 0; i < static_cast<int>(state.repeater_entries.size()); i++) {
            if (i > 0) ImGui::SameLine();
            bool is_sel = (state.repeater_selected == i);
            char label[32];
            snprintf(label, sizeof(label), "#%d##rep_tab", i + 1);
            if (is_sel) ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), 80));
            if (ImGui::SmallButton(label)) state.repeater_selected = i;
            if (is_sel) ImGui::PopStyleColor();
        }

        ImGui::Spacing();

        if (state.repeater_selected >= 0 && state.repeater_selected < static_cast<int>(state.repeater_entries.size())) {
            auto& rep = state.repeater_entries[static_cast<size_t>(state.repeater_selected)];

            float half_w = (w - 8.f) * 0.5f;
            float panel_h = h - ImGui::GetCursorPosY() - 40.f;

            // Left: Request editor
            ImGui::BeginChild("##rep_req", ImVec2(half_w, panel_h), false, ImGuiWindowFlags_NoBackground);
            ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Request");

            ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(20, 20, 30, static_cast<int>(200 * alpha)));
            // Use a dynamically sized buffer
            static char req_buf[65536] = {};
            if (rep.raw_request.size() < sizeof(req_buf)) {
                memcpy(req_buf, rep.raw_request.data(), rep.raw_request.size());
                req_buf[rep.raw_request.size()] = '\0';
            }
            if (ImGui::InputTextMultiline("##rep_req_edit", req_buf, sizeof(req_buf),
                ImVec2(half_w - 4.f, panel_h - 50.f))) {
                rep.raw_request = req_buf;
            }
            ImGui::PopStyleColor();

            if (!rep.in_progress) {
                if (ImGui::SmallButton("Send")) {
                    rep.in_progress = true;
                    auto* entry_ptr = &rep;
                    std::thread([entry_ptr]() {
                        std::vector<uint8_t> raw(entry_ptr->raw_request.begin(), entry_ptr->raw_request.end());
                        auto result = mitm_proxy::repeat_request(
                            entry_ptr->host, entry_ptr->port, entry_ptr->use_tls, raw);
                        if (result.success) {
                            entry_ptr->raw_response = std::string(result.exchange.raw_response.begin(),
                                result.exchange.raw_response.end());
                            entry_ptr->status_code = result.exchange.response.status_code;
                            entry_ptr->latency_ms = result.exchange.latency_ms;
                        } else {
                            entry_ptr->raw_response = "Error: " + result.error;
                            entry_ptr->status_code = 0;
                        }
                        entry_ptr->in_progress = false;
                    }).detach();
                }
            } else {
                ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Sending...");
            }

            ImGui::EndChild();

            ImGui::SameLine();

            // Right: Response viewer
            ImGui::BeginChild("##rep_resp", ImVec2(half_w, panel_h), false, ImGuiWindowFlags_NoBackground);
            ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Response");

            if (rep.status_code > 0) {
                ImGui::SameLine();
                ImVec4 sc_col = rep.status_code < 300 ? ImVec4(0.4f, 1.f, 0.4f, alpha)
                    : rep.status_code < 400 ? ImVec4(1.f, 0.8f, 0.3f, alpha)
                    : ImVec4(1.f, 0.3f, 0.3f, alpha);
                ImGui::TextColored(sc_col, " %d", rep.status_code);
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), " %llums",
                    static_cast<unsigned long long>(rep.latency_ms));
            }

            ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(20, 20, 30, static_cast<int>(200 * alpha)));
            ImGui::InputTextMultiline("##rep_resp_view", const_cast<char*>(rep.raw_response.c_str()),
                rep.raw_response.size() + 1,
                ImVec2(half_w - 4.f, panel_h - 50.f),
                ImGuiInputTextFlags_ReadOnly);
            ImGui::PopStyleColor();

            ImGui::EndChild();
        }
    } else {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha),
            "No repeater entries. Use 'New' to create one or send from proxy history.");
    }

    ImGui::EndChild();
}

// ─── Intercept Tab ────────────────────────────────────────────────

static void render_intercept(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_intercept", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));

    bool running = mitm_proxy::is_running();
    if (!running) {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Start the proxy first to use intercept mode.");
    } else {
        if (ImGui::Checkbox("Intercept Enabled", &state.intercept_enabled)) {
            mitm_proxy::set_intercept_enabled(state.intercept_enabled);
        }

        ImGui::SameLine();
        if (ImGui::SmallButton("Forward All")) mitm_proxy::forward_all();
        ImGui::SameLine();
        if (ImGui::SmallButton("Drop All")) mitm_proxy::drop_all();

        if (state.intercept_enabled) {
            ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Intercepting requests...");
        }
    }

    ImGui::PopStyleColor();
    ImGui::EndChild();
}

// ─── KeyLog Tab ───────────────────────────────────────────────────

static void render_keylog(state_t& state, float x, float y, float w, float h,
                           float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_keylog", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 40, static_cast<int>(180 * alpha)));

    // Launch with SSLKEYLOGFILE
    ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "SSL Key Logger");
    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Executable:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(300.f);
    ImGui::InputText("##kl_exe", state.kl_exe_path, sizeof(state.kl_exe_path));

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Arguments:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(300.f);
    ImGui::InputText("##kl_args", state.kl_args, sizeof(state.kl_args));

    ImGui::Spacing();

    if (!ssl_keylog::g_state.watching.load()) {
        if (ImGui::SmallButton("Launch & Watch")) {
            auto result = ssl_keylog::launch_with_keylog(state.kl_exe_path, state.kl_args);
            if (result.success) {
                ssl_keylog::start_watching(result.keylog_path);
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Watch File Only")) {
            // Watch an existing keylog file
            char path[MAX_PATH] = {};
            GetTempPathA(MAX_PATH, path);
            std::string kpath = std::string(path) + "aida_sslkeylog_" + std::to_string(GetCurrentProcessId()) + ".log";
            ssl_keylog::start_watching(kpath);
        }
    } else {
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Watching: %s", ssl_keylog::g_state.keylog_path.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Stop Watching")) ssl_keylog::stop_watching();
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear##kl")) ssl_keylog::clear_entries();
    }

    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Captured Keys: %zu", ssl_keylog::entry_count());

    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Key entries list
    float list_h = h - ImGui::GetCursorPosY() - 8.f;
    ImGui::BeginChild("##kl_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    auto entries = ssl_keylog::get_entries(500); // last 500
    float row_h = 16.f;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 list_org = ImGui::GetWindowPos();

    for (int i = static_cast<int>(entries.size()) - 1; i >= 0; i--) {
        auto& e = entries[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;

        // Truncate secrets for display
        std::string cr_short = e.client_random_hex.substr(0, 16) + "...";
        std::string sec_short = e.secret_hex.size() > 16 ? e.secret_hex.substr(0, 16) + "..." : e.secret_hex;

        ImU32 label_col;
        if (e.label == "CLIENT_RANDOM")
            label_col = IM_COL32(100, 200, 255, static_cast<int>(0.9f * alpha * 255));
        else if (e.label.find("HANDSHAKE") != std::string::npos)
            label_col = IM_COL32(255, 200, 100, static_cast<int>(0.9f * alpha * 255));
        else
            label_col = IM_COL32(100, 255, 180, static_cast<int>(0.9f * alpha * 255));

        dl->AddText(ImVec2(list_org.x + 4.f, abs_ry), label_col, e.label.c_str());
        dl->AddText(ImVec2(list_org.x + 250.f, abs_ry),
            IM_COL32(180, 180, 200, static_cast<int>(0.6f * alpha * 255)), cr_short.c_str());
        dl->AddText(ImVec2(list_org.x + 420.f, abs_ry),
            IM_COL32(180, 180, 200, static_cast<int>(0.6f * alpha * 255)), sec_short.c_str());

        ImGui::SetCursorPosY(ry + row_h);
    }

    if (state.kl_auto_scroll && !entries.empty())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();
    ImGui::EndChild();
}

// ─── Main Render Function ─────────────────────────────────────────

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b) {
    float dt = ImGui::GetIO().DeltaTime;

    // Tab bar
    float tab_h = 30.f;
    render_tab_bar(g_state, pos_x, pos_y, width, alpha, accent_r, accent_g, accent_b, dt);

    float content_y = pos_y + tab_h + 4.f;
    float content_h = height - tab_h - 4.f;

    // Dispatch to active sub-tab
    switch (g_state.active_tab) {
        case sub_tab_t::connections:
            render_connections(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::capture:
            render_capture(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::intercept:
            render_intercept(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::proxy:
            render_proxy(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::dns:
            render_dns(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::filters:
            render_filters(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::bandwidth:
            render_bandwidth(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::repeater:
            render_repeater(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::keylog:
            render_keylog(g_state, pos_x, content_y, width, content_h, alpha, accent_r, accent_g, accent_b);
            break;
        default:
            break;
    }
}

} // namespace network_view
