#include "network_view.hpp"
#include "work_queue.hpp"
#include "standalone_driver.hpp"
#include "protocol_parser.hpp"
#include "mitm_proxy.hpp"
#include "cert_pin_bypass.hpp"
#include "ssl_keylog.hpp"
#include "script_engine.hpp"
#include "decoder_pipeline.hpp"
#include "ui_anim.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace network_view {


static std::string format_ip(const uint8_t* addr, uint8_t af) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (af == 2) {
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else if (af == 23) {
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

    std::string lower_filter(filter);
    std::string lower_text = text;
    for (auto& c : lower_filter) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    for (auto& c : lower_text) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lower_text.find(lower_filter) != std::string::npos;
}


static void connection_poll_thread(state_t& state) {
    driver_bridge::debug_log("[network] connection_poll_thread STARTED\n");
    int poll_iter = 0;
    while (state.conn_polling.load()) {
        bool drv_ok = driver_bridge::using_kernel_driver();
        if (poll_iter < 5 || (poll_iter % 100) == 0) {
            char dbg[128];
            snprintf(dbg, sizeof(dbg), "[network] conn_poll iter=%d drv_ok=%d\n", poll_iter, drv_ok ? 1 : 0);
            driver_bridge::debug_log(dbg);
        }
        ++poll_iter;
        if (drv_ok) {
            auto raw_conns = driver_bridge::enumerate_connections(
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


        for (int i = 0; i < 100 && state.conn_polling.load(); i++)
            Sleep(10);
    }
}

static void capture_poll_thread(state_t& state) {
    driver_bridge::debug_log("[network] capture_poll_thread STARTED\n");
    state.cap_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.cap_cv_mutex);
            state.cap_cv.wait(lk, [&state]() {
                return state.cap_polling.load() || !state.cap_thread_alive.load();
            });
        }
        if (!state.cap_thread_alive.load())
            break;
        poll_iter = 0;
        while (state.cap_polling.load()) {
            bool drv_ok = driver_bridge::using_kernel_driver();
            if (poll_iter < 5 || (poll_iter % 100) == 0) {
                char dbg[128];
                snprintf(dbg, sizeof(dbg), "[network] capture_poll iter=%d drv_ok=%d\n", poll_iter, drv_ok ? 1 : 0);
                driver_bridge::debug_log(dbg);
            }
            ++poll_iter;
            if (drv_ok) {
                auto raw_packets = driver_bridge::get_captured_packets(64);

                if (!raw_packets.empty()) {
                    char dbg[128];
                    snprintf(dbg, sizeof(dbg), "[network] capture_poll got %zu packets\n", raw_packets.size());
                    driver_bridge::debug_log(dbg);
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

            for (int i = 0; i < 10 && state.cap_polling.load(); i++)
                Sleep(10);
        }
    }
}

static void dns_poll_thread(state_t& state) {
    driver_bridge::debug_log("[network] dns_poll_thread STARTED\n");
    state.dns_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.dns_cv_mutex);
            state.dns_cv.wait(lk, [&state]() {
                return state.dns_polling.load() || !state.dns_thread_alive.load();
            });
        }
        if (!state.dns_thread_alive.load())
            break;
        poll_iter = 0;
        while (state.dns_polling.load()) {
            bool drv_ok = driver_bridge::using_kernel_driver();
            if (poll_iter < 5 || (poll_iter % 100) == 0) {
                char dbg[128];
                snprintf(dbg, sizeof(dbg), "[network] dns_poll iter=%d drv_ok=%d\n", poll_iter, drv_ok ? 1 : 0);
                driver_bridge::debug_log(dbg);
            }
            ++poll_iter;
            if (drv_ok) {
                auto raw_dns = driver_bridge::get_dns_queries(state.dns_filter_pid);

                if (!raw_dns.empty()) {
                    char dbg[128];
                    snprintf(dbg, sizeof(dbg), "[network] dns_poll got %zu entries\n", raw_dns.size());
                    driver_bridge::debug_log(dbg);
                    std::lock_guard<std::mutex> lock(state.dns_mutex);
                    for (auto& d : raw_dns) {
                        bool duplicate = false;
                        for (auto it = state.dns_entries.rbegin();
                             it != state.dns_entries.rend() && it != state.dns_entries.rbegin() + (std::min)(static_cast<size_t>(256), state.dns_entries.size());
                             ++it) {
                            if (it->timestamp == d.timestamp && it->domain == d.domain && it->pid == d.pid) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
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
                    while (state.dns_entries.size() > state.dns_max_entries)
                        state.dns_entries.pop_front();
                }
            }

            for (int i = 0; i < 50 && state.dns_polling.load(); i++)
                Sleep(10);
        }
    }
}

static void bandwidth_poll_thread(state_t& state) {
    state.bw_thread_alive.store(true);
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.bw_cv_mutex);
            state.bw_cv.wait(lk, [&state]() {
                return state.bw_polling.load() || !state.bw_thread_alive.load();
            });
        }
        if (!state.bw_thread_alive.load())
            break;
        while (state.bw_polling.load()) {
            if (driver_bridge::using_kernel_driver()) {
                auto raw_bw = driver_bridge::get_bw_per_process();

            std::vector<bw_entry> old_entries;
            {
                std::lock_guard<std::mutex> lock(state.bw_mutex);
                old_entries = state.bw_entries;
            }

            std::vector<bw_entry> entries;
            entries.reserve(raw_bw.size());
            for (auto& b : raw_bw) {
                bw_entry e;
                e.pid = b.pid;
                e.bytes_in = b.bytes_recv;
                e.bytes_out = b.bytes_sent;
                e.rate_in = 0.f;
                e.rate_out = 0.f;

                for (auto& old : old_entries) {
                    if (old.pid == b.pid) {
                        if (old.bytes_in > 0 || old.bytes_out > 0) {
                            float dt = 0.5f;
                            e.rate_in = static_cast<float>(b.bytes_recv > old.bytes_in ? b.bytes_recv - old.bytes_in : 0) / dt;
                            e.rate_out = static_cast<float>(b.bytes_sent > old.bytes_out ? b.bytes_sent - old.bytes_out : 0) / dt;
                        }
                        memcpy(e.rate_history, old.rate_history, sizeof(e.rate_history));
                        e.history_index = old.history_index;
                        break;
                    }
                }

                e.rate_history[e.history_index % 64] = e.rate_in + e.rate_out;
                e.history_index++;

                entries.push_back(std::move(e));
            }

            {
                std::lock_guard<std::mutex> lock(state.bw_mutex);
                state.bw_entries = std::move(entries);
            }
            }


            for (int i = 0; i < 50 && state.bw_polling.load(); i++)
                Sleep(10);
        }
    }
}


static void run_fuzzer_thread(state_t& state);

void initialize() {
    g_state.active = true;

    work_queue::initialize();

    g_state.conn_polling.store(true);
    g_state.conn_thread = std::thread(connection_poll_thread, std::ref(g_state));

    g_state.cap_thread_alive.store(true);
    g_state.cap_thread = std::thread(capture_poll_thread, std::ref(g_state));

    g_state.dns_thread_alive.store(true);
    g_state.dns_thread = std::thread(dns_poll_thread, std::ref(g_state));

    g_state.bw_thread_alive.store(true);
    g_state.bw_thread = std::thread(bandwidth_poll_thread, std::ref(g_state));

    g_state.fuzz_thread_alive.store(true);
    g_state.fuzz_thread = std::thread([]() {
        while (true) {
            {
                std::unique_lock<std::mutex> lk(g_state.fuzz_cv_mutex);
                g_state.fuzz_cv.wait(lk, []() {
                    return g_state.fuzz_running.load() || !g_state.fuzz_thread_alive.load();
                });
            }
            if (!g_state.fuzz_thread_alive.load())
                break;
            run_fuzzer_thread(g_state);
        }
    });
}

void shutdown() {
    g_state.conn_polling.store(false);
    g_state.bw_polling.store(false);
    g_state.bw_thread_alive.store(false);
    g_state.bw_cv.notify_all();

    g_state.cap_polling.store(false);
    g_state.cap_thread_alive.store(false);
    g_state.cap_cv.notify_all();

    g_state.dns_polling.store(false);
    g_state.dns_thread_alive.store(false);
    g_state.dns_cv.notify_all();

    g_state.fuzz_running.store(false);
    g_state.fuzz_thread_alive.store(false);
    g_state.fuzz_cv.notify_all();

    if (g_state.conn_thread.joinable()) g_state.conn_thread.join();
    if (g_state.cap_thread.joinable()) g_state.cap_thread.join();
    if (g_state.dns_thread.joinable()) g_state.dns_thread.join();
    if (g_state.bw_thread.joinable()) g_state.bw_thread.join();
    if (g_state.fuzz_thread.joinable()) g_state.fuzz_thread.join();

    work_queue::shutdown();
    mitm_proxy::stop();
    ssl_keylog::stop_watching();
    g_state.active = false;
}


static const char* tab_names[] = {
    "Connections", "Capture", "Intercept", "Proxy",
    "DNS", "Filters", "Bandwidth", "Repeater", "KeyLog",
    "PCAP", "Fuzzer", "WebSocket", "Scripting", "Decoder"
};


static void render_tab_bar(state_t& state, float x, float y, float w, float alpha,
                            float ar, float ag, float ab, float dt) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();

    float tab_h = 28.f;
    int count = static_cast<int>(sub_tab_t::COUNT);

    ui_anim::render_gradient_header(dl, origin.x + x, origin.y + y, w, tab_h, ar, ag, ab, alpha);

    float total_w = 0.f;
    float tab_widths[static_cast<int>(sub_tab_t::COUNT)];
    float tab_offsets[static_cast<int>(sub_tab_t::COUNT)];
    for (int i = 0; i < count; i++) {
        tab_widths[i] = ImGui::CalcTextSize(tab_names[i]).x + 20.f;
        tab_offsets[i] = total_w;
        total_w += tab_widths[i] + 2.f;
    }

    float clip_x0 = origin.x + x;
    float clip_x1 = origin.x + x + w;
    float clip_y0 = origin.y + y;
    float clip_y1 = origin.y + y + tab_h;

    if (ImGui::IsMouseHoveringRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), false)) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            state.tab_target_scroll_x -= wheel * 60.f;
    }

    float max_scroll = std::max(0.f, total_w - w);
    state.tab_target_scroll_x = std::clamp(state.tab_target_scroll_x, 0.f, max_scroll);
    state.tab_scroll_x = ui_anim::smooth_lerp(state.tab_scroll_x, state.tab_target_scroll_x, 14.f, dt);

    int active_idx = static_cast<int>(state.active_tab);
    float active_left = tab_offsets[active_idx] - state.tab_scroll_x;
    float active_right = active_left + tab_widths[active_idx];
    if (active_left < 0.f)
        state.tab_target_scroll_x = tab_offsets[active_idx];
    else if (active_right > w)
        state.tab_target_scroll_x = tab_offsets[active_idx] + tab_widths[active_idx] - w;

    float target_ux = clip_x0 + tab_offsets[active_idx] - state.tab_scroll_x + 4.f;
    float target_uw = tab_widths[active_idx] - 8.f;
    if (state.underline_w < 0.1f) {
        state.underline_x = target_ux;
        state.underline_w = target_uw;
    }
    state.underline_x = ui_anim::spring_interp(state.underline_x, target_ux, state.underline_vel, 280.f, 22.f, dt);
    state.underline_w = ui_anim::smooth_lerp(state.underline_w, target_uw, 16.f, dt);

    ImGui::PushClipRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), true);

    for (int i = 0; i < count; i++) {
        float bx0 = clip_x0 + tab_offsets[i] - state.tab_scroll_x;
        float bx1 = bx0 + tab_widths[i];
        float by0 = clip_y0;
        float by1 = clip_y0 + tab_h;
        bool is_active = (i == active_idx);

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= bx0 && mouse.x < bx1 && mouse.y >= by0 && mouse.y < by1);
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            if (state.active_tab != static_cast<sub_tab_t>(i)) {
                state.prev_tab = state.active_tab;
                state.content_fade = 0.f;
            }
            state.active_tab = static_cast<sub_tab_t>(i);
        }

        float bg_alpha = is_active ? 0.15f : (hovered ? 0.08f : 0.f);
        if (bg_alpha > 0.01f)
            dl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1),
                IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                         static_cast<int>(ab * 255), static_cast<int>(bg_alpha * alpha * 255)),
                4.f);

        ImVec2 ts = ImGui::CalcTextSize(tab_names[i]);
        float text_alpha = is_active ? 0.95f : (hovered ? 0.7f : 0.5f);
        dl->AddText(ImVec2(bx0 + (tab_widths[i] - ts.x) * 0.5f, by0 + (tab_h - ts.y) * 0.5f),
            IM_COL32(255, 255, 255, static_cast<int>(text_alpha * alpha * 255)),
            tab_names[i]);
    }

    float ux = state.underline_x;
    float uw = state.underline_w;
    float uy = clip_y1 - 2.f;
    ImU32 ul_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                             static_cast<int>(ab * 255), static_cast<int>(alpha * 255));
    dl->AddRectFilled(ImVec2(ux, uy), ImVec2(ux + uw, uy + 2.f), ul_col, 1.f);
    dl->AddRectFilled(ImVec2(ux - 3.f, uy - 1.f), ImVec2(ux + uw + 3.f, uy + 3.f),
        IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                 static_cast<int>(ab * 255), static_cast<int>(alpha * 40)), 2.f);
    dl->AddRectFilled(ImVec2(ux - 6.f, uy - 2.f), ImVec2(ux + uw + 6.f, uy + 5.f),
        IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                 static_cast<int>(ab * 255), static_cast<int>(alpha * 15)), 3.f);

    ImGui::PopClipRect();

    if (state.tab_scroll_x > 1.f) {
        dl->AddRectFilledMultiColor(
            ImVec2(clip_x0, clip_y0), ImVec2(clip_x0 + 30.f, clip_y1),
            IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)),
            IM_COL32(18, 20, 26, 0),
            IM_COL32(18, 20, 26, 0),
            IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)));
    }
    if (state.tab_scroll_x < max_scroll - 1.f) {
        dl->AddRectFilledMultiColor(
            ImVec2(clip_x1 - 30.f, clip_y0), ImVec2(clip_x1, clip_y1),
            IM_COL32(18, 20, 26, 0),
            IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)),
            IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)),
            IM_COL32(18, 20, 26, 0));
    }

    dl->AddLine(
        ImVec2(origin.x + x, origin.y + y + tab_h),
        ImVec2(origin.x + x + w, origin.y + y + tab_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

    dl->AddRectFilledMultiColor(
        ImVec2(origin.x + x, origin.y + y + tab_h + 1.f),
        ImVec2(origin.x + x + w, origin.y + y + tab_h + 4.f),
        IM_COL32(0, 0, 0, static_cast<int>(30.f * alpha)),
        IM_COL32(0, 0, 0, static_cast<int>(30.f * alpha)),
        IM_COL32(0, 0, 0, 0),
        IM_COL32(0, 0, 0, 0));
}


static void render_connections(state_t& state, float x, float y, float w, float h,
                                float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_conn", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);


    ImGui::SetNextItemWidth(120.f);
    ImGui::InputTextWithHint("##conn_search", "Filter...", state.conn_filter_text, sizeof(state.conn_filter_text));
    ImGui::SameLine();

    bool driver_ok = driver_bridge::using_kernel_driver();
    if (!driver_ok) ImGui::BeginDisabled();
    if (ImGui::SmallButton(state.conn_auto_refresh ? "Auto" : "Manual")) {
        state.conn_auto_refresh = !state.conn_auto_refresh;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) {

        if (driver_ok) {
            auto raw = driver_bridge::enumerate_connections(state.conn_filter_pid, state.conn_filter_protocol);
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

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 20.f;
    float hdr_y = org.y + cursor.y;


    float col_pid = 60.f, col_proto = 45.f, col_state = 90.f;
    float col_local = (w - col_pid - col_proto - col_state - 20.f) * 0.5f;
    float col_remote = col_local;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
        IM_COL32(25, 27, 35, static_cast<int>(220 * alpha)));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.35f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
        IM_COL32(static_cast<int>(ar*60), static_cast<int>(ag*60), static_cast<int>(ab*60), static_cast<int>(80 * alpha)));

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(140, 145, 155, static_cast<int>(0.6f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "PID");   cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Proto"); cx += col_proto;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "State"); cx += col_state;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Local"); cx += col_local;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Remote");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x + 2.f, hdr_y + row_h), ImVec2(org.x + w - 2.f, hdr_y + row_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));


    float list_h = h - (cursor.y + row_h + 8.f);
    ImGui::BeginChild("##conn_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.conn_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 list_sz  = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y), true);
    int conn_visible_row = 0;

    for (int i = 0; i < static_cast<int>(state.connections.size()); i++) {
        auto& c = state.connections[static_cast<size_t>(i)];

        if (c.pid == 0 && c.protocol == 0 && c.local_port == 0 && c.remote_port == 0)
            continue;

        std::string local_str = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        std::string remote_str = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);


        if (state.conn_filter_text[0]) {
            std::string all = std::to_string(c.pid) + " " + protocol_name(c.protocol) + " " +
                tcp_state_name(c.state) + " " + local_str + " " + remote_str;
            if (!filter_text_match(state.conn_filter_text, all)) continue;
        }

        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;

        if (conn_visible_row & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), IM_COL32(255, 255, 255, 3));

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.conn_selected == i);

        if (hovered || selected) {
            ImU32 bg = selected
                ? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.2f * alpha * 255))
                : IM_COL32(255, 255, 255, static_cast<int>(0.04f * alpha * 255));
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg, 3.f);
            if (selected) {
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                    IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.8f * alpha * 255)));
                for (int gi = 1; gi <= 2; ++gi) {
                    float ga = (0.06f - static_cast<float>(gi) * 0.02f) * alpha;
                    dl->AddRectFilled(ImVec2(list_org.x, abs_ry - static_cast<float>(gi)),
                        ImVec2(list_org.x + w, abs_ry + row_h + static_cast<float>(gi)),
                        IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
                                 static_cast<int>(ab*255), static_cast<int>(ga * 255.f)), 2.f);
                }
            } else {
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 2.f, abs_ry + row_h),
                    IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.4f * alpha * 255)));
            }
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.conn_selected = i;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>((selected ? 0.95f : 0.75f) * alpha * 255));

        cx = list_org.x + 4.f;
        char pid_buf[16];
        snprintf(pid_buf, sizeof(pid_buf), "%u", c.pid);
        dl->AddText(ImVec2(cx, abs_ry), txt_col, pid_buf);                            cx += col_pid;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, protocol_name(c.protocol));          cx += col_proto;


        ImU32 state_col = IM_COL32(150, 150, 170, static_cast<int>(0.6f * alpha * 255));
        ImU32 state_bg = IM_COL32(40, 42, 55, static_cast<int>(180 * alpha));
        if (c.state == 4) { state_col = IM_COL32(100, 255, 100, static_cast<int>(0.85f * alpha * 255)); state_bg = IM_COL32(30, 60, 30, static_cast<int>(180 * alpha)); }
        else if (c.state == 1) { state_col = IM_COL32(100, 180, 255, static_cast<int>(0.85f * alpha * 255)); state_bg = IM_COL32(25, 40, 60, static_cast<int>(180 * alpha)); }
        else if (c.state == 10) { state_col = IM_COL32(255, 220, 80, static_cast<int>(0.85f * alpha * 255)); state_bg = IM_COL32(60, 55, 25, static_cast<int>(180 * alpha)); }
        else if (c.state == 7) { state_col = IM_COL32(255, 160, 80, static_cast<int>(0.85f * alpha * 255)); state_bg = IM_COL32(55, 40, 20, static_cast<int>(180 * alpha)); }
        else if (c.state == 2) { state_col = IM_COL32(180, 120, 255, static_cast<int>(0.85f * alpha * 255)); state_bg = IM_COL32(40, 30, 60, static_cast<int>(180 * alpha)); }
        ui_anim::render_badge(dl, tcp_state_name(c.state), cx, abs_ry + 2.f, state_bg, state_col);
        cx += col_state;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, local_str.c_str());                  cx += col_local;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, remote_str.c_str());

        conn_visible_row++;
        ImGui::SetCursorPosY(ry + row_h);
    }

    dl->PopClipRect();
    ImGui::EndChild();
    ImGui::EndChild();
}


static void render_capture(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_cap", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();


    {
        ImDrawList* dot_dl = ImGui::GetWindowDrawList();
        ImVec2 dpos = ImGui::GetCursorScreenPos();
        static float cap_dot_time = 0.f;
        cap_dot_time += ImGui::GetIO().DeltaTime;
        ImU32 dot_col = state.cap_running
            ? IM_COL32(80, 220, 80, static_cast<int>(alpha * 255))
            : IM_COL32(220, 60, 60, static_cast<int>(alpha * 255));
        ui_anim::render_status_dot(dot_dl, dpos.x + 5.f, dpos.y + 7.f, 4.f, dot_col, cap_dot_time, state.cap_running);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16.f);
    }
    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.cap_running) {
        if (ImGui::SmallButton("Start Capture")) {
            char dbg[256];
            snprintf(dbg, sizeof(dbg), "[network] START_CAPTURE clicked: filter_pid=%u filter_port=%u filter_proto=%u drv_ok=%d\n",
                state.cap_filter_pid, state.cap_filter_port, state.cap_filter_protocol,
                driver_bridge::using_kernel_driver() ? 1 : 0);
            driver_bridge::debug_log(dbg);
            if (driver_bridge::start_capture(state.cap_filter_pid, state.cap_filter_port,
                                       state.cap_filter_protocol, nullptr)) {
                driver_bridge::debug_log("[network] start_capture returned TRUE, signaling poll thread\n");
                state.cap_running = true;
                state.cap_polling.store(true);
                state.cap_cv.notify_all();
            } else {
                driver_bridge::debug_log("[network] start_capture returned FALSE — driver IOCTL may have failed or capture_active=0\n");

                char fail_msg[256];
                snprintf(fail_msg, sizeof(fail_msg),
                    "[network] start_capture FAILED (kernel_mode=%d). Check driver capture/WFP support.",
                    driver_bridge::using_kernel_driver() ? 1 : 0);
                driver_bridge::debug_log(fail_msg);
            }
        }
    } else {
        if (ImGui::SmallButton("Stop Capture")) {
            driver_bridge::stop_capture();
            state.cap_running = false;
            state.cap_polling.store(false);
        }
    }

    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        state.captured_packets.clear();
        state.cap_selected = -1;
    }

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

    ImGui::Spacing();


    float split_y = h * state.detail_ratio;
    float detail_h = h - split_y - 30.f;


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 18.f;
    float hdr_y = org.y + cursor.y;

    float col_no = 40.f, col_time = 100.f, col_proto = 55.f, col_src = 160.f, col_dst = 160.f;
    float col_info = w - col_no - col_time - col_src - col_dst - col_proto - 20.f;
    if (col_info < 60.f) col_info = 60.f;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
        IM_COL32(25, 27, 35, static_cast<int>(220 * alpha)));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.35f);

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(140, 145, 155, static_cast<int>(0.6f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "#");     cx += col_no;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Time");  cx += col_time;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Src");   cx += col_src;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Dst");   cx += col_dst;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Proto"); cx += col_proto;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Info");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
        IM_COL32(static_cast<int>(ar*60), static_cast<int>(ag*60), static_cast<int>(ab*60), static_cast<int>(80 * alpha)));

    float list_top = cursor.y + row_h + 4.f;
    float list_h = split_y - list_top;

    ImGui::SetCursorPosY(list_top);
    ImGui::BeginChild("##cap_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        ImVec2 list_org = ImGui::GetWindowPos();
        ImVec2 list_sz  = ImGui::GetWindowSize();
        dl->PushClipRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y), true);
        int cap_visible_row = 0;

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

            if (cap_visible_row & 1)
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), IM_COL32(255, 255, 255, 3));

            ImVec2 mouse = ImGui::GetMousePos();
            bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                            mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
            bool selected = (state.cap_selected == i);

            ImU32 proto_col = IM_COL32(150, 150, 170, static_cast<int>(0.6f * alpha * 255));
            if (p.protocol_label == "HTTP") proto_col = IM_COL32(100, 160, 255, static_cast<int>(0.9f * alpha * 255));
            else if (p.protocol_label == "TLS") proto_col = IM_COL32(80, 220, 120, static_cast<int>(0.9f * alpha * 255));
            else if (p.protocol_label == "DNS") proto_col = IM_COL32(255, 180, 80, static_cast<int>(0.9f * alpha * 255));
            else if (p.protocol_label == "QUIC") proto_col = IM_COL32(180, 120, 255, static_cast<int>(0.9f * alpha * 255));
            else if (p.protocol_label == "TCP") proto_col = IM_COL32(150, 150, 170, static_cast<int>(0.7f * alpha * 255));
            else if (p.protocol_label == "UDP") proto_col = IM_COL32(80, 220, 230, static_cast<int>(0.9f * alpha * 255));

            if (hovered || selected) {
                ImU32 bg = selected
                    ? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.2f * alpha * 255))
                    : IM_COL32(255, 255, 255, static_cast<int>(0.04f * alpha * 255));
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg, 2.f);
                if (selected) {
                    for (int gi = 1; gi <= 2; ++gi) {
                        float ga = (0.06f - static_cast<float>(gi) * 0.02f) * alpha;
                        dl->AddRectFilled(ImVec2(list_org.x, abs_ry - static_cast<float>(gi)),
                            ImVec2(list_org.x + w, abs_ry + row_h + static_cast<float>(gi)),
                            IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
                                     static_cast<int>(ab*255), static_cast<int>(ga * 255.f)), 2.f);
                    }
                }
            }

            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                proto_col);

            if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                state.cap_selected = i;

            ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>((selected ? 0.95f : 0.7f) * alpha * 255));

            cx = list_org.x + 4.f;
            char no_buf[16]; snprintf(no_buf, sizeof(no_buf), "%d", i + 1);
            dl->AddText(ImVec2(cx, abs_ry), IM_COL32(130, 130, 150, static_cast<int>(0.6f * alpha * 255)), no_buf);
            cx += col_no;

            dl->AddText(ImVec2(cx, abs_ry), IM_COL32(150, 150, 170, static_cast<int>(0.6f * alpha * 255)),
                format_timestamp(p.timestamp).c_str());
            cx += col_time;

            dl->AddText(ImVec2(cx, abs_ry), txt_col, src_str.c_str()); cx += col_src;
            dl->AddText(ImVec2(cx, abs_ry), txt_col, dst_str.c_str()); cx += col_dst;

            dl->AddText(ImVec2(cx, abs_ry), proto_col, p.protocol_label.c_str()); cx += col_proto;


            std::string info = p.summary;
            if (info.size() > 60) info = info.substr(0, 57) + "...";
            ImU32 info_col = IM_COL32(200, 200, 210, static_cast<int>(0.65f * alpha * 255));
            if (!info.empty()) {
                const char* methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "};
                for (auto* m : methods) {
                    if (info.compare(0, strlen(m), m) == 0) {
                        info_col = ui_anim::http_method_color(m, alpha * 0.85f);
                        break;
                    }
                }
            }
            dl->AddText(ImVec2(cx, abs_ry), info_col, info.c_str());

            cap_visible_row++;
            ImGui::SetCursorPosY(ry + row_h);
        }


        if (state.cap_auto_scroll && !state.captured_packets.empty())
            ImGui::SetScrollHereY(1.0f);
        dl->PopClipRect();
    }

    ImGui::EndChild();


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


static void render_dns(state_t& state, float x, float y, float w, float h,
                        float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_dns", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();

    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.dns_polling.load()) {
        if (ImGui::SmallButton("Start DNS Monitor")) {
            state.dns_polling.store(true);
            state.dns_cv.notify_all();
        }
    } else {
        if (ImGui::SmallButton("Stop DNS Monitor")) {
            state.dns_polling.store(false);
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) {
        if (driver_ok) {
            auto raw = driver_bridge::get_dns_queries(state.dns_filter_pid);
            std::lock_guard<std::mutex> lock(state.dns_mutex);
            for (auto& d : raw) {
                bool duplicate = false;
                for (auto it = state.dns_entries.rbegin();
                     it != state.dns_entries.rend() && it != state.dns_entries.rbegin() + (std::min)(static_cast<size_t>(256), state.dns_entries.size());
                     ++it) {
                    if (it->timestamp == d.timestamp && it->domain == d.domain && it->pid == d.pid) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
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
            while (state.dns_entries.size() > state.dns_max_entries)
                state.dns_entries.pop_front();
        }
    }

    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.f);
    ImGui::InputTextWithHint("##dns_filter", "Filter...", state.dns_filter_text, sizeof(state.dns_filter_text));

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 18.f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 60.f, col_type = 50.f, col_rcode = 55.f, col_ttl = 50.f;
    float remaining = w - col_pid - col_type - col_rcode - col_ttl - 20.f;
    float col_domain = remaining * 0.55f;
    float col_addr = remaining * 0.45f;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
        IM_COL32(25, 27, 35, static_cast<int>(220 * alpha)));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.35f);

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(140, 145, 155, static_cast<int>(0.6f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "PID");     cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Type");    cx += col_type;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Domain");  cx += col_domain;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Address"); cx += col_addr;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "RCode");   cx += col_rcode;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "TTL");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
        IM_COL32(static_cast<int>(ar*60), static_cast<int>(ag*60), static_cast<int>(ab*60), static_cast<int>(80 * alpha)));
    dl->AddLine(ImVec2(org.x + 2.f, hdr_y + row_h), ImVec2(org.x + w - 2.f, hdr_y + row_h),
        IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

    float list_h = h - (cursor.y + row_h + 8.f);
    ImGui::BeginChild("##dns_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.dns_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 dns_list_sz = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + dns_list_sz.x, list_org.y + dns_list_sz.y), true);

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
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg, 2.f);
            if (selected) {
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                    IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.8f * alpha * 255)));
                for (int gi = 1; gi <= 2; ++gi) {
                    float ga = (0.06f - static_cast<float>(gi) * 0.02f) * alpha;
                    dl->AddRectFilled(ImVec2(list_org.x, abs_ry - static_cast<float>(gi)),
                        ImVec2(list_org.x + w, abs_ry + row_h + static_cast<float>(gi)),
                        IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
                                 static_cast<int>(ab*255), static_cast<int>(ga * 255.f)), 2.f);
                }
            } else {
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 2.f, abs_ry + row_h),
                    IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.4f * alpha * 255)));
            }
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

    dl->PopClipRect();
    ImGui::EndChild();
    ImGui::EndChild();
}


static void render_proxy(state_t& state, float x, float y, float w, float h,
                          float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_proxy", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool running = mitm_proxy::is_running();


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


    ImGui::Spacing();
    if (cert_pin_bypass::is_bypass_active()) {
        ImGui::TextColored(ImVec4(0.2f, 1.f, 0.2f, alpha), "Cert pinning bypass: ACTIVE (%zu patches)",
            cert_pin_bypass::get_active_bypasses().size());
        ImGui::SameLine();
        if (ImGui::SmallButton("Revert Bypasses")) {
            cert_pin_bypass::revert_all_bypasses();
        }
    }

    ImGui::Spacing();


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


        if (!ex.request.headers.empty()) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, alpha), "Request Headers:");
            for (auto& h : ex.request.headers) {
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "  %s: %s", h.name.c_str(), h.value.c_str());
            }
        }


        if (ex.response.status_code > 0) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, alpha), "Response: %d %s",
                ex.response.status_code, ex.response.reason.c_str());
            for (auto& h : ex.response.headers) {
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "  %s: %s", h.name.c_str(), h.value.c_str());
            }
        }


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


static void render_filters(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_filters", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();


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

        driver_bridge::add_filter_rule(
            static_cast<uint32_t>(state.nf_action),
            static_cast<uint32_t>(state.nf_direction),
            static_cast<uint32_t>(state.nf_protocol),
            pid, port, ip_bytes, nullptr, nullptr);
    }

    ImGui::SameLine();
    if (ImGui::SmallButton("Clear All")) {
        driver_bridge::clear_filter_rules();
        state.filters.clear();
    }
    if (!driver_ok) ImGui::EndDisabled();

    ImGui::Spacing();


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


static void render_bandwidth(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_bw", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();

    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.bw_polling.load()) {
        if (ImGui::SmallButton("Start Monitoring")) {
            driver_bridge::bw_monitor_op(0);
            state.bw_monitoring = true;
            state.bw_polling.store(true);
            state.bw_cv.notify_one();
        }
    } else {
        if (ImGui::SmallButton("Stop Monitoring")) {
            driver_bridge::bw_monitor_op(1);
            state.bw_monitoring = false;
            state.bw_polling.store(false);
        }
    }

    if (!driver_ok) ImGui::EndDisabled();
    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 20.f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 60.f, col_name = 150.f, col_spark = 80.f;
    float col_in = (w - col_pid - col_name - col_spark - 20.f) * 0.25f;
    float col_out = col_in, col_rin = col_in, col_rout = col_in;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
        IM_COL32(25, 27, 35, static_cast<int>(220 * alpha)));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.35f);

    float cx = org.x + 4.f;
    ImU32 hdr_col = IM_COL32(140, 145, 155, static_cast<int>(0.6f * alpha * 255));
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "PID");       cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Process");   cx += col_name;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "In");        cx += col_in;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Out");       cx += col_out;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "In Rate");   cx += col_rin;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Out Rate");  cx += col_rout;
    dl->AddText(ImVec2(cx, hdr_y + 2.f), hdr_col, "Trend");

    ImGui::SetCursorPosY(cursor.y + row_h + 2.f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
        IM_COL32(static_cast<int>(ar*60), static_cast<int>(ag*60), static_cast<int>(ab*60), static_cast<int>(80 * alpha)));

    float list_h = h - (cursor.y + row_h + 8.f);
    ImGui::BeginChild("##bw_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.bw_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 bw_list_sz = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + bw_list_sz.x, list_org.y + bw_list_sz.y), true);

    for (int i = 0; i < static_cast<int>(state.bw_entries.size()); i++) {
        auto& b = state.bw_entries[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.bw_selected == i);

        if (i & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), IM_COL32(255, 255, 255, 3));

        if (hovered || selected) {
            ImU32 bg = selected
                ? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.2f * alpha * 255))
                : IM_COL32(255, 255, 255, static_cast<int>(0.04f * alpha * 255));
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h), bg, 3.f);
            if (selected) {
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                    IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.8f * alpha * 255)));
            } else {
                dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 2.f, abs_ry + row_h),
                    IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255), static_cast<int>(ab*255), static_cast<int>(0.4f * alpha * 255)));
            }
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.bw_selected = i;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>((selected ? 0.95f : 0.8f) * alpha * 255));
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
        dl->AddText(ImVec2(cx, abs_ry), txt_col, format_rate(b.rate_out).c_str()); cx += col_rout;

        int hist_count = std::min(b.history_index, 64);
        if (hist_count > 1) {
            float ordered[64];
            for (int hi = 0; hi < hist_count; hi++) {
                int idx = (b.history_index - hist_count + hi) % 64;
                if (idx < 0) idx += 64;
                ordered[hi] = b.rate_history[idx];
            }
            ImU32 spark_line = ui_anim::accent_col_u8(ar, ag, ab, static_cast<int>(180 * alpha));
            ImU32 spark_fill = ui_anim::accent_col_u8(ar, ag, ab, static_cast<int>(40 * alpha));
            ui_anim::render_sparkline(dl, cx, abs_ry + 2.f, col_spark - 4.f, row_h - 4.f,
                                      ordered, hist_count, spark_line, spark_fill);
        }

        ImGui::SetCursorPosY(ry + row_h);
    }

    dl->PopClipRect();
    ImGui::EndChild();
    ImGui::EndChild();
}


static void render_repeater(state_t& state, float x, float y, float w, float h,
                             float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_rep", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);


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


            ImGui::BeginChild("##rep_req", ImVec2(half_w, panel_h), false, ImGuiWindowFlags_NoBackground);
            ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Request");

            static char req_buf[65536] = {};
            if (rep.raw_request.size() < sizeof(req_buf)) {
                memcpy(req_buf, rep.raw_request.data(), rep.raw_request.size());
                req_buf[rep.raw_request.size()] = '\0';
            }
            if (ImGui::InputTextMultiline("##rep_req_edit", req_buf, sizeof(req_buf),
                ImVec2(half_w - 4.f, panel_h - 50.f))) {
                rep.raw_request = req_buf;
            }

            if (!rep.in_progress) {
                if (ImGui::SmallButton("Send")) {
                    rep.in_progress = true;
                    auto* entry_ptr = &rep;
                    work_queue::post([entry_ptr]() {
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
                    });
                }
            } else {
                ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Sending...");
            }

            ImGui::EndChild();

            ImGui::SameLine();


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

            ImGui::InputTextMultiline("##rep_resp_view", const_cast<char*>(rep.raw_response.c_str()),
                rep.raw_response.size() + 1,
                ImVec2(half_w - 4.f, panel_h - 50.f),
                ImGuiInputTextFlags_ReadOnly);

            ImGui::EndChild();
        }
    } else {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha),
            "No repeater entries. Use 'New' to create one or send from proxy history.");
    }

    ImGui::EndChild();
}


static void render_intercept(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_intercept", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool running = mitm_proxy::is_running();
    if (!running) {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Start the proxy first to use intercept mode.");
        ImGui::EndChild();
        return;
    }

    if (ImGui::Checkbox("Intercept Enabled", &state.intercept_enabled)) {
        mitm_proxy::set_intercept_enabled(state.intercept_enabled);
    }

    ImGui::SameLine();
    if (ImGui::SmallButton("Forward All (Shift+F)")) mitm_proxy::forward_all();
    ImGui::SameLine();
    if (ImGui::SmallButton("Drop All (Shift+D)")) mitm_proxy::drop_all();

    if (state.intercept_enabled) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), " [INTERCEPTING]");
    }

    ImGui::Spacing();


    auto held = mitm_proxy::get_held_exchanges();
    auto stats = mitm_proxy::get_stats();

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Held: %zu", held.size());


    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows)) {
        bool shift = ImGui::GetIO().KeyShift;
        if (shift && ImGui::IsKeyPressed(ImGuiKey_F)) mitm_proxy::forward_all();
        if (shift && ImGui::IsKeyPressed(ImGuiKey_D)) mitm_proxy::drop_all();


        if (state.intercept_selected >= 0 && state.intercept_selected < static_cast<int>(held.size())) {
            auto& sel = held[static_cast<size_t>(state.intercept_selected)];
            if (ImGui::IsKeyPressed(ImGuiKey_F)) mitm_proxy::forward_exchange(sel.id);
            if (ImGui::IsKeyPressed(ImGuiKey_D)) mitm_proxy::drop_exchange(sel.id);
        }
    }

    ImGui::Spacing();


    float split_y = h * 0.45f;


    ImGui::BeginChild("##held_list", ImVec2(w - 4.f, split_y), false, ImGuiWindowFlags_NoBackground);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 list_org = ImGui::GetWindowPos();
    float row_h = 18.f;


    float cx = list_org.x + 4.f;
    float cy = list_org.y + ImGui::GetCursorPosY();
    ImU32 hdr_col = IM_COL32(180, 180, 200, static_cast<int>(0.6f * alpha * 255));
    float col_id = 50.f, col_method = 60.f, col_host = 200.f, col_path = 250.f, col_size = 80.f;

    dl->AddText(ImVec2(cx, cy), hdr_col, "ID"); cx += col_id;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Method"); cx += col_method;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Host"); cx += col_host;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Path"); cx += col_path;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Size");
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 2.f);

    for (int i = 0; i < static_cast<int>(held.size()); i++) {
        auto& ex = held[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;
        bool is_sel = (state.intercept_selected == i);


        if (is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w - 4.f, abs_ry + row_h),
                IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                         static_cast<int>(ab * 255), static_cast<int>(0.2f * alpha * 255)));
        }


        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= list_org.x && mouse.x < list_org.x + w - 4.f &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0))
            state.intercept_selected = i;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.8f * alpha * 255));
        cx = list_org.x + 4.f;

        char id_buf[16];
        snprintf(id_buf, sizeof(id_buf), "%llu", static_cast<unsigned long long>(ex.id));
        dl->AddText(ImVec2(cx, abs_ry), txt_col, id_buf); cx += col_id;

        dl->AddText(ImVec2(cx, abs_ry),
            IM_COL32(100, 200, 100, static_cast<int>(0.9f * alpha * 255)),
            ex.request.method.c_str()); cx += col_method;

        dl->AddText(ImVec2(cx, abs_ry), txt_col, ex.target_host.c_str()); cx += col_host;

        std::string path_display = ex.request.uri.size() > 40 ? ex.request.uri.substr(0, 40) + "..." : ex.request.uri;
        dl->AddText(ImVec2(cx, abs_ry), txt_col, path_display.c_str()); cx += col_path;

        char size_buf[32];
        snprintf(size_buf, sizeof(size_buf), "%zu B", ex.raw_request.size());
        dl->AddText(ImVec2(cx, abs_ry), txt_col, size_buf);

        ImGui::SetCursorPosY(ry + row_h);
    }
    ImGui::EndChild();


    if (state.intercept_selected >= 0 && state.intercept_selected < static_cast<int>(held.size())) {
        auto& sel = held[static_cast<size_t>(state.intercept_selected)];
        if (ImGui::SmallButton("Forward (F)")) mitm_proxy::forward_exchange(sel.id);
        ImGui::SameLine();
        if (ImGui::SmallButton("Drop (D)")) mitm_proxy::drop_exchange(sel.id);
        ImGui::SameLine();
        if (ImGui::SmallButton("Forward Modified (M)")) {

            static char mod_buf[65536] = {};
            size_t len = strlen(mod_buf);
            if (len > 0) {
                std::vector<uint8_t> mod_data(mod_buf, mod_buf + len);
                mitm_proxy::forward_modified(sel.id, mod_data);
            } else {
                mitm_proxy::forward_exchange(sel.id);
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Send to Repeater")) {
            repeater_entry rep;
            rep.host = sel.target_host;
            rep.port = sel.target_port;
            rep.use_tls = sel.is_tls;
            rep.raw_request = std::string(sel.raw_request.begin(), sel.raw_request.end());
            state.repeater_entries.push_back(std::move(rep));
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Send to Fuzzer")) {
            state.fuzz_config.host = sel.target_host;
            state.fuzz_config.port = sel.target_port;
            state.fuzz_config.use_tls = sel.is_tls;
            state.fuzz_config.base_request = std::string(sel.raw_request.begin(), sel.raw_request.end());
            state.active_tab = sub_tab_t::fuzzer;
        }

        ImGui::Spacing();


        float detail_h = h - ImGui::GetCursorPosY() + y - 8.f;
        ImGui::BeginChild("##intercept_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        float half_w = (w - 12.f) * 0.5f;

        ImGui::BeginChild("##int_req_pane", ImVec2(half_w, detail_h - 4.f), false, ImGuiWindowFlags_NoBackground);
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Request (Editable)");
        static char int_req_buf[65536] = {};
        if (sel.raw_request.size() < sizeof(int_req_buf)) {
            memcpy(int_req_buf, sel.raw_request.data(), sel.raw_request.size());
            int_req_buf[sel.raw_request.size()] = '\0';
        }
        ImGui::InputTextMultiline("##int_req_edit", int_req_buf, sizeof(int_req_buf),
            ImVec2(half_w - 4.f, detail_h - 30.f));
        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild("##int_resp_pane", ImVec2(half_w, detail_h - 4.f), false, ImGuiWindowFlags_NoBackground);
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Headers");
        for (auto& hdr : sel.request.headers) {
            ImGui::TextColored(ImVec4(0.6f, 0.7f, 0.8f, alpha), "%s:", hdr.name.c_str());
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.85f, alpha), "%s", hdr.value.c_str());
        }
        ImGui::EndChild();

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


static void render_keylog(state_t& state, float x, float y, float w, float h,
                           float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_keylog", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);


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

    ImGui::Spacing();


    float list_h = h - ImGui::GetCursorPosY() - 8.f;
    ImGui::BeginChild("##kl_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    auto entries = ssl_keylog::get_entries(500);
    float row_h = 16.f;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 list_org = ImGui::GetWindowPos();

    for (int i = static_cast<int>(entries.size()) - 1; i >= 0; i--) {
        auto& e = entries[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;


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


static void write_pcap_header(std::ofstream& f) {

    uint32_t magic = 0xa1b2c3d4;
    uint16_t ver_major = 2, ver_minor = 4;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0, snaplen = 65535, network = 1;
    f.write(reinterpret_cast<const char*>(&magic), 4);
    f.write(reinterpret_cast<const char*>(&ver_major), 2);
    f.write(reinterpret_cast<const char*>(&ver_minor), 2);
    f.write(reinterpret_cast<const char*>(&thiszone), 4);
    f.write(reinterpret_cast<const char*>(&sigfigs), 4);
    f.write(reinterpret_cast<const char*>(&snaplen), 4);
    f.write(reinterpret_cast<const char*>(&network), 4);
}

static void write_pcap_packet(std::ofstream& f, const packet_entry& pkt) {

    uint32_t ts_sec = static_cast<uint32_t>(pkt.timestamp / 1000);
    uint32_t ts_usec = static_cast<uint32_t>((pkt.timestamp % 1000) * 1000);


    uint32_t transport_hdr_len = (pkt.protocol == 6) ? 20 : 8;
    uint32_t ip_total_len = 20 + transport_hdr_len + pkt.payload_size;
    uint32_t frame_len = 14 + ip_total_len;

    std::vector<uint8_t> frame(frame_len, 0);


    frame[12] = 0x08; frame[13] = 0x00;


    uint8_t* ip = frame.data() + 14;
    ip[0] = 0x45;
    ip[2] = static_cast<uint8_t>((ip_total_len >> 8) & 0xff);
    ip[3] = static_cast<uint8_t>(ip_total_len & 0xff);
    ip[8] = 64;
    ip[9] = pkt.protocol;


    if (pkt.direction == 1) {
        memcpy(ip + 12, pkt.src_addr, 4);
        memcpy(ip + 16, pkt.dst_addr, 4);
    } else {
        memcpy(ip + 12, pkt.dst_addr, 4);
        memcpy(ip + 16, pkt.src_addr, 4);
    }


    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += (static_cast<uint32_t>(ip[i]) << 8) | ip[i + 1];
    while (cksum >> 16) cksum = (cksum & 0xffff) + (cksum >> 16);
    uint16_t ip_cksum = static_cast<uint16_t>(~cksum);
    ip[10] = static_cast<uint8_t>(ip_cksum >> 8);
    ip[11] = static_cast<uint8_t>(ip_cksum & 0xff);


    uint8_t* th = ip + 20;
    uint16_t sp = pkt.direction == 1 ? pkt.src_port : pkt.dst_port;
    uint16_t dp = pkt.direction == 1 ? pkt.dst_port : pkt.src_port;
    th[0] = static_cast<uint8_t>(sp >> 8); th[1] = static_cast<uint8_t>(sp & 0xff);
    th[2] = static_cast<uint8_t>(dp >> 8); th[3] = static_cast<uint8_t>(dp & 0xff);
    if (pkt.protocol == 6) {
        th[12] = 0x50;
        th[13] = 0x18;
    } else {
        uint16_t udp_len = static_cast<uint16_t>(8 + pkt.payload_size);
        th[4] = static_cast<uint8_t>(udp_len >> 8);
        th[5] = static_cast<uint8_t>(udp_len & 0xff);
    }


    if (pkt.payload_size > 0 && !pkt.payload.empty()) {
        memcpy(th + transport_hdr_len, pkt.payload.data(),
            std::min<size_t>(pkt.payload_size, pkt.payload.size()));
    }


    f.write(reinterpret_cast<const char*>(&ts_sec), 4);
    f.write(reinterpret_cast<const char*>(&ts_usec), 4);
    f.write(reinterpret_cast<const char*>(&frame_len), 4);
    f.write(reinterpret_cast<const char*>(&frame_len), 4);
    f.write(reinterpret_cast<const char*>(frame.data()), static_cast<std::streamsize>(frame_len));
}

static void render_pcap_export(state_t& state, float x, float y, float w, float h,
                                float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_pcap", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "PCAP Export");
    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Output File:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(400.f);
    ImGui::InputText("##pcap_path", state.pcap_path, sizeof(state.pcap_path));

    if (state.pcap_path[0] == '\0') {
        char temp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp);
        snprintf(state.pcap_path, sizeof(state.pcap_path), "%saida_capture.pcap", temp);
    }

    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Filter PID:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.f);
    int fpid = static_cast<int>(state.pcap_filter_pid);
    if (ImGui::InputInt("##pcap_fpid", &fpid, 0, 0))
        state.pcap_filter_pid = static_cast<uint32_t>(std::max(0, fpid));
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "(0 = all)");

    ImGui::SameLine(0, 20.f);
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Protocol:");
    ImGui::SameLine();
    const char* proto_names[] = { "All", "TCP", "UDP" };
    int proto_idx = state.pcap_filter_protocol == 6 ? 1 : (state.pcap_filter_protocol == 17 ? 2 : 0);
    ImGui::SetNextItemWidth(80.f);
    if (ImGui::Combo("##pcap_proto", &proto_idx, proto_names, 3)) {
        state.pcap_filter_protocol = proto_idx == 1 ? 6 : (proto_idx == 2 ? 17 : 0);
    }

    ImGui::Spacing();

    size_t cap_count = 0;
    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        cap_count = state.captured_packets.size();
    }

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Captured packets available: %zu", cap_count);

    ImGui::Spacing();

    if (!state.pcap_writing) {
        if (ImGui::Button("Export to PCAP")) {
            state.pcap_writing = true;
            state.pcap_written_count = 0;


            std::deque<packet_entry> packets_copy;
            {
                std::lock_guard<std::mutex> lock(state.cap_mutex);
                packets_copy = state.captured_packets;
            }

            auto path = std::string(state.pcap_path);
            auto filter_pid = state.pcap_filter_pid;
            auto filter_proto = state.pcap_filter_protocol;
            auto* written_count = &state.pcap_written_count;
            auto* writing_flag = &state.pcap_writing;

            work_queue::post([packets_copy = std::move(packets_copy), path, filter_pid, filter_proto,
                         written_count, writing_flag]() {
                std::ofstream f(path, std::ios::binary);
                if (!f.is_open()) {
                    *writing_flag = false;
                    return;
                }
                write_pcap_header(f);

                uint32_t count = 0;
                for (auto& pkt : packets_copy) {
                    if (filter_pid != 0 && pkt.pid != filter_pid) continue;
                    if (filter_proto != 0 && pkt.protocol != filter_proto) continue;
                    write_pcap_packet(f, pkt);
                    count++;
                }
                *written_count = count;
                f.close();
                *writing_flag = false;
            });
        }
    } else {
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Writing PCAP file...");
    }

    if (state.pcap_written_count > 0 && !state.pcap_writing) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 1.f, 0.4f, alpha),
            "Exported %u packets to %s", state.pcap_written_count, state.pcap_path);
    }


    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Export Proxy History");
    ImGui::Spacing();

    size_t proxy_count = mitm_proxy::history_count();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Proxy exchanges available: %zu", proxy_count);

    if (ImGui::Button("Export Proxy as HAR")) {
        char temp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp);
        std::string har_path = std::string(temp) + "aida_proxy_export.har";

        auto history = mitm_proxy::get_history(0);
        work_queue::post([history = std::move(history), har_path]() {

            std::ofstream f(har_path);
            if (!f.is_open()) return;

            f << "{\n  \"log\": {\n    \"version\": \"1.2\",\n    \"entries\": [\n";
            for (size_t i = 0; i < history.size(); i++) {
                auto& ex = history[i];
                if (i > 0) f << ",\n";
                f << "      {\n";
                f << "        \"request\": {\n";
                f << "          \"method\": \"" << ex.request.method << "\",\n";
                f << "          \"url\": \"" << (ex.is_tls ? "https://" : "http://")
                  << ex.target_host << ex.request.uri << "\",\n";
                f << "          \"httpVersion\": \"" << ex.request.version << "\",\n";
                f << "          \"bodySize\": " << ex.request_size << "\n";
                f << "        },\n";
                f << "        \"response\": {\n";
                f << "          \"status\": " << ex.response.status_code << ",\n";
                f << "          \"statusText\": \"" << ex.response.reason << "\",\n";
                f << "          \"bodySize\": " << ex.response_size << "\n";
                f << "        },\n";
                f << "        \"time\": " << ex.latency_ms << "\n";
                f << "      }";
            }
            f << "\n    ]\n  }\n}\n";
            f.close();
        });
    }

    ImGui::EndChild();
}


static void run_fuzzer_thread(state_t& state) {
    auto& cfg = state.fuzz_config;


    auto load_set = [](const payload_set_t& ps) -> std::vector<std::string> {
        std::vector<std::string> lines;
        auto push_line = [&](std::istream& is) {
            std::string line;
            while (std::getline(is, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty()) lines.push_back(std::move(line));
            }
        };
        if (ps.type == 0) {
            std::ifstream f(ps.source);
            if (f.is_open()) push_line(f);
        } else {
            std::istringstream ss(ps.source);
            push_line(ss);
        }
        return lines;
    };


    auto load_legacy_set = [&]() -> std::vector<std::string> {
        payload_set_t tmp;
        tmp.type   = cfg.payload_type;
        tmp.source = cfg.payload_source;
        if (cfg.payload_type == 1) {
            std::vector<std::string> nums;
            int start_n = 0, end_n = 100;
            if (sscanf(cfg.payload_source.c_str(), "%d-%d", &start_n, &end_n) >= 1)
                for (int n = start_n; n <= end_n; n++)
                    nums.push_back(std::to_string(n));
            return nums;
        } else if (cfg.payload_type == 2) {
            std::string charset = cfg.payload_source.empty()
                ? "abcdefghijklmnopqrstuvwxyz0123456789" : cfg.payload_source;
            std::vector<std::string> v;
            for (char c : charset) v.push_back(std::string(1, c));
            for (char a : charset)
                for (char b : charset)
                    v.push_back(std::string(1, a) + b);
            return v;
        }
        return load_set(tmp);
    };


    auto make_request_multi = [](const std::string& tmpl,
                                  const std::vector<std::string>& payloads) -> std::string {
        const std::string marker = "\xc2\xa7";
        std::string result;
        result.reserve(tmpl.size() + 512);
        size_t pos = 0;
        size_t pi  = 0;
        while (pos < tmpl.size()) {
            size_t s = tmpl.find(marker, pos);
            if (s == std::string::npos) { result.append(tmpl, pos, std::string::npos); break; }
            size_t e = tmpl.find(marker, s + marker.size());
            if (e == std::string::npos) { result.append(tmpl, pos, std::string::npos); break; }
            result.append(tmpl, pos, s - pos);
            if (pi < payloads.size()) result.append(payloads[pi]);
            pi++;
            pos = e + marker.size();
        }

        if (!payloads.empty()) {
            size_t fp = 0;
            const std::string fuzz_tok = "FUZZ";
            while ((fp = result.find(fuzz_tok, fp)) != std::string::npos) {
                result.replace(fp, fuzz_tok.size(), payloads[0]);
                fp += payloads[0].size();
            }
        }
        return result;
    };


    auto do_grep_extract = [](const std::string& body,
                               const char* re_str,
                               const char* grp_str) -> std::string {
        if (!re_str || re_str[0] == '\0') return {};
        try {
            std::regex re(re_str);
            std::smatch m;
            if (std::regex_search(body, m, re)) {
                int grp = 1;
                try { grp = std::stoi(grp_str); } catch (...) {}
                if (grp >= 0 && grp < static_cast<int>(m.size()))
                    return m[static_cast<size_t>(grp)].str();
            }
        } catch (...) {}
        return {};
    };


    auto check_match = [&](int sc, const std::string& body, size_t len) -> bool {
        if (cfg.match_status > 0 && sc != cfg.match_status) return false;
        if (!cfg.match_body.empty() && body.find(cfg.match_body) == std::string::npos) return false;
        if (cfg.match_size_op == 1 && static_cast<int>(len) != cfg.match_size) return false;
        if (cfg.match_size_op == 2 && static_cast<int>(len) <= cfg.match_size) return false;
        if (cfg.match_size_op == 3 && static_cast<int>(len) >= cfg.match_size) return false;
        return true;
    };


    using combo_t = std::vector<std::string>;
    std::vector<combo_t> combos;

    switch (cfg.attack_mode) {

        case fuzzer_attack_mode_t::sniper: {
            std::vector<std::string> payloads = cfg.payload_sets.empty()
                ? load_legacy_set()
                : load_set(cfg.payload_sets[0]);
            combos.reserve(payloads.size());
            for (auto& p : payloads) combos.push_back({ p });
            break;
        }

        case fuzzer_attack_mode_t::pitchfork: {
            if (cfg.payload_sets.empty()) { state.fuzz_running.store(false); return; }
            std::vector<std::vector<std::string>> sets;
            sets.reserve(cfg.payload_sets.size());
            for (auto& ps : cfg.payload_sets) {
                sets.push_back(load_set(ps));
                if (sets.back().empty()) { state.fuzz_running.store(false); return; }
            }
            size_t min_len = sets[0].size();
            for (auto& s : sets) min_len = std::min(min_len, s.size());
            combos.reserve(min_len);
            for (size_t i = 0; i < min_len; i++) {
                combo_t c;
                c.reserve(sets.size());
                for (auto& s : sets) c.push_back(s[i]);
                combos.push_back(std::move(c));
            }
            break;
        }

        case fuzzer_attack_mode_t::clusterbomb: {
            if (cfg.payload_sets.empty()) { state.fuzz_running.store(false); return; }
            std::vector<std::vector<std::string>> sets;
            sets.reserve(cfg.payload_sets.size());
            for (auto& ps : cfg.payload_sets) {
                sets.push_back(load_set(ps));
                if (sets.back().empty()) { state.fuzz_running.store(false); return; }
            }

            combos.push_back(combo_t{});
            for (auto& s : sets) {
                std::vector<combo_t> next;
                next.reserve(combos.size() * s.size());
                for (auto& base : combos)
                    for (auto& val : s) {
                        combo_t nc = base;
                        nc.push_back(val);
                        next.push_back(std::move(nc));
                    }
                combos = std::move(next);
            }
            break;
        }
    }

    if (combos.empty()) { state.fuzz_running.store(false); return; }

    state.fuzz_total.store(static_cast<int>(combos.size()));
    state.fuzz_progress.store(0);

    std::atomic<int> next_index{0};
    int total   = static_cast<int>(combos.size());
    int threads = std::min(cfg.thread_count, 32);

    auto worker = [&]() {
        while (state.fuzz_running.load()) {
            int idx = next_index.fetch_add(1);
            if (idx >= total) break;

            auto& combo       = combos[static_cast<size_t>(idx)];
            std::string req_s = make_request_multi(cfg.base_request, combo);
            std::vector<uint8_t> raw_req(req_s.begin(), req_s.end());

            auto t0 = GetTickCount64();
            auto res = mitm_proxy::repeat_request(cfg.host, cfg.port, cfg.use_tls, raw_req);
            auto elapsed = GetTickCount64() - t0;

            state_t::fuzzer_result fr;
            fr.index     = idx;
            fr.payloads  = combo;
            fr.payload   = combo.empty() ? std::string() : combo[0];
            fr.latency_ms = elapsed;

            if (res.success) {
                fr.status_code  = res.exchange.response.status_code;
                fr.response_len = res.exchange.raw_response.size();
                std::string body(res.exchange.raw_response.begin(),
                                 res.exchange.raw_response.end());
                fr.response_preview = body.substr(0, std::min<size_t>(200, body.size()));
                fr.match = check_match(fr.status_code, body, fr.response_len);


                if (!cfg.payload_sets.empty()) {
                    fr.extracted_value = do_grep_extract(body,
                        cfg.payload_sets[0].grep_regex,
                        cfg.payload_sets[0].grep_group);
                }
            }

            {
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                state.fuzz_results.push_back(std::move(fr));
            }
            state.fuzz_progress.fetch_add(1);

            if (cfg.stop_on_match && fr.match) {
                state.fuzz_running.store(false);
                break;
            }
            if (cfg.delay_ms > 0) Sleep(static_cast<DWORD>(cfg.delay_ms));
        }
    };

    std::atomic<int> remaining{threads};
    std::mutex done_mtx;
    std::condition_variable done_cv;

    for (int t = 0; t < threads; t++) {
        work_queue::post([&worker, &remaining, &done_cv]() {
            worker();
            if (--remaining == 0)
                done_cv.notify_all();
        });
    }
    {
        std::unique_lock<std::mutex> lk(done_mtx);
        done_cv.wait(lk, [&remaining]() { return remaining.load() == 0; });
    }

    state.fuzz_running.store(false);
}

static void render_fuzzer(state_t& state, float x, float y, float w, float h,
                           float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_fuzzer", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Fuzzer / Intruder");
    ImGui::Spacing();

    auto& cfg = state.fuzz_config;


    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Host:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.f);
    static char fuzz_host[256] = {};
    if (cfg.host.size() < sizeof(fuzz_host)) { memcpy(fuzz_host, cfg.host.c_str(), cfg.host.size() + 1); }
    if (ImGui::InputText("##fuzz_host", fuzz_host, sizeof(fuzz_host))) cfg.host = fuzz_host;
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Port:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60.f);
    int fp = cfg.port;
    if (ImGui::InputInt("##fuzz_port", &fp, 0, 0))
        cfg.port = static_cast<uint16_t>(std::max(1, std::min(65535, fp)));
    ImGui::SameLine();
    ImGui::Checkbox("TLS##fuzz", &cfg.use_tls);

    ImGui::Spacing();


    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Attack Mode:");
    ImGui::SameLine();
    int am = static_cast<int>(cfg.attack_mode);
    if (ImGui::RadioButton("Sniper##fuzz",      &am, 0)) cfg.attack_mode = fuzzer_attack_mode_t::sniper;
    ImGui::SameLine();
    if (ImGui::RadioButton("Pitchfork##fuzz",   &am, 1)) cfg.attack_mode = fuzzer_attack_mode_t::pitchfork;
    ImGui::SameLine();
    if (ImGui::RadioButton("Clusterbomb##fuzz", &am, 2)) cfg.attack_mode = fuzzer_attack_mode_t::clusterbomb;

    ImGui::Spacing();


    if (cfg.attack_mode == fuzzer_attack_mode_t::sniper) {

        const char* payload_types[] = { "Wordlist File", "Sequential Numbers", "Charset Brute" };
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Payload Type:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(160.f);
        ImGui::Combo("##fuzz_pt", &cfg.payload_type, payload_types, 3);

        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Payload Source:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(300.f);
        static char pl_src[512] = {};
        if (cfg.payload_source.size() < sizeof(pl_src)) {
            memcpy(pl_src, cfg.payload_source.c_str(), cfg.payload_source.size() + 1);
        }
        if (ImGui::InputText("##fuzz_src", pl_src, sizeof(pl_src))) cfg.payload_source = pl_src;
        ImGui::SameLine();
        if (cfg.payload_type == 0) ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "(path to wordlist)");
        else if (cfg.payload_type == 1) ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "(start-end)");
        else ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "(charset)");


        if (cfg.payload_sets.empty()) cfg.payload_sets.emplace_back();
        auto& ps0 = cfg.payload_sets[0];
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Grep Extract:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(250.f);
        ImGui::InputTextWithHint("##fuzz_grep0", "regex (leave empty to skip)",
                                 ps0.grep_regex, sizeof(ps0.grep_regex));
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "Group:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(40.f);
        ImGui::InputText("##fuzz_grp0", ps0.grep_group, sizeof(ps0.grep_group));

    } else {

        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Payload Sets");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "(one set per injection position §...§)");
        ImGui::SameLine();
        if (ImGui::SmallButton("+##fuzz_addset")) cfg.payload_sets.emplace_back();
        ImGui::SameLine();
        if (ImGui::SmallButton("-##fuzz_remset") && !cfg.payload_sets.empty())
            cfg.payload_sets.pop_back();

        float sets_h = std::min(h * 0.35f, 200.f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(20, 20, 30, static_cast<int>(160 * alpha)));
        ImGui::BeginChild("##fuzz_sets_panel", ImVec2(w - 8.f, sets_h), true,
                          ImGuiWindowFlags_NoBackground);

        static int  set_sel = 0;
        const char* set_type_items[] = { "Wordlist File", "Inline List" };

        for (int si = 0; si < static_cast<int>(cfg.payload_sets.size()); si++) {
            auto& ps = cfg.payload_sets[static_cast<size_t>(si)];
            ImGui::PushID(si);


            char set_label[32];
            snprintf(set_label, sizeof(set_label), "Set %d", si + 1);
            if (ImGui::CollapsingHeader(set_label)) {
                ImGui::Indent(12.f);

                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Name:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(160.f);
                char name_buf[128] = {};
                if (ps.name.size() < sizeof(name_buf))
                    memcpy(name_buf, ps.name.c_str(), ps.name.size() + 1);
                if (ImGui::InputText("##ps_name", name_buf, sizeof(name_buf)))
                    ps.name = name_buf;

                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Type:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(120.f);
                ImGui::Combo("##ps_type", &ps.type, set_type_items, 2);

                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Source:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(w - 160.f);
                char src_buf[512] = {};
                if (ps.source.size() < sizeof(src_buf))
                    memcpy(src_buf, ps.source.c_str(), ps.source.size() + 1);
                if (ps.type == 0) {
                    if (ImGui::InputText("##ps_src", src_buf, sizeof(src_buf)))
                        ps.source = src_buf;
                } else {
                    if (ImGui::InputTextMultiline("##ps_src_ml", src_buf, sizeof(src_buf),
                                                  ImVec2(w - 170.f, 60.f)))
                        ps.source = src_buf;
                }


                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Grep Extract:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(240.f);
                ImGui::InputTextWithHint("##ps_grep", "regex (leave empty to skip)",
                                         ps.grep_regex, sizeof(ps.grep_regex));
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "Group:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(40.f);
                ImGui::InputText("##ps_grp", ps.grep_group, sizeof(ps.grep_group));

                ImGui::Unindent(12.f);
            }

            ImGui::PopID();
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();


    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Threads:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60.f);
    ImGui::InputInt("##fuzz_threads", &cfg.thread_count, 1, 4);
    cfg.thread_count = std::max(1, std::min(32, cfg.thread_count));
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Delay (ms):");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60.f);
    ImGui::InputInt("##fuzz_delay", &cfg.delay_ms, 0, 0);
    cfg.delay_ms = std::max(0, cfg.delay_ms);


    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Match Status:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60.f);
    ImGui::InputInt("##fuzz_ms", &cfg.match_status, 0, 0);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha), "(0=any)");
    ImGui::SameLine();
    ImGui::Checkbox("Stop on match##fuzz", &cfg.stop_on_match);

    ImGui::Spacing();


    ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Request Template");
    ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, alpha),
                       "Mark injection points with §value§  (FUZZ also accepted)");
    ImGui::Spacing();

    static char tmpl_buf[65536] = {};
    if (cfg.base_request.size() < sizeof(tmpl_buf) && !state.fuzz_running.load()) {
        memcpy(tmpl_buf, cfg.base_request.c_str(), cfg.base_request.size());
        tmpl_buf[cfg.base_request.size()] = '\0';
    }

    float tmpl_h = std::min(h * 0.22f, 180.f);
    if (ImGui::InputTextMultiline("##fuzz_tmpl", tmpl_buf, sizeof(tmpl_buf),
                                   ImVec2(w - 8.f, tmpl_h)))
        cfg.base_request = tmpl_buf;

    ImGui::Spacing();


    if (!state.fuzz_running.load()) {
        if (ImGui::Button("Start Fuzzer")) {
            {
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                state.fuzz_results.clear();
            }
            state.fuzz_progress.store(0);
            state.fuzz_total.store(0);
            state.fuzz_running.store(true);
            state.fuzz_cv.notify_one();
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear Results##fuzz")) {
            std::lock_guard<std::mutex> lk(state.fuzz_mutex);
            state.fuzz_results.clear();
        }
    } else {
        int prog = state.fuzz_progress.load();
        int tot  = state.fuzz_total.load();
        {
            static float fuzz_spin_time = 0.f;
            fuzz_spin_time += ImGui::GetIO().DeltaTime;
            ImDrawList* sdl = ImGui::GetWindowDrawList();
            ImVec2 spos = ImGui::GetCursorScreenPos();
            ui_anim::render_spinner(sdl, spos.x + 8.f, spos.y + 8.f, 6.f, 2.f,
                                    ui_anim::accent_col_u8(ar, ag, ab, static_cast<int>(220 * alpha)),
                                    fuzz_spin_time);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 20.f);
        }
        ImGui::TextColored(ImVec4(ar, ag, ab, alpha), "Running: %d / %d", prog, tot);
        float frac = tot > 0 ? static_cast<float>(prog) / static_cast<float>(tot) : 0.f;
        ImGui::ProgressBar(frac, ImVec2(300.f, 0.f));
        ImGui::SameLine();
        if (ImGui::SmallButton("Stop")) state.fuzz_running.store(false);
    }

    ImGui::Spacing();


    std::vector<state_t::fuzzer_result> results_copy;
    {
        std::lock_guard<std::mutex> lk(state.fuzz_mutex);
        results_copy = state.fuzz_results;
    }


    size_t max_cols = 1;
    for (auto& fr : results_copy)
        max_cols = std::max(max_cols, fr.payloads.size());
    bool show_extract = false;
    for (auto& fr : results_copy)
        if (!fr.extracted_value.empty()) { show_extract = true; break; }

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, alpha), "Results: %zu", results_copy.size());

    float results_h = h - ImGui::GetCursorPosY() + y - 8.f;
    ImGui::BeginChild("##fuzz_results", ImVec2(w - 4.f, results_h), false,
                      ImGuiWindowFlags_NoBackground);

    ImDrawList* dl   = ImGui::GetWindowDrawList();
    ImVec2 list_org  = ImGui::GetWindowPos();
    float row_h      = 18.f;


    float c_idx     = 50.f;
    float c_payload = std::min(180.f, (w - 50.f - 60.f - 80.f - 80.f - 50.f
                                       - (show_extract ? 120.f : 0.f))
                                      / static_cast<float>(std::max<size_t>(1, max_cols)));
    float c_status  = 60.f;
    float c_len     = 80.f;
    float c_time    = 80.f;
    float c_match   = 50.f;
    float c_extract = show_extract ? 120.f : 0.f;

    float cy  = list_org.y + ImGui::GetCursorPosY();
    float cx0 = list_org.x + 4.f;
    ImU32 hdr_col = IM_COL32(180, 180, 200, static_cast<int>(0.6f * alpha * 255));

    {
        float cx = cx0;
        char hbuf[32];
        dl->AddText(ImVec2(cx, cy), hdr_col, "#"); cx += c_idx;
        for (size_t pi = 0; pi < max_cols; pi++) {
            snprintf(hbuf, sizeof(hbuf), "Payload %zu", pi + 1);
            dl->AddText(ImVec2(cx, cy), hdr_col, hbuf); cx += c_payload;
        }
        dl->AddText(ImVec2(cx, cy), hdr_col, "Status");  cx += c_status;
        dl->AddText(ImVec2(cx, cy), hdr_col, "Length");  cx += c_len;
        dl->AddText(ImVec2(cx, cy), hdr_col, "Time");    cx += c_time;
        dl->AddText(ImVec2(cx, cy), hdr_col, "Match");   cx += c_match;
        if (show_extract) dl->AddText(ImVec2(cx, cy), hdr_col, "Extracted");
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 2.f);
    }

    for (auto& fr : results_copy) {
        float ry     = ImGui::GetCursorPosY();
        float abs_ry = list_org.y + ry;
        bool  is_sel = (state.fuzz_selected == fr.index);

        if (fr.match) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry),
                              ImVec2(list_org.x + w - 4.f, abs_ry + row_h),
                              IM_COL32(40, 100, 40, static_cast<int>(0.3f * alpha * 255)));
        } else if (is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry),
                              ImVec2(list_org.x + w - 4.f, abs_ry + row_h),
                              IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                                       static_cast<int>(ab * 255),
                                       static_cast<int>(0.15f * alpha * 255)));
        }

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= list_org.x && mouse.x < list_org.x + w - 4.f &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0))
            state.fuzz_selected = fr.index;

        ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.8f * alpha * 255));
        float cx = cx0;
        char buf[64];

        snprintf(buf, sizeof(buf), "%d", fr.index);
        dl->AddText(ImVec2(cx, abs_ry), txt_col, buf); cx += c_idx;


        for (size_t pi = 0; pi < max_cols; pi++) {
            std::string pl;
            if (pi < fr.payloads.size()) {
                pl = fr.payloads[pi].size() > 28
                    ? fr.payloads[pi].substr(0, 28) + ".." : fr.payloads[pi];
            }
            dl->AddText(ImVec2(cx, abs_ry), txt_col, pl.c_str()); cx += c_payload;
        }


        ImU32 sc_col = txt_col;
        if (fr.status_code >= 200 && fr.status_code < 300)
            sc_col = IM_COL32(100, 255, 100, static_cast<int>(0.9f * alpha * 255));
        else if (fr.status_code >= 300 && fr.status_code < 400)
            sc_col = IM_COL32(100, 160, 255, static_cast<int>(0.9f * alpha * 255));
        else if (fr.status_code >= 400 && fr.status_code < 500)
            sc_col = IM_COL32(255, 180, 80, static_cast<int>(0.9f * alpha * 255));
        else if (fr.status_code >= 500)
            sc_col = IM_COL32(255, 80, 80, static_cast<int>(0.9f * alpha * 255));
        snprintf(buf, sizeof(buf), "%d", fr.status_code);
        dl->AddText(ImVec2(cx, abs_ry), sc_col, buf); cx += c_status;

        snprintf(buf, sizeof(buf), "%zu", fr.response_len);
        dl->AddText(ImVec2(cx, abs_ry), txt_col, buf); cx += c_len;

        snprintf(buf, sizeof(buf), "%llums",
                 static_cast<unsigned long long>(fr.latency_ms));
        dl->AddText(ImVec2(cx, abs_ry), txt_col, buf); cx += c_time;

        if (fr.match)
            dl->AddText(ImVec2(cx, abs_ry),
                        IM_COL32(100, 255, 100, static_cast<int>(0.9f * alpha * 255)), "YES");
        cx += c_match;

        if (show_extract && !fr.extracted_value.empty()) {
            std::string ev = fr.extracted_value.size() > 20
                ? fr.extracted_value.substr(0, 20) + ".." : fr.extracted_value;
            dl->AddText(ImVec2(cx, abs_ry),
                        IM_COL32(255, 220, 80, static_cast<int>(0.9f * alpha * 255)),
                        ev.c_str());
        }

        ImGui::SetCursorPosY(ry + row_h);
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

static void render_websocket(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
    ImGui::BeginChild("##ws_tab", ImVec2(w, h), false);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();
    ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.9f * alpha * 255));
    ImU32 dim_col = IM_COL32(180, 180, 190, static_cast<int>(0.6f * alpha * 255));
    ImU32 accent = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                             static_cast<int>(ab * 255), static_cast<int>(0.9f * alpha * 255));


    float ty = 4.f;
    ImGui::SetCursorPos(ImVec2(8.f, ty));
    ImGui::PushItemWidth(200.f);
    ImGui::InputTextWithHint("##ws_filter", "Filter...", state.ws_filter_text, sizeof(state.ws_filter_text));
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (ImGui::Button("Clear##ws")) {
        std::lock_guard<std::mutex> lock(state.ws_mutex);
        state.ws_frames.clear();
        state.ws_selected = -1;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll##ws", &state.ws_auto_scroll);

    float header_y = ty + 30.f;


    float c_dir = 30.f, c_host = 200.f, c_opcode = 60.f, c_size = 80.f, c_time = 80.f;
    float cx = 8.f;
    dl->AddText(ImVec2(origin.x + cx, origin.y + header_y), dim_col, "Dir"); cx += c_dir;
    dl->AddText(ImVec2(origin.x + cx, origin.y + header_y), dim_col, "Host"); cx += c_host;
    dl->AddText(ImVec2(origin.x + cx, origin.y + header_y), dim_col, "Opcode"); cx += c_opcode;
    dl->AddText(ImVec2(origin.x + cx, origin.y + header_y), dim_col, "Size"); cx += c_size;
    dl->AddText(ImVec2(origin.x + cx, origin.y + header_y), dim_col, "Preview");

    float list_y = header_y + 20.f;
    float list_h = h * 0.55f;
    ImGui::SetCursorPos(ImVec2(0.f, list_y));
    ImGui::BeginChild("##ws_list", ImVec2(w, list_h), false);

    std::lock_guard<std::mutex> lock(state.ws_mutex);
    float row_h = 18.f;
    std::string filter(state.ws_filter_text);
    int visible_idx = 0;

    for (size_t i = 0; i < state.ws_frames.size(); i++) {
        const auto& fr = state.ws_frames[i];
        if (!filter.empty() && fr.host.find(filter) == std::string::npos &&
            fr.preview.find(filter) == std::string::npos)
            continue;

        float ry = static_cast<float>(visible_idx) * row_h;
        float abs_ry = ImGui::GetWindowPos().y + ry;

        bool is_selected = (state.ws_selected == static_cast<int>(i));
        if (is_selected) {
            dl->AddRectFilled(ImVec2(ImGui::GetWindowPos().x, abs_ry),
                ImVec2(ImGui::GetWindowPos().x + w, abs_ry + row_h),
                IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                         static_cast<int>(ab * 255), static_cast<int>(0.15f * alpha * 255)));
        }

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= ImGui::GetWindowPos().x && mouse.x < ImGui::GetWindowPos().x + w &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0))
            state.ws_selected = static_cast<int>(i);

        cx = 8.f;
        ImU32 dir_col = fr.is_outbound
            ? IM_COL32(255, 180, 100, static_cast<int>(0.9f * alpha * 255))
            : IM_COL32(100, 200, 255, static_cast<int>(0.9f * alpha * 255));
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry), dir_col,
            fr.is_outbound ? "\xe2\x86\x91" : "\xe2\x86\x93"); cx += c_dir;

        char buf[512];
        snprintf(buf, sizeof(buf), "%s:%u", fr.host.c_str(), fr.port);
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry), txt_col, buf); cx += c_host;

        snprintf(buf, sizeof(buf), "0x%02X", fr.opcode);
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry), dim_col, buf); cx += c_opcode;

        snprintf(buf, sizeof(buf), "%zu", fr.payload.size());
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry), txt_col, buf); cx += c_size;

        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry), dim_col,
            fr.preview.empty() ? "(empty)" : fr.preview.c_str());

        ImGui::SetCursorPosY(ry + row_h);
        visible_idx++;
    }

    if (state.ws_auto_scroll && !state.ws_frames.empty())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();


    float detail_y = list_y + list_h + 4.f;
    float detail_h = h - detail_y;
    ImGui::SetCursorPos(ImVec2(0.f, detail_y));
    ImGui::BeginChild("##ws_detail", ImVec2(w, detail_h), false);

    if (state.ws_selected >= 0 && state.ws_selected < static_cast<int>(state.ws_frames.size())) {
        const auto& fr = state.ws_frames[static_cast<size_t>(state.ws_selected)];
        dl = ImGui::GetWindowDrawList();
        ImVec2 dp = ImGui::GetWindowPos();


        float dy = 4.f;
        for (size_t off = 0; off < fr.payload.size() && dy < detail_h - 14.f; off += 16) {
            char line[128];
            int pos = snprintf(line, sizeof(line), "%04zx  ", off);
            for (size_t j = 0; j < 16; j++) {
                if (off + j < fr.payload.size())
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02x ", fr.payload[off + j]);
                else
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
            }
            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
            for (size_t j = 0; j < 16 && off + j < fr.payload.size(); j++) {
                uint8_t c = fr.payload[off + j];
                line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
            }
            line[pos] = '\0';
            dl->AddText(ImVec2(dp.x + 8.f, dp.y + dy), dim_col, line);
            dy += 14.f;
        }
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
}


static void render_scripting(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
    ImGui::BeginChild("##script_tab", ImVec2(w, h), false);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();
    ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.9f * alpha * 255));
    ImU32 dim_col = IM_COL32(180, 180, 190, static_cast<int>(0.6f * alpha * 255));
    (void)dim_col;

    float panel_w = 200.f;


    ImGui::SetCursorPos(ImVec2(0.f, 0.f));
    ImGui::BeginChild("##script_list_panel", ImVec2(panel_w, h), false);

    dl = ImGui::GetWindowDrawList();
    ImVec2 lp = ImGui::GetWindowPos();
    dl->AddText(ImVec2(lp.x + 8.f, lp.y + 4.f), txt_col, "Scripts");

    float ly = 24.f;
    for (size_t i = 0; i < state.scripts.size(); i++) {
        auto& s = state.scripts[i];
        float abs_ly = lp.y + ly;
        bool sel = (state.script_selected == static_cast<int>(i));

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= lp.x && mouse.x < lp.x + panel_w &&
                        mouse.y >= abs_ly && mouse.y < abs_ly + 20.f);

        if (sel)
            dl->AddRectFilled(ImVec2(lp.x, abs_ly), ImVec2(lp.x + panel_w, abs_ly + 20.f),
                IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                         static_cast<int>(ab * 255), static_cast<int>(0.15f * alpha * 255)));

        if (hovered && ImGui::IsMouseClicked(0))
            state.script_selected = static_cast<int>(i);

        ImU32 name_col = s.enabled ? txt_col
            : IM_COL32(120, 120, 130, static_cast<int>(0.6f * alpha * 255));
        dl->AddText(ImVec2(lp.x + 8.f, abs_ly + 2.f), name_col, s.name.c_str());

        ly += 20.f;
    }


    ly += 8.f;
    ImGui::SetCursorPos(ImVec2(8.f, ly));
    if (ImGui::SmallButton("Load##scr")) {

    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Unload##scr") && state.script_selected >= 0 &&
        state.script_selected < static_cast<int>(state.scripts.size())) {
        auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
        if (s.loaded) {
            script_engine::unload_script(s.name);
            s.loaded = false;
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Toggle##scr") && state.script_selected >= 0 &&
        state.script_selected < static_cast<int>(state.scripts.size())) {
        auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
        s.enabled = !s.enabled;
        script_engine::set_script_enabled(s.name, s.enabled);
    }

    ImGui::EndChild();


    float right_x = panel_w + 2.f;
    float right_w = w - right_x;

    ImGui::SetCursorPos(ImVec2(right_x, 0.f));
    ImGui::BeginChild("##script_right", ImVec2(right_w, h), false);


    float editor_h = h * 0.4f;
    float console_h = 42.f;
    float log_h = h - editor_h - console_h;

    ImGui::BeginChild("##script_editor", ImVec2(right_w, editor_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 ep = ImGui::GetWindowPos();
    dl->AddText(ImVec2(ep.x + 8.f, ep.y + 2.f), txt_col, "Editor");

    ImGui::SetCursorPos(ImVec2(4.f, 18.f));
    ImGui::InputTextMultiline("##script_edit", state.script_editor_buf, sizeof(state.script_editor_buf),
        ImVec2(right_w - 8.f, editor_h - 48.f), ImGuiInputTextFlags_AllowTabInput);

    ImGui::SetCursorPos(ImVec2(4.f, editor_h - 26.f));
    if (ImGui::SmallButton("Run##script_run")) {
        std::string src(state.script_editor_buf);
        if (!src.empty()) {
            bool ok = script_engine::load_script_source("_editor_", src);
            std::lock_guard<std::mutex> lock(state.script_log_mutex);
            state.script_log.push_back(ok ? "[editor] Loaded successfully" : "[editor] Load failed");
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear Editor##scr_clear"))
        memset(state.script_editor_buf, 0, sizeof(state.script_editor_buf));

    ImGui::EndChild();


    ImGui::BeginChild("##script_console", ImVec2(right_w, console_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 cp = ImGui::GetWindowPos();
    dl->AddText(ImVec2(cp.x + 8.f, cp.y + 2.f), txt_col, "Console");

    ImGui::SetCursorPos(ImVec2(4.f, 18.f));
    ImGui::PushItemWidth(right_w - 80.f);
    bool enter = ImGui::InputText("##scr_input", state.script_console_buf,
        sizeof(state.script_console_buf), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (ImGui::SmallButton("Exec##scr") || enter) {
        std::string cmd(state.script_console_buf);
        if (!cmd.empty()) {
            std::string result = script_engine::execute(cmd);
            std::lock_guard<std::mutex> lock(state.script_log_mutex);
            state.script_log.push_back("> " + cmd);
            if (!result.empty())
                state.script_log.push_back(result);
            memset(state.script_console_buf, 0, sizeof(state.script_console_buf));
        }
    }
    ImGui::EndChild();


    ImGui::BeginChild("##script_log", ImVec2(right_w, log_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 lop = ImGui::GetWindowPos();
    dl->AddText(ImVec2(lop.x + 8.f, lop.y + 2.f), txt_col, "Log");

    ImGui::SetCursorPos(ImVec2(0.f, 18.f));
    ImGui::BeginChild("##script_log_scroll", ImVec2(right_w, log_h - 18.f), false);

    {
        std::lock_guard<std::mutex> lock(state.script_log_mutex);

        auto engine_log = script_engine::get_log();
        for (const auto& line : engine_log)
            state.script_log.push_back(line.message);

        while (state.script_log.size() > state.script_log_max)
            state.script_log.pop_front();

        for (const auto& line : state.script_log) {
            ImGui::TextUnformatted(line.c_str());
        }
    }

    if (state.script_log_auto_scroll)
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();
    ImGui::EndChild();
    ImGui::EndChild();

    ImGui::PopStyleColor();
    ImGui::EndChild();
}


static void render_decoder(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
    ImGui::BeginChild("##decoder_tab", ImVec2(w, h), false);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();
    ImU32 txt_col = IM_COL32(220, 220, 230, static_cast<int>(0.9f * alpha * 255));
    ImU32 dim_col = IM_COL32(180, 180, 190, static_cast<int>(0.6f * alpha * 255));


    float pipe_w = w * 0.3f;
    ImGui::SetCursorPos(ImVec2(0.f, 0.f));
    ImGui::BeginChild("##dec_pipeline", ImVec2(pipe_w, h), false);

    dl = ImGui::GetWindowDrawList();
    ImVec2 pp = ImGui::GetWindowPos();
    dl->AddText(ImVec2(pp.x + 8.f, pp.y + 4.f), txt_col, "Pipeline");


    ImGui::SetCursorPos(ImVec2(4.f, 24.f));
    auto& reg = decoder_pipeline::registry::instance();
    auto transforms = reg.all();


    static std::string combo_str;
    if (combo_str.empty()) {
        for (const auto& t : transforms) {
            combo_str += t->name;
            combo_str += '\0';
        }
        combo_str += '\0';
    }

    ImGui::PushItemWidth(pipe_w - 80.f);
    ImGui::Combo("##dec_add", &state.decoder_add_transform, combo_str.c_str());
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (ImGui::SmallButton("Add##dec")) {
        if (state.decoder_add_transform >= 0 &&
            state.decoder_add_transform < static_cast<int>(transforms.size())) {
            state_t::decoder_step step;
            step.transform_name = transforms[static_cast<size_t>(state.decoder_add_transform)]->id;
            state.decoder_pipeline.push_back(std::move(step));
        }
    }


    float py = 50.f;
    for (size_t i = 0; i < state.decoder_pipeline.size(); i++) {
        auto& step = state.decoder_pipeline[i];
        float abs_py = pp.y + py;
        bool sel = (state.decoder_selected_step == static_cast<int>(i));

        if (sel)
            dl->AddRectFilled(ImVec2(pp.x, abs_py), ImVec2(pp.x + pipe_w, abs_py + 22.f),
                IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                         static_cast<int>(ab * 255), static_cast<int>(0.15f * alpha * 255)));

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= pp.x && mouse.x < pp.x + pipe_w &&
            mouse.y >= abs_py && mouse.y < abs_py + 22.f && ImGui::IsMouseClicked(0))
            state.decoder_selected_step = static_cast<int>(i);

        char label[256];
        snprintf(label, sizeof(label), "%zu. %s", i + 1, step.transform_name.c_str());
        dl->AddText(ImVec2(pp.x + 8.f, abs_py + 3.f), txt_col, label);


        ImGui::SetCursorPos(ImVec2(pipe_w - 24.f, py + 2.f));
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::SmallButton("X##dec_rm")) {
            state.decoder_pipeline.erase(state.decoder_pipeline.begin() + static_cast<ptrdiff_t>(i));
            if (state.decoder_selected_step >= static_cast<int>(i))
                state.decoder_selected_step--;
            ImGui::PopID();
            break;
        }
        ImGui::PopID();

        if (i + 1 < state.decoder_pipeline.size()) {
            float arrow_base_y = pp.y + py + 22.f;
            float arrow_cx = pp.x + pipe_w * 0.5f;
            ImU32 arrow_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
                                       static_cast<int>(ab * 255), static_cast<int>(0.5f * alpha * 255));
            dl->AddLine(ImVec2(arrow_cx, arrow_base_y + 2.f), ImVec2(arrow_cx, arrow_base_y + 12.f), arrow_col, 1.5f);
            dl->AddTriangleFilled(
                ImVec2(arrow_cx - 4.f, arrow_base_y + 10.f),
                ImVec2(arrow_cx + 4.f, arrow_base_y + 10.f),
                ImVec2(arrow_cx, arrow_base_y + 16.f),
                arrow_col);
            py += 40.f;
        } else {
            py += 24.f;
        }
    }

    ImGui::SetCursorPos(ImVec2(4.f, py + 8.f));
    if (ImGui::SmallButton("Clear Pipeline##dec")) {
        state.decoder_pipeline.clear();
        state.decoder_selected_step = -1;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Execute##dec")) {

        std::string input(state.decoder_input);
        std::vector<uint8_t> data(input.begin(), input.end());

        for (const auto& step : state.decoder_pipeline) {

            std::map<std::string, std::string> params;
            for (const auto& p : step.params)
                params[p.first] = p.second;
            auto result = decoder_pipeline::apply_single(step.transform_name, data, params);
            if (result.success)
                data = std::move(result.data);
            else {
                state.decoder_output = "Error at '" + step.transform_name + "': " + result.error;
                data.clear();
                break;
            }
        }

        if (!data.empty()) {

            bool printable = true;
            for (uint8_t b : data) {
                if (b != '\n' && b != '\r' && b != '\t' && (b < 32 || b > 126)) {
                    printable = false;
                    break;
                }
            }
            if (printable) {
                state.decoder_output.assign(data.begin(), data.end());
            } else {

                state.decoder_output.clear();
                for (size_t off = 0; off < data.size(); off += 16) {
                    char line[128];
                    int pos = snprintf(line, sizeof(line), "%04zx  ", off);
                    for (size_t j = 0; j < 16; j++) {
                        if (off + j < data.size())
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos),
                                "%02x ", data[off + j]);
                        else
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
                    }
                    for (size_t j = 0; j < 16 && off + j < data.size(); j++) {
                        uint8_t c = data[off + j];
                        line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
                    }
                    line[pos] = '\0';
                    state.decoder_output += line;
                    state.decoder_output += '\n';
                }
            }
        }
    }

    ImGui::EndChild();


    float right_x = pipe_w + 2.f;
    float right_w = w - right_x;
    float input_h = h * 0.45f;
    float output_h = h - input_h;


    ImGui::SetCursorPos(ImVec2(right_x, 0.f));
    ImGui::BeginChild("##dec_input", ImVec2(right_w, input_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 ip = ImGui::GetWindowPos();
    dl->AddText(ImVec2(ip.x + 8.f, ip.y + 4.f), txt_col, "Input");

    ImGui::SetCursorPos(ImVec2(4.f, 22.f));
    ImGui::InputTextMultiline("##dec_in", state.decoder_input, sizeof(state.decoder_input),
        ImVec2(right_w - 8.f, input_h - 28.f), ImGuiInputTextFlags_AllowTabInput);
    ImGui::EndChild();


    ImGui::SetCursorPos(ImVec2(right_x, input_h));
    ImGui::BeginChild("##dec_output", ImVec2(right_w, output_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 op = ImGui::GetWindowPos();
    dl->AddText(ImVec2(op.x + 8.f, op.y + 4.f), txt_col, "Output");

    ImGui::SetCursorPos(ImVec2(4.f, 22.f));
    ImGui::InputTextMultiline("##dec_out",
        const_cast<char*>(state.decoder_output.c_str()),
        state.decoder_output.size() + 1,
        ImVec2(right_w - 8.f, output_h - 28.f),
        ImGuiInputTextFlags_ReadOnly);
    ImGui::EndChild();

    ImGui::PopStyleColor();
    ImGui::EndChild();
}


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b) {
    float dt = ImGui::GetIO().DeltaTime;


    float tab_h = 30.f;
    render_tab_bar(g_state, pos_x, pos_y, width, alpha, accent_r, accent_g, accent_b, dt);

    g_state.content_fade = ui_anim::smooth_lerp(g_state.content_fade, 1.f, 14.f, dt);
    float ca = alpha * std::max(g_state.content_fade, 0.3f);

    float content_y = pos_y + tab_h + 4.f;
    float content_h = height - tab_h - 4.f;

    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(35, 38, 52, static_cast<int>(220 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, IM_COL32(48, 52, 70, static_cast<int>(235 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, IM_COL32(58, 62, 82, static_cast<int>(245 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(70, 75, 100, static_cast<int>(160 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarBg, IM_COL32(20, 22, 30, static_cast<int>(120 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrab, IM_COL32(60, 65, 85, static_cast<int>(180 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabHovered, IM_COL32(80, 85, 110, static_cast<int>(200 * alpha)));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabActive, IM_COL32(100, 105, 135, static_cast<int>(220 * alpha)));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.0f);

    switch (g_state.active_tab) {
        case sub_tab_t::connections:
            render_connections(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::capture:
            render_capture(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::intercept:
            render_intercept(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::proxy:
            render_proxy(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::dns:
            render_dns(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::filters:
            render_filters(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::bandwidth:
            render_bandwidth(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::repeater:
            render_repeater(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::keylog:
            render_keylog(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::pcap_export:
            render_pcap_export(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::fuzzer:
            render_fuzzer(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::websocket:
            render_websocket(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::scripting:
            render_scripting(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::decoder:
            render_decoder(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        default:
            break;
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(8);
}

}
