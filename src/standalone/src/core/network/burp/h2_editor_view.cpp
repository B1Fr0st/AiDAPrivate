#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#endif

#ifdef small
#undef small
#endif

#include "h2_editor_view.hpp"
#include "../network_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_routed.hpp"
#else
#include "h2_editor.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_executor.hpp"
#else
#include "../executor_status.hpp"
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
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <utility>

namespace aida {
namespace burp {
namespace h2_editor_view {

namespace {

struct ui_state_t
{
    std::mutex                                       mtx;
    char                                             host[256] = "example.com";
    int                                              port = 443;
    char                                             method[16] = "GET";
    char                                             path[1024] = "/";
    char                                             scheme[16] = "https";
    char                                             authority[256] = "";
    char                                             header_name_buf[128] = "";
    char                                             header_value_buf[512] = "";
    std::vector<std::pair<std::string, std::string>> headers;
    char                                             body[16384] = "";
    int                                              timeout_ms = 15000;
    bool                                             use_raw = false;
    char                                             raw_frames_hex[16384] = "";
    bool                                             end_stream = true;
    bool                                             end_headers = true;
    bool                                             padded = false;
    bool                                             priority = false;

    h2_editor::response_t                            last_response;
    bool                                             has_response = false;
    std::atomic<bool>                                accepting{true};
    std::atomic<bool>                                in_flight{false};
    std::atomic<uint64_t>                            lifetime_generation{1};
    std::mutex                                       resp_mtx;
    uint64_t                                         next_exchange_id = 1;
    uint64_t                                         retained_exchange_id = 0;
    uint64_t                                         retained_generation = 0;
    std::vector<uint8_t>                             retained_request;
    std::vector<uint8_t>                             retained_response;
    std::string                                      retained_host;
    uint16_t                                         retained_port = 0;
    bool                                             retained_tls = true;
    bool                                             retained_raw_protocol = false;
    uint64_t                                         retained_request_hash = 0;
    uint64_t                                         retained_response_hash = 0;
    size_t                                           retained_request_size = 0;
    size_t                                           retained_response_size = 0;
};

static std::shared_ptr<ui_state_t> ui()
{
    static const auto state = std::make_shared<ui_state_t>();
    return state;
}

static bool hex_char(char c, uint8_t& out)
{
    if (c >= '0' && c <= '9') { out = static_cast<uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<uint8_t>(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<uint8_t>(c - 'A' + 10); return true; }
    return false;
}

static std::vector<uint8_t> hex_decode(const std::string& s)
{
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    uint8_t high = 0;
    bool have_high = false;
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        uint8_t v = 0;
        if (!hex_char(c, v)) return {};
        if (!have_high) { high = v; have_high = true; }
        else { out.push_back(static_cast<uint8_t>((high << 4) | v)); have_high = false; }
    }
    return out;
}

static std::string hex_encode(const std::vector<uint8_t>& v, size_t max_bytes)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    size_t n = v.size() < max_bytes ? v.size() : max_bytes;
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(hex[(v[i] >> 4) & 0xF]);
        out.push_back(hex[v[i] & 0xF]);
        if ((i & 0xF) == 0xF) out.push_back('\n');
        else out.push_back(' ');
    }
    if (v.size() > max_bytes) out += "... (truncated)";
    return out;
}

static uint64_t artifact_hash(const std::vector<uint8_t>& bytes)
{
    uint64_t hash = 14695981039346656037ULL;
    for (uint8_t value : bytes) { hash ^= value; hash *= 1099511628211ULL; }
    hash ^= static_cast<uint64_t>(bytes.size());
    hash *= 1099511628211ULL;
    return hash == 0 ? 1 : hash;
}

static std::vector<uint8_t> request_bytes(const h2_editor::request_t& request)
{
    if (request.use_raw_frames) {
        std::vector<uint8_t> bytes;
        for (const auto& frame : request.raw_frames) {
            auto encoded = h2_editor::encode_frame(frame);
            bytes.insert(bytes.end(), encoded.begin(), encoded.end());
        }
        return bytes;
    }
    std::string raw = request.pseudo.method + " " + request.pseudo.path + " HTTP/2\r\n";
    raw += "Host: " + request.pseudo.authority + "\r\n";
    raw += ":scheme: " + request.pseudo.scheme + "\r\n";
    for (const auto& header : request.headers) raw += header.first + ": " + header.second + "\r\n";
    raw += "\r\n";
    raw.append(reinterpret_cast<const char*>(request.body.data()), request.body.size());
    return std::vector<uint8_t>(raw.begin(), raw.end());
}

static std::vector<uint8_t> response_bytes(const h2_editor::response_t& response)
{
    std::string raw = "HTTP/2 " + std::to_string(response.status_code) + "\r\n";
    for (const auto& header : response.headers) raw += header.first + ": " + header.second + "\r\n";
    raw += "\r\n";
    raw.append(reinterpret_cast<const char*>(response.body.data()), response.body.size());
    return std::vector<uint8_t>(raw.begin(), raw.end());
}

static network_view::artifact_identity_t artifact_identity(const ui_state_t& state, bool response)
{
    network_view::artifact_identity_t identity;
    const uint64_t hash = response ? state.retained_response_hash : state.retained_request_hash;
    const size_t size = response ? state.retained_response_size : state.retained_request_size;
    if (hash == 0 || size == 0) return identity;
    identity.kind = response ? network_view::artifact_kind_t::http2_response
                             : network_view::artifact_kind_t::http2_request;
    identity.id = "network.h2." + std::to_string(state.retained_exchange_id) +
        (response ? ".response" : ".request");
    identity.parent_id = "network.h2." + std::to_string(state.retained_exchange_id);
    identity.source_view_id = "view.network.h2_editor";
    identity.source_id = state.retained_exchange_id;
    identity.timestamp = state.retained_generation;
    identity.revision = state.retained_generation;
    identity.content_size = size;
    identity.content_hash = hash;
    identity.label = response ? "HTTP/2 response" : "HTTP/2 request";
    identity.target_host = state.retained_host;
    identity.target_port = state.retained_port;
    identity.use_tls = state.retained_tls;
    identity.raw_protocol = !response && state.retained_raw_protocol;
    return identity;
}

}

bool resolve_retained_artifact(uint64_t exchange_id, uint64_t generation, bool response,
                               std::vector<uint8_t>& bytes, std::string& unavailable_reason)
{
    const auto state = ui();
    std::lock_guard<std::mutex> lk(state->resp_mtx);
    if (!state->accepting.load(std::memory_order_acquire) ||
        state->retained_exchange_id != exchange_id || state->retained_generation != generation) {
        unavailable_reason = "The HTTP/2 editor now owns a newer exchange; reopen actions on the current request.";
        return false;
    }
    bytes = response ? state->retained_response : state->retained_request;
    if (bytes.empty()) {
        unavailable_reason = response ? "The HTTP/2 exchange has no retained response."
                                      : "The HTTP/2 exchange has no retained request.";
        return false;
    }
    unavailable_reason.clear();
    return true;
}

void initialize()
{
    const auto state = ui();
    state->lifetime_generation.fetch_add(1, std::memory_order_acq_rel);
    state->accepting.store(true, std::memory_order_release);
    state->in_flight.store(false, std::memory_order_release);
    ::diag::log_tagged("h2_v", "initialize");
}

void shutdown()
{
    const auto state = ui();
    state->accepting.store(false, std::memory_order_release);
    state->lifetime_generation.fetch_add(1, std::memory_order_acq_rel);
    state->in_flight.store(false, std::memory_order_release);
    ::diag::log_tagged("h2_v", "shutdown");
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    const auto state = ui();
    auto& st = *state;

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_h2_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "HTTP/2 Frame Editor");
    ImGui::Spacing();

    float left_w = width * 0.55f;
    if (left_w < 360.f) left_w = 360.f;
    float right_w = width - left_w - 8.f;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, aida::ui::with_alpha(th.panel_bg, 0.55f * alpha));
    ImGui::BeginChild("##burp_h2_edit", ImVec2(left_w, height - 36.f), true, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Target");
    ImGui::SetNextItemWidth(220.f);
    ImGui::InputText("Host##h2_host", st.host, sizeof(st.host));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputInt("Port##h2_port", &st.port);
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputInt("Timeout ms##h2_to", &st.timeout_ms);

    ImGui::Separator();
    ImGui::Checkbox("Raw frames mode##h2_raw", &st.use_raw);

    if (!st.use_raw) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Pseudo-headers");
        ImGui::SetNextItemWidth(80.f);
        ImGui::InputText(":method##h2_m", st.method, sizeof(st.method));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80.f);
        ImGui::InputText(":scheme##h2_s", st.scheme, sizeof(st.scheme));
        ImGui::SetNextItemWidth(left_w - 60.f);
        ImGui::InputText(":path##h2_p", st.path, sizeof(st.path));
        ImGui::SetNextItemWidth(left_w - 100.f);
        ImGui::InputText(":authority##h2_a", st.authority, sizeof(st.authority));

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Stream flags");
        ImGui::Checkbox("END_STREAM##h2_es", &st.end_stream);
        ImGui::SameLine();
        ImGui::Checkbox("END_HEADERS##h2_eh", &st.end_headers);
        ImGui::SameLine();
        ImGui::Checkbox("PADDED##h2_pad", &st.padded);
        ImGui::SameLine();
        ImGui::Checkbox("PRIORITY##h2_pri", &st.priority);

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Headers");
        ImGui::SetNextItemWidth(160.f);
        ImGui::InputText("##h2_hn", st.header_name_buf, sizeof(st.header_name_buf));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(left_w - 280.f);
        ImGui::InputText("##h2_hv", st.header_value_buf, sizeof(st.header_value_buf));
        ImGui::SameLine();
        if (aida::ui::button("+", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            std::string n = st.header_name_buf;
            std::string v = st.header_value_buf;
            if (!n.empty()) {
                ::diag::log_tagged_fmt("h2_v", "header_added name='%s' value='%s'", n.c_str(), v.c_str());
                std::lock_guard<std::mutex> lk(st.mtx);
                st.headers.push_back({ std::move(n), std::move(v) });
                st.header_name_buf[0] = '\0';
                st.header_value_buf[0] = '\0';
            }
        }
        {
            std::lock_guard<std::mutex> lk(st.mtx);
            for (size_t i = 0; i < st.headers.size(); ++i) {
                ImGui::PushID(static_cast<int>(i));
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                   "%s:", st.headers[i].first.c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                                   "%s", st.headers[i].second.c_str());
                ImGui::SameLine();
                if (aida::ui::button("X", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
                    ::diag::log_tagged_fmt("h2_v", "header_removed idx=%zu name='%s'", i, st.headers[i].first.c_str());
                    st.headers.erase(st.headers.begin() + static_cast<ptrdiff_t>(i));
                    ImGui::PopID();
                    break;
                }
                ImGui::PopID();
            }
        }

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Body");
        ImGui::InputTextMultiline("##h2_body", st.body, sizeof(st.body),
                                  ImVec2(left_w - 24.f, 100.f));
    } else {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Hex frames (length(3) type(1) flags(1) Rbit+stream(4) payload):");
        ImGui::InputTextMultiline("##h2_raw_hex", st.raw_frames_hex, sizeof(st.raw_frames_hex),
                                  ImVec2(left_w - 24.f, 280.f));
    }

    ImGui::Separator();
    bool in_flight = st.in_flight.load();
    if (!in_flight) {
        if (aida::ui::button("Send", aida::ui::button_kind_t::primary, aida::ui::size_t_::md)) {
            h2_editor::request_t req;
            req.host = st.host;
            req.port = static_cast<uint16_t>(std::max(1, std::min(65535, st.port)));
            req.timeout_ms = std::max(500, st.timeout_ms);
            if (st.use_raw) {
                std::vector<uint8_t> bytes = hex_decode(st.raw_frames_hex);
                req.use_raw_frames = true;
                std::vector<h2_editor::frame_t> frames;
                h2_editor::decode_frames(bytes, frames);
                req.raw_frames = std::move(frames);
            } else {
                req.pseudo.method = st.method;
                req.pseudo.path = st.path;
                req.pseudo.scheme = st.scheme;
                req.pseudo.authority = st.authority[0] ? std::string(st.authority) : std::string(st.host);
                {
                    std::lock_guard<std::mutex> lk(st.mtx);
                    req.headers = st.headers;
                }
                req.body.assign(st.body, st.body + strlen(st.body));
                uint32_t flg = 0;
                if (st.end_stream)  flg |= static_cast<uint32_t>(h2_editor::send_flags_t::end_stream);
                if (st.end_headers) flg |= static_cast<uint32_t>(h2_editor::send_flags_t::end_headers);
                if (st.padded)      flg |= static_cast<uint32_t>(h2_editor::send_flags_t::padded);
                if (st.priority)    flg |= static_cast<uint32_t>(h2_editor::send_flags_t::priority);
                req.flags = flg;
            }

            uint64_t exchange_id = 0;
            uint64_t lifetime_generation = 0;
            {
                std::lock_guard<std::mutex> lk(st.resp_mtx);
                exchange_id = st.next_exchange_id++;
                lifetime_generation = st.lifetime_generation.load(std::memory_order_acquire);
                st.retained_exchange_id = exchange_id;
                st.retained_generation = exchange_id;
                st.retained_request = request_bytes(req);
                st.retained_response.clear();
                st.retained_request_size = st.retained_request.size();
                st.retained_request_hash = artifact_hash(st.retained_request);
                st.retained_response_size = 0;
                st.retained_response_hash = 0;
                st.retained_host = req.host;
                st.retained_port = req.port;
                st.retained_tls = req.pseudo.scheme != "http";
                st.retained_raw_protocol = req.use_raw_frames;
                st.has_response = false;
            }
            st.in_flight.store(true);
            try {
                const ULONGLONG post_ms = GetTickCount64();
                const bool posted = [&]() {
                    ::aida::infra::executor::submission_t sub;
                    sub.owner_subsystem = "burp.h2_view";
                    sub.label = "h2.send_request";
                    sub.thread_class = "bounded_task";
                    sub.domain = aida::infra::executor::domain_t::external_tool;
                    sub.priority = 3;
                    sub.body = [state, req, post_ms, exchange_id, lifetime_generation]() {
                    const DWORD tid = GetCurrentThreadId();
                    const ULONGLONG start_ms = GetTickCount64();
                    ::diag::log_tagged_fmt("h2_v",
                        "send_worker_enter host=%s port=%u raw=%d queued_ms=%llu tid=%lu",
                        req.host.c_str(),
                        static_cast<unsigned>(req.port),
                        req.use_raw_frames ? 1 : 0,
                        static_cast<unsigned long long>(start_ms >= post_ms ? start_ms - post_ms : 0),
                        static_cast<unsigned long>(tid));
                    try {
                        h2_editor::response_t r = h2_editor::send(req);
                        const int status_code = r.status_code;
                        const bool ok = r.ok;
                        const uint64_t latency_ms = r.latency_ms;
                        {
                            std::lock_guard<std::mutex> lk(state->resp_mtx);
                            if (state->accepting.load(std::memory_order_acquire) &&
                                state->lifetime_generation.load(std::memory_order_acquire) == lifetime_generation) {
                                state->last_response = r;
                                if (state->retained_exchange_id == exchange_id) {
                                    state->retained_response = response_bytes(r);
                                    state->retained_response_size = state->retained_response.size();
                                    state->retained_response_hash = artifact_hash(state->retained_response);
                                    state->has_response = true;
                                }
                            }
                        }
                        ::diag::log_tagged_fmt("h2_v",
                            "send_worker_exit status=%d ok=%d latency=%llums elapsed_ms=%llu tid=%lu",
                            status_code,
                            ok ? 1 : 0,
                            static_cast<unsigned long long>(latency_ms),
                            static_cast<unsigned long long>(GetTickCount64() - start_ms),
                            static_cast<unsigned long>(tid));
                    } catch (const std::exception& ex) {
                        ::diag::log_tagged_fmt("h2_v",
                            "send_worker_exception elapsed_ms=%llu tid=%lu err=%s",
                            static_cast<unsigned long long>(GetTickCount64() - start_ms),
                            static_cast<unsigned long>(tid),
                            ex.what());
                    } catch (...) {
                        ::diag::log_tagged_fmt("h2_v",
                            "send_worker_exception elapsed_ms=%llu tid=%lu err=unknown",
                            static_cast<unsigned long long>(GetTickCount64() - start_ms),
                            static_cast<unsigned long>(tid));
                    }
                    if (state->accepting.load(std::memory_order_acquire) &&
                        state->lifetime_generation.load(std::memory_order_acquire) == lifetime_generation)
                        state->in_flight.store(false, std::memory_order_release);
                };
                    return ::aida::infra::executor::submit(std::move(sub)).submitted;
                }();
                if (!posted) {
                    const auto qs = aida::network::executor_status::work_stats();
                    st.in_flight.store(false);
                    ::diag::log_tagged_fmt("h2_v",
                        "send_worker_post_failed host=%s port=%u raw=%d executor_alive=%d executor_shutdown=%d executor_pending=%llu executor_active=%u executor_posted=%llu executor_rejected=%llu",
                        req.host.c_str(),
                        static_cast<unsigned>(req.port),
                        req.use_raw_frames ? 1 : 0,
                        qs.alive ? 1 : 0,
                        qs.shutting_down ? 1 : 0,
                        static_cast<unsigned long long>(qs.pending),
                        qs.active,
                        static_cast<unsigned long long>(qs.posted),
                        static_cast<unsigned long long>(qs.rejected));
                }
            } catch (const std::exception& ex) {
                st.in_flight.store(false);
                ::diag::log_tagged_fmt("h2_v", "send_worker_post_exception err=%s", ex.what());
            } catch (...) {
                st.in_flight.store(false);
                ::diag::log_tagged("h2_v", "send_worker_post_exception");
            }
            ::diag::log_tagged_fmt("h2_v", "send host=%s port=%d method=%s path=%s raw=%d",
                                 req.host.c_str(), req.port,
                                 req.pseudo.method.c_str(), req.pseudo.path.c_str(),
                                 req.use_raw_frames ? 1 : 0);
        }
    } else {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                           "Sending...");
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0.f, 8.f);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, aida::ui::with_alpha(th.panel_bg, 0.45f * alpha));
    ImGui::BeginChild("##burp_h2_resp", ImVec2(right_w, height - 36.f), true, ImGuiWindowFlags_NoBackground);

    h2_editor::response_t r_copy;
    bool have;
    size_t response_body_size = 0;
    network_view::artifact_identity_t request_identity;
    network_view::artifact_identity_t response_identity;
    {
        std::lock_guard<std::mutex> lk(st.resp_mtx);
        r_copy.ok = st.last_response.ok;
        r_copy.status_code = st.last_response.status_code;
        r_copy.headers = st.last_response.headers;
        r_copy.latency_ms = st.last_response.latency_ms;
        r_copy.error_msg = st.last_response.error_msg;
        response_body_size = st.last_response.body.size();
        const size_t body_preview_size = (std::min)(st.last_response.body.size(), static_cast<size_t>(4096));
        r_copy.body.assign(st.last_response.body.begin(),
            st.last_response.body.begin() + static_cast<ptrdiff_t>(body_preview_size));
        const size_t wire_preview_size = (std::min)(st.last_response.raw_wire_in.size(), static_cast<size_t>(1024));
        r_copy.raw_wire_in.assign(st.last_response.raw_wire_in.begin(),
            st.last_response.raw_wire_in.begin() + static_cast<ptrdiff_t>(wire_preview_size));
        have = st.has_response;
        request_identity = artifact_identity(st, false);
        response_identity = artifact_identity(st, true);
    }
    if (request_identity.valid()) {
        if (aida::ui::button("Exchange actions", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
            network_view::open_exchange_context(request_identity, response_identity,
                network_view::exchange_context_origin_t::pointer);
        const bool menu_key_context = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
            ImGui::IsKeyPressed(ImGuiKey_Menu, false);
        const bool shift_f10_context = !menu_key_context &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
            ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
        const bool keyboard_context = menu_key_context || shift_f10_context;
        if (ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows) && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
            network_view::open_exchange_context(response_identity.valid() ? response_identity : request_identity,
                response_identity.valid() ? request_identity : network_view::artifact_identity_t{},
                network_view::exchange_context_origin_t::pointer);
        if (keyboard_context)
            network_view::open_exchange_context(response_identity.valid() ? response_identity : request_identity,
                response_identity.valid() ? request_identity : network_view::artifact_identity_t{},
                menu_key_context
                    ? network_view::exchange_context_origin_t::menu_key
                    : network_view::exchange_context_origin_t::shift_f10);
        ImGui::Separator();
    }
    if (!have) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "(no response yet)");
    } else {
        char hdr[256];
        snprintf(hdr, sizeof(hdr), "Status: %d  Latency: %llums  %s",
                 r_copy.status_code,
                 static_cast<unsigned long long>(r_copy.latency_ms),
                 r_copy.ok ? "OK" : "ERROR");
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                           "%s", hdr);
        if (!r_copy.error_msg.empty()) {
            ::diag::log_tagged_fmt("h2_v", "response_error msg='%s'", r_copy.error_msg.c_str());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.error, alpha)),
                               "%s", r_copy.error_msg.c_str());
        }
        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Headers");
        for (auto& h : r_copy.headers) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s: %s", h.first.c_str(), h.second.c_str());
        }
        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Body (%zu bytes)", response_body_size);
        std::string preview;
        size_t cap = r_copy.body.size() < 4096 ? r_copy.body.size() : 4096;
        preview.reserve(cap);
        for (size_t i = 0; i < cap; ++i) {
            uint8_t b = r_copy.body[i];
            if (b == '\r' || b == '\n' || b == '\t' || (b >= 0x20 && b < 0x7f)) preview.push_back(static_cast<char>(b));
            else preview.push_back('.');
        }
        ImGui::TextWrapped("%.*s", static_cast<int>(preview.size()), preview.c_str());

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Raw wire (hex)");
        std::string hex_in = hex_encode(r_copy.raw_wire_in, 1024);
        ImGui::TextWrapped("%.*s", static_cast<int>(hex_in.size()), hex_in.c_str());
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::EndChild();
}

}
}
}
