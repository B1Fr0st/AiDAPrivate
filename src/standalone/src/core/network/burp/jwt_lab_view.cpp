#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#ifdef small
#undef small
#endif

#include "jwt_lab_view.hpp"
#include "jwt_lab.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/components.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "../../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace jwt_lab_view {

namespace {

struct view_state_t
{
    char            token_buf[8192]   = {};
    char            secret_buf[1024]  = {};
    char            rsa_pub_buf[8192] = {};
    char            jku_url_buf[512]  = {};
    char            forge_header_buf[2048] = {};
    char            forge_payload_buf[4096] = {};
    char            forge_alg_buf[32] = {};
    char            forge_secret_buf[1024] = {};
    char            forge_rsa_priv_buf[8192] = {};
    char            forge_ecdsa_priv_buf[8192] = {};
    char            wordlist_buf[128] = "common_passwords";

    int             active_inner_tab = 0;
    int             attack_choice = 0;
    int             crack_concurrency = 8;
    int             crack_max_attempts = 1000000;

    std::string     decoded_summary;
    std::string     decoded_header_json;
    std::string     decoded_payload_json;
    std::string     decoded_alg;
    std::string     decoded_kid;
    bool            decoded_valid = false;
    std::string     forge_output;
    std::string     verify_result;
    std::vector<std::string> attack_results;
    uint64_t        active_crack_id = 0;
    bool            initialized = false;
};

view_state_t& s()
{
    static view_state_t st;
    return st;
}

void copy_to_buf(char* dst, size_t cap, const std::string& src)
{
    const size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = s();

    if (!st.initialized) {
        aida::burp::jwt_lab::initialize();
        if (st.forge_alg_buf[0] == '\0') std::strncpy(st.forge_alg_buf, "HS256", sizeof(st.forge_alg_buf) - 1);
        st.initialized = true;
        diag::log_tagged("jwt_v", "render_first_init");
    }

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_jwt_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha), "JWT Lab");

    const float top_y = 36.f;
    const float left_w = width * 0.45f;
    const float gap = 8.f;
    const float right_x = left_w + gap;
    const float right_w = width - right_x - 8.f;

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + top_y));
    ImGui::BeginChild("##jwt_left", ImVec2(left_w, height - top_y - 6.f), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Token");
    ImGui::SetNextItemWidth(left_w - 12.f);
    ImGui::InputTextMultiline("##jwt_token", st.token_buf, sizeof(st.token_buf),
        ImVec2(left_w - 12.f, 96.f), ImGuiInputTextFlags_AllowTabInput);

    if (aida::ui::button("Decode", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        const auto parsed = aida::burp::jwt_lab::decode(st.token_buf);
        st.decoded_valid = parsed.valid_structure;
        st.decoded_alg = parsed.alg;
        st.decoded_kid = parsed.kid;
        st.decoded_header_json = parsed.header.is_object() ? parsed.header.dump(2) : std::string("(invalid)");
        st.decoded_payload_json = parsed.payload.is_object() ? parsed.payload.dump(2) : std::string("(invalid)");
        diag::log_tagged_fmt("burp", "jwt_decode alg=%s kid=%s valid=%d",
            st.decoded_alg.c_str(), st.decoded_kid.c_str(), st.decoded_valid ? 1 : 0);
    }
    ImGui::SameLine();
    if (aida::ui::button("Clear", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
        st.token_buf[0] = '\0';
        st.decoded_header_json.clear();
        st.decoded_payload_json.clear();
        st.decoded_alg.clear();
        st.decoded_kid.clear();
        st.decoded_valid = false;
        diag::log_tagged("jwt_v", "token_cleared");
    }

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
        st.decoded_valid ? "Decoded (valid)" : "Decoded");
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "alg=%s  kid=%s", st.decoded_alg.c_str(), st.decoded_kid.c_str());

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Header");
    ImGui::InputTextMultiline("##jwt_dec_hdr",
        const_cast<char*>(st.decoded_header_json.c_str()),
        st.decoded_header_json.size() + 1,
        ImVec2(left_w - 12.f, 96.f), ImGuiInputTextFlags_ReadOnly);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Payload");
    ImGui::InputTextMultiline("##jwt_dec_pl",
        const_cast<char*>(st.decoded_payload_json.c_str()),
        st.decoded_payload_json.size() + 1,
        ImVec2(left_w - 12.f, 128.f), ImGuiInputTextFlags_ReadOnly);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "HMAC verify");
    ImGui::SetNextItemWidth(left_w - 120.f);
    ImGui::InputText("##jwt_secret", st.secret_buf, sizeof(st.secret_buf));
    ImGui::SameLine();
    if (aida::ui::button("Verify HMAC", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        const bool ok = aida::burp::jwt_lab::verify_hmac(st.token_buf, st.secret_buf);
        st.verify_result = ok ? std::string("HMAC verified") : std::string("HMAC failed");
        diag::log_tagged_fmt("jwt_v", "verify_hmac ok=%d", ok ? 1 : 0);
    }
    if (!st.verify_result.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "%s", st.verify_result.c_str());
    }

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "RSA public PEM (for verify or alg-confusion)");
    ImGui::InputTextMultiline("##jwt_rsa_pub", st.rsa_pub_buf, sizeof(st.rsa_pub_buf),
        ImVec2(left_w - 12.f, 96.f), ImGuiInputTextFlags_AllowTabInput);
    if (aida::ui::button("Verify RSA", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        const bool ok = aida::burp::jwt_lab::verify_rsa(st.token_buf, st.rsa_pub_buf);
        st.verify_result = ok ? std::string("RSA verified") : std::string("RSA failed");
        diag::log_tagged_fmt("jwt_v", "verify_rsa ok=%d", ok ? 1 : 0);
    }
    ImGui::SameLine();
    if (aida::ui::button("Verify ECDSA", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        const bool ok = aida::burp::jwt_lab::verify_ecdsa(st.token_buf, st.rsa_pub_buf);
        st.verify_result = ok ? std::string("ECDSA verified") : std::string("ECDSA failed");
        diag::log_tagged_fmt("jwt_v", "verify_ecdsa ok=%d", ok ? 1 : 0);
    }

    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(pos_x + right_x, pos_y + top_y));
    ImGui::BeginChild("##jwt_right", ImVec2(right_w, height - top_y - 6.f), false, ImGuiWindowFlags_NoBackground);

    const char* tab_labels[] = { "Forge", "Crack", "Attacks" };
    for (int i = 0; i < 3; ++i) {
        if (i > 0) ImGui::SameLine();
        ImGui::PushID(i);
        if (aida::ui::button(tab_labels[i],
            st.active_inner_tab == i ? aida::ui::button_kind_t::primary : aida::ui::button_kind_t::ghost,
            aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("jwt_v", "tab_switch tab=%s", tab_labels[i]);
            st.active_inner_tab = i;
        }
        ImGui::PopID();
    }

    ImGui::Spacing();
    if (st.active_inner_tab == 0) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Header JSON");
        ImGui::InputTextMultiline("##jwt_forge_hdr", st.forge_header_buf, sizeof(st.forge_header_buf),
            ImVec2(right_w - 4.f, 96.f), ImGuiInputTextFlags_AllowTabInput);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Payload JSON");
        ImGui::InputTextMultiline("##jwt_forge_pl", st.forge_payload_buf, sizeof(st.forge_payload_buf),
            ImVec2(right_w - 4.f, 128.f), ImGuiInputTextFlags_AllowTabInput);
        ImGui::SetNextItemWidth(140.f);
        ImGui::InputText("alg##jwt_forge_alg", st.forge_alg_buf, sizeof(st.forge_alg_buf));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Supported: none, HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512");
        ImGui::InputText("HMAC secret##jwt_forge_secret", st.forge_secret_buf, sizeof(st.forge_secret_buf));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "RSA private PEM");
        ImGui::InputTextMultiline("##jwt_forge_rsa_priv", st.forge_rsa_priv_buf, sizeof(st.forge_rsa_priv_buf),
            ImVec2(right_w - 4.f, 80.f), ImGuiInputTextFlags_AllowTabInput);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "ECDSA private PEM");
        ImGui::InputTextMultiline("##jwt_forge_ec_priv", st.forge_ecdsa_priv_buf, sizeof(st.forge_ecdsa_priv_buf),
            ImVec2(right_w - 4.f, 80.f), ImGuiInputTextFlags_AllowTabInput);

        if (aida::ui::button("Forge", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            aida::burp::jwt_lab::jwt_forge_input_t in;
            try {
                in.header = nlohmann::json::parse(st.forge_header_buf[0] == '\0' ? std::string("{}") : std::string(st.forge_header_buf), nullptr, false);
            } catch (...) { in.header = nlohmann::json::object(); }
            try {
                in.payload = nlohmann::json::parse(st.forge_payload_buf[0] == '\0' ? std::string("{}") : std::string(st.forge_payload_buf), nullptr, false);
            } catch (...) { in.payload = nlohmann::json::object(); }
            if (!in.header.is_object()) in.header = nlohmann::json::object();
            if (!in.payload.is_object()) in.payload = nlohmann::json::object();
            in.alg = st.forge_alg_buf;
            in.hmac_secret = st.forge_secret_buf;
            in.rsa_private_pem = st.forge_rsa_priv_buf;
            in.ecdsa_private_pem = st.forge_ecdsa_priv_buf;
            const std::string out_token = aida::burp::jwt_lab::forge(in);
            st.forge_output = out_token.empty() ? std::string("(error: ") + aida::burp::jwt_lab::last_error() + ")" : out_token;
            diag::log_tagged_fmt("burp", "jwt_forge alg=%s success=%d", in.alg.c_str(), out_token.empty() ? 0 : 1);
        }
        ImGui::SameLine();
        if (aida::ui::button("Copy to token", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            if (!st.forge_output.empty() && st.forge_output[0] != '(') {
                copy_to_buf(st.token_buf, sizeof(st.token_buf), st.forge_output);
                diag::log_tagged("jwt_v", "forged_token_copied_to_input");
            }
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Forged token");
        ImGui::InputTextMultiline("##jwt_forge_out",
            const_cast<char*>(st.forge_output.c_str()), st.forge_output.size() + 1,
            ImVec2(right_w - 4.f, 96.f), ImGuiInputTextFlags_ReadOnly);
    }
    else if (st.active_inner_tab == 1) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Wordlist id");
        ImGui::SetNextItemWidth(280.f);
        ImGui::InputText("##jwt_wordlist", st.wordlist_buf, sizeof(st.wordlist_buf));
        ImGui::SetNextItemWidth(160.f);
        ImGui::InputInt("Concurrency##jwt_conc", &st.crack_concurrency);
        if (st.crack_concurrency < 1) st.crack_concurrency = 1;
        if (st.crack_concurrency > 32) st.crack_concurrency = 32;
        ImGui::SetNextItemWidth(160.f);
        ImGui::InputInt("Max attempts##jwt_max", &st.crack_max_attempts);
        if (st.crack_max_attempts < 1) st.crack_max_attempts = 1;

        if (aida::ui::button("Start crack", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            aida::burp::jwt_lab::crack_config_t cfg;
            cfg.token = st.token_buf;
            cfg.wordlist_id = st.wordlist_buf;
            cfg.concurrency = static_cast<size_t>(st.crack_concurrency);
            cfg.max_attempts = static_cast<size_t>(st.crack_max_attempts);
            st.active_crack_id = aida::burp::jwt_lab::start_crack(cfg);
            diag::log_tagged_fmt("burp", "jwt_crack_button id=%llu", static_cast<unsigned long long>(st.active_crack_id));
        }
        ImGui::SameLine();
        if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            if (st.active_crack_id != 0) {
                diag::log_tagged_fmt("jwt_v", "crack_stop id=%llu", static_cast<unsigned long long>(st.active_crack_id));
                aida::burp::jwt_lab::crack_stop(st.active_crack_id);
            }
        }

        const auto status = aida::burp::jwt_lab::crack_status(st.active_crack_id);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "id=%llu  attempts=%zu  running=%s",
            static_cast<unsigned long long>(status.id), status.attempts, status.running ? "yes" : "no");
        if (!status.secret_found.empty()) {
            static std::string s_last_found;
            if (status.secret_found != s_last_found) {
                s_last_found = status.secret_found;
                diag::log_tagged_fmt("jwt_v", "crack_secret_found secret='%s' id=%llu",
                    status.secret_found.c_str(), static_cast<unsigned long long>(st.active_crack_id));
            }
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.success, alpha)),
                "Secret: %s", status.secret_found.c_str());
        }
    }
    else if (st.active_inner_tab == 2) {
        const char* atk_labels[] = { "alg=none", "alg confusion", "kid traversal", "jku injection", "signature strip" };
        ImGui::SetNextItemWidth(240.f);
        ImGui::Combo("Attack##jwt_attack", &st.attack_choice, atk_labels, 5);
        ImGui::SetNextItemWidth(right_w - 12.f);
        ImGui::InputText("Attacker URL (jku)##jwt_jku", st.jku_url_buf, sizeof(st.jku_url_buf));

        if (aida::ui::button("Run attack", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            st.attack_results.clear();
            const std::string token(st.token_buf);
            switch (st.attack_choice) {
                case 0: st.attack_results = aida::burp::jwt_lab::attack_alg_none(token); break;
                case 1: st.attack_results = aida::burp::jwt_lab::attack_alg_confusion(token, std::string(st.rsa_pub_buf)); break;
                case 2: st.attack_results = aida::burp::jwt_lab::attack_kid_traversal(token); break;
                case 3: st.attack_results = aida::burp::jwt_lab::attack_jku_injection(token, std::string(st.jku_url_buf)); break;
                case 4: st.attack_results = aida::burp::jwt_lab::attack_signature_strip(token); break;
                default: break;
            }
            diag::log_tagged_fmt("burp", "jwt_attack choice=%d candidates=%zu", st.attack_choice, st.attack_results.size());
        }
        ImGui::SameLine();
        if (aida::ui::button("Pack: All", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            diag::log_tagged("jwt_v", "attack_pack_all");
            st.attack_results.clear();
            const std::string token(st.token_buf);
            auto add_set = [](std::vector<std::string>& dst, const std::vector<std::string>& src) {
                for (const auto& v : src) dst.push_back(v);
            };
            add_set(st.attack_results, aida::burp::jwt_lab::attack_alg_none(token));
            add_set(st.attack_results, aida::burp::jwt_lab::attack_alg_confusion(token, std::string(st.rsa_pub_buf)));
            add_set(st.attack_results, aida::burp::jwt_lab::attack_kid_traversal(token));
            add_set(st.attack_results, aida::burp::jwt_lab::attack_jku_injection(token, std::string(st.jku_url_buf)));
            add_set(st.attack_results, aida::burp::jwt_lab::attack_signature_strip(token));
        }

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "Candidates: %zu", st.attack_results.size());
        ImGui::BeginChild("##jwt_attack_results", ImVec2(right_w - 4.f, height - top_y - 240.f), false);
        for (size_t i = 0; i < st.attack_results.size(); ++i) {
            ImGui::PushID(static_cast<int>(i));
            if (aida::ui::button("Use", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
                copy_to_buf(st.token_buf, sizeof(st.token_buf), st.attack_results[i]);
                diag::log_tagged_fmt("jwt_v", "attack_candidate_used idx=%zu", i);
            }
            ImGui::SameLine();
            std::string preview = st.attack_results[i];
            if (preview.size() > 160) preview = preview.substr(0, 160) + "...";
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                "%s", preview.c_str());
            ImGui::PopID();
        }
        ImGui::EndChild();
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
