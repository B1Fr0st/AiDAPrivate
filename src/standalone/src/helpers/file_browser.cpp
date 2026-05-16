
#include <windows.h>
#include <shlobj.h>

#include "globals.h"
#include "zydis_disasm.hpp"
#include "function_index.hpp"
#include "xref_index.hpp"
#include "standalone_license.hpp"
#include "hex_view.hpp"
#include "initial_analysis.hpp"
#include "loading_binary_overlay.hpp"
#include "analysis_session.hpp"
#include "standalone_settings.hpp"
#include "diag_log.hpp"
#include "imgui/imgui.h"
#include "components.hpp"
#include "theme.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <algorithm>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

extern HWND g_hwnd;
extern DisasmState g_disasm;


void file_browser::refresh(const std::string& dir)
{
    std::string root = dir;


    if (root.empty() && current_dir.empty()) {
        char buf[MAX_PATH] = {};
        GetCurrentDirectoryA(MAX_PATH, buf);
        root = buf;
    }

    if (!root.empty())
        current_dir = root;

    if (current_dir.empty()) return;


    strncpy_s(path_buf, sizeof(path_buf), current_dir.c_str(), _TRUNCATE);


    std::vector<std::string> expanded_paths;
    for (auto& e : entries)
        if (e.is_dir && e.expanded)
            expanded_paths.push_back(e.full_path);

    entries.clear();
    needs_refresh = false;


    struct local {
        static void scan(const std::string& path, int depth,
                         const std::vector<std::string>& expanded_set,
                         std::vector<FileBrowserEntry>& out)
        {
            std::error_code ec;
            std::vector<FileBrowserEntry> dirs, files;

            for (auto& it : fs::directory_iterator(path, ec)) {
                if (ec) break;
                FileBrowserEntry e;
                e.full_path = it.path().string();
                e.name      = it.path().filename().string();
                e.depth     = depth;


                if (!e.name.empty() && e.name[0] == '.') continue;

                if (it.is_directory(ec) && !ec) {
                    e.is_dir = true;

                    for (auto& ep : expanded_set)
                        if (ep == e.full_path) { e.expanded = true; break; }
                    dirs.push_back(std::move(e));
                } else if (it.is_regular_file(ec) && !ec) {
                    e.is_dir = false;
                    files.push_back(std::move(e));
                }
            }


            std::sort(dirs.begin(), dirs.end(),
                [](const FileBrowserEntry& a, const FileBrowserEntry& b)
                { return _stricmp(a.name.c_str(), b.name.c_str()) < 0; });
            std::sort(files.begin(), files.end(),
                [](const FileBrowserEntry& a, const FileBrowserEntry& b)
                { return _stricmp(a.name.c_str(), b.name.c_str()) < 0; });

            for (auto& d : dirs) {
                bool exp = d.expanded;
                out.push_back(std::move(d));
                if (exp)
                    scan(out.back().full_path, depth + 1, expanded_set, out);
            }
            for (auto& f : files)
                out.push_back(std::move(f));
        }
    };

    local::scan(current_dir, 0, expanded_paths, entries);
}


void file_browser::toggle_dir(int idx)
{
    if (idx < 0 || idx >= (int)entries.size()) return;
    auto& ent = entries[idx];
    if (!ent.is_dir) return;

    ent.expanded = !ent.expanded;
    needs_refresh = true;
}


void file_browser::open_file(int idx)
{
    if (idx < 0 || idx >= (int)entries.size()) return;
    auto& ent = entries[idx];
    if (ent.is_dir) return;


    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_file_browser_open);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_file_browser_open, gt) < 0.5)
            return;
    }

    std::string ext;
    auto dot = ent.name.rfind('.');
    if (dot != std::string::npos)
        ext = ent.name.substr(dot);
    for (auto& c : ext) c = (char)tolower((unsigned char)c);


    static const char* text_exts[] = {
        ".cpp", ".c", ".h", ".hpp", ".hxx", ".cxx", ".cc",
        ".py", ".js", ".ts", ".json", ".xml", ".yaml", ".yml",
        ".md", ".txt", ".log", ".cfg", ".ini", ".toml",
        ".java", ".cs", ".rs", ".go", ".rb", ".php",
        ".html", ".css", ".scss", ".lua", ".sh", ".bat", ".ps1",
        ".cmake", ".asm", ".s", ".inc", ".def", ".rules",
    };

    bool is_text = false;
    for (auto& te : text_exts) {
        if (ext == te) { is_text = true; break; }
    }

    if (is_text) {

        std::ifstream ifs(ent.full_path, std::ios::binary);
        if (ifs.is_open()) {
            std::ostringstream ss;
            ss << ifs.rdbuf();
            file_tabs::open_or_focus(ent.full_path, ent.name, ss.str());

            g_disasm.file = DisasmFile{};
            globals::ui::active_center_view = center_view_t::code_editor;
        }
    } else {

        static const char* archive_exts[] = {
            ".rar", ".zip", ".7z", ".tar", ".gz", ".bz2", ".xz",
            ".cab", ".iso", ".img",
        };
        bool is_archive = false;
        for (auto& ae : archive_exts) {
            if (ext == ae) { is_archive = true; break; }
        }

        if (is_archive) {
            code_editor::active = false;
            code_editor::buffer.clear();
            code_editor::filename.clear();
            code_editor::filepath.clear();
            g_disasm.file = DisasmFile{};
            hex_view::load_from_file(ent.full_path, 0, 0);
            globals::ui::active_center_view = center_view_t::hex_view;
        } else {
            uint64_t file_size_bytes = 0;
            {
                std::error_code fec;
                auto sz = fs::file_size(ent.full_path, fec);
                if (!fec) file_size_bytes = static_cast<uint64_t>(sz);
            }
            diag::log_tagged_fmt("file_browser",
                "click_binary path=%s ext=%s size=%llu",
                ent.full_path.c_str(),
                ext.c_str(),
                static_cast<unsigned long long>(file_size_bytes));

            size_t existing_idx = static_cast<size_t>(-1);
            bool found = analysis_session::find_session_by_path(ent.full_path, &existing_idx);
            diag::log_tagged_fmt("file_browser",
                "lookup_session found=%d idx=%llu",
                found ? 1 : 0,
                static_cast<unsigned long long>(existing_idx));

            if (found) {
                diag::log_tagged_fmt("file_browser", "dispatch path=existing_session");
                if (analysis_session::switch_session(existing_idx)) {
                    globals::ui::active_center_view = center_view_t::disassembly;
                    diag::log_tagged_fmt("file_browser",
                        "sidebar_switch_existing idx=%llu path=%s",
                        static_cast<unsigned long long>(existing_idx),
                        ent.full_path.c_str());
                    file_browser::record_recent_workspace(ent.full_path);
                } else {
                    diag::log_tagged_fmt("file_browser",
                        "sidebar_switch_existing_failed idx=%llu err=%s",
                        static_cast<unsigned long long>(existing_idx),
                        analysis_session::last_error()
                            ? analysis_session::last_error()
                            : "(null)");
                }
            } else {
                diag::log_tagged_fmt("file_browser", "dispatch path=new_load");
                if (loading_binary_overlay::is_active()) {
                    diag::log_tagged_fmt("file_browser",
                        "sidebar_load_skipped_overlay_active path=%s",
                        ent.full_path.c_str());
                } else {
                    diag::log_tagged_fmt("file_browser",
                        "loading_overlay_begin_called path=%s action=switch_to_disassembly_or_hex",
                        ent.full_path.c_str());
                    bool started = analysis_session::open_session(ent.full_path);
                    if (started) {
                        globals::ui::active_center_view = center_view_t::disassembly;
                        diag::log_tagged_fmt("file_browser",
                            "sidebar_load_direct path=%s",
                            ent.full_path.c_str());
                        file_browser::record_recent_workspace(ent.full_path);
                    } else {
                        diag::log_tagged_fmt("file_browser",
                            "sidebar_load_direct_failed path=%s err=%s",
                            ent.full_path.c_str(),
                            analysis_session::last_error()
                                ? analysis_session::last_error()
                                : "(null)");
                    }
                }
            }
        }
    }
}

namespace file_browser {

namespace {

inline std::string truncate_middle(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    if (max_len <= 5) return s.substr(0, max_len);
    size_t keep_head = (max_len - 3) / 2;
    size_t keep_tail = max_len - 3 - keep_head;
    std::string out;
    out.reserve(max_len);
    out.append(s, 0, keep_head);
    out.append("...");
    out.append(s, s.size() - keep_tail, keep_tail);
    return out;
}

}

void record_recent_workspace(const std::string& path)
{
    if (path.empty()) return;

    std::vector<std::string> list;
    if (!g_sa_settings.recent_workspaces_json.empty()) {
        auto j = nlohmann::json::parse(g_sa_settings.recent_workspaces_json,
                                       nullptr, false);
        if (!j.is_discarded() && j.is_array()) {
            for (auto& el : j) {
                if (el.is_string()) {
                    list.push_back(el.get<std::string>());
                }
            }
        }
    }

    auto same_path = [&](const std::string& a, const std::string& b) -> bool {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            char ca = a[i];
            char cb = b[i];
            if (ca == '/') ca = '\\';
            if (cb == '/') cb = '\\';
            if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
            if (ca != cb) return false;
        }
        return true;
    };

    list.erase(std::remove_if(list.begin(), list.end(),
                              [&](const std::string& s) { return same_path(s, path); }),
               list.end());
    list.insert(list.begin(), path);
    if (list.size() > 20) list.resize(20);

    nlohmann::json out = nlohmann::json::array();
    for (auto& s : list) out.push_back(s);
    g_sa_settings.recent_workspaces_json = out.dump();
}

void render_pending_confirm_modal()
{
    if (file_browser::pending_open_should_open) {
        ImGui::OpenPopup("##aida_open_binary_confirm");
        file_browser::pending_open_should_open = false;
        file_browser::pending_open_modal_visible = true;
    }

    if (!file_browser::pending_open_modal_visible) return;

    const auto& tk = aida::ui::resolved();

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.f, 16.f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.f, 8.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tk.bg_overlay));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(tk.panel_bg));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_primary));
    ImGui::SetNextWindowBgAlpha(1.0f);

    ImVec2 viewport_center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(viewport_center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(460.f, 0.f), ImGuiCond_Appearing);

    bool open_flag_local = true;
    bool open_now    = false;
    bool switch_now  = false;
    bool cancel_now  = false;
    size_t existing_idx = static_cast<size_t>(-1);
    bool already_open = analysis_session::find_session_by_path(
        file_browser::pending_open_path, &existing_idx);

    if (ImGui::BeginPopupModal("Open binary?###aida_open_binary_confirm",
                               &open_flag_local,
                               ImGuiWindowFlags_NoSavedSettings
                               | ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGuiIO& io = ImGui::GetIO();

        std::string fname = file_browser::pending_open_filename;
        if (fname.empty()) {
            size_t sl = file_browser::pending_open_path.find_last_of("/\\");
            fname = (sl != std::string::npos)
                ? file_browser::pending_open_path.substr(sl + 1)
                : file_browser::pending_open_path;
        }

        ImFont* base_font = ImGui::GetFont();
        if (base_font) {
            ImGui::PushFont(base_font);
            ImGui::SetWindowFontScale(1.18f);
            ImGui::TextUnformatted(fname.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopFont();
        } else {
            ImGui::TextUnformatted(fname.c_str());
        }

        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_dim));
        std::string path_display = file_browser::pending_open_path;
        std::string path_clip = truncate_middle(path_display, 70);
        ImGui::TextWrapped("%s", path_clip.c_str());
        ImGui::PopStyleColor();

        ImGui::Spacing();

        if (already_open) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_secondary));
            ImGui::TextWrapped("Already open in a tab -- click 'Switch' to focus it.");
            ImGui::PopStyleColor();
        } else if (analysis_session::session_count() >= analysis_session::kMaxSessions) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_secondary));
            ImGui::TextWrapped("Already at %zu open binaries. The oldest will be closed to make room.",
                               analysis_session::kMaxSessions);
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) cancel_now = true;
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false)
            || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)) {
            if (already_open) switch_now = true;
            else              open_now = true;
        }
        (void)io;

        if (already_open) {
            if (aida::ui::button("Switch to tab", aida::ui::button_kind_t::primary,
                                 aida::ui::size_t_::md, ImVec2(150.f, 0.f),
                                 false, nullptr, false))
                switch_now = true;
        } else {
            if (aida::ui::button("Open in new tab", aida::ui::button_kind_t::primary,
                                 aida::ui::size_t_::md, ImVec2(160.f, 0.f),
                                 false, nullptr, false))
                open_now = true;
        }
        ImGui::SameLine();
        if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
                             aida::ui::size_t_::md, ImVec2(110.f, 0.f),
                             false, nullptr, false))
            cancel_now = true;

        if (open_now && !already_open) {
            std::string path_copy = file_browser::pending_open_path;
            bool started = analysis_session::open_session(path_copy);
            if (started) {
                globals::ui::active_center_view = center_view_t::disassembly;
                diag::log_tagged_fmt("file_open", "explorer_click_open path=%s",
                    path_copy.c_str());
                file_browser::record_recent_workspace(path_copy);
            }
            ImGui::CloseCurrentPopup();
            file_browser::pending_open_modal_visible = false;
            file_browser::pending_open_path.clear();
            file_browser::pending_open_filename.clear();
        } else if (switch_now && already_open) {
            if (analysis_session::switch_session(existing_idx)) {
                globals::ui::active_center_view = center_view_t::disassembly;
                diag::log_tagged_fmt("file_open", "explorer_click_switch idx=%llu",
                    static_cast<unsigned long long>(existing_idx));
            }
            ImGui::CloseCurrentPopup();
            file_browser::pending_open_modal_visible = false;
            file_browser::pending_open_path.clear();
            file_browser::pending_open_filename.clear();
        } else if (cancel_now || !open_flag_local) {
            ImGui::CloseCurrentPopup();
            file_browser::pending_open_modal_visible = false;
            file_browser::pending_open_path.clear();
            file_browser::pending_open_filename.clear();
        }

        ImGui::EndPopup();
    } else {
        file_browser::pending_open_modal_visible = false;
    }

    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar(4);
}

}
