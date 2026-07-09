
#include <windows.h>
#include <shlobj.h>
#ifdef small
#undef small
#endif

#include "globals.h"
#include "zydis_disasm.hpp"
#include "function_index.hpp"
#include "xref_index.hpp"
#include "standalone_license.hpp"
#include "hex_view.hpp"
#include "image_view.hpp"
#include "initial_analysis.hpp"
#include "loading_binary_overlay.hpp"
#include "analysis_session.hpp"
#include "standalone_settings.hpp"
#include "diag_log.hpp"
#include "imgui/imgui.h"
#include "components.hpp"
#include "theme.hpp"
#include "../core/infra/executor.hpp"
#include "../core/ui/ui_thread_dispatcher.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <algorithm>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <atomic>
#include <thread>
#include <mutex>
#include <cstring>

namespace fs = std::filesystem;

extern HWND g_hwnd;
extern DisasmState g_disasm;


void file_browser::refresh(const std::string& dir)
{
    if (!aida::ui_thread::is_owner_thread()) {
        const bool routed = aida::ui_thread::post([dir]() {
            file_browser::refresh(dir);
        }, "file_browser", "refresh", "entry");
        if (!routed)
            diag::log_tagged_fmt("file_browser", "refresh denied dir=%s reason=ui_affinity_route_failed", dir.c_str());
        return;
    }
    if (!aida::ui_thread::require_owner("file_browser", "refresh", "entry"))
        return;

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

    std::error_code dir_ec;
    if (!fs::is_directory(fs::path(current_dir), dir_ec)) {
        selected_idx = -1;
        diag::log_tagged_fmt("file_browser",
            "refresh_skipped_invalid_dir dir=%s ec=%d",
            current_dir.c_str(), dir_ec.value());
        return;
    }


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

    try {
        local::scan(current_dir, 0, expanded_paths, entries);
    }
    catch (const std::exception& ex) {
        entries.clear();
        needs_refresh = false;
        diag::log_tagged_fmt("file_browser", "refresh_exception dir=%s err=%s",
            current_dir.c_str(), ex.what());
    }
    catch (...) {
        entries.clear();
        needs_refresh = false;
        diag::log_tagged_fmt("file_browser", "refresh_exception_unknown dir=%s",
            current_dir.c_str());
    }
}


void file_browser::toggle_dir(int idx)
{
    if (idx < 0 || idx >= (int)entries.size()) return;
    auto& ent = entries[idx];
    if (!ent.is_dir) return;

    ent.expanded = !ent.expanded;
    needs_refresh = true;
}


namespace file_browser {

namespace ext_classify {

static const char* k_text_exts[] = {
    ".cpp", ".c", ".h", ".hpp", ".hxx", ".cxx", ".cc",
    ".py", ".js", ".ts", ".json", ".xml", ".yaml", ".yml",
    ".md", ".txt", ".log", ".cfg", ".ini", ".toml",
    ".java", ".cs", ".rs", ".go", ".rb", ".php",
    ".html", ".css", ".scss", ".lua", ".sh", ".bat", ".ps1",
    ".cmake", ".asm", ".s", ".inc", ".def", ".rules",
    ".vcxproj", ".vcproj", ".filters", ".props", ".targets",
    ".sln", ".csproj", ".proj", ".gradle", ".gn", ".gni",
    ".diff", ".patch", ".gitignore", ".gitattributes",
    ".srt", ".vtt", ".tsv", ".csv",
    ".env", ".rc", ".pbxproj", ".plist",
};

static const char* k_binary_exts[] = {
    ".exe", ".dll", ".sys", ".efi", ".scr", ".cpl",
    ".ocx", ".ax", ".drv", ".mui", ".tsp", ".node",
    ".bin", ".lib", ".obj", ".o", ".a", ".so", ".dylib",
    ".elf", ".out", ".com", ".ko", ".kext", ".dmp",
    ".pdb", ".rom", ".img", ".uefi",
    ".class", ".jar",
    ".pyc", ".pyo",
};

static const char* k_archive_exts[] = {
    ".rar", ".zip", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".iso",
};

inline std::string lower_ext(const std::string& filename)
{
    std::string ext;
    auto dot = filename.rfind('.');
    if (dot != std::string::npos)
        ext = filename.substr(dot);
    for (auto& c : ext) c = (char)tolower((unsigned char)c);
    return ext;
}

inline bool matches(const std::string& ext, const char* const* table, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (ext == table[i]) return true;
    }
    return false;
}

inline bool is_text(const std::string& ext)
{
    return matches(ext, k_text_exts, sizeof(k_text_exts)/sizeof(k_text_exts[0]));
}

inline bool is_binary(const std::string& ext)
{
    return matches(ext, k_binary_exts, sizeof(k_binary_exts)/sizeof(k_binary_exts[0]));
}

inline bool is_archive(const std::string& ext)
{
    return matches(ext, k_archive_exts, sizeof(k_archive_exts)/sizeof(k_archive_exts[0]));
}

}

void open_path(const std::string& path)
{
    if (path.empty()) return;
    if (!aida::ui_thread::is_owner_thread()) {
        const bool routed = aida::ui_thread::post([path]() {
            file_browser::open_path(path);
        }, "file_browser", "open_path", "entry");
        if (!routed)
            diag::log_tagged_fmt("file_browser", "open_path denied path=%s reason=ui_affinity_route_failed", path.c_str());
        return;
    }
    if (!aida::ui_thread::require_owner("file_browser", "open_path", "entry"))
        return;

    std::error_code ec;
    if (fs::is_directory(path, ec) && !ec) {
        diag::log_tagged_fmt("file_browser", "open_path directory=%s", path.c_str());
        refresh(path);
        globals::ui::active_activity = activity_item_t::explorer;
        globals::ui::panel_left_visible = true;
        return;
    }

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_file_browser_open);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_file_browser_open, gt) < 0.5) {
            diag::log_tagged_fmt("file_browser", "open_path denied path=%s reason=gate", path.c_str());
            return;
        }
    }

    std::string fname;
    {
        size_t sl = path.find_last_of("/\\");
        fname = (sl != std::string::npos) ? path.substr(sl + 1) : path;
    }
    std::string ext = ext_classify::lower_ext(fname);

    diag::log_tagged_fmt("file_browser",
        "open_path begin path=%s ext=%s", path.c_str(), ext.c_str());

    if (image_view::is_image_extension(ext)) {
        image_view::load_from_file(path);
        globals::ui::active_center_view = center_view_t::image_view;
        diag::log_tagged_fmt("file_browser", "open_path -> image_view path=%s", path.c_str());
        return;
    }

    if (ext_classify::is_text(ext)) {
        std::ifstream ifs(path, std::ios::binary);
        if (ifs.is_open()) {
            std::ostringstream ss;
            ss << ifs.rdbuf();
            file_tabs::open_or_focus(path, fname, ss.str());
            globals::ui::active_center_view = center_view_t::code_editor;
            diag::log_tagged_fmt("file_browser", "open_path -> code_editor path=%s", path.c_str());
            return;
        }
        diag::log_tagged_fmt("file_browser",
            "open_path text open_failed path=%s", path.c_str());
    }

    if (ext_classify::is_archive(ext)) {
        code_editor::active = false;
        code_editor::buffer.clear();
        code_editor::filename.clear();
        code_editor::filepath.clear();
        g_disasm.file = DisasmFile{};
        hex_view::load_from_file(path, 0, 0);
        globals::ui::active_center_view = center_view_t::hex_view;
        diag::log_tagged_fmt("file_browser", "open_path -> hex_view archive path=%s", path.c_str());
        return;
    }

    uint64_t file_size_bytes = 0;
    {
        std::error_code fec;
        auto sz = fs::file_size(path, fec);
        if (!fec) file_size_bytes = static_cast<uint64_t>(sz);
    }
    diag::log_tagged_fmt("file_browser",
        "open_path binary_branch path=%s ext=%s size=%llu",
        path.c_str(),
        ext.c_str(),
        static_cast<unsigned long long>(file_size_bytes));

    size_t existing_idx = static_cast<size_t>(-1);
    bool found = analysis_session::find_session_by_path(path, &existing_idx);
    if (found) {
        if (analysis_session::switch_session(existing_idx)) {
            globals::ui::active_center_view = center_view_t::disassembly;
            record_recent_workspace(path);
            diag::log_tagged_fmt("file_browser",
                "open_path -> existing_session idx=%llu",
                static_cast<unsigned long long>(existing_idx));
            return;
        }
        diag::log_tagged_fmt("file_browser",
            "open_path switch_existing_failed idx=%llu err=%s",
            static_cast<unsigned long long>(existing_idx),
            analysis_session::last_error() ? analysis_session::last_error() : "(null)");
    }

    if (loading_binary_overlay::is_active()) {
        diag::log_tagged_fmt("file_browser",
            "open_path skipped overlay_active path=%s", path.c_str());
        return;
    }

    bool started = analysis_session::open_session(path);
    if (started) {
        globals::ui::active_center_view = center_view_t::disassembly;
        record_recent_workspace(path);
        diag::log_tagged_fmt("file_browser",
            "open_path -> new_session path=%s ext=%s", path.c_str(), ext.c_str());
        return;
    }

    const char* err = analysis_session::last_error();
    bool err_says_not_pe = err && (
        std::strstr(err, "not a PE") != nullptr ||
        std::strstr(err, "not_pe")   != nullptr ||
        std::strstr(err, "PE header") != nullptr ||
        std::strstr(err, "magic") != nullptr);

    if (ext_classify::is_binary(ext) || err_says_not_pe) {
        code_editor::active = false;
        code_editor::buffer.clear();
        code_editor::filename.clear();
        code_editor::filepath.clear();
        g_disasm.file = DisasmFile{};
        hex_view::load_from_file(path, 0, 0);
        globals::ui::active_center_view = center_view_t::hex_view;
        diag::log_tagged_fmt("file_browser",
            "open_path -> hex_view fallback path=%s err=%s",
            path.c_str(), err ? err : "(null)");
        return;
    }

    diag::log_tagged_fmt("file_browser",
        "open_path failed path=%s err=%s", path.c_str(),
        err ? err : "(null)");
}

}

void file_browser::open_file(int idx)
{
    if (idx < 0 || idx >= (int)entries.size()) return;
    auto& ent = entries[idx];
    if (ent.is_dir) return;
    file_browser::request_open_confirmation(ent.full_path);
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

void request_open_confirmation(const std::string& path)
{
    if (path.empty()) return;
    if (!aida::ui_thread::is_owner_thread()) {
        const bool routed = aida::ui_thread::post([path]() {
            file_browser::request_open_confirmation(path);
        }, "file_browser", "request_open_confirmation", "entry");
        if (!routed)
            diag::log_tagged_fmt("file_open", "explorer_confirm_denied path=%s reason=ui_affinity_route_failed", path.c_str());
        return;
    }
    if (!aida::ui_thread::require_owner("file_browser", "request_open_confirmation", "entry"))
        return;

    std::error_code ec;
    if (fs::is_directory(path, ec) && !ec) {
        open_path(path);
        return;
    }

    pending_open_path = path;
    size_t sl = path.find_last_of("/\\");
    pending_open_filename = (sl != std::string::npos) ? path.substr(sl + 1) : path;
    pending_open_should_open = true;
    pending_open_modal_visible = true;
    diag::log_tagged_fmt("file_open", "explorer_confirm_requested path=%s", path.c_str());
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

    if (ImGui::BeginPopupModal("Load file?###aida_open_binary_confirm",
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
        ImGui::TextWrapped("do you want to load this file?");
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
            if (aida::ui::button("Switch", aida::ui::button_kind_t::primary,
                                 aida::ui::size_t_::md, ImVec2(150.f, 0.f),
                                 false, nullptr, false))
                switch_now = true;
        } else {
            if (aida::ui::button("Load", aida::ui::button_kind_t::primary,
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
            diag::log_tagged_fmt("file_open", "explorer_confirm_load path=%s",
                path_copy.c_str());
            file_browser::open_path(path_copy);
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

namespace watcher_detail {

struct watcher_t {
    std::atomic<bool>       running{false};
    std::atomic<bool>       stop{false};
    std::atomic<bool>       has_change{false};
    std::atomic<bool>       worker_done{true};
    std::atomic<uint64_t>   retry_after_ms{0};
    std::string             watched_dir;
    HANDLE                  wake_event = nullptr;
    std::mutex              mtx;
};

inline watcher_t& g_watcher()
{
    static watcher_t w;
    return w;
}

inline uint64_t now_ms()
{
    return ::GetTickCount64();
}

inline bool utf8_to_wide(const std::string& in, std::wstring& out)
{
    out.clear();
    int n = ::MultiByteToWideChar(CP_UTF8, 0, in.c_str(), -1, nullptr, 0);
    if (n <= 0) return false;
    out.resize(static_cast<size_t>(n) - 1);
    return ::MultiByteToWideChar(CP_UTF8, 0, in.c_str(), -1, out.data(), n) > 0;
}

inline bool directory_ready(const std::string& dir, DWORD& err)
{
    std::wstring wdir;
    if (!utf8_to_wide(dir, wdir) || wdir.empty()) {
        err = ERROR_INVALID_NAME;
        return false;
    }
    DWORD attrs = ::GetFileAttributesW(wdir.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        err = ::GetLastError();
        return false;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        err = ERROR_DIRECTORY;
        return false;
    }
    err = ERROR_SUCCESS;
    return true;
}

inline void close_completed_wake_event_locked(watcher_t& w)
{
    if (w.wake_event && w.worker_done.load(std::memory_order_acquire)) {
        ::CloseHandle(w.wake_event);
        w.wake_event = nullptr;
    }
}

inline void stop_watcher_locked(watcher_t& w)
{
    if (!w.running.load(std::memory_order_acquire)) return;
    w.stop.store(true, std::memory_order_release);
    if (w.wake_event) ::SetEvent(w.wake_event);
    for (int i = 0; i < 200 && !w.worker_done.load(std::memory_order_acquire); ++i)
        ::Sleep(5);
    w.running.store(false, std::memory_order_release);
    w.stop.store(false, std::memory_order_release);
    if (w.wake_event && w.worker_done.load(std::memory_order_acquire)) {
        ::CloseHandle(w.wake_event);
        w.wake_event = nullptr;
    }
    w.watched_dir.clear();
    diag::log_tagged("file_browser_watcher", "stopped");
}

inline bool is_noise_basename(const std::wstring& bn)
{
    if (bn.empty()) return true;
    if (bn.size() >= 14) {
        const wchar_t* tail = bn.c_str() + bn.size() - 14;
        if (_wcsicmp(tail, L"aida_debug.log") == 0) return true;
    }
    if (bn.size() >= 4) {
        const wchar_t* ext = bn.c_str() + bn.size() - 4;
        if (_wcsicmp(ext, L".log") == 0) return true;
        if (_wcsicmp(ext, L".tmp") == 0) return true;
    }
    if (bn.size() >= 1 && bn[0] == L'.') return true;
    return false;
}

inline void watcher_thread(std::string dir, HANDLE wake_event)
{
    watcher_t& w = g_watcher();

    std::wstring wdir;
    if (!utf8_to_wide(dir, wdir) || wdir.empty()) {
        diag::log_tagged("file_browser_watcher", "thread_exit empty_dir");
        w.retry_after_ms.store(now_ms() + 5000ull, std::memory_order_release);
        w.worker_done.store(true, std::memory_order_release);
        w.running.store(false, std::memory_order_release);
        return;
    }

    HANDLE h = ::CreateFileW(wdir.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = ::GetLastError();
        w.retry_after_ms.store(now_ms() + 5000ull, std::memory_order_release);
        diag::log_tagged_fmt("file_browser_watcher",
            "thread_exit CreateFileW failed err=%lu dir=%s",
            static_cast<unsigned long>(err), dir.c_str());
        w.worker_done.store(true, std::memory_order_release);
        w.running.store(false, std::memory_order_release);
        return;
    }

    diag::log_tagged_fmt("file_browser_watcher",
        "thread_started dir=%s", dir.c_str());

    constexpr DWORD kBufSize = 32768;
    std::vector<uint8_t> buf(kBufSize);

    uint64_t last_signal_ms = 0;

    while (!w.stop.load(std::memory_order_acquire)) {
        OVERLAPPED ov{};
        ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) break;

        DWORD bytes_returned = 0;
        BOOL ok = ::ReadDirectoryChangesW(
            h,
            buf.data(),
            kBufSize,
            FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE,
            &bytes_returned,
            &ov,
            nullptr);
        if (!ok) {
            DWORD err = ::GetLastError();
            w.retry_after_ms.store(now_ms() + 5000ull, std::memory_order_release);
            diag::log_tagged_fmt("file_browser_watcher",
                "ReadDirectoryChangesW failed err=%lu",
                static_cast<unsigned long>(err));
            ::CloseHandle(ov.hEvent);
            break;
        }

        HANDLE waits[2] = { ov.hEvent, wake_event };
        DWORD wait_count = wake_event ? 2u : 1u;
        DWORD waited = ::WaitForMultipleObjects(wait_count, waits, FALSE, INFINITE);

        if (waited == WAIT_OBJECT_0) {
            DWORD transferred = 0;
            if (::GetOverlappedResult(h, &ov, &transferred, FALSE) && transferred > 0) {
                bool has_meaningful = false;
                DWORD off = 0;
                const uint8_t* p = buf.data();
                while (off + sizeof(FILE_NOTIFY_INFORMATION) <= transferred) {
                    const FILE_NOTIFY_INFORMATION* fni =
                        reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(p + off);
                    USHORT name_chars = static_cast<USHORT>(fni->FileNameLength / sizeof(WCHAR));
                    std::wstring bn(fni->FileName, name_chars);
                    if (!is_noise_basename(bn)) {
                        has_meaningful = true;
                        break;
                    }
                    if (fni->NextEntryOffset == 0) break;
                    off += fni->NextEntryOffset;
                }

                if (has_meaningful) {
                    uint64_t stamp_ms = now_ms();
                    if (stamp_ms - last_signal_ms >= 500ull) {
                        last_signal_ms = stamp_ms;
                        w.has_change.store(true, std::memory_order_release);
                    }
                }
            }
        } else {
            ::CancelIoEx(h, &ov);
            DWORD tmp = 0;
            ::GetOverlappedResult(h, &ov, &tmp, TRUE);
        }
        ::CloseHandle(ov.hEvent);
    }

    ::CloseHandle(h);
    diag::log_tagged_fmt("file_browser_watcher",
        "thread_exit dir=%s", dir.c_str());
    w.worker_done.store(true, std::memory_order_release);
    w.running.store(false, std::memory_order_release);
}

inline void ensure_running_for(const std::string& dir)
{
    watcher_t& w = g_watcher();
    std::lock_guard<std::mutex> lk(w.mtx);
    if (w.running.load(std::memory_order_acquire) && w.watched_dir == dir) return;

    const uint64_t stamp_ms = now_ms();
    const uint64_t retry_after_ms = w.retry_after_ms.load(std::memory_order_acquire);
    if (w.watched_dir == dir && retry_after_ms != 0 && stamp_ms < retry_after_ms) return;

    if (w.running.load(std::memory_order_acquire)) {
        stop_watcher_locked(w);
    }
    close_completed_wake_event_locked(w);
    if (dir.empty()) return;

    DWORD dir_err = ERROR_SUCCESS;
    if (!directory_ready(dir, dir_err)) {
        w.watched_dir = dir;
        w.retry_after_ms.store(stamp_ms + 5000ull, std::memory_order_release);
        diag::log_tagged_fmt("file_browser_watcher",
            "invalid_dir err=%lu dir=%s",
            static_cast<unsigned long>(dir_err), dir.c_str());
        return;
    }

    w.wake_event = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!w.wake_event) return;
    w.stop.store(false, std::memory_order_release);
    w.has_change.store(false, std::memory_order_release);
    w.watched_dir = dir;
    HANDLE we = w.wake_event;
    std::string cap = dir;
    w.worker_done.store(false, std::memory_order_release);
    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "file_browser_watcher";
    sub.label = "file_browser_watcher.watch";
    sub.thread_class = "long_lived_service";
    sub.domain = aida::infra::executor::domain_t::service;
    sub.priority = 3;
    sub.body = [cap, we]() { watcher_thread(cap, we); };
    if (aida::infra::executor::submit(std::move(sub)).submitted) {
        w.running.store(true, std::memory_order_release);
        w.retry_after_ms.store(0, std::memory_order_release);
        diag::log_tagged_fmt("file_browser_watcher", "ensure_running_for dir=%s", dir.c_str());
    }
    else {
        if (w.wake_event) {
            ::CloseHandle(w.wake_event);
            w.wake_event = nullptr;
        }
        w.watched_dir = dir;
        w.stop.store(false, std::memory_order_release);
        w.running.store(false, std::memory_order_release);
        w.worker_done.store(true, std::memory_order_release);
        w.retry_after_ms.store(stamp_ms + 5000ull, std::memory_order_release);
        diag::log_tagged_fmt("file_browser_watcher", "executor_submit_failed dir=%s",
            dir.c_str());
    }
}

}

void tick_watcher()
{
    watcher_detail::ensure_running_for(current_dir);
    watcher_detail::watcher_t& w = watcher_detail::g_watcher();
    if (w.has_change.exchange(false, std::memory_order_acq_rel)) {
        needs_refresh = true;
    }
}

}
