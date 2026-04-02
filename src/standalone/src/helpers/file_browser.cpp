
#include <windows.h>
#include <shlobj.h>

#include "globals.h"
#include "../core/zydis_disasm.hpp"
#include "../core/standalone_license.hpp"
#include "../core/hex_view.hpp"

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

        std::ifstream ifs(ent.full_path, std::ios::in);
        if (ifs.is_open()) {
            std::ostringstream ss;
            ss << ifs.rdbuf();
            file_tabs::open_or_focus(ent.full_path, ent.name, ss.str());

            g_disasm.file = DisasmFile{};
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
            code_editor::active = false;
            code_editor::buffer.clear();
            code_editor::filename.clear();
            code_editor::filepath.clear();
            g_disasm.file = DisasmFile{};
            disasm::load_pe(ent.full_path, g_disasm.file);
            if (g_disasm.file.loaded) {
                disasm::decode_section(g_disasm.file);
                globals::ui::active_center_view = center_view_t::disassembly;
            } else {
                hex_view::load_from_file(ent.full_path, 0, 0);
                globals::ui::active_center_view = center_view_t::hex_view;
            }
        }
    }
}
