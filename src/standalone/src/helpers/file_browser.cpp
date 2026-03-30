/*
 * file_browser.cpp
 *
 * Implements the file browser panel for the standalone AiDA IDE layout.
 * Provides filesystem tree navigation (expand/collapse directories) and
 * opens PE files into the Zydis disassembler when clicked.
 */

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "globals.h"
#include "../core/zydis_disasm.hpp"

#include <filesystem>
#include <algorithm>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

extern HWND g_hwnd;
extern DisasmState g_disasm;

// ============================================================================
//  file_browser::refresh
// ============================================================================
void file_browser::refresh(const std::string& dir)
{
    std::string root = dir;

    // Default to current working directory on first call
    if (root.empty() && current_dir.empty()) {
        char buf[MAX_PATH] = {};
        GetCurrentDirectoryA(MAX_PATH, buf);
        root = buf;
    }

    if (!root.empty())
        current_dir = root;

    if (current_dir.empty()) return;

    // Copy path to editable buffer
    strncpy_s(path_buf, sizeof(path_buf), current_dir.c_str(), _TRUNCATE);

    // Build a flat list from the directory tree, preserving expanded state
    // First, collect which paths were previously expanded
    std::vector<std::string> expanded_paths;
    for (auto& e : entries)
        if (e.is_dir && e.expanded)
            expanded_paths.push_back(e.full_path);

    entries.clear();
    needs_refresh = false;

    // Recursive helper to populate entries
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

                // Skip hidden/system files
                if (!e.name.empty() && e.name[0] == '.') continue;

                if (it.is_directory(ec) && !ec) {
                    e.is_dir = true;
                    // Restore expanded state
                    for (auto& ep : expanded_set)
                        if (ep == e.full_path) { e.expanded = true; break; }
                    dirs.push_back(std::move(e));
                } else if (it.is_regular_file(ec) && !ec) {
                    e.is_dir = false;
                    files.push_back(std::move(e));
                }
            }

            // Sort: directories first, then files, alphabetical within each
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

// ============================================================================
//  file_browser::toggle_dir
// ============================================================================
void file_browser::toggle_dir(int idx)
{
    if (idx < 0 || idx >= (int)entries.size()) return;
    auto& ent = entries[idx];
    if (!ent.is_dir) return;

    ent.expanded = !ent.expanded;
    needs_refresh = true;
}

// ============================================================================
//  file_browser::open_file
// ============================================================================
void file_browser::open_file(int idx)
{
    if (idx < 0 || idx >= (int)entries.size()) return;
    auto& ent = entries[idx];
    if (ent.is_dir) return;

    // Determine extension
    std::string ext;
    auto dot = ent.name.rfind('.');
    if (dot != std::string::npos)
        ext = ent.name.substr(dot);
    for (auto& c : ext) c = (char)tolower((unsigned char)c);

    // Text/source file extensions
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
        // Load as text file into the code editor
        std::ifstream ifs(ent.full_path, std::ios::in);
        if (ifs.is_open()) {
            std::ostringstream ss;
            ss << ifs.rdbuf();
            code_editor::load(ss.str(), ent.name, ent.full_path);
            // Deactivate disasm view
            g_disasm.file = DisasmFile{};
        }
    } else {
        // Try loading as PE binary
        code_editor::active = false;
        code_editor::buffer.clear();
        code_editor::filename.clear();
        code_editor::filepath.clear();
        g_disasm.file = DisasmFile{};
        disasm::load_pe(ent.full_path, g_disasm.file);
        if (g_disasm.file.loaded)
            disasm::decode_section(g_disasm.file);
    }
}
