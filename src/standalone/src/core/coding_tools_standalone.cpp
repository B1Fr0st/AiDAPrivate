

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "mcp_standalone.hpp"
#include "standalone_tools_fwd.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "../helpers/globals.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;


namespace coding_tools
{


static bool is_text_extension(const std::string& ext)
{
    static const char* text_exts[] = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".py", ".pyw", ".pyi", ".rb", ".rs", ".go", ".java", ".kt",
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".cs", ".fs", ".vb", ".swift", ".m", ".mm",
        ".lua", ".pl", ".pm", ".tcl", ".sh", ".bash", ".zsh", ".fish",
        ".bat", ".cmd", ".ps1", ".psm1",
        ".asm", ".s", ".inc", ".nasm",
        ".json", ".jsonc", ".json5",
        ".xml", ".html", ".htm", ".xhtml", ".svg",
        ".css", ".scss", ".sass", ".less",
        ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
        ".md", ".markdown", ".rst", ".txt", ".log",
        ".cmake", ".make", ".makefile", ".mk",
        ".dockerfile", ".gitignore", ".editorconfig",
        ".sql", ".graphql", ".proto", ".thrift",
        ".r", ".R", ".jl", ".m", ".nb",
        ".vue", ".svelte", ".astro",
        ".tf", ".hcl", ".nix", ".dhall",
        ".def", ".map", ".ld", ".lds",
    };
    std::string lower_ext = ext;
    std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const char* e : text_exts)
        if (lower_ext == e) return true;
    return false;
}


static std::string sanitize_path(const std::string& raw)
{

    std::string p = raw;

    for (char& c : p) { if (c == '/') c = '\\'; }


    if (!file_browser::current_dir.empty() && !p.empty() && p[0] != '\\' &&
        (p.size() < 2 || p[1] != ':'))
    {
        p = file_browser::current_dir + "\\" + p;
    }


    std::error_code ec;
    auto canonical = fs::weakly_canonical(fs::path(p), ec);
    if (ec) return raw;
    return canonical.string();
}


static bool path_within_workspace(const std::string& canonical_path)
{
    if (file_browser::current_dir.empty())
        return true;

    std::error_code ec;
    auto ws = fs::weakly_canonical(fs::path(file_browser::current_dir), ec);
    if (ec) return false;

    auto ws_str = ws.string();
    auto p_str  = canonical_path;

    std::transform(ws_str.begin(), ws_str.end(), ws_str.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(p_str.begin(), p_str.end(), p_str.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return p_str.find(ws_str) == 0;
}


static tool_result_t tool_read_file(const json& params)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_coding_tool_exec);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_coding_tool_exec, gt) < 0.5)
            return tool_result_t::error("Service unavailable.");
    }

    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");

    std::string path = sanitize_path(params["path"].get<std::string>());
    if (!path_within_workspace(path))
        return tool_result_t::error("Path is outside the workspace.");

    std::error_code ec;
    if (!fs::exists(path, ec))
        return tool_result_t::error("File not found: " + path);

    if (fs::is_directory(path, ec))
        return tool_result_t::error("Path is a directory, not a file. Use list_directory instead.");

    auto file_size = fs::file_size(path, ec);
    if (ec || file_size > 2 * 1024 * 1024)
        return tool_result_t::error("File too large (>2MB). Use read_file with line range instead.");

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open())
        return tool_result_t::error("Cannot open file: " + path);

    std::string content((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());
    ifs.close();

    int start_line = 1;
    int end_line   = 0;

    if (params.contains("start_line") && params["start_line"].is_number_integer())
        start_line = (std::max)(1, params["start_line"].get<int>());
    if (params.contains("end_line") && params["end_line"].is_number_integer())
        end_line = params["end_line"].get<int>();


    if (start_line > 1 || end_line > 0) {
        std::istringstream ss(content);
        std::string line;
        std::string result;
        int line_num = 0;
        while (std::getline(ss, line)) {
            ++line_num;
            if (line_num < start_line) continue;
            if (end_line > 0 && line_num > end_line) break;
            result += std::to_string(line_num) + " | " + line + "\n";
        }
        if (result.empty())
            return tool_result_t::error("Line range out of bounds (file has " +
                                        std::to_string(line_num) + " lines).");
        return tool_result_t::ok(result);
    }


    if (content.size() < 200000) {
        std::istringstream ss(content);
        std::string line;
        std::string numbered;
        int line_num = 0;
        while (std::getline(ss, line)) {
            ++line_num;
            numbered += std::to_string(line_num) + " | " + line + "\n";
        }
        return tool_result_t::ok(numbered);
    }

    return tool_result_t::ok(content);
}


static tool_result_t tool_write_file(const json& params)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_coding_tool_exec);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_coding_tool_exec, gt) < 0.5)
            return tool_result_t::error("Service unavailable.");
    }

    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    if (!params.contains("content") || !params["content"].is_string())
        return tool_result_t::error("Missing required parameter: content");

    std::string path = sanitize_path(params["path"].get<std::string>());
    if (!path_within_workspace(path))
        return tool_result_t::error("Path is outside the workspace.");

    const std::string& content = params["content"].get_ref<const std::string&>();


    std::error_code ec;
    auto parent = fs::path(path).parent_path();
    if (!parent.empty())
        fs::create_directories(parent, ec);

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        return tool_result_t::error("Cannot create/open file: " + path);

    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    ofs.close();


    if (code_editor::active && code_editor::filepath == path) {
        code_editor::load(content, code_editor::filename, path);
    }


    file_browser::needs_refresh = true;

    return tool_result_t::ok("File written: " + path + " (" +
                             std::to_string(content.size()) + " bytes)");
}


static tool_result_t tool_edit_file(const json& params)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_coding_tool_exec);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_coding_tool_exec, gt) < 0.5)
            return tool_result_t::error("Service unavailable.");
    }

    if (!params.contains("path") || !params["path"].is_string())
        return tool_result_t::error("Missing required parameter: path");
    if (!params.contains("old_text") || !params["old_text"].is_string())
        return tool_result_t::error("Missing required parameter: old_text");
    if (!params.contains("new_text") || !params["new_text"].is_string())
        return tool_result_t::error("Missing required parameter: new_text");

    std::string path = sanitize_path(params["path"].get<std::string>());
    if (!path_within_workspace(path))
        return tool_result_t::error("Path is outside the workspace.");

    std::error_code ec;
    if (!fs::exists(path, ec))
        return tool_result_t::error("File not found: " + path);


    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open())
        return tool_result_t::error("Cannot open file: " + path);
    std::string content((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());
    ifs.close();

    const std::string& old_text = params["old_text"].get_ref<const std::string&>();
    const std::string& new_text = params["new_text"].get_ref<const std::string&>();


    size_t pos = content.find(old_text);
    if (pos == std::string::npos)
        return tool_result_t::error("old_text not found in file. Ensure it matches exactly "
                                    "(including whitespace and indentation).");


    size_t second = content.find(old_text, pos + old_text.size());
    if (second != std::string::npos)
        return tool_result_t::error("old_text matches multiple locations (" +
            std::to_string(2) + "+). Include more surrounding context to match uniquely.");


    content.replace(pos, old_text.size(), new_text);


    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        return tool_result_t::error("Cannot write file: " + path);
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    ofs.close();


    if (code_editor::active && code_editor::filepath == path) {
        code_editor::load(content, code_editor::filename, path);
    }


    int line_num = 1;
    for (size_t i = 0; i < pos && i < content.size(); ++i)
        if (content[i] == '\n') ++line_num;

    return tool_result_t::ok("Edit applied at line " + std::to_string(line_num) +
                             " in " + path);
}


static tool_result_t tool_list_directory(const json& params)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_coding_tool_exec);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_coding_tool_exec, gt) < 0.5)
            return tool_result_t::error("Service unavailable.");
    }

    std::string path;
    if (params.contains("path") && params["path"].is_string())
        path = sanitize_path(params["path"].get<std::string>());
    else if (!file_browser::current_dir.empty())
        path = file_browser::current_dir;
    else
        return tool_result_t::error("No path specified and no workspace directory set.");

    std::error_code ec;
    if (!fs::is_directory(path, ec))
        return tool_result_t::error("Not a directory: " + path);

    std::string output;
    int count = 0;
    constexpr int MAX_ENTRIES = 500;

    for (auto& entry : fs::directory_iterator(path, ec)) {
        if (++count > MAX_ENTRIES) {
            output += "... (truncated at " + std::to_string(MAX_ENTRIES) + " entries)\n";
            break;
        }
        auto name = entry.path().filename().string();
        if (entry.is_directory(ec))
            output += name + "/\n";
        else {
            auto sz = entry.file_size(ec);
            output += name;
            if (!ec && sz > 0) {
                if (sz >= 1048576)
                    output += "  (" + std::to_string(sz / 1048576) + " MB)";
                else if (sz >= 1024)
                    output += "  (" + std::to_string(sz / 1024) + " KB)";
                else
                    output += "  (" + std::to_string(sz) + " B)";
            }
            output += "\n";
        }
    }

    if (output.empty())
        return tool_result_t::ok("Directory is empty: " + path);

    return tool_result_t::ok("Contents of " + path + ":\n" + output);
}


static tool_result_t tool_search_workspace(const json& params)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_coding_tool_exec);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_coding_tool_exec, gt) < 0.5)
            return tool_result_t::error("Service unavailable.");
    }

    if (!params.contains("query") || !params["query"].is_string())
        return tool_result_t::error("Missing required parameter: query");

    std::string query = params["query"].get<std::string>();
    if (query.empty())
        return tool_result_t::error("Query cannot be empty.");

    std::string root = file_browser::current_dir;
    if (params.contains("path") && params["path"].is_string()) {
        std::string custom = sanitize_path(params["path"].get<std::string>());
        std::error_code ec;
        if (fs::is_directory(custom, ec))
            root = custom;
    }
    if (root.empty())
        return tool_result_t::error("No workspace directory set.");

    std::string include_pattern;
    std::string exclude_pattern;
    bool use_regex = false;

    if (params.contains("include") && params["include"].is_string())
        include_pattern = params["include"].get<std::string>();
    if (params.contains("exclude") && params["exclude"].is_string())
        exclude_pattern = params["exclude"].get<std::string>();
    if (params.contains("regex") && params["regex"].is_boolean())
        use_regex = params["regex"].get<bool>();


    struct match_t {
        std::string filepath;
        int         line_number;
        std::string line_text;
    };
    std::vector<match_t> matches;
    constexpr int MAX_MATCHES = 100;
    constexpr int MAX_FILES = 5000;
    int files_scanned = 0;

    std::regex re;
    bool regex_valid = false;
    if (use_regex) {
        try {
            re = std::regex(query, std::regex::ECMAScript | std::regex::optimize);
            regex_valid = true;
        } catch (...) {
            return tool_result_t::error("Invalid regex pattern: " + query);
        }
    }


    std::string lower_query = query;
    if (!use_regex)
        std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });


    std::vector<std::string> excluded_dirs;
    if (!exclude_pattern.empty()) {
        std::istringstream ess(exclude_pattern);
        std::string tok;
        while (std::getline(ess, tok, ',')) {
            while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
            while (!tok.empty() && tok.back() == ' ') tok.pop_back();
            if (!tok.empty()) excluded_dirs.push_back(tok);
        }
    }

    excluded_dirs.push_back("node_modules");
    excluded_dirs.push_back(".git");
    excluded_dirs.push_back("__pycache__");
    excluded_dirs.push_back(".vs");

    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root,
            fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it)
    {
        if (static_cast<int>(matches.size()) >= MAX_MATCHES) break;
        if (files_scanned >= MAX_FILES) break;

        if (it->is_directory(ec)) {
            auto dirname = it->path().filename().string();
            bool skip = false;
            for (auto& ex : excluded_dirs) {
                if (dirname == ex) { skip = true; break; }
            }
            if (skip) { it.disable_recursion_pending(); continue; }
            continue;
        }

        if (!it->is_regular_file(ec)) continue;

        auto ext = it->path().extension().string();
        if (!is_text_extension(ext) && ext != "") continue;


        if (!include_pattern.empty()) {
            auto fname = it->path().filename().string();
            std::string lower_fname = fname;
            std::transform(lower_fname.begin(), lower_fname.end(), lower_fname.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::string lower_inc = include_pattern;
            std::transform(lower_inc.begin(), lower_inc.end(), lower_inc.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lower_fname.find(lower_inc) == std::string::npos &&
                ext.find(lower_inc) == std::string::npos)
                continue;
        }

        ++files_scanned;


        auto fsz = it->file_size(ec);
        if (ec || fsz > 2 * 1024 * 1024) continue;

        std::ifstream ifs(it->path(), std::ios::binary);
        if (!ifs.is_open()) continue;

        std::string line;
        int line_num = 0;
        while (std::getline(ifs, line)) {
            ++line_num;
            if (static_cast<int>(matches.size()) >= MAX_MATCHES) break;

            bool found = false;
            if (use_regex && regex_valid) {
                found = std::regex_search(line, re);
            } else {
                std::string lower_line = line;
                std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                found = (lower_line.find(lower_query) != std::string::npos);
            }

            if (found) {

                std::string display_line = line;
                if (display_line.size() > 200)
                    display_line = display_line.substr(0, 200) + "...";

                auto first = display_line.find_first_not_of(" \t");
                if (first != std::string::npos && first > 0)
                    display_line = display_line.substr(first);

                matches.push_back({
                    it->path().string(),
                    line_num,
                    display_line
                });
            }
        }
    }

    if (matches.empty())
        return tool_result_t::ok("No matches found for \"" + query + "\" in " +
                                 std::to_string(files_scanned) + " files.");

    std::string result = "Found " + std::to_string(matches.size()) + " match(es) in " +
                         std::to_string(files_scanned) + " files:\n\n";
    for (auto& m : matches) {

        std::string display_path = m.filepath;
        if (!root.empty() && display_path.find(root) == 0)
            display_path = display_path.substr(root.size() + 1);
        result += display_path + ":" + std::to_string(m.line_number) + ": " +
                  m.line_text + "\n";
    }

    return tool_result_t::ok(result);
}


static tool_result_t tool_run_command(const json& params)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_coding_tool_exec);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_coding_tool_exec, gt) < 0.5)
            return tool_result_t::error("Service unavailable.");
    }

    if (!params.contains("command") || !params["command"].is_string())
        return tool_result_t::error("Missing required parameter: command");

    std::string command = params["command"].get<std::string>();
    if (command.empty())
        return tool_result_t::error("Command cannot be empty.");

    int timeout_ms = 30000;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        timeout_ms = (std::clamp)(params["timeout_ms"].get<int>(), 1000, 120000);

    std::string cwd = file_browser::current_dir;
    if (params.contains("cwd") && params["cwd"].is_string()) {
        std::string custom = sanitize_path(params["cwd"].get<std::string>());
        std::error_code ec;
        if (fs::is_directory(custom, ec))
            cwd = custom;
    }

    output_log::push(bottom_tab_t::sandbox_log,
        "[run_command] $ " + command);


    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE h_stdout_rd = nullptr, h_stdout_wr = nullptr;
    if (!CreatePipe(&h_stdout_rd, &h_stdout_wr, &sa, 0))
        return tool_result_t::error("Failed to create pipe for stdout.");
    SetHandleInformation(h_stdout_rd, HANDLE_FLAG_INHERIT, 0);


    std::string cmdline = "cmd.exe /c \"" + command + "\"";

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = h_stdout_wr;
    si.hStdError = h_stdout_wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    BOOL created = CreateProcessA(
        nullptr,
        &cmdline[0],
        nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        cwd.empty() ? nullptr : cwd.c_str(),
        &si, &pi);

    CloseHandle(h_stdout_wr);

    if (!created) {
        CloseHandle(h_stdout_rd);
        return tool_result_t::error("Failed to launch command: " + command +
                                    " (error " + std::to_string(GetLastError()) + ")");
    }


    std::string output;
    constexpr size_t MAX_OUTPUT = 64000;
    auto start = std::chrono::steady_clock::now();
    bool timed_out = false;

    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeout_ms) {
            timed_out = true;
            TerminateProcess(pi.hProcess, 1);
            break;
        }

        DWORD avail = 0;
        if (!PeekNamedPipe(h_stdout_rd, nullptr, 0, nullptr, &avail, nullptr))
            break;

        if (avail > 0) {
            char buf[4096];
            DWORD read_bytes = 0;
            DWORD to_read = (std::min)(static_cast<DWORD>(sizeof(buf)),
                                       static_cast<DWORD>(MAX_OUTPUT - output.size()));
            if (to_read == 0) break;
            if (ReadFile(h_stdout_rd, buf, (std::min)(avail, to_read), &read_bytes, nullptr) && read_bytes > 0) {
                output.append(buf, read_bytes);
                if (output.size() >= MAX_OUTPUT) break;
            }
        } else {

            DWORD exit_code = 0;
            if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {

                while (true) {
                    char buf[4096];
                    DWORD read_bytes = 0;
                    if (!ReadFile(h_stdout_rd, buf, sizeof(buf), &read_bytes, nullptr) || read_bytes == 0)
                        break;
                    output.append(buf, read_bytes);
                    if (output.size() >= MAX_OUTPUT) break;
                }
                break;
            }
        }
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(h_stdout_rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);


    output_log::push(bottom_tab_t::sandbox_log,
        "[run_command] exit=" + std::to_string(exit_code) +
        (timed_out ? " (TIMED OUT)" : ""));

    std::string result;
    result += "Exit code: " + std::to_string(exit_code);
    if (timed_out)
        result += " (timed out after " + std::to_string(timeout_ms) + "ms)";
    result += "\n";
    if (!output.empty()) {
        if (output.size() >= MAX_OUTPUT)
            result += "(output truncated to " + std::to_string(MAX_OUTPUT) + " bytes)\n";
        result += output;
    } else {
        result += "(no output)";
    }

    return tool_result_t::ok(result);
}


void register_coding_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;

    srv.register_tool({
        "read_file",
        "Read the contents of a file. Returns contents with line numbers. "
        "Supports optional line range (start_line / end_line, 1-indexed). "
        "Maximum file size: 2MB.",
        {
            {"path",       "string", "Absolute or workspace-relative path to the file.", true},
            {"start_line", "integer", "Starting line number (1-indexed, inclusive). Optional.", false},
            {"end_line",   "integer", "Ending line number (1-indexed, inclusive). Optional.", false},
        },
        true,
        tool_read_file
    });

    srv.register_tool({
        "write_file",
        "Create or overwrite a file with the given content. "
        "Parent directories will be created automatically. "
        "If the file is open in the editor, it will be synced.",
        {
            {"path",    "string", "Absolute or workspace-relative path.", true},
            {"content", "string", "Complete file content to write.", true},
        },
        false,
        tool_write_file
    });

    srv.register_tool({
        "edit_file",
        "Edit a file by replacing an exact text occurrence (str_replace pattern). "
        "old_text must match exactly one location in the file. Include enough context "
        "(3-5 surrounding lines) to ensure uniqueness.",
        {
            {"path",     "string", "Absolute or workspace-relative path.", true},
            {"old_text", "string", "Exact text to find and replace. Must match exactly once.", true},
            {"new_text", "string", "Replacement text.", true},
        },
        false,
        tool_edit_file
    });

    srv.register_tool({
        "list_directory",
        "List files and subdirectories in a directory. Shows names with sizes. "
        "Directories have trailing '/'. If path is omitted, lists the workspace root.",
        {
            {"path", "string", "Directory path. Defaults to workspace root if omitted.", false},
        },
        true,
        tool_list_directory
    });

    srv.register_tool({
        "search_workspace",
        "Search for text in files across the workspace. Returns matching lines with "
        "file paths and line numbers. Supports regex. Case-insensitive by default.",
        {
            {"query",   "string",  "Text or regex pattern to search for.", true},
            {"path",    "string",  "Restrict search to this subdirectory. Optional.", false},
            {"include", "string",  "Only search files matching this name/extension pattern.", false},
            {"exclude", "string",  "Comma-separated directory names to exclude.", false},
            {"regex",   "boolean", "Treat query as ECMAScript regex. Default: false.", false},
        },
        true,
        tool_search_workspace
    });

    srv.register_tool({
        "run_command",
        "Execute a shell command and return its output. Runs via cmd.exe. "
        "Default timeout: 30 seconds. Maximum timeout: 120 seconds. "
        "Output is captured (stdout + stderr) and truncated at 64KB.",
        {
            {"command",    "string",  "Shell command to execute.", true},
            {"timeout_ms", "integer", "Timeout in milliseconds (1000-120000). Default: 30000.", false},
            {"cwd",        "string",  "Working directory. Defaults to workspace root.", false},
        },
        false,
        tool_run_command
    });
}

}
