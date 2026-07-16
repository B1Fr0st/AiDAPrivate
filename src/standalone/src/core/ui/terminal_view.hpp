#pragma once


#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "../infra/win_thread.hpp"
#endif
#include "imgui/imgui.h"
#include "theme.hpp"
#include "clock.hpp"
#include "motion.hpp"
#include "transition.hpp"
#include "fonts.hpp"

#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace terminal_view
{


struct Cell {
    char     ch    = ' ';
    ImU32    fg    = IM_COL32(204, 204, 204, 255);
    ImU32    bg    = IM_COL32(0, 0, 0, 0);
    bool     bold  = false;
};


struct TerminalSession
{
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    HPCON                hPC          = INVALID_HANDLE_VALUE;
    HANDLE               hPipeIn      = INVALID_HANDLE_VALUE;
    HANDLE               hPipeOut     = INVALID_HANDLE_VALUE;
    HANDLE               hProcess     = INVALID_HANDLE_VALUE;
    HANDLE               hThread      = INVALID_HANDLE_VALUE;


    aida::infra::win_thread::joinable_thread_t reader_thread;
    std::atomic<bool>    stop_reader{false};
    std::atomic<bool>    reader_done{true};
#else
    std::atomic<bool>    stop_reader{false};
    std::atomic<bool>    reader_done{true};
#endif


    std::mutex           buffer_mtx;
    std::deque<std::vector<Cell>> lines;
    static constexpr int MAX_LINES = 10000;
    int                  cols     = 120;
    int                  rows_vis = 24;


    ImU32                cur_fg   = IM_COL32(204, 204, 204, 255);
    ImU32                cur_bg   = IM_COL32(0, 0, 0, 0);
    bool                 cur_bold = false;


    int                  cursor_row = 0;
    int                  cursor_col = 0;


    float                scroll_y = 0.f;
    bool                 scroll_to_bottom = true;
    bool                 auto_follow = true;


    std::string          title = "Terminal";
    std::atomic<bool>    alive{false};


    char                 input_buf[4096] = {};


    int                  prev_line_count = 0;
    std::deque<float>    line_entrance_time;
    aida::ui::flash_t    bell_flash;
    std::atomic<bool>    bell_pending{false};
};


inline ImU32 ansi_color(int idx, bool bright)
{

    static const ImU32 normal[8] = {
        IM_COL32(  0,   0,   0, 255), IM_COL32(170,   0,   0, 255),
        IM_COL32(  0, 170,   0, 255), IM_COL32(170, 170,   0, 255),
        IM_COL32(  0,   0, 170, 255), IM_COL32(170,   0, 170, 255),
        IM_COL32(  0, 170, 170, 255), IM_COL32(170, 170, 170, 255),
    };
    static const ImU32 bold[8] = {
        IM_COL32( 85,  85,  85, 255), IM_COL32(255,  85,  85, 255),
        IM_COL32( 85, 255,  85, 255), IM_COL32(255, 255,  85, 255),
        IM_COL32( 85,  85, 255, 255), IM_COL32(255,  85, 255, 255),
        IM_COL32( 85, 255, 255, 255), IM_COL32(255, 255, 255, 255),
    };
    if (idx < 0 || idx > 7) idx = 7;
    return bright ? bold[idx] : normal[idx];
}


inline void parse_ansi_sgr(TerminalSession& s, const std::string& params)
{

    std::vector<int> codes;
    {
        int val = 0;
        bool has = false;
        for (char c : params) {
            if (c >= '0' && c <= '9') {
                val = val * 10 + (c - '0');
                has = true;
            } else if (c == ';') {
                codes.push_back(has ? val : 0);
                val = 0;
                has = false;
            }
        }
        codes.push_back(has ? val : 0);
    }

    for (size_t i = 0; i < codes.size(); ++i) {
        int c = codes[i];
        if (c == 0) {
            s.cur_fg = IM_COL32(204, 204, 204, 255);
            s.cur_bg = IM_COL32(0, 0, 0, 0);
            s.cur_bold = false;
        } else if (c == 1) {
            s.cur_bold = true;
        } else if (c == 22) {
            s.cur_bold = false;
        } else if (c >= 30 && c <= 37) {
            s.cur_fg = ansi_color(c - 30, s.cur_bold);
        } else if (c == 39) {
            s.cur_fg = IM_COL32(204, 204, 204, 255);
        } else if (c >= 40 && c <= 47) {
            s.cur_bg = ansi_color(c - 40, false);
        } else if (c == 49) {
            s.cur_bg = IM_COL32(0, 0, 0, 0);
        } else if (c >= 90 && c <= 97) {
            s.cur_fg = ansi_color(c - 90, true);
        } else if (c >= 100 && c <= 107) {
            s.cur_bg = ansi_color(c - 100, true);
        } else if (c == 38 && i + 2 < codes.size() && codes[i + 1] == 5) {

            int n = codes[i + 2];
            i += 2;
            if (n < 8)        s.cur_fg = ansi_color(n, false);
            else if (n < 16)  s.cur_fg = ansi_color(n - 8, true);
            else if (n < 232) {
                n -= 16;
                int r = (n / 36) * 51, g = ((n % 36) / 6) * 51, b = (n % 6) * 51;
                s.cur_fg = IM_COL32(r, g, b, 255);
            } else {
                int v = 8 + (n - 232) * 10;
                s.cur_fg = IM_COL32(v, v, v, 255);
            }
        } else if (c == 48 && i + 2 < codes.size() && codes[i + 1] == 5) {
            int n = codes[i + 2];
            i += 2;
            if (n < 8)        s.cur_bg = ansi_color(n, false);
            else if (n < 16)  s.cur_bg = ansi_color(n - 8, true);
            else if (n < 232) {
                n -= 16;
                int r = (n / 36) * 51, g = ((n % 36) / 6) * 51, b = (n % 6) * 51;
                s.cur_bg = IM_COL32(r, g, b, 255);
            } else {
                int v = 8 + (n - 232) * 10;
                s.cur_bg = IM_COL32(v, v, v, 255);
            }
        } else if (c == 38 && i + 4 < codes.size() && codes[i + 1] == 2) {

            s.cur_fg = IM_COL32(codes[i + 2], codes[i + 3], codes[i + 4], 255);
            i += 4;
        } else if (c == 48 && i + 4 < codes.size() && codes[i + 1] == 2) {
            s.cur_bg = IM_COL32(codes[i + 2], codes[i + 3], codes[i + 4], 255);
            i += 4;
        }
    }
}

inline void ensure_line(TerminalSession& s, int row)
{
    if (row < 0)
        return;
    const size_t row_index = static_cast<size_t>(row);
    const size_t column_count = static_cast<size_t>(std::max(0, s.cols));
    while (s.lines.size() <= row_index)
        s.lines.push_back(std::vector<Cell>(column_count));
}

inline void push_char(TerminalSession& s, char ch)
{
    if (ch == '\n') {
        s.cursor_row++;
        s.cursor_col = 0;
        s.scroll_to_bottom = true;
        return;
    }
    if (ch == '\r') {
        s.cursor_col = 0;
        return;
    }
    if (ch == '\t') {
        int next = (s.cursor_col + 8) & ~7;
        while (s.cursor_col < next && s.cursor_col < s.cols) {
            ensure_line(s, s.cursor_row);
            auto& row = s.lines[static_cast<size_t>(s.cursor_row)];
            if (s.cursor_col < static_cast<int>(row.size())) {
                row[static_cast<size_t>(s.cursor_col)] = Cell{' ', s.cur_fg, s.cur_bg, s.cur_bold};
            }
            s.cursor_col++;
        }
        return;
    }
    if (ch == '\b') {
        if (s.cursor_col > 0) s.cursor_col--;
        return;
    }
    if (ch == '\x07') {
        s.bell_pending.store(true, std::memory_order_release);
        return;
    }

    ensure_line(s, s.cursor_row);
    auto& row = s.lines[static_cast<size_t>(s.cursor_row)];
    if (s.cursor_col >= static_cast<int>(row.size()))
        row.resize(static_cast<size_t>(s.cursor_col) + 1U);
    row[static_cast<size_t>(s.cursor_col)] = Cell{ch, s.cur_fg, s.cur_bg, s.cur_bold};
    s.cursor_col++;
    if (s.cursor_col >= s.cols) {
        s.cursor_col = 0;
        s.cursor_row++;
    }
}


inline void process_output(TerminalSession& s, const char* data, size_t len)
{
    std::lock_guard<std::mutex> lk(s.buffer_mtx);

    enum { NORMAL, ESC, CSI } state = NORMAL;
    std::string csi_params;

    for (size_t i = 0; i < len; ++i) {
        char ch = data[i];
        switch (state) {
        case NORMAL:
            if (ch == '\x1b') {
                state = ESC;
            } else {
                push_char(s, ch);
            }
            break;
        case ESC:
            if (ch == '[') {
                state = CSI;
                csi_params.clear();
            } else if (ch == ']') {

                for (++i; i < len; ++i) {
                    if (data[i] == '\x07') {
                        s.bell_pending.store(true, std::memory_order_release);
                        break;
                    }
                    if (data[i] == '\x1b' && i + 1 < len && data[i + 1] == '\\') { ++i; break; }
                }
                state = NORMAL;
            } else {
                state = NORMAL;
            }
            break;
        case CSI:
            if ((ch >= '0' && ch <= '9') || ch == ';' || ch == '?') {
                csi_params += ch;
            } else {

                if (ch == 'm') {
                    parse_ansi_sgr(s, csi_params);
                } else if (ch == 'H' || ch == 'f') {

                    int r = 1, c2 = 1;
                    if (!csi_params.empty()) {
                        auto semi = csi_params.find(';');
                        if (semi != std::string::npos) {
                            r  = std::max(1, atoi(csi_params.substr(0, semi).c_str()));
                            c2 = std::max(1, atoi(csi_params.substr(semi + 1).c_str()));
                        } else {
                            r = std::max(1, atoi(csi_params.c_str()));
                        }
                    }
                    s.cursor_row = r - 1;
                    s.cursor_col = c2 - 1;
                } else if (ch == 'J') {

                    int mode = csi_params.empty() ? 0 : atoi(csi_params.c_str());
                    if (mode == 2 || mode == 3) {
                        s.lines.clear();
                        s.cursor_row = 0;
                        s.cursor_col = 0;
                    }
                } else if (ch == 'K') {

                    ensure_line(s, s.cursor_row);
                    auto& row = s.lines[static_cast<size_t>(s.cursor_row)];
                    int mode = csi_params.empty() ? 0 : atoi(csi_params.c_str());
                    if (mode == 0) {
                        for (int j = s.cursor_col; j < static_cast<int>(row.size()); ++j)
                            row[static_cast<size_t>(j)] = Cell{};
                    } else if (mode == 1) {
                        for (int j = 0; j <= s.cursor_col && j < static_cast<int>(row.size()); ++j)
                            row[static_cast<size_t>(j)] = Cell{};
                    } else if (mode == 2) {
                        for (auto& cell : row) cell = Cell{};
                    }
                } else if (ch == 'A') {
                    int n = csi_params.empty() ? 1 : std::max(1, atoi(csi_params.c_str()));
                    s.cursor_row = std::max(0, s.cursor_row - n);
                } else if (ch == 'B') {
                    int n = csi_params.empty() ? 1 : std::max(1, atoi(csi_params.c_str()));
                    s.cursor_row += n;
                } else if (ch == 'C') {
                    int n = csi_params.empty() ? 1 : std::max(1, atoi(csi_params.c_str()));
                    s.cursor_col = std::min(s.cols - 1, s.cursor_col + n);
                } else if (ch == 'D') {
                    int n = csi_params.empty() ? 1 : std::max(1, atoi(csi_params.c_str()));
                    s.cursor_col = std::max(0, s.cursor_col - n);
                }

                state = NORMAL;
            }
            break;
        }
    }


    while (static_cast<int>(s.lines.size()) > TerminalSession::MAX_LINES) {
        s.lines.pop_front();
        if (s.cursor_row > 0) s.cursor_row--;
    }
    if (s.cursor_row < 0) s.cursor_row = 0;
}


inline void reader_thread_func(TerminalSession* s)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (s)
        s->reader_done.store(true, std::memory_order_release);
#else
    if (!s)
        return;
    char buf[4096];
    try {
        while (!s->stop_reader.load(std::memory_order_acquire)) {
            DWORD bytes_read = 0;
            BOOL ok = ReadFile(s->hPipeIn, buf, sizeof(buf), &bytes_read, nullptr);
            if (!ok || bytes_read == 0) {
                s->alive.store(false, std::memory_order_release);
                break;
            }
            process_output(*s, buf, bytes_read);
        }
    } catch (...) {
        s->alive.store(false, std::memory_order_release);
    }
    s->reader_done.store(true, std::memory_order_release);
#endif
}


inline bool create_session(TerminalSession& s, const wchar_t* shell = nullptr)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    (void)shell;
    {
        std::lock_guard<std::mutex> lk(s.buffer_mtx);
        s.lines.clear();
        s.line_entrance_time.clear();
        s.cursor_row = 0;
        s.cursor_col = 0;
        s.scroll_y = 0.f;
        s.scroll_to_bottom = true;
        s.auto_follow = true;
        s.prev_line_count = 0;
    }
    const char fixture[] =
        "\x1b[38;5;75mAiDA Reverse Engineering Console\x1b[0m\r\n"
        "Workspace  C:\\samples\\nightfall.exe\r\n"
        "Architecture  x86-64  |  Image base  0x140000000\r\n"
        "\r\n"
        "PS C:\\analysis> aida inspect .\\nightfall.exe\r\n"
        "\x1b[38;5;114m[ready]\x1b[0m  2,814 functions  47,203 xrefs  186 imports\r\n"
        "PS C:\\analysis> ";
    process_output(s, fixture, sizeof(fixture) - 1);
    s.title = "PowerShell - AiDA Workspace";
    s.alive.store(true, std::memory_order_release);
    s.reader_done.store(true, std::memory_order_release);
    return true;
#else
    if (!shell)
        shell = L"powershell.exe";


    HANDLE hPipeInRead = INVALID_HANDLE_VALUE, hPipeInWrite = INVALID_HANDLE_VALUE;
    HANDLE hPipeOutRead = INVALID_HANDLE_VALUE, hPipeOutWrite = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&hPipeInRead, &hPipeInWrite, nullptr, 0))
        return false;
    if (!CreatePipe(&hPipeOutRead, &hPipeOutWrite, nullptr, 0)) {
        CloseHandle(hPipeInRead);
        CloseHandle(hPipeInWrite);
        return false;
    }


    COORD size{};
    size.X = static_cast<SHORT>(s.cols);
    size.Y = static_cast<SHORT>(s.rows_vis);

    HRESULT hr = CreatePseudoConsole(size, hPipeInRead, hPipeOutWrite, 0, &s.hPC);
    if (FAILED(hr)) {
        CloseHandle(hPipeInRead);
        CloseHandle(hPipeInWrite);
        CloseHandle(hPipeOutRead);
        CloseHandle(hPipeOutWrite);
        return false;
    }


    CloseHandle(hPipeInRead);
    CloseHandle(hPipeOutWrite);

    s.hPipeIn  = hPipeOutRead;
    s.hPipeOut = hPipeInWrite;


    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    std::vector<BYTE> attr_buf(attr_size);
    auto attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
    if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
        ClosePseudoConsole(s.hPC);
        s.hPC = INVALID_HANDLE_VALUE;
        CloseHandle(s.hPipeIn);
        CloseHandle(s.hPipeOut);
        return false;
    }
    if (!UpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   s.hPC, sizeof(HPCON), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attr_list);
        ClosePseudoConsole(s.hPC);
        s.hPC = INVALID_HANDLE_VALUE;
        CloseHandle(s.hPipeIn);
        CloseHandle(s.hPipeOut);
        return false;
    }

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attr_list;

    PROCESS_INFORMATION pi{};
    wchar_t cmd[512];
    wcscpy_s(cmd, shell);

    BOOL created = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                                  EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                                  nullptr, nullptr, &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attr_list);

    if (!created) {
        ClosePseudoConsole(s.hPC);
        s.hPC = INVALID_HANDLE_VALUE;
        CloseHandle(s.hPipeIn);
        CloseHandle(s.hPipeOut);
        return false;
    }

    s.hProcess = pi.hProcess;
    s.hThread  = pi.hThread;
    s.alive.store(true, std::memory_order_release);


    s.stop_reader.store(false, std::memory_order_release);
    s.reader_done.store(false, std::memory_order_release);
    std::string reader_err;
    if (!s.reader_thread.start([&s]() { reader_thread_func(&s); },
            &reader_err,
            aida::infra::win_thread::default_stack_reserve,
            "terminal_reader")) {
        s.stop_reader.store(true, std::memory_order_release);
        s.reader_done.store(true, std::memory_order_release);
        s.alive.store(false, std::memory_order_release);
        if (s.hPC != INVALID_HANDLE_VALUE) {
            ClosePseudoConsole(s.hPC);
            s.hPC = INVALID_HANDLE_VALUE;
        }
        if (s.hPipeIn != INVALID_HANDLE_VALUE) {
            CloseHandle(s.hPipeIn);
            s.hPipeIn = INVALID_HANDLE_VALUE;
        }
        if (s.hPipeOut != INVALID_HANDLE_VALUE) {
            CloseHandle(s.hPipeOut);
            s.hPipeOut = INVALID_HANDLE_VALUE;
        }
        if (s.hProcess != INVALID_HANDLE_VALUE) {
            TerminateProcess(s.hProcess, 1);
            CloseHandle(s.hProcess);
            s.hProcess = INVALID_HANDLE_VALUE;
        }
        if (s.hThread != INVALID_HANDLE_VALUE) {
            CloseHandle(s.hThread);
            s.hThread = INVALID_HANDLE_VALUE;
        }
        return false;
    }

    return true;
#endif
}


inline void send_input(TerminalSession& s, const char* data, size_t len)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (!s.alive.load(std::memory_order_acquire) || data == nullptr || len == 0)
        return;
    process_output(s, data, len);
#else
    if (s.hPipeOut == INVALID_HANDLE_VALUE || !s.alive.load(std::memory_order_acquire))
        return;
    DWORD written = 0;
    WriteFile(s.hPipeOut, data, static_cast<DWORD>(len), &written, nullptr);
#endif
}

inline void clear_session(TerminalSession& s)
{
    std::lock_guard<std::mutex> lk(s.buffer_mtx);
    s.lines.clear();
    s.line_entrance_time.clear();
    s.cursor_row = 0;
    s.cursor_col = 0;
    s.scroll_y = 0.f;
    s.scroll_to_bottom = true;
    s.auto_follow = true;
    s.prev_line_count = 0;
}

inline bool try_clear_session(TerminalSession& s)
{
    std::unique_lock<std::mutex> lk(s.buffer_mtx, std::try_to_lock);
    if (!lk.owns_lock())
        return false;
    s.lines.clear();
    s.line_entrance_time.clear();
    s.cursor_row = 0;
    s.cursor_col = 0;
    s.scroll_y = 0.f;
    s.scroll_to_bottom = true;
    s.auto_follow = true;
    s.prev_line_count = 0;
    return true;
}

inline bool try_copy_all_text(TerminalSession& s, std::string& all_text)
{
    std::unique_lock<std::mutex> lk(s.buffer_mtx, std::try_to_lock);
    if (!lk.owns_lock())
        return false;
    all_text.clear();
    all_text.reserve(s.lines.size() * static_cast<size_t>(std::max(1, s.cols + 1)));
    for (auto& row : s.lines) {
        for (auto& cell : row)
            all_text += cell.ch;
        while (!all_text.empty() && all_text.back() == ' ')
            all_text.pop_back();
        all_text += '\n';
    }
    return true;
}

inline void send_key(TerminalSession& s, char ch)
{
    send_input(s, &ch, 1);
}


inline void resize_pty(TerminalSession& s, int cols, int rows)
{
    s.cols = cols;
    s.rows_vis = rows;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (s.hPC != INVALID_HANDLE_VALUE) {
        COORD size;
        size.X = static_cast<SHORT>(cols);
        size.Y = static_cast<SHORT>(rows);
        ResizePseudoConsole(s.hPC, size);
    }
#endif
}


inline void destroy_session(TerminalSession& s)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    s.stop_reader.store(true, std::memory_order_release);
    s.alive.store(false, std::memory_order_release);
    s.reader_done.store(true, std::memory_order_release);
#else
    s.stop_reader.store(true, std::memory_order_release);
    s.alive.store(false, std::memory_order_release);

    unsigned reader_tid = 0;
    const HANDLE log_pipe_in = s.hPipeIn;
    const HANDLE log_pipe_out = s.hPipeOut;
    const HPCON log_hpc = s.hPC;
    const HANDLE log_process = s.hProcess;
    if (s.reader_thread.joinable()) {
        reader_tid = s.reader_thread.id();
        if (reader_tid != 0) {
            HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, static_cast<DWORD>(reader_tid));
            if (hThread) {
                CancelSynchronousIo(hThread);
                CloseHandle(hThread);
            }
        }
    }

    if (s.hPipeOut != INVALID_HANDLE_VALUE) {
        CloseHandle(s.hPipeOut);
        s.hPipeOut = INVALID_HANDLE_VALUE;
    }
    if (s.hPipeIn != INVALID_HANDLE_VALUE) {
        CloseHandle(s.hPipeIn);
        s.hPipeIn = INVALID_HANDLE_VALUE;
    }
    if (s.hPC != INVALID_HANDLE_VALUE) {
        ClosePseudoConsole(s.hPC);
        s.hPC = INVALID_HANDLE_VALUE;
    }
    if (s.hProcess != INVALID_HANDLE_VALUE)
        TerminateProcess(s.hProcess, 0);
    if (s.reader_thread.joinable()) {
        if (!s.reader_thread.join_for(10000)) {
            diag::log_tagged_fmt("terminal",
                "reader_join_timeout tid=%u pipe_in=%p pipe_out=%p hpc=%p process=%p",
                reader_tid,
                log_pipe_in,
                log_pipe_out,
                log_hpc,
                log_process);
            s.reader_thread.join();
        }
    }
    while (!s.reader_done.load(std::memory_order_acquire)) {
        Sleep(1);
    }
    if (s.hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(s.hProcess);
        s.hProcess = INVALID_HANDLE_VALUE;
    }
    if (s.hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(s.hThread);
        s.hThread = INVALID_HANDLE_VALUE;
    }
#endif
}


inline void render_terminal(TerminalSession& s, const ImVec2& size, ImU32 bg_color,
                            ImU32 accent_color)
{
    const auto& th = aida::ui::resolved();
    ImU32 surface_bg = (bg_color != 0) ? bg_color : th.bg_elevated;
    const ImU32 terminal_accent = accent_color != 0 ? accent_color : th.accent_u32;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, surface_bg);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.f, 6.f));

    if (!ImGui::BeginChild("##term_view", size, false,
                           ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        return;
    }

    ImFont* mono = aida::ui::fonts::code();
    bool pushed_font = false;
    if (mono) { ImGui::PushFont(mono); pushed_font = true; }

    const float line_height = ImGui::GetTextLineHeight();
    const float char_width  = ImGui::GetFont()->CalcTextSizeA(ImGui::GetFontSize(), FLT_MAX, 0.f, "M").x;
    const ImVec2 origin     = ImGui::GetCursorScreenPos();
    const ImVec2 win_pos    = ImGui::GetWindowPos();
    const ImVec2 win_size   = ImGui::GetWindowSize();
    auto* dl = ImGui::GetWindowDrawList();


    const float avail_h = ImGui::GetContentRegionAvail().y;
    const int vis_rows  = static_cast<int>(avail_h / line_height);

    int total_lines;
    int new_lines_added = 0;
    int lines_popped_front = 0;
    {
        std::unique_lock<std::mutex> lk(s.buffer_mtx, std::try_to_lock);
        if (!lk.owns_lock()) {
            if (pushed_font) ImGui::PopFont();
            ImGui::EndChild();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor();
            return;
        }
        total_lines = static_cast<int>(s.lines.size());
        int raw_delta = total_lines - s.prev_line_count;
        if (raw_delta >= 0) {
            new_lines_added = raw_delta;
        } else {
            lines_popped_front = -raw_delta;
        }
        s.prev_line_count = total_lines;
    }

    while (lines_popped_front > 0 && !s.line_entrance_time.empty()) {
        s.line_entrance_time.pop_front();
        --lines_popped_front;
    }
    while (s.line_entrance_time.size() > static_cast<size_t>(total_lines))
        s.line_entrance_time.pop_front();

    bool burst = (new_lines_added > 100);
    if (!burst && new_lines_added > 0) {
        for (int i = 0; i < new_lines_added; ++i) {
            int line_idx = total_lines - new_lines_added + i;
            if (line_idx < 0) continue;
            s.line_entrance_time.push_back(aida::ui::clock::seconds());
            while (s.line_entrance_time.size() > static_cast<size_t>(TerminalSession::MAX_LINES))
                s.line_entrance_time.pop_front();
        }
    } else if (burst) {
        s.line_entrance_time.clear();
    }


    float max_scroll = static_cast<float>(std::max(0, total_lines - vis_rows));

    if (ImGui::IsWindowHovered()) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f) {
            s.scroll_y -= wheel * 3.f;
            s.scroll_y = std::max(0.f, std::min(s.scroll_y, max_scroll));
            s.auto_follow = (s.scroll_y >= max_scroll - 0.5f);
        }
    }

    if (s.scroll_to_bottom) {
        s.auto_follow = true;
        s.scroll_to_bottom = false;
    }

    if (s.auto_follow) {
        s.scroll_y = max_scroll;
    } else if (s.scroll_y > max_scroll) {
        s.scroll_y = max_scroll;
    }

    if (s.bell_pending.exchange(false, std::memory_order_acq_rel)) {
        s.bell_flash.trigger();
    }

    const int start_line = static_cast<int>(s.scroll_y);
    const bool window_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    const float now = aida::ui::clock::seconds();
    const float entrance_dur = 0.080f;

    {
        std::unique_lock<std::mutex> lk(s.buffer_mtx, std::try_to_lock);
        if (!lk.owns_lock()) {
            if (pushed_font) ImGui::PopFont();
            ImGui::EndChild();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor();
            return;
        }

        const int render_total_lines = static_cast<int>(s.lines.size());
        size_t entrance_offset = 0;
        if (s.line_entrance_time.size() < static_cast<size_t>(render_total_lines))
            entrance_offset = static_cast<size_t>(render_total_lines) - s.line_entrance_time.size();

        for (int vi = 0; vi < vis_rows && (start_line + vi) < render_total_lines; ++vi) {
            int line_idx = start_line + vi;
            const auto& row = s.lines[static_cast<size_t>(line_idx)];

            float row_alpha = 1.f;
            float row_y_off = 0.f;
            if (!burst && static_cast<size_t>(line_idx) >= entrance_offset) {
                size_t et_idx = static_cast<size_t>(line_idx) - entrance_offset;
                if (et_idx < s.line_entrance_time.size()) {
                    float age = now - s.line_entrance_time[et_idx];
                    if (age < entrance_dur) {
                        float t01 = age / entrance_dur;
                        if (t01 < 0.f) t01 = 0.f;
                        float eased = aida::motion::ease::out_cubic(t01);
                        row_alpha = eased;
                        row_y_off = (1.f - eased) * (line_height * 0.5f);
                    }
                }
            }

            const float y = origin.y + static_cast<float>(vi) * line_height + row_y_off;

            const size_t rendered_columns = std::min(row.size(),
                static_cast<size_t>(std::max(0, s.cols)));
            for (size_t ci = 0; ci < rendered_columns; ++ci) {
                const auto& cell = row[ci];
                const float x = origin.x + static_cast<float>(ci) * char_width;


                if ((cell.bg & IM_COL32_A_MASK) != 0) {
                    dl->AddRectFilled(ImVec2(x, y), ImVec2(x + char_width, y + line_height),
                                      aida::ui::with_alpha(cell.bg, row_alpha));
                }


                if (cell.ch > ' ') {
                    char str[2] = {cell.ch, 0};
                    dl->AddText(ImVec2(x, y), aida::ui::with_alpha(cell.fg, row_alpha), str);
                }
            }
        }


        if (s.alive.load(std::memory_order_acquire) && s.cursor_row >= start_line && s.cursor_row < start_line + vis_rows) {
            const float cx = origin.x + static_cast<float>(s.cursor_col) * char_width;
            const float cy = origin.y + static_cast<float>(s.cursor_row - start_line) * line_height;
            float blink_alpha = 0.85f;
            if (window_focused) {
                blink_alpha = aida::ui::clock::pulse(2.0f, 0.30f, 1.0f);
            } else {
                blink_alpha = 0.30f;
            }
            ImU32 cursor_col = aida::ui::with_alpha(terminal_accent, blink_alpha);
            dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + char_width, cy + line_height), cursor_col);
            if (window_focused) {
                ImU32 glow = aida::ui::with_alpha(th.accent_glow, blink_alpha * 0.7f);
                dl->AddRectFilled(ImVec2(cx - 1.f, cy - 1.f),
                                   ImVec2(cx + char_width + 1.f, cy + line_height + 1.f), glow);
            }
        }
    }

    if (pushed_font) ImGui::PopFont();

    float bell_v = s.bell_flash.tick(aida::ui::clock::dt(), 3.3f);
    if (bell_v > 0.001f) {
        ImU32 bell_col = aida::ui::with_alpha(terminal_accent, bell_v);
        dl->AddRect(ImVec2(win_pos.x + 1.f, win_pos.y + 1.f),
                    ImVec2(win_pos.x + win_size.x - 1.f, win_pos.y + win_size.y - 1.f),
                    bell_col, 0.f, 0, 2.f);
    }

    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();


}


struct TerminalManager
{
    std::vector<TerminalSession*> sessions;
    int active_tab = -1;

    TerminalSession* create_terminal(const wchar_t* shell = nullptr)
    {
        auto* s = new TerminalSession();
        s->title = "Terminal " + std::to_string(sessions.size() + 1);
        if (create_session(*s, shell)) {
            sessions.push_back(s);
            active_tab = static_cast<int>(sessions.size()) - 1;
            return s;
        }
        delete s;
        return nullptr;
    }

    void close_terminal(int idx)
    {
        if (idx < 0 || idx >= static_cast<int>(sessions.size()))
            return;
        const size_t session_index = static_cast<size_t>(idx);
        destroy_session(*sessions[session_index]);
        delete sessions[session_index];
        sessions.erase(sessions.begin() + static_cast<std::ptrdiff_t>(session_index));
        if (active_tab >= static_cast<int>(sessions.size()))
            active_tab = static_cast<int>(sessions.size()) - 1;
    }

    void shutdown()
    {
        for (auto* s : sessions) {
            destroy_session(*s);
            delete s;
        }
        sessions.clear();
        active_tab = -1;
    }

    bool has_active() const { return active_tab >= 0 && active_tab < static_cast<int>(sessions.size()); }
    TerminalSession* current() { return has_active() ? sessions[static_cast<size_t>(active_tab)] : nullptr; }
};

}
