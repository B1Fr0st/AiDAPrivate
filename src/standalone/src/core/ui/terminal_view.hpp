#pragma once


#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "work_queue.hpp"
#include "imgui/imgui.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
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

    HPCON                hPC          = INVALID_HANDLE_VALUE;
    HANDLE               hPipeIn      = INVALID_HANDLE_VALUE;
    HANDLE               hPipeOut     = INVALID_HANDLE_VALUE;
    HANDLE               hProcess     = INVALID_HANDLE_VALUE;
    HANDLE               hThread      = INVALID_HANDLE_VALUE;


    std::thread          reader_thread;
    std::atomic<bool>    stop_reader{false};


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


    std::string          title = "Terminal";
    bool                 alive = false;


    char                 input_buf[4096] = {};
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
    while (static_cast<int>(s.lines.size()) <= row)
        s.lines.push_back(std::vector<Cell>(s.cols));
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
            auto& row = s.lines[s.cursor_row];
            if (s.cursor_col < static_cast<int>(row.size())) {
                row[s.cursor_col] = Cell{' ', s.cur_fg, s.cur_bg, s.cur_bold};
            }
            s.cursor_col++;
        }
        return;
    }
    if (ch == '\b') {
        if (s.cursor_col > 0) s.cursor_col--;
        return;
    }

    ensure_line(s, s.cursor_row);
    auto& row = s.lines[s.cursor_row];
    if (s.cursor_col >= static_cast<int>(row.size()))
        row.resize(s.cursor_col + 1);
    row[s.cursor_col] = Cell{ch, s.cur_fg, s.cur_bg, s.cur_bold};
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
                    if (data[i] == '\x07') break;
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
                    auto& row = s.lines[s.cursor_row];
                    int mode = csi_params.empty() ? 0 : atoi(csi_params.c_str());
                    if (mode == 0) {
                        for (int j = s.cursor_col; j < static_cast<int>(row.size()); ++j)
                            row[j] = Cell{};
                    } else if (mode == 1) {
                        for (int j = 0; j <= s.cursor_col && j < static_cast<int>(row.size()); ++j)
                            row[j] = Cell{};
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
        s.cursor_row--;
    }
}


inline void reader_thread_func(TerminalSession* s)
{
    char buf[4096];
    while (!s->stop_reader.load(std::memory_order_acquire)) {
        DWORD bytes_read = 0;
        BOOL ok = ReadFile(s->hPipeIn, buf, sizeof(buf), &bytes_read, nullptr);
        if (!ok || bytes_read == 0) {

            s->alive = false;
            break;
        }
        process_output(*s, buf, bytes_read);
    }
}


inline bool create_session(TerminalSession& s, const wchar_t* shell = nullptr)
{
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
    s.alive    = true;


    s.stop_reader.store(false);
    s.reader_thread = {};
    work_queue::post([&s]() { reader_thread_func(&s); });

    return true;
}


inline void send_input(TerminalSession& s, const char* data, size_t len)
{
    if (s.hPipeOut == INVALID_HANDLE_VALUE || !s.alive)
        return;
    DWORD written = 0;
    WriteFile(s.hPipeOut, data, static_cast<DWORD>(len), &written, nullptr);
}

inline void send_key(TerminalSession& s, char ch)
{
    send_input(s, &ch, 1);
}


inline void resize_pty(TerminalSession& s, int cols, int rows)
{
    s.cols = cols;
    s.rows_vis = rows;
    if (s.hPC != INVALID_HANDLE_VALUE) {
        COORD size;
        size.X = static_cast<SHORT>(cols);
        size.Y = static_cast<SHORT>(rows);
        ResizePseudoConsole(s.hPC, size);
    }
}


inline void destroy_session(TerminalSession& s)
{
    s.stop_reader.store(true, std::memory_order_release);
    s.alive = false;

    if (s.hPipeOut != INVALID_HANDLE_VALUE) {
        CloseHandle(s.hPipeOut);
        s.hPipeOut = INVALID_HANDLE_VALUE;
    }
    if (s.hPipeIn != INVALID_HANDLE_VALUE) {
        CloseHandle(s.hPipeIn);
        s.hPipeIn = INVALID_HANDLE_VALUE;
    }
    if (s.reader_thread.joinable())
        s.reader_thread.join();
    if (s.hPC != INVALID_HANDLE_VALUE) {
        ClosePseudoConsole(s.hPC);
        s.hPC = INVALID_HANDLE_VALUE;
    }
    if (s.hProcess != INVALID_HANDLE_VALUE) {
        TerminateProcess(s.hProcess, 0);
        CloseHandle(s.hProcess);
        s.hProcess = INVALID_HANDLE_VALUE;
    }
    if (s.hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(s.hThread);
        s.hThread = INVALID_HANDLE_VALUE;
    }
}


inline void render_terminal(TerminalSession& s, const ImVec2& size, ImU32 bg_color,
                            ImU32 accent_color)
{
    ImGui::PushStyleColor(ImGuiCol_ChildBg, bg_color);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6, 4));

    if (!ImGui::BeginChild("##term_view", size, false,
                           ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        return;
    }

    const float line_height = ImGui::GetTextLineHeight();
    const float char_width  = ImGui::CalcTextSize("M").x;
    const ImVec2 origin     = ImGui::GetCursorScreenPos();
    auto* dl = ImGui::GetWindowDrawList();


    const float avail_h = ImGui::GetContentRegionAvail().y;
    const int vis_rows  = static_cast<int>(avail_h / line_height);

    int total_lines;
    {
        std::lock_guard<std::mutex> lk(s.buffer_mtx);
        total_lines = static_cast<int>(s.lines.size());
    }


    if (s.scroll_to_bottom) {
        s.scroll_y = static_cast<float>(std::max(0, total_lines - vis_rows));
        s.scroll_to_bottom = false;
    }


    if (ImGui::IsWindowHovered()) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f) {
            s.scroll_y -= wheel * 3.f;
            s.scroll_y = std::max(0.f, std::min(s.scroll_y,
                static_cast<float>(std::max(0, total_lines - vis_rows))));
        }
    }

    const int start_line = static_cast<int>(s.scroll_y);

    {
        std::lock_guard<std::mutex> lk(s.buffer_mtx);
        for (int vi = 0; vi < vis_rows && (start_line + vi) < total_lines; ++vi) {
            const auto& row = s.lines[start_line + vi];
            const float y = origin.y + vi * line_height;

            for (int ci = 0; ci < static_cast<int>(row.size()) && ci < s.cols; ++ci) {
                const auto& cell = row[ci];
                const float x = origin.x + ci * char_width;


                if ((cell.bg & IM_COL32_A_MASK) != 0) {
                    dl->AddRectFilled(ImVec2(x, y), ImVec2(x + char_width, y + line_height), cell.bg);
                }


                if (cell.ch > ' ') {
                    char str[2] = {cell.ch, 0};
                    dl->AddText(ImVec2(x, y), cell.fg, str);
                }
            }
        }


        if (s.alive && s.cursor_row >= start_line && s.cursor_row < start_line + vis_rows) {
            const float cx = origin.x + s.cursor_col * char_width;
            const float cy = origin.y + (s.cursor_row - start_line) * line_height;
            dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + char_width, cy + line_height),
                              (accent_color & 0x00FFFFFFu) | 0x80000000u);
        }
    }

    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();


    if (ImGui::IsItemHovered() || ImGui::IsItemFocused()) {
        auto& io = ImGui::GetIO();
        for (int k = 0; k < io.InputQueueCharacters.Size; ++k) {
            ImWchar wc = io.InputQueueCharacters[k];
            if (wc < 128) {
                char c = static_cast<char>(wc);
                send_key(s, c);
            }
        }


        if (ImGui::IsKeyPressed(ImGuiKey_Enter))
            send_input(s, "\r", 1);
        if (ImGui::IsKeyPressed(ImGuiKey_Backspace))
            send_input(s, "\x7f", 1);
        if (ImGui::IsKeyPressed(ImGuiKey_Tab))
            send_input(s, "\t", 1);
        if (ImGui::IsKeyPressed(ImGuiKey_Escape))
            send_input(s, "\x1b", 1);
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow))
            send_input(s, "\x1b[A", 3);
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow))
            send_input(s, "\x1b[B", 3);
        if (ImGui::IsKeyPressed(ImGuiKey_RightArrow))
            send_input(s, "\x1b[C", 3);
        if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow))
            send_input(s, "\x1b[D", 3);
        if (ImGui::IsKeyPressed(ImGuiKey_Home))
            send_input(s, "\x1b[H", 3);
        if (ImGui::IsKeyPressed(ImGuiKey_End))
            send_input(s, "\x1b[F", 3);
        if (ImGui::IsKeyPressed(ImGuiKey_Delete))
            send_input(s, "\x1b[3~", 4);


        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C))
            send_input(s, "\x03", 1);

        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_D))
            send_input(s, "\x04", 1);

        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z))
            send_input(s, "\x1a", 1);
    }
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
        destroy_session(*sessions[idx]);
        delete sessions[idx];
        sessions.erase(sessions.begin() + idx);
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
    TerminalSession* current() { return has_active() ? sessions[active_tab] : nullptr; }
};

}
