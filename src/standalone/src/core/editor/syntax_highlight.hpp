#pragma once


#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "imgui/imgui.h"
#include "../ui/theme.hpp"

namespace syntax {


enum class token_type : int {
    keyword = 0,
    type_name,
    string_lit,
    number,
    comment_line,
    comment_block,
    preprocessor,
    operator_sym,
    function_call,
    identifier,
    whitespace,
    punctuation,
    decorator,
    boolean_lit,
    register_name,
    directive,
    COUNT
};

struct token_t {
    token_type type;
    uint32_t   start;
    uint32_t   length;
};


struct language_def_t {
    const char*                    name;
    std::unordered_set<std::string> keywords;
    std::unordered_set<std::string> types;
    std::unordered_set<std::string> registers;
    std::unordered_set<std::string> directives;
    const char*                    line_comment;
    const char*                    block_start;
    const char*                    block_end;
    char                           preproc_char;
    bool                           has_decorators;
    bool                           is_json;
};


inline language_def_t lang_cpp() {
    language_def_t d{};
    d.name = "C/C++";
    d.keywords = {
        "alignas","alignof","auto","break","case","catch","class","const","constexpr",
        "const_cast","continue","decltype","default","delete","do","dynamic_cast","else",
        "enum","explicit","export","extern","false","for","friend","goto","if","inline",
        "mutable","namespace","new","noexcept","nullptr","operator","override","private",
        "protected","public","register","reinterpret_cast","requires","return","short",
        "signed","sizeof","static","static_assert","static_cast","struct","switch",
        "template","this","thread_local","throw","true","try","typedef","typeid",
        "typename","union","unsigned","using","virtual","volatile","while","co_await",
        "co_return","co_yield","concept","consteval","constinit","final","import","module"
    };
    d.types = {
        "void","bool","char","wchar_t","char8_t","char16_t","char32_t","int","float",
        "double","long","size_t","ssize_t","ptrdiff_t","intptr_t","uintptr_t",
        "int8_t","int16_t","int32_t","int64_t","uint8_t","uint16_t","uint32_t","uint64_t",
        "string","vector","map","unordered_map","set","unordered_set","array","deque",
        "list","pair","tuple","optional","variant","any","function","thread","mutex",
        "atomic","shared_ptr","unique_ptr","weak_ptr","string_view","span",
        "DWORD","HANDLE","HMODULE","LPVOID","LPCSTR","LPCWSTR","BOOL","BYTE","WORD",
        "PVOID","SIZE_T","ULONG","ULONG_PTR","NTSTATUS","HRESULT","HWND","HINSTANCE",
        "LPARAM","WPARAM","LRESULT","WNDPROC","LARGE_INTEGER","ULARGE_INTEGER",
        "IMAGE_DOS_HEADER","IMAGE_NT_HEADERS","IMAGE_SECTION_HEADER",
        "IMAGE_IMPORT_DESCRIPTOR","IMAGE_EXPORT_DIRECTORY",
        "PIMAGE_DOS_HEADER","PIMAGE_NT_HEADERS","FILE","nullptr_t"
    };
    d.line_comment  = "//";
    d.block_start   = "/*";
    d.block_end     = "*/";
    d.preproc_char  = '#';
    d.has_decorators = false;
    d.is_json = false;
    return d;
}

inline language_def_t lang_asm() {
    language_def_t d{};
    d.name = "x86 Assembly";
    d.keywords = {
        "mov","movzx","movsx","movsxd","lea","push","pop","call","ret","retn",
        "jmp","je","jne","jz","jnz","jg","jge","jl","jle","ja","jae","jb","jbe",
        "jc","jnc","jo","jno","js","jns","jp","jnp","jecxz","jrcxz","loop","loope","loopne",
        "add","sub","mul","imul","div","idiv","inc","dec","neg","not","and","or","xor",
        "shl","shr","sar","sal","rol","ror","rcl","rcr","bt","bts","btr","btc","bsf","bsr",
        "cmp","test","nop","int","syscall","sysenter","sysret","cpuid","rdtsc","rdtscp",
        "cmove","cmovne","cmovz","cmovnz","cmovg","cmovge","cmovl","cmovle",
        "cmova","cmovae","cmovb","cmovbe","cmovo","cmovno","cmovs","cmovns",
        "sete","setne","setg","setge","setl","setle","seta","setae","setb","setbe",
        "rep","repe","repne","movsb","movsw","movsd","movsq","stosb","stosw","stosd","stosq",
        "lodsb","lodsw","lodsd","lodsq","scasb","scasw","scasd","scasq","cmpsb","cmpsw",
        "cld","std","clc","stc","cli","sti","hlt","wait","lock","xchg","cmpxchg","xadd",
        "bswap","cdq","cqo","cbw","cwde","cdqe","enter","leave",
        "movss","movsd","movaps","movups","movdqa","movdqu","addss","addsd","subss","subsd",
        "mulss","mulsd","divss","divsd","sqrtss","sqrtsd","comiss","comisd","ucomiss","ucomisd",
        "pxor","por","pand","pandn","paddb","paddw","paddd","paddq",
        "punpcklbw","punpckhbw","punpcklwd","punpckhwd","punpckldq","punpckhdq",
        "cvtsi2ss","cvtsi2sd","cvtss2sd","cvtsd2ss","cvtss2si","cvtsd2si",
        "db","dw","dd","dq","dt","resb","resw","resd","resq","equ","times"
    };
    d.registers = {
        "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp","rip",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "eax","ebx","ecx","edx","esi","edi","esp","ebp","eip",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
        "ax","bx","cx","dx","si","di","sp","bp",
        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
        "al","bl","cl","dl","sil","dil","spl","bpl",
        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
        "ah","bh","ch","dh",
        "cs","ds","es","fs","gs","ss",
        "cr0","cr2","cr3","cr4","cr8","dr0","dr1","dr2","dr3","dr6","dr7",
        "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
        "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
        "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
        "ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15",
        "st0","st1","st2","st3","st4","st5","st6","st7"
    };
    d.directives = {
        "section",".text",".data",".bss",".rodata",".code",".const",
        "global","extern","segment","bits","org","align","default",
        "proc","endp","macro","endm","struc","endstruc","include","incbin"
    };
    d.line_comment  = ";";
    d.block_start   = nullptr;
    d.block_end     = nullptr;
    d.preproc_char  = 0;
    d.has_decorators = false;
    d.is_json = false;
    return d;
}

inline language_def_t lang_python() {
    language_def_t d{};
    d.name = "Python";
    d.keywords = {
        "and","as","assert","async","await","break","class","continue","def","del",
        "elif","else","except","finally","for","from","global","if","import","in",
        "is","lambda","nonlocal","not","or","pass","raise","return","try","while",
        "with","yield","True","False","None","match","case","type"
    };
    d.types = {
        "int","float","str","bool","list","dict","tuple","set","frozenset","bytes",
        "bytearray","memoryview","range","complex","type","object","property",
        "classmethod","staticmethod","super","Exception","TypeError","ValueError",
        "KeyError","IndexError","RuntimeError","OSError","IOError","StopIteration"
    };
    d.line_comment  = "#";
    d.block_start   = nullptr;
    d.block_end     = nullptr;
    d.preproc_char  = 0;
    d.has_decorators = true;
    d.is_json = false;
    return d;
}

inline language_def_t lang_json() {
    language_def_t d{};
    d.name = "JSON";
    d.line_comment = nullptr;
    d.block_start  = nullptr;
    d.block_end    = nullptr;
    d.preproc_char = 0;
    d.has_decorators = false;
    d.is_json = true;
    return d;
}

inline language_def_t lang_lua() {
    language_def_t d{};
    d.name = "Lua";
    d.keywords = {
        "and","break","do","else","elseif","end","false","for","function","goto",
        "if","in","local","nil","not","or","repeat","return","then","true","until","while"
    };
    d.types = {
        "string","table","math","io","os","coroutine","debug","package","utf8",
        "number","boolean","thread","userdata"
    };
    d.line_comment = "--";
    d.block_start  = "--[[";
    d.block_end    = "]]";
    d.preproc_char = 0;
    d.has_decorators = false;
    d.is_json = false;
    return d;
}


inline const language_def_t& detect_language(const std::string& filename) {
    static auto s_cpp    = lang_cpp();
    static auto s_asm    = lang_asm();
    static auto s_python = lang_python();
    static auto s_json   = lang_json();
    static auto s_lua    = lang_lua();

    auto ext_pos = filename.rfind('.');
    if (ext_pos == std::string::npos) return s_cpp;
    std::string ext = filename.substr(ext_pos);
    for (auto& c : ext) c = (char)tolower((unsigned char)c);

    if (ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx" ||
        ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".inl")
        return s_cpp;
    if (ext == ".asm" || ext == ".s" || ext == ".nasm" || ext == ".masm" || ext == ".inc")
        return s_asm;
    if (ext == ".py" || ext == ".pyw" || ext == ".pyi")
        return s_python;
    if (ext == ".json" || ext == ".jsonl")
        return s_json;
    if (ext == ".lua" || ext == ".luac")
        return s_lua;

    return s_cpp;
}


inline void tokenize(std::string_view src, const language_def_t& lang,
                     std::vector<token_t>& out)
{
    out.clear();
    const uint32_t n = (uint32_t)src.size();
    uint32_t i = 0;

    auto is_ident_start = [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; };
    auto is_ident_char  = [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'; };
    auto is_digit       = [](char c) { return c >= '0' && c <= '9'; };
    auto starts_with    = [&](uint32_t pos, const char* s) -> bool {
        if (!s) return false;
        for (uint32_t k = 0; s[k]; k++) {
            if (pos + k >= n || src[pos + k] != s[k]) return false;
        }
        return true;
    };

    while (i < n) {

        if (src[i] == ' ' || src[i] == '\t' || src[i] == '\r' || src[i] == '\n') {
            uint32_t s = i;
            while (i < n && (src[i] == ' ' || src[i] == '\t' || src[i] == '\r' || src[i] == '\n'))
                i++;
            out.push_back({ token_type::whitespace, s, i - s });
            continue;
        }


        if (starts_with(i, lang.block_start)) {
            uint32_t s = i;
            uint32_t end_len = lang.block_end ? (uint32_t)strlen(lang.block_end) : 0;
            i += (uint32_t)strlen(lang.block_start);
            while (i < n && !starts_with(i, lang.block_end))
                i++;
            if (i < n) i += end_len;
            out.push_back({ token_type::comment_block, s, i - s });
            continue;
        }


        if (starts_with(i, lang.line_comment)) {
            uint32_t s = i;
            while (i < n && src[i] != '\n')
                i++;
            out.push_back({ token_type::comment_line, s, i - s });
            continue;
        }


        if (lang.preproc_char && src[i] == lang.preproc_char) {
            uint32_t s = i;
            while (i < n && src[i] != '\n') {
                if (src[i] == '\\' && i + 1 < n && src[i + 1] == '\n')
                    i += 2;
                else
                    i++;
            }
            out.push_back({ token_type::preprocessor, s, i - s });
            continue;
        }


        if (lang.has_decorators && src[i] == '@') {
            uint32_t s = i;
            i++;
            while (i < n && is_ident_char(src[i])) i++;
            out.push_back({ token_type::decorator, s, i - s });
            continue;
        }


        if (src[i] == '"' || src[i] == '\'') {
            uint32_t s = i;
            char q = src[i];

            if (i + 2 < n && src[i + 1] == q && src[i + 2] == q) {
                i += 3;
                while (i + 2 < n && !(src[i] == q && src[i + 1] == q && src[i + 2] == q))
                    i++;
                if (i + 2 < n) i += 3;
            } else {
                i++;
                while (i < n && src[i] != q && src[i] != '\n') {
                    if (src[i] == '\\') i++;
                    i++;
                }
                if (i < n && src[i] == q) i++;
            }


            if (lang.is_json) {
                uint32_t peek = i;
                while (peek < n && (src[peek] == ' ' || src[peek] == '\t')) peek++;
                if (peek < n && src[peek] == ':')
                    out.push_back({ token_type::keyword, s, i - s });
                else
                    out.push_back({ token_type::string_lit, s, i - s });
            } else {
                out.push_back({ token_type::string_lit, s, i - s });
            }
            continue;
        }


        if (is_digit(src[i]) || (src[i] == '.' && i + 1 < n && is_digit(src[i + 1]))) {
            uint32_t s = i;
            if (src[i] == '0' && i + 1 < n && (src[i + 1] == 'x' || src[i + 1] == 'X')) {
                i += 2;
                while (i < n && ((src[i] >= '0' && src[i] <= '9') ||
                                  (src[i] >= 'a' && src[i] <= 'f') ||
                                  (src[i] >= 'A' && src[i] <= 'F')))
                    i++;
            } else if (src[i] == '0' && i + 1 < n && (src[i + 1] == 'b' || src[i + 1] == 'B')) {
                i += 2;
                while (i < n && (src[i] == '0' || src[i] == '1')) i++;
            } else {
                while (i < n && (is_digit(src[i]) || src[i] == '.'))
                    i++;
                if (i < n && (src[i] == 'e' || src[i] == 'E')) {
                    i++;
                    if (i < n && (src[i] == '+' || src[i] == '-')) i++;
                    while (i < n && is_digit(src[i])) i++;
                }
            }

            while (i < n && (src[i] == 'u' || src[i] == 'U' || src[i] == 'l' ||
                              src[i] == 'L' || src[i] == 'f' || src[i] == 'F'))
                i++;
            out.push_back({ token_type::number, s, i - s });
            continue;
        }


        if (is_ident_start(src[i]) || (src[i] == '.' && !lang.directives.empty())) {
            uint32_t s = i;

            if (src[i] == '.') i++;
            while (i < n && is_ident_char(src[i])) i++;
            std::string word(src.data() + s, i - s);


            uint32_t peek = i;
            while (peek < n && (src[peek] == ' ' || src[peek] == '\t')) peek++;
            bool is_func = (peek < n && src[peek] == '(');


            std::string lower = word;
            for (auto& c : lower) c = (char)tolower((unsigned char)c);


            if (lang.is_json && (word == "true" || word == "false" || word == "null")) {
                out.push_back({ token_type::boolean_lit, s, i - s });
            }
            else if (!lang.directives.empty() && lang.directives.count(lower)) {
                out.push_back({ token_type::directive, s, i - s });
            }
            else if (!lang.registers.empty() && lang.registers.count(lower)) {
                out.push_back({ token_type::register_name, s, i - s });
            }
            else if (lang.keywords.count(word) || (!lang.keywords.empty() && lang.keywords.count(lower))) {
                out.push_back({ token_type::keyword, s, i - s });
            }
            else if (lang.types.count(word)) {
                out.push_back({ token_type::type_name, s, i - s });
            }
            else if (is_func) {
                out.push_back({ token_type::function_call, s, i - s });
            }
            else {
                out.push_back({ token_type::identifier, s, i - s });
            }
            continue;
        }


        if (src[i] == '+' || src[i] == '-' || src[i] == '*' || src[i] == '/' ||
            src[i] == '%' || src[i] == '=' || src[i] == '!' || src[i] == '<' ||
            src[i] == '>' || src[i] == '&' || src[i] == '|' || src[i] == '^' ||
            src[i] == '~' || src[i] == '?') {
            uint32_t s = i;
            i++;

            if (i < n && (src[i] == '=' || src[i] == src[i-1] || src[i] == '>'))
                i++;
            out.push_back({ token_type::operator_sym, s, i - s });
            continue;
        }


        {
            out.push_back({ token_type::punctuation, i, 1 });
            i++;
        }
    }
}


inline void get_token_colors(ImU32 colors[(int)token_type::COUNT],
                              float ax, float ay, float az, float alpha)
{
    (void)ax; (void)ay; (void)az;
    const auto& t = aida::ui::resolved();

    colors[(int)token_type::keyword]       = aida::ui::with_alpha(t.syn_keyword,       alpha);
    colors[(int)token_type::type_name]     = aida::ui::with_alpha(t.syn_type,          alpha);
    colors[(int)token_type::string_lit]    = aida::ui::with_alpha(t.syn_string,        alpha);
    colors[(int)token_type::number]        = aida::ui::with_alpha(t.syn_number,        alpha);
    colors[(int)token_type::comment_line]  = aida::ui::with_alpha(t.syn_comment,       alpha);
    colors[(int)token_type::comment_block] = aida::ui::with_alpha(t.syn_comment,       alpha);
    colors[(int)token_type::preprocessor]  = aida::ui::with_alpha(t.syn_preprocessor,  alpha);
    colors[(int)token_type::operator_sym]  = aida::ui::with_alpha(t.syn_operator,      alpha);
    colors[(int)token_type::function_call] = aida::ui::with_alpha(t.syn_function,      alpha);
    colors[(int)token_type::identifier]    = aida::ui::with_alpha(t.syn_identifier,    alpha);
    colors[(int)token_type::whitespace]    = IM_COL32(0, 0, 0, 0);
    colors[(int)token_type::punctuation]   = aida::ui::with_alpha(t.syn_operator,      alpha * 0.85f);
    colors[(int)token_type::decorator]     = aida::ui::with_alpha(t.syn_preprocessor,  alpha);
    colors[(int)token_type::boolean_lit]   = aida::ui::with_alpha(t.syn_number,        alpha);
    colors[(int)token_type::register_name] = aida::ui::with_alpha(t.syn_register,      alpha);
    colors[(int)token_type::directive]     = aida::ui::with_alpha(t.syn_preprocessor,  alpha);
}

}
