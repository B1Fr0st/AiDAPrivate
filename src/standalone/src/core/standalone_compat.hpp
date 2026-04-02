

#pragma once

#include "mcp_standalone.hpp"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>


using uchar = unsigned char;


inline void show_wait_box(const char*, ...) {}
inline void hide_wait_box() {}
inline void replace_wait_box(const char*, ...) {}


#ifndef SEGPERM_READ
#define SEGPERM_READ   1
#define SEGPERM_WRITE  2
#define SEGPERM_EXEC   4
#endif
#ifndef ADDSEG_QUIET
#define ADDSEG_QUIET   1
#define ADDSEG_NOSREG  2
#endif
#ifndef SEG_CODE
#define SEG_CODE 2
#define SEG_DATA 3
#define SEG_NORM 7
#endif
#ifndef saRelByte
#define saRelByte 1
#define scPub     2
#endif
struct segment_t {
    uint64_t start_ea = 0;
    uint64_t end_ea   = 0;
    uint64_t size     = 0;
    unsigned char perm = 0;
    int type           = 0;
    int bitness        = 0;
    int align          = 0;
    int comb           = 0;

    uint64_t& startEA = start_ea;
    void update() {}
};
inline segment_t* getseg(uint64_t) { return nullptr; }
inline bool add_segm_ex(segment_t*, const char*, const char*, int) { return false; }
inline void put_byte(uint64_t, unsigned char) {}
inline void put_bytes(uint64_t, const void*, size_t) {}
inline void patch_byte(uint64_t, unsigned char) {}
inline bool is_mapped(uint64_t) { return false; }


#ifndef qsnprintf_defined
#define qsnprintf_defined
inline int qsnprintf(char* buf, size_t n, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf_s(buf, n, _TRUNCATE, fmt, ap);
    va_end(ap);
    return r;
}
#endif


inline bool sa_parse_address(const std::string& text, uint64_t& out)
{
    if (text.empty()) return false;
    try {
        size_t idx = 0;
        out = std::stoull(text, &idx, 0);
        return idx == text.size();
    } catch (...) {
        return false;
    }
}


inline std::optional<uint64_t> sa_parse_address(const std::string& text)
{
    uint64_t val = 0;
    if (sa_parse_address(text, val))
        return val;
    return std::nullopt;
}

inline std::string sa_format_address(uint64_t addr)
{
    std::ostringstream os;
    os << "0x" << std::uppercase << std::hex << addr;
    return os.str();
}


struct compat_param_t
{
    std::string name;
    std::string type;
    std::string description;
    bool        required = false;

    std::vector<std::string>  enum_values   = {};
    nlohmann::json            items_schema  = {};


    operator mcp_standalone::tool_param_t() const
    {
        return {name, type, description, required};
    }
};


struct compat_tool_def_t
{
    std::string name;
    std::string category;
    std::string description;
    std::vector<compat_param_t> params;
    std::function<mcp_standalone::tool_result_t(const nlohmann::json&)> handler;
    bool read_only = true;
};


inline void register_compat(mcp_standalone::server_t& srv,
                            compat_tool_def_t          def)
{
    std::vector<mcp_standalone::tool_param_t> converted_params;
    converted_params.reserve(def.params.size());
    for (auto& p : def.params)
        converted_params.push_back(static_cast<mcp_standalone::tool_param_t>(p));

    srv.register_tool({
        std::move(def.name),
        std::move(def.description),
        std::move(converted_params),
        def.read_only,
        std::move(def.handler)
    });
}


inline std::string get_downloads_folder()
{
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len) + "\\Downloads\\";
    return "C:\\Users\\Public\\Downloads\\";
}

inline void ensure_parent_dir_exists(const std::string& file_path)
{
    std::string::size_type pos = 0;
    while ((pos = file_path.find_first_of("\\/", pos + 1)) != std::string::npos)
    {
        std::string dir = file_path.substr(0, pos);
        if (dir.size() == 2 && dir[1] == ':') { pos++; continue; }
        CreateDirectoryA(dir.c_str(), nullptr);
    }
}
