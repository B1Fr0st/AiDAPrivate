// standalone_compat.hpp — Compatibility layer for porting DLL agent-tools
// to the standalone application.  Bridges the type/API differences between
// the IDA plugin (agent_tools.hpp) and the standalone MCP server
// (mcp_standalone.hpp).  Included by all *_standalone.cpp files.

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

// IDA type alias
using uchar = unsigned char;

// IDA UI stubs — show_wait_box / hide_wait_box are progress dialogs
// that only exist inside IDA.  In standalone they are no-ops.
inline void show_wait_box(const char*, ...) {}
inline void hide_wait_box() {}
inline void replace_wait_box(const char*, ...) {}

// IDA segment / patching stubs — these APIs manipulate the IDA database (IDB).
// In standalone there is no IDB, so patch_idb code paths are effectively dead.
// We provide minimal stubs so the code compiles; the runtime path never reaches
// them because standalone callers don't set patch_idb=true, and even if they
// did, getseg always returns nullptr so the block is skipped.
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
    // alias used in the source
    uint64_t& startEA = start_ea;
    void update() {}
};
inline segment_t* getseg(uint64_t) { return nullptr; }
inline bool add_segm_ex(segment_t*, const char*, const char*, int) { return false; }
inline void put_byte(uint64_t, unsigned char) {}
inline void put_bytes(uint64_t, const void*, size_t) {}
inline void patch_byte(uint64_t, unsigned char) {}
inline bool is_mapped(uint64_t) { return false; }

// IDA stubs provide qvsnprintf (pro.h) but NOT qsnprintf.
// Many ported tool functions use qsnprintf, so we define it here.
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

// ---------------------------------------------------------------------------
// Address helpers — standalone replacements for IDA's helpers::parse_address
// and helpers::format_address.  The IDA versions also resolve symbol names;
// the standalone versions handle numeric hex/dec only (no symbol database).
// ---------------------------------------------------------------------------

inline bool sa_parse_address(const std::string& text, uint64_t& out)
{
    if (text.empty()) return false;
    try {
        size_t idx = 0;
        out = std::stoull(text, &idx, 0);   // handles 0x prefix and plain decimal
        return idx == text.size();
    } catch (...) {
        return false;
    }
}

// 1-arg overload matching the DLL's helpers::parse_address() that returns optional<ea_t>.
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

// ---------------------------------------------------------------------------
// Compatibility parameter struct — mirrors the DLL's tool_param_t aggregate
// initialization which has 6 fields (name, type, desc, required,
// enum_values, items_schema).  The standalone tool_param_t only has 4 fields.
// This struct accepts the extra fields and silently discards them so that
// the existing aggregate initializers compile unchanged.
// ---------------------------------------------------------------------------

struct compat_param_t
{
    std::string name;
    std::string type;
    std::string description;
    bool        required = false;
    // These two exist in the DLL but are ignored in standalone:
    std::vector<std::string>  enum_values   = {};
    nlohmann::json            items_schema  = {};

    // Implicit conversion to standalone tool_param_t (drops extra fields).
    operator mcp_standalone::tool_param_t() const
    {
        return {name, type, description, required};
    }
};

// ---------------------------------------------------------------------------
// Tool‐definition compatibility struct — mirrors the DLL's tool_definition_t
// aggregate { name, category, description, params, handler, read_only }
// but adapts to standalone's tool_def_t { name, description, params,
// read_only, handler }.  Field order and extra fields differ.
// ---------------------------------------------------------------------------

struct compat_tool_def_t
{
    std::string name;
    std::string category;      // dropped — standalone has no category
    std::string description;
    std::vector<compat_param_t> params;
    std::function<mcp_standalone::tool_result_t(const nlohmann::json&)> handler;
    bool read_only = true;
};

// ---------------------------------------------------------------------------
// register_compat — register a tool on the standalone MCP server using the
// DLL's field order (name, category, desc, params, handler, read_only).
// Converts compat_param_t → tool_param_t and reorders fields.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Shared utility functions — used by multiple standalone tool files.
// ---------------------------------------------------------------------------

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
