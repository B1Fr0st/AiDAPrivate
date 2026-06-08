#pragma once

namespace aida {
namespace diagnostic_exception_scope {

inline thread_local int g_depth = 0;
inline thread_local const char* g_label = "";

inline void enter(const char* label) noexcept
{
    ++g_depth;
    g_label = label ? label : "";
}

inline void leave() noexcept
{
    if (g_depth > 0)
        --g_depth;
    if (g_depth == 0)
        g_label = "";
}

inline bool active() noexcept
{
    return g_depth > 0;
}

inline const char* label() noexcept
{
    return g_label ? g_label : "";
}

struct scope_t
{
    explicit scope_t(const char* label) noexcept
    {
        enter(label);
    }

    ~scope_t()
    {
        leave();
    }

    scope_t(const scope_t&) = delete;
    scope_t& operator=(const scope_t&) = delete;
};

}
}
