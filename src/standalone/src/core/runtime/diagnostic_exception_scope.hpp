#pragma once

#include <Windows.h>

namespace aida {
namespace diagnostic_exception_scope {

struct state_t
{
    int depth;
    const char* label;
};

inline INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
inline DWORD g_fls_index = FLS_OUT_OF_INDEXES;

inline void NTAPI cleanup(void* value) noexcept
{
    if (value)
        HeapFree(GetProcessHeap(), 0, value);
}

inline BOOL CALLBACK initialize_once(PINIT_ONCE, PVOID, PVOID*) noexcept
{
    DWORD index = FlsAlloc(cleanup);
    g_fls_index = index;
    return index != FLS_OUT_OF_INDEXES;
}

inline DWORD index() noexcept
{
    if (g_fls_index != FLS_OUT_OF_INDEXES)
        return g_fls_index;
    if (!InitOnceExecuteOnce(&g_once, initialize_once, nullptr, nullptr))
        return FLS_OUT_OF_INDEXES;
    return g_fls_index;
}

inline bool initialize() noexcept
{
    return index() != FLS_OUT_OF_INDEXES;
}

inline state_t* state(bool create) noexcept
{
    DWORD slot = index();
    if (slot == FLS_OUT_OF_INDEXES)
        return nullptr;
    auto* s = static_cast<state_t*>(FlsGetValue(slot));
    if (!s && create)
    {
        s = static_cast<state_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(state_t)));
        if (!s)
            return nullptr;
        if (!FlsSetValue(slot, s))
        {
            HeapFree(GetProcessHeap(), 0, s);
            return nullptr;
        }
    }
    return s;
}

inline void enter(const char* label) noexcept
{
    state_t* s = state(true);
    if (!s)
        return;
    if (s->depth < 0x7fffffff)
        ++s->depth;
    s->label = label ? label : "";
}

inline void leave() noexcept
{
    state_t* s = state(false);
    if (!s)
        return;
    if (s->depth > 0)
        --s->depth;
    if (s->depth == 0)
        s->label = "";
}

inline bool active() noexcept
{
    state_t* s = state(false);
    return s && s->depth > 0;
}

inline const char* label() noexcept
{
    state_t* s = state(false);
    return (s && s->label) ? s->label : "";
}

struct scope_t
{
    explicit scope_t(const char* label) noexcept
    {
        enter(label);
    }

    ~scope_t() noexcept
    {
        leave();
    }

    scope_t(const scope_t&) = delete;
    scope_t& operator=(const scope_t&) = delete;
};

}
}
