#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winnt.h>

#include <cstdint>
#include <cstring>
#include <limits>

#if defined(_M_X64)
#include <intrin.h>
#endif

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace aida {
namespace manual_map_tls {
namespace detail {

struct layout_t
{
    DWORD index = 0;
    const unsigned char* raw = nullptr;
    SIZE_T raw_size = 0;
    SIZE_T total_size = 0;
    bool valid = false;
};

inline INIT_ONCE g_layout_once = INIT_ONCE_STATIC_INIT;
inline layout_t g_layout;
inline INIT_ONCE g_fls_once = INIT_ONCE_STATIC_INIT;
inline DWORD g_fls_index = FLS_OUT_OF_INDEXES;

inline BOOL CALLBACK initialize_layout_once(PINIT_ONCE, PVOID, PVOID*) noexcept
{
    auto base = reinterpret_cast<std::uintptr_t>(&__ImageBase);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return TRUE;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uint32_t>(dos->e_lfanew));
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return TRUE;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_TLS_DIRECTORY64))
        return TRUE;
    auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(base + dir.VirtualAddress);
    if (!tls->AddressOfIndex)
        return TRUE;
    auto raw_start = static_cast<std::uintptr_t>(tls->StartAddressOfRawData);
    auto raw_end = static_cast<std::uintptr_t>(tls->EndAddressOfRawData);
    if (raw_end < raw_start)
        return TRUE;
    auto raw_size = static_cast<SIZE_T>(raw_end - raw_start);
    auto total_size = raw_size + static_cast<SIZE_T>(tls->SizeOfZeroFill);
    if (total_size == 0)
        total_size = 1;
    g_layout.index = *reinterpret_cast<const DWORD*>(static_cast<std::uintptr_t>(tls->AddressOfIndex));
    g_layout.raw = reinterpret_cast<const unsigned char*>(raw_start);
    g_layout.raw_size = raw_size;
    g_layout.total_size = total_size;
    g_layout.valid = true;
    return TRUE;
}

inline void NTAPI cleanup(void* value) noexcept;

inline BOOL CALLBACK initialize_fls_once(PINIT_ONCE, PVOID, PVOID*) noexcept
{
    DWORD index = FlsAlloc(cleanup);
    g_fls_index = index;
    return index != FLS_OUT_OF_INDEXES;
}

inline const layout_t* layout() noexcept
{
    InitOnceExecuteOnce(&g_layout_once, initialize_layout_once, nullptr, nullptr);
    return g_layout.valid ? &g_layout : nullptr;
}

inline DWORD fls_index() noexcept
{
    if (g_fls_index != FLS_OUT_OF_INDEXES)
        return g_fls_index;
    if (!InitOnceExecuteOnce(&g_fls_once, initialize_fls_once, nullptr, nullptr))
        return FLS_OUT_OF_INDEXES;
    return g_fls_index;
}

inline void** current_static_tls_vector() noexcept
{
#if defined(_M_X64)
    return reinterpret_cast<void**>(__readgsqword(0x58));
#else
    return nullptr;
#endif
}

inline bool poison_pointer(void* value) noexcept
{
    auto v = reinterpret_cast<std::uintptr_t>(value);
    return v == 0xABABABABABABABABull ||
           v == 0xFEEEFEEEFEEEFEEEull ||
           v == 0xBAADF00DBAADF00Dull ||
           (v & 0xFFFFFFFF00000000ull) == 0xBAADF00D00000000ull;
}

inline bool committed_readable(void* value, SIZE_T size) noexcept
{
    if (!value || poison_pointer(value))
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(value, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
        return false;
    auto protect = mbi.Protect & 0xffu;
    if (protect != PAGE_READONLY &&
        protect != PAGE_READWRITE &&
        protect != PAGE_WRITECOPY &&
        protect != PAGE_EXECUTE_READ &&
        protect != PAGE_EXECUTE_READWRITE &&
        protect != PAGE_EXECUTE_WRITECOPY)
        return false;
    auto begin = reinterpret_cast<std::uintptr_t>(value);
    auto region_begin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    auto region_end = region_begin + mbi.RegionSize;
    if (region_end < region_begin || begin < region_begin || begin >= region_end)
        return false;
    if (size > region_end - begin)
        return false;
    return true;
}

inline bool read_pointer(void* address, void** value) noexcept
{
#if defined(_MSC_VER)
    __try
    {
        *value = *reinterpret_cast<void**>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *value = nullptr;
        return false;
    }
#else
    *value = *reinterpret_cast<void**>(address);
    return true;
#endif
}

inline void* allocation_from_tls_data(void* value) noexcept
{
    if (!value || poison_pointer(value))
        return nullptr;
    auto data = reinterpret_cast<std::uintptr_t>(value);
    if (data < sizeof(void*))
        return nullptr;
    auto* header = reinterpret_cast<void*>(data - sizeof(void*));
    if (!committed_readable(header, sizeof(void*)))
        return nullptr;
    void* allocation = nullptr;
    if (!read_pointer(header, &allocation) || !allocation || poison_pointer(allocation))
        return nullptr;
    auto alloc = reinterpret_cast<std::uintptr_t>(allocation);
    if (data < alloc || data - alloc != sizeof(void*))
        return nullptr;
    return allocation;
}

inline bool valid_tls_block(void* value, SIZE_T size) noexcept
{
    if (!committed_readable(value, size))
        return false;
    void* allocation = allocation_from_tls_data(value);
    if (!allocation)
        return false;
    HANDLE heap = GetProcessHeap();
    return heap && HeapValidate(heap, 0, allocation);
}

inline void* allocate_tls_block(const layout_t& layout) noexcept
{
    if (layout.total_size > std::numeric_limits<SIZE_T>::max() - sizeof(void*))
        return nullptr;
    HANDLE heap = GetProcessHeap();
    if (!heap)
        return nullptr;
    auto bytes = layout.total_size + sizeof(void*);
    auto* allocation = static_cast<unsigned char*>(HeapAlloc(heap, HEAP_ZERO_MEMORY, bytes));
    if (!allocation)
        return nullptr;
    *reinterpret_cast<void**>(allocation) = allocation;
    auto* data = allocation + sizeof(void*);
    if (layout.raw && layout.raw_size)
        std::memcpy(data, layout.raw, layout.raw_size);
    return data;
}

inline void NTAPI cleanup(void* value) noexcept
{
    void* allocation = allocation_from_tls_data(value);
    HANDLE heap = GetProcessHeap();
    if (allocation && heap && HeapValidate(heap, 0, allocation))
        HeapFree(heap, 0, allocation);
}

inline bool read_vector_slot(void** vector, DWORD index, void** value) noexcept
{
#if defined(_MSC_VER)
    __try
    {
        *value = vector[index];
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *value = nullptr;
        return false;
    }
#else
    *value = vector[index];
    return true;
#endif
}

inline bool write_vector_slot(void** vector, DWORD index, void* value) noexcept
{
#if defined(_MSC_VER)
    __try
    {
        vector[index] = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
#else
    vector[index] = value;
    return true;
#endif
}

}

#if defined(_MSC_VER)
__declspec(noinline)
#endif
inline bool ensure_current_thread() noexcept
{
    const detail::layout_t* layout = detail::layout();
    if (!layout)
        return false;
    void** vector = detail::current_static_tls_vector();
    if (!vector)
        return false;
    DWORD fls = detail::fls_index();
    void* existing = fls != FLS_OUT_OF_INDEXES ? FlsGetValue(fls) : nullptr;
    if (existing)
    {
        if (detail::valid_tls_block(existing, layout->total_size))
            return detail::write_vector_slot(vector, layout->index, existing);
        FlsSetValue(fls, nullptr);
    }
    void* current = nullptr;
    if (detail::read_vector_slot(vector, layout->index, &current) &&
        detail::valid_tls_block(current, layout->total_size))
    {
        if (fls != FLS_OUT_OF_INDEXES)
            FlsSetValue(fls, current);
        return true;
    }
    void* block = detail::allocate_tls_block(*layout);
    if (!block)
        return false;
    if (!detail::write_vector_slot(vector, layout->index, block))
    {
        detail::cleanup(block);
        return false;
    }
    if (fls != FLS_OUT_OF_INDEXES)
        FlsSetValue(fls, block);
    return true;
}

}
}
