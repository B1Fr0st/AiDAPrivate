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
constexpr std::uintptr_t block_magic = 0x41494441544C5331ull;
constexpr SIZE_T block_alignment = 64;

struct block_header_t
{
    std::uintptr_t magic = block_magic;
    void* allocation = nullptr;
    SIZE_T data_size = 0;
    SIZE_T allocation_size = 0;
};

inline SIZE_T align_up(SIZE_T value, SIZE_T alignment) noexcept
{
    if (alignment == 0)
        return value;
    SIZE_T mask = alignment - 1;
    if ((alignment & mask) != 0)
        return value;
    if (value > (std::numeric_limits<SIZE_T>::max)() - mask)
        return 0;
    return (value + mask) & ~mask;
}

inline SIZE_T data_offset() noexcept
{
    return align_up(sizeof(block_header_t), block_alignment);
}

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

inline block_header_t* header_from_tls_data(void* value) noexcept
{
    if (!value || poison_pointer(value))
        return nullptr;
    auto data = reinterpret_cast<std::uintptr_t>(value);
    SIZE_T offset = data_offset();
    if (offset == 0 || data < offset)
        return nullptr;
    auto* header = reinterpret_cast<block_header_t*>(data - offset);
    if (!committed_readable(header, sizeof(block_header_t)))
        return nullptr;
    if (header->magic != block_magic)
        return nullptr;
    if (!header->allocation || poison_pointer(header->allocation))
        return nullptr;
    if (header->allocation != header)
        return nullptr;
    if (header->data_size == 0 || header->allocation_size < offset)
        return nullptr;
    if (header->data_size > (std::numeric_limits<SIZE_T>::max)() - offset)
        return nullptr;
    if (header->allocation_size < offset + header->data_size)
        return nullptr;
    return header;
}

inline void* allocation_from_tls_data(void* value) noexcept
{
    block_header_t* header = header_from_tls_data(value);
    return header ? header->allocation : nullptr;
}

inline bool valid_tls_block(void* value, SIZE_T size) noexcept
{
    if (!committed_readable(value, size))
        return false;
    block_header_t* header = header_from_tls_data(value);
    if (!header || header->data_size < size)
        return false;
    return true;
}

inline void* allocate_tls_block(const layout_t& layout) noexcept
{
    SIZE_T offset = data_offset();
    if (offset == 0)
        return nullptr;
    if (layout.total_size > (std::numeric_limits<SIZE_T>::max)() - offset)
        return nullptr;
    SIZE_T bytes = offset + layout.total_size;
    auto* allocation = static_cast<unsigned char*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!allocation)
        return nullptr;
    auto* header = reinterpret_cast<block_header_t*>(allocation);
    header->magic = block_magic;
    header->allocation = allocation;
    header->data_size = layout.total_size;
    header->allocation_size = bytes;
    auto* data = allocation + offset;
    if (layout.raw && layout.raw_size)
        std::memcpy(data, layout.raw, layout.raw_size);
    return data;
}

inline void NTAPI cleanup(void* value) noexcept
{
    DWORD fls = g_fls_index;
    if (fls != FLS_OUT_OF_INDEXES)
    {
#if defined(_MSC_VER)
        __try
        {
            if (FlsGetValue(fls) == value)
                FlsSetValue(fls, nullptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
#else
        if (FlsGetValue(fls) == value)
            FlsSetValue(fls, nullptr);
#endif
    }
    block_header_t* header = nullptr;
#if defined(_MSC_VER)
    __try
    {
        header = header_from_tls_data(value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        header = nullptr;
    }
#else
    header = header_from_tls_data(value);
#endif
    if (!header)
        return;
    void* allocation = header->allocation;
    header->magic = 0;
    if (allocation)
        VirtualFree(allocation, 0, MEM_RELEASE);
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
