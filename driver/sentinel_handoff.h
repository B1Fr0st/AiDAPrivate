#pragma once

#pragma pack(push, 1)
struct aida_sentinel_handoff_block {
    ULONG magic;
    USHORT version;
    USHORT size;
    ULONGLONG target_base;
    ULONGLONG target_object;
    ULONG target_size;
    ULONG checksum;
};
#pragma pack(pop)

static constexpr ULONG AIDA_SENTINEL_HANDOFF_MAGIC = 0x4C544E53u;
static constexpr USHORT AIDA_SENTINEL_HANDOFF_VERSION = 1;

static_assert(sizeof(aida_sentinel_handoff_block) == 0x20, "aida_sentinel_handoff_block");
static_assert(sizeof(void*) == 8, "aida_sentinel_handoff_pointer_size");

inline ULONG aida_sentinel_handoff_checksum(ULONGLONG target_base, ULONGLONG target_object, ULONG target_size)
{
    ULONGLONG value = 0x9E3779B97F4A7C15ULL;
    value ^= target_base + 0xBF58476D1CE4E5B9ULL + (value << 6) + (value >> 2);
    value ^= target_object + 0x94D049BB133111EBULL + (value << 6) + (value >> 2);
    value ^= static_cast<ULONGLONG>(target_size) + 0xD6E8FEB86659FD93ULL + (value << 6) + (value >> 2);
    value ^= static_cast<ULONGLONG>(AIDA_SENTINEL_HANDOFF_MAGIC) << 32;
    value ^= AIDA_SENTINEL_HANDOFF_VERSION;
    return static_cast<ULONG>(value ^ (value >> 32));
}

inline void aida_sentinel_handoff_prepare(aida_sentinel_handoff_block* block, PVOID target_base, PVOID target_object, ULONG target_size)
{
    if (!block)
        return;
    block->magic = AIDA_SENTINEL_HANDOFF_MAGIC;
    block->version = AIDA_SENTINEL_HANDOFF_VERSION;
    block->size = static_cast<USHORT>(sizeof(aida_sentinel_handoff_block));
    block->target_base = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(target_base));
    block->target_object = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(target_object));
    block->target_size = target_size;
    block->checksum = aida_sentinel_handoff_checksum(block->target_base, block->target_object, block->target_size);
}

inline BOOLEAN aida_sentinel_handoff_valid(const aida_sentinel_handoff_block* block)
{
    if (!block)
        return FALSE;
    if (block->magic != AIDA_SENTINEL_HANDOFF_MAGIC)
        return FALSE;
    if (block->version != AIDA_SENTINEL_HANDOFF_VERSION)
        return FALSE;
    if (block->size != static_cast<USHORT>(sizeof(aida_sentinel_handoff_block)))
        return FALSE;
    ULONG expected = aida_sentinel_handoff_checksum(block->target_base, block->target_object, block->target_size);
    return block->checksum == expected ? TRUE : FALSE;
}
