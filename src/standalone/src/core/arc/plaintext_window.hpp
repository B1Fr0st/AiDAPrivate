#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>

namespace aida::arc::plaintext_window
{
    constexpr size_t   kArcPageSize        = 4096;
    constexpr size_t   kAesGcmTagSize      = 16;
    constexpr size_t   kAesGcmIvSize       = 12;
    constexpr size_t   kOsPageSize         = 4096;
    constexpr size_t   kPageSlotSize       = kOsPageSize;
    constexpr uint64_t kHoldMs             = 50;
    constexpr size_t   kSealingKeySize     = 32;
    constexpr size_t   kOverwritePasses    = 3;
    constexpr uint32_t kHandleSignature    = 0x504C5457u;

    struct page_metadata_t
    {
        uint32_t cipher_len;
        uint8_t  iv[kAesGcmIvSize];
        uint8_t  tag[kAesGcmTagSize];
        bool     populated;
    };

    struct handle_t
    {
        uint32_t signature;
        void*    base;
        size_t   total_bytes;
        size_t   reserved_pages;
        size_t   logical_pages;
        uint64_t allocation_id;
        uint8_t  sealing_key[kSealingKeySize];
        uint64_t live_page_index;
        bool     live_page_active;
        uint64_t live_page_revealed_qpc_us;
        uint64_t freq_us;
        page_metadata_t* metadata;
    };

    bool create(size_t logical_pages, handle_t& out, std::string& last_error);

    bool consume_page(handle_t& h,
                      size_t page_index,
                      const uint8_t* src_plain,
                      uint32_t src_size,
                      std::string& last_error);

    bool reveal_page(handle_t& h,
                     size_t page_index,
                     uint8_t* out_plain,
                     uint32_t out_capacity,
                     uint32_t& out_size,
                     std::string& last_error);

    bool finish_reveal(handle_t& h,
                       size_t page_index,
                       std::string& last_error);

    bool stream_to_loader(handle_t& h,
                          const std::function<bool(const uint8_t* page_bytes,
                                                   uint32_t page_size,
                                                   size_t page_index,
                                                   size_t total_pages)>& sink,
                          std::string& last_error);

    void destroy(handle_t& h);

    const char* last_error_global();
}
