#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "pe_file.hpp"
#include "transforms.hpp"

namespace protector {
namespace watermark {

inline bool extract_watermark_id(const pe_file::pe_image_t& pe, uint8_t out_id[8]) {
    uint32_t lo = pe.optional_header.Win32VersionValue;
    uint32_t hi = pe.optional_header.LoaderFlags;
    std::memcpy(out_id + 0, &lo, 4);
    std::memcpy(out_id + 4, &hi, 4);
    bool nonzero = false;
    for (int i = 0; i < 8; ++i) {
        if (out_id[i] != 0u) { nonzero = true; break; }
    }
    return nonzero;
}

inline bool find_aux_block(const pe_file::pe_image_t& pe, aux_block_t& out_aux) {
    for (const auto& sec : pe.sections) {
        if (sec.data.size() < sizeof(packed_header_t) + sizeof(aux_block_t)) {
            continue;
        }
        packed_header_t hdr{};
        std::memcpy(&hdr, sec.data.data(), sizeof(hdr));
        if (hdr.magic != kPackedMagic) {
            continue;
        }
        if (hdr.aux_offset == 0u || hdr.aux_size != sizeof(aux_block_t)) {
            continue;
        }
        if (static_cast<size_t>(hdr.aux_offset) + sizeof(aux_block_t) > sec.data.size()) {
            continue;
        }
        std::memcpy(&out_aux, sec.data.data() + hdr.aux_offset, sizeof(aux_block_t));
        return out_aux.magic == kAuxMagic;
    }
    return false;
}

inline bool extract_full_watermark(const pe_file::pe_image_t& pe, uint8_t out_watermark[16]) {
    aux_block_t aux{};
    if (!find_aux_block(pe, aux)) {
        return false;
    }
    std::memcpy(out_watermark, aux.watermark, 16);
    return true;
}

}
}
