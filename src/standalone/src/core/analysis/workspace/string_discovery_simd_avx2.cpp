#include <cstddef>
#include <cstdint>

#include <immintrin.h>

namespace aida::analysis::string_simd {

namespace {

constexpr std::uint8_t kPrintableLow = 0x20U;
constexpr std::uint8_t kPrintableHigh = 0x7eU;

}

std::size_t ascii_run_avx2(const std::uint8_t* data, std::size_t size) noexcept {
    std::size_t index = 0;
    const auto lower = _mm256_set1_epi8(0x1f);
    const auto upper = _mm256_set1_epi8(0x7f);
    while (index + 32 <= size) {
        const auto value = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(data + index));
        const auto printable = _mm256_and_si256(_mm256_cmpgt_epi8(value, lower),
            _mm256_cmpgt_epi8(upper, value));
        const auto mask =
            static_cast<std::uint32_t>(_mm256_movemask_epi8(printable));
        if (mask != 0xffffffffU) {
            auto inverse = ~mask;
            std::size_t run = 0;
            while ((inverse & 1U) != 0U) {
                ++run;
                inverse >>= 1U;
            }
            return index + run;
        }
        index += 32;
    }
    while (index < size && data[index] >= kPrintableLow && data[index] <= kPrintableHigh)
        ++index;
    return index;
}

std::size_t utf16_ascii_unit_run_avx2(const std::uint8_t* data, std::size_t size) noexcept {
    std::size_t units = 0;
    const std::size_t limit = size & ~static_cast<std::size_t>(1);
    const auto lower = _mm256_set1_epi8(0x1f);
    const auto upper = _mm256_set1_epi8(0x7f);
    const auto zero = _mm256_setzero_si256();
    while ((units + 16) * 2 <= limit) {
        const auto value = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(data + units * 2));
        const auto printable = _mm256_and_si256(_mm256_cmpgt_epi8(value, lower),
            _mm256_cmpgt_epi8(upper, value));
        const auto is_zero = _mm256_cmpeq_epi8(value, zero);
        const auto printable_mask =
            static_cast<std::uint32_t>(_mm256_movemask_epi8(printable));
        const auto zero_mask =
            static_cast<std::uint32_t>(_mm256_movemask_epi8(is_zero));
        const auto unit_ok =
            (printable_mask & 0x55555555U) & ((zero_mask & 0xaaaaaaaaU) >> 1U);
        if (unit_ok != 0x55555555U) {
            auto inverse = (~unit_ok) & 0x55555555U;
            while ((inverse & 1U) == 0U) {
                ++units;
                inverse >>= 2U;
            }
            return units;
        }
        units += 16;
    }
    while ((units + 1) * 2 <= limit && data[units * 2] >= kPrintableLow &&
           data[units * 2] <= kPrintableHigh && data[units * 2 + 1] == 0)
        ++units;
    return units;
}

}
