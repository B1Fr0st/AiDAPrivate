#include "ghidra_ir_adapter.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4099)
#endif
#include "funcdata.hh"
#include "database.hh"
#include "fspec.hh"
#include "opcodes.hh"
#include "type.hh"
#include "variable.hh"
#include "architecture.hh"
#include "userop.hh"
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#include "../../builtin_typelib.hpp"

namespace aida::analysis::ghidra_ir_adapter {
namespace {

constexpr std::uint32_t k_artifact_magic = 0x41524947U;
constexpr std::uint32_t k_artifact_version = 1;
constexpr std::size_t k_artifact_max_bytes = 32U * 1024U * 1024U;
constexpr std::size_t k_provider_text_max_bytes = 4096U;

std::string bounded_utf8(const std::string_view input)
{
    std::string output;
    output.reserve((std::min)(input.size(), k_provider_text_max_bytes));
    const auto replacement = [&output]() {
        if (output.size() <= k_provider_text_max_bytes - 3U)
            output.append("\xEF\xBF\xBD", 3U);
    };
    for (std::size_t index = 0; index < input.size() && output.size() < k_provider_text_max_bytes;) {
        const auto first = static_cast<unsigned char>(input[index]);
        if (first <= 0x7FU) {
            if (first >= 0x20U && first != 0x7FU)
                output.push_back(static_cast<char>(first));
            else
                replacement();
            ++index;
            continue;
        }
        std::size_t length = 0;
        std::uint32_t scalar = 0;
        std::uint32_t minimum = 0;
        if (first >= 0xC2U && first <= 0xDFU) {
            length = 2;
            scalar = first & 0x1FU;
            minimum = 0x80U;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            length = 3;
            scalar = first & 0x0FU;
            minimum = 0x800U;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            length = 4;
            scalar = first & 0x07U;
            minimum = 0x10000U;
        }
        bool valid = length != 0 && length <= input.size() - index;
        if (valid) {
            for (std::size_t offset = 1; offset < length; ++offset) {
                const auto continuation = static_cast<unsigned char>(input[index + offset]);
                if ((continuation & 0xC0U) != 0x80U) {
                    valid = false;
                    break;
                }
                scalar = (scalar << 6U) | (continuation & 0x3FU);
            }
        }
        if (valid && (scalar < minimum || scalar > 0x10FFFFU ||
                      (scalar >= 0xD800U && scalar <= 0xDFFFU)))
            valid = false;
        if (!valid) {
            replacement();
            ++index;
            continue;
        }
        if (length > k_provider_text_max_bytes - output.size())
            break;
        output.append(input.data() + index, length);
        index += length;
    }
    return output;
}

std::string address_symbol(const std::uint64_t address)
{
    std::ostringstream stream;
    stream << "sub_" << std::hex << address;
    return stream.str();
}

std::string symbol_name(const ghidra::Symbol* symbol)
{
    if (!symbol || symbol->isNameUndefined())
        return {};
    auto result = bounded_utf8(symbol->getDisplayName());
    if (result.empty())
        result = bounded_utf8(symbol->getName());
    return result;
}

std::string varnode_symbol_name(const ghidra::Varnode* node)
{
    if (!node || node->isAnnotation())
        return {};
    if (const auto* high = node->getHigh()) {
        auto result = symbol_name(high->getSymbol());
        if (!result.empty())
            return result;
    }
    const auto* entry = node->getSymbolEntry();
    return entry ? symbol_name(entry->getSymbol()) : std::string{};
}

bool unknown_datatype(const ghidra::Datatype* type)
{
    return !type || type->getMetatype() == ghidra::TYPE_UNKNOWN;
}

std::uint8_t datatype_confidence(const ghidra::Datatype* type)
{
    return unknown_datatype(type) ? std::uint8_t{50} : std::uint8_t{100};
}

std::string datatype_name(const ghidra::Datatype* type)
{
    if (!type)
        return "unknown";
    auto result = bounded_utf8(type->getName());
    if (result.empty())
        result = bounded_utf8(type->getDisplayName());
    if (!result.empty())
        return result;
    const auto size = type->getSize() > 0 ? static_cast<std::uint64_t>(type->getSize()) : 0U;
    const auto bits = size <= (std::numeric_limits<std::uint64_t>::max)() / 8U ? size * 8U : 0U;
    switch (type->getMetatype()) {
    case ghidra::TYPE_VOID: return "void";
    case ghidra::TYPE_BOOL: return "bool";
    case ghidra::TYPE_INT: return bits == 0 ? "signed_integer" : "int" + std::to_string(bits) + "_t";
    case ghidra::TYPE_UINT: return bits == 0 ? "unsigned_integer" : "uint" + std::to_string(bits) + "_t";
    case ghidra::TYPE_FLOAT: return bits == 0 ? "floating_point" : "float" + std::to_string(bits);
    case ghidra::TYPE_PTR: return bits == 0 ? "pointer" : "pointer" + std::to_string(bits);
    case ghidra::TYPE_ARRAY: return "array";
    case ghidra::TYPE_STRUCT: return "structure";
    case ghidra::TYPE_UNION: return "union";
    case ghidra::TYPE_CODE: return "function";
    default: return bits == 0 ? "unknown" : "undefined" + std::to_string(size);
    }
}

const ghidra::Datatype* stronger_datatype(const ghidra::Datatype* current,
                                          const ghidra::Datatype* candidate)
{
    if (!candidate)
        return current;
    if (!current)
        return candidate;
    if (unknown_datatype(current) != unknown_datatype(candidate))
        return unknown_datatype(current) ? candidate : current;
    return candidate->typeOrder(*current) < 0 ? candidate : current;
}

struct simd_intrinsic_entry_t {
    const char* pcodeop;
    const char* intrinsic;
};

inline constexpr simd_intrinsic_entry_t kSimdIntrinsics[] = {
    { "MaskedMoveQWord", "_mm_maskmove_si64" },
    { "aesdec", "_mm_aesdec_si128" },
    { "aesdeclast", "_mm_aesdeclast_si128" },
    { "aesenc", "_mm_aesenc_si128" },
    { "aesenclast", "_mm_aesenclast_si128" },
    { "aesimc", "_mm_aesimc_si128" },
    { "aeskeygenassist", "_mm_aeskeygenassist_si128" },
    { "blendpd", "_mm_blend_pd" },
    { "blendps", "_mm_blend_ps" },
    { "blendvpd", "_mm_blendv_pd" },
    { "blendvps", "_mm_blendv_ps" },
    { "cmppd", "_mm_cmp_pd" },
    { "cmpps", "_mm_cmp_ps" },
    { "cmpsd", "_mm_cmp_sd" },
    { "cmpss", "_mm_cmp_ss" },
    { "crc32", "_mm_crc32_u8" },
    { "divpd", "_mm_div_pd" },
    { "divps", "_mm_div_ps" },
    { "dppd", "_mm_dp_pd" },
    { "dpps", "_mm_dp_ps" },
    { "extractps", "_mm_extract_ps" },
    { "insertps", "_mm_insert_ps" },
    { "lddqu", "_mm_lddqu_si128" },
    { "maskmovdqu", "_mm_maskmoveu_si128" },
    { "pclmulqdq", "_mm_clmulepi64_si128" },
    { "pmovsxbd", "_mm_cvtepi8_epi32" },
    { "pmovsxbq", "_mm_cvtepi8_epi64" },
    { "pmovsxbw", "_mm_cvtepi8_epi16" },
    { "pmovsxdq", "_mm_cvtepi32_epi64" },
    { "pmovsxwd", "_mm_cvtepi16_epi32" },
    { "pmovsxwq", "_mm_cvtepi16_epi64" },
    { "pmovzxbd", "_mm_cvtepu8_epi32" },
    { "pmovzxbq", "_mm_cvtepu8_epi64" },
    { "pmovzxbw", "_mm_cvtepu8_epi16" },
    { "pmovzxdq", "_mm_cvtepu32_epi64" },
    { "pmovzxwd", "_mm_cvtepu16_epi32" },
    { "pmovzxwq", "_mm_cvtepu16_epi64" },
    { "pmuldq", "_mm_mul_epi32" },
    { "pmulhrsw", "_mm_mulhrs_epi16" },
    { "pmulhuw", "_mm_mulhi_epu16" },
    { "pmulhw", "_mm_mulhi_epi16" },
    { "pmulld", "_mm_mullo_epi32" },
    { "psadbw", "_mm_sad_epu8" },
    { "pshufb", "_mm_shuffle_epi8" },
    { "pshufhw", "_mm_shufflehi_epi16" },
    { "pshuflw", "_mm_shufflelo_epi16" },
    { "pshufw", "_mm_shuffle_pi16" },
    { "psignb", "_mm_sign_epi8" },
    { "psignd", "_mm_sign_epi32" },
    { "psignw", "_mm_sign_epi16" },
    { "psllw", "_mm_sll_epi16" },
    { "psraw", "_mm_sra_epi16" },
    { "psubsb", "_mm_subs_epi8" },
    { "psubsw", "_mm_subs_epi16" },
    { "psubusb", "_mm_subs_epu8" },
    { "psubusw", "_mm_subs_epu16" },
    { "punpcklqdq", "_mm_unpacklo_epi64" },
    { "rcpps", "_mm_rcp_ps" },
    { "rcpss", "_mm_rcp_ss" },
    { "roundpd", "_mm_round_pd" },
    { "roundps", "_mm_round_ps" },
    { "roundsd", "_mm_round_sd" },
    { "roundss", "_mm_round_ss" },
    { "rsqrtps", "_mm_rsqrt_ps" },
    { "rsqrtss", "_mm_rsqrt_ss" },
    { "sha1msg1_sha", "_mm_sha1msg1_epu32" },
    { "sha1msg2_sha", "_mm_sha1msg2_epu32" },
    { "sha1nexte_sha", "_mm_sha1nexte_epu32" },
    { "sha1rnds4_sha", "_mm_sha1rnds4_epu32" },
    { "sha256msg1_sha", "_mm_sha256msg1_epu32" },
    { "sha256msg2_sha", "_mm_sha256msg2_epu32" },
    { "sha256rnds2_sha", "_mm_sha256rnds2_epu32" },
    { "sqrtpd", "_mm_sqrt_pd" },
    { "sqrtps", "_mm_sqrt_ps" },
    { "vaddsubpd_avx", "_mm256_addsub_pd" },
    { "vaddsubps_avx", "_mm256_addsub_ps" },
    { "vaesdec_vaes", "_mm256_aesdec_epi128" },
    { "vaesdeclast_vaes", "_mm256_aesdeclast_epi128" },
    { "vaesenc_vaes", "_mm256_aesenc_epi128" },
    { "vaesenclast_vaes", "_mm256_aesenclast_epi128" },
    { "vandnpd_avx", "_mm256_andnot_pd" },
    { "vandnps_avx", "_mm256_andnot_ps" },
    { "vandpd_avx", "_mm256_and_pd" },
    { "vandps_avx", "_mm256_and_ps" },
    { "vblendpd_avx", "_mm256_blend_pd" },
    { "vblendps_avx", "_mm256_blend_ps" },
    { "vblendvpd_avx", "_mm256_blendv_pd" },
    { "vblendvps_avx", "_mm256_blendv_ps" },
    { "vcmppd_avx", "_mm256_cmp_pd" },
    { "vcmpps_avx", "_mm256_cmp_ps" },
    { "vcmpsd_avx", "_mm_cmp_sd" },
    { "vcmpss_avx", "_mm_cmp_ss" },
    { "vcvtdq2pd_avx", "_mm256_cvtepi32_pd" },
    { "vcvtdq2ps_avx", "_mm256_cvtepi32_ps" },
    { "vcvtpd2dq_avx", "_mm256_cvtpd_epi32" },
    { "vcvtpd2ps_avx", "_mm256_cvtpd_ps" },
    { "vcvtph2ps_f16c", "_mm256_cvtph_ps" },
    { "vcvtps2dq_avx", "_mm256_cvtps_epi32" },
    { "vcvtps2pd_avx", "_mm256_cvtps_pd" },
    { "vcvtps2ph_f16c", "_mm256_cvtps_ph" },
    { "vdivpd_avx", "_mm256_div_pd" },
    { "vdivps_avx", "_mm256_div_ps" },
    { "vdppd_avx", "_mm_dp_pd" },
    { "vdpps_avx", "_mm256_dp_ps" },
    { "vextractps_avx", "_mm_extract_ps" },
    { "vfmadd132pd_fma", "_mm256_fmadd_pd" },
    { "vfmadd132ps_fma", "_mm256_fmadd_ps" },
    { "vfmadd132sd_fma", "_mm_fmadd_sd" },
    { "vfmadd132ss_fma", "_mm_fmadd_ss" },
    { "vfmadd213pd_fma", "_mm256_fmadd_pd" },
    { "vfmadd213ps_fma", "_mm256_fmadd_ps" },
    { "vfmadd213sd_fma", "_mm_fmadd_sd" },
    { "vfmadd213ss_fma", "_mm_fmadd_ss" },
    { "vfmadd231pd_fma", "_mm256_fmadd_pd" },
    { "vfmadd231ps_fma", "_mm256_fmadd_ps" },
    { "vfmadd231sd_fma", "_mm_fmadd_sd" },
    { "vfmadd231ss_fma", "_mm_fmadd_ss" },
    { "vfmaddsub132pd_fma", "_mm256_fmaddsub_pd" },
    { "vfmaddsub132ps_fma", "_mm256_fmaddsub_ps" },
    { "vfmaddsub213pd_fma", "_mm256_fmaddsub_pd" },
    { "vfmaddsub213ps_fma", "_mm256_fmaddsub_ps" },
    { "vfmaddsub231pd_fma", "_mm256_fmaddsub_pd" },
    { "vfmaddsub231ps_fma", "_mm256_fmaddsub_ps" },
    { "vfmsub132pd_fma", "_mm256_fmsub_pd" },
    { "vfmsub132ps_fma", "_mm256_fmsub_ps" },
    { "vfmsub132sd_fma", "_mm_fmsub_sd" },
    { "vfmsub132ss_fma", "_mm_fmsub_ss" },
    { "vfmsub213pd_fma", "_mm256_fmsub_pd" },
    { "vfmsub213ps_fma", "_mm256_fmsub_ps" },
    { "vfmsub213sd_fma", "_mm_fmsub_sd" },
    { "vfmsub213ss_fma", "_mm_fmsub_ss" },
    { "vfmsub231pd_fma", "_mm256_fmsub_pd" },
    { "vfmsub231ps_fma", "_mm256_fmsub_ps" },
    { "vfmsub231sd_fma", "_mm_fmsub_sd" },
    { "vfmsub231ss_fma", "_mm_fmsub_ss" },
    { "vfmsubadd132pd_fma", "_mm256_fmsubadd_pd" },
    { "vfmsubadd132ps_fma", "_mm256_fmsubadd_ps" },
    { "vfmsubadd213pd_fma", "_mm256_fmsubadd_pd" },
    { "vfmsubadd213ps_fma", "_mm256_fmsubadd_ps" },
    { "vfmsubadd231pd_fma", "_mm256_fmsubadd_pd" },
    { "vfmsubadd231ps_fma", "_mm256_fmsubadd_ps" },
    { "vfnmadd132pd_fma", "_mm256_fnmadd_pd" },
    { "vfnmadd132ps_fma", "_mm256_fnmadd_ps" },
    { "vfnmadd132sd_fma", "_mm_fnmadd_sd" },
    { "vfnmadd132ss_fma", "_mm_fnmadd_ss" },
    { "vfnmadd213pd_fma", "_mm256_fnmadd_pd" },
    { "vfnmadd213ps_fma", "_mm256_fnmadd_ps" },
    { "vfnmadd213sd_fma", "_mm_fnmadd_sd" },
    { "vfnmadd213ss_fma", "_mm_fnmadd_ss" },
    { "vfnmadd231pd_fma", "_mm256_fnmadd_pd" },
    { "vfnmadd231ps_fma", "_mm256_fnmadd_ps" },
    { "vfnmadd231sd_fma", "_mm_fnmadd_sd" },
    { "vfnmadd231ss_fma", "_mm_fnmadd_ss" },
    { "vfnmsub132pd_fma", "_mm256_fnmsub_pd" },
    { "vfnmsub132ps_fma", "_mm256_fnmsub_ps" },
    { "vfnmsub132sd_fma", "_mm_fnmsub_sd" },
    { "vfnmsub132ss_fma", "_mm_fnmsub_ss" },
    { "vfnmsub213pd_fma", "_mm256_fnmsub_pd" },
    { "vfnmsub213ps_fma", "_mm256_fnmsub_ps" },
    { "vfnmsub213sd_fma", "_mm_fnmsub_sd" },
    { "vfnmsub213ss_fma", "_mm_fnmsub_ss" },
    { "vfnmsub231pd_fma", "_mm256_fnmsub_pd" },
    { "vfnmsub231ps_fma", "_mm256_fnmsub_ps" },
    { "vfnmsub231sd_fma", "_mm_fnmsub_sd" },
    { "vfnmsub231ss_fma", "_mm_fnmsub_ss" },
    { "vgatherdpd", "_mm256_i32gather_pd" },
    { "vgatherdps", "_mm256_i32gather_ps" },
    { "vgatherqpd", "_mm256_i64gather_pd" },
    { "vgatherqps", "_mm_i64gather_ps" },
    { "vhaddps_avx", "_mm256_hadd_ps" },
    { "vhsubpd_avx", "_mm256_hsub_pd" },
    { "vhsubps_avx", "_mm256_hsub_ps" },
    { "vinserti128", "_mm256_inserti128_si256" },
    { "vinsertps_avx", "_mm_insert_ps" },
    { "vlddqu_avx", "_mm256_lddqu_si256" },
    { "vldmxcsr_avx", "_mm_ldmxcsr" },
    { "vmaskmovdqu_avx", "_mm_maskmoveu_si128" },
    { "vmaskmovpd_avx", "_mm256_maskload_pd" },
    { "vmaskmovps_avx", "_mm256_maskload_ps" },
    { "vmaxpd_avx", "_mm256_max_pd" },
    { "vmaxps_avx", "_mm256_max_ps" },
    { "vmaxsd_avx", "_mm_max_sd" },
    { "vmaxss_avx", "_mm_max_ss" },
    { "vminpd_avx", "_mm256_min_pd" },
    { "vminps_avx", "_mm256_min_ps" },
    { "vminsd_avx", "_mm_min_sd" },
    { "vminss_avx", "_mm_min_ss" },
    { "vmovhlps_avx", "_mm_movehl_ps" },
    { "vmovhpd_avx", "_mm_loadh_pd" },
    { "vmovhps_avx", "_mm_loadh_pi" },
    { "vmovlhps_avx", "_mm_movelh_ps" },
    { "vmovlpd_avx", "_mm_loadl_pd" },
    { "vmovlps_avx", "_mm_loadl_pi" },
    { "vmovmskpd_avx", "_mm256_movemask_pd" },
    { "vmovmskps_avx", "_mm256_movemask_ps" },
    { "vmovntdq_avx", "_mm256_stream_si256" },
    { "vmovntdqa_avx", "_mm256_stream_load_si256" },
    { "vmovntdqa_avx2", "_mm256_stream_load_si256" },
    { "vmovntpd_avx", "_mm256_stream_pd" },
    { "vmovntps_avx", "_mm256_stream_ps" },
    { "vmovshdup_avx", "_mm256_movehdup_ps" },
    { "vmovsldup_avx", "_mm256_moveldup_ps" },
    { "vmpsadbw_avx", "_mm_mpsadbw_epu8" },
    { "vmpsadbw_avx2", "_mm256_mpsadbw_epu8" },
    { "vorpd_avx", "_mm256_or_pd" },
    { "vorps_avx", "_mm256_or_ps" },
    { "vpabsb_avx", "_mm_abs_epi8" },
    { "vpabsb_avx2", "_mm256_abs_epi8" },
    { "vpabsd_avx", "_mm_abs_epi32" },
    { "vpabsd_avx2", "_mm256_abs_epi32" },
    { "vpabsw_avx", "_mm_abs_epi16" },
    { "vpabsw_avx2", "_mm256_abs_epi16" },
    { "vpackssdw_avx", "_mm_packs_epi32" },
    { "vpackssdw_avx2", "_mm256_packs_epi32" },
    { "vpacksswb_avx", "_mm_packs_epi16" },
    { "vpacksswb_avx2", "_mm256_packs_epi16" },
    { "vpackusdw_avx", "_mm_packus_epi32" },
    { "vpackusdw_avx2", "_mm256_packus_epi32" },
    { "vpackuswb_avx", "_mm_packus_epi16" },
    { "vpackuswb_avx2", "_mm256_packus_epi16" },
    { "vpaddb_avx", "_mm_add_epi8" },
    { "vpaddb_avx2", "_mm256_add_epi8" },
    { "vpaddd_avx", "_mm_add_epi32" },
    { "vpaddd_avx2", "_mm256_add_epi32" },
    { "vpaddq_avx", "_mm_add_epi64" },
    { "vpaddq_avx2", "_mm256_add_epi64" },
    { "vpaddsb_avx", "_mm_adds_epi8" },
    { "vpaddsb_avx2", "_mm256_adds_epi8" },
    { "vpaddsw_avx", "_mm_adds_epi16" },
    { "vpaddsw_avx2", "_mm256_adds_epi16" },
    { "vpaddusb_avx", "_mm_adds_epu8" },
    { "vpaddusb_avx2", "_mm256_adds_epu8" },
    { "vpaddusw_avx", "_mm_adds_epu16" },
    { "vpaddusw_avx2", "_mm256_adds_epu16" },
    { "vpaddw_avx", "_mm_add_epi16" },
    { "vpaddw_avx2", "_mm256_add_epi16" },
    { "vpalignr_avx", "_mm_alignr_epi8" },
    { "vpalignr_avx2", "_mm256_alignr_epi8" },
    { "vpand_avx", "_mm_and_si128" },
    { "vpand_avx2", "_mm256_and_si256" },
    { "vpandn_avx", "_mm_andnot_si128" },
    { "vpandn_avx2", "_mm256_andnot_si256" },
    { "vpavgb_avx", "_mm_avg_epu8" },
    { "vpavgb_avx2", "_mm256_avg_epu8" },
    { "vpavgw_avx", "_mm_avg_epu16" },
    { "vpavgw_avx2", "_mm256_avg_epu16" },
    { "vpblendd_avx2", "_mm256_blend_epi32" },
    { "vpblendvb_avx", "_mm_blendv_epi8" },
    { "vpblendvb_avx2", "_mm256_blendv_epi8" },
    { "vpblendw_avx", "_mm_blend_epi16" },
    { "vpblendw_avx2", "_mm256_blend_epi16" },
    { "vpclmulqdq_vpclmulqdq", "_mm256_clmulepi64_epi128" },
    { "vpcmpeqb_avx", "_mm_cmpeq_epi8" },
    { "vpcmpeqb_avx2", "_mm256_cmpeq_epi8" },
    { "vpcmpeqd_avx", "_mm_cmpeq_epi32" },
    { "vpcmpeqd_avx2", "_mm256_cmpeq_epi32" },
    { "vpcmpeqw_avx", "_mm_cmpeq_epi16" },
    { "vpcmpeqw_avx2", "_mm256_cmpeq_epi16" },
    { "vpcmpestri_avx", "_mm_cmpestri_epi8" },
    { "vpcmpestrm_avx", "_mm_cmpestrm_epi8" },
    { "vpcmpgtb_avx", "_mm_cmpgt_epi8" },
    { "vpcmpgtb_avx2", "_mm256_cmpgt_epi8" },
    { "vpcmpgtd_avx", "_mm_cmpgt_epi32" },
    { "vpcmpgtd_avx2", "_mm256_cmpgt_epi32" },
    { "vpcmpgtq_avx", "_mm_cmpgt_epi64" },
    { "vpcmpgtq_avx2", "_mm256_cmpgt_epi64" },
    { "vpcmpgtw_avx", "_mm_cmpgt_epi16" },
    { "vpcmpgtw_avx2", "_mm256_cmpgt_epi16" },
    { "vpcmpistri_avx", "_mm_cmpistri_epi8" },
    { "vpcmpistrm_avx", "_mm_cmpistrm_epi8" },
    { "vperm2f128_avx", "_mm256_permute2f128_si256" },
    { "vperm2i128_avx2", "_mm256_permute2x128_si256" },
    { "vpermd_avx2", "_mm256_permutevar8x32_epi32" },
    { "vpermilpd_avx", "_mm256_permute_pd" },
    { "vpermilps_avx", "_mm256_permute_ps" },
    { "vpermpd_avx2", "_mm256_permute4x64_pd" },
    { "vpermps_avx2", "_mm256_permutevar8x32_ps" },
    { "vpermq_avx2", "_mm256_permute4x64_epi64" },
    { "vpextrb_avx", "_mm_extract_epi8" },
    { "vpextrd_avx", "_mm_extract_epi32" },
    { "vpextrq_avx", "_mm_extract_epi64" },
    { "vpextrw_avx", "_mm_extract_epi16" },
    { "vpgatherdd", "_mm256_i32gather_epi32" },
    { "vpgatherdq", "_mm256_i32gather_epi64" },
    { "vpgatherqd", "_mm_i32gather_epi64" },
    { "vpgatherqq", "_mm256_i64gather_epi64" },
    { "vphaddd_avx", "_mm_hadd_epi32" },
    { "vphaddd_avx2", "_mm256_hadd_epi32" },
    { "vphaddsw_avx", "_mm_hadds_epi16" },
    { "vphaddsw_avx2", "_mm256_hadds_epi16" },
    { "vphaddw_avx", "_mm_hadd_epi16" },
    { "vphaddw_avx2", "_mm256_hadd_epi16" },
    { "vphminposuw_avx", "_mm_minpos_epu16" },
    { "vphsubd_avx", "_mm_hsub_epi32" },
    { "vphsubd_avx2", "_mm256_hsub_epi32" },
    { "vphsubsw_avx", "_mm_hsubs_epi16" },
    { "vphsubsw_avx2", "_mm256_hsubs_epi16" },
    { "vphsubw_avx", "_mm_hsub_epi16" },
    { "vphsubw_avx2", "_mm256_hsub_epi16" },
    { "vpinsrb_avx", "_mm_insert_epi8" },
    { "vpinsrd_avx", "_mm_insert_epi32" },
    { "vpinsrq_avx", "_mm_insert_epi64" },
    { "vpinsrw_avx", "_mm_insert_epi16" },
    { "vpmaddubsw_avx", "_mm_maddubs_epi16" },
    { "vpmaddubsw_avx2", "_mm256_maddubs_epi16" },
    { "vpmaddwd_avx", "_mm_madd_epi16" },
    { "vpmaddwd_avx2", "_mm256_madd_epi16" },
    { "vpmaskmovd_avx2", "_mm256_maskload_epi32" },
    { "vpmaskmovq_avx2", "_mm256_maskload_epi64" },
    { "vpmaxsb_avx", "_mm_max_epi8" },
    { "vpmaxsb_avx2", "_mm256_max_epi8" },
    { "vpmaxsd_avx", "_mm_max_epi32" },
    { "vpmaxsd_avx2", "_mm256_max_epi32" },
    { "vpmaxsw_avx", "_mm_max_epi16" },
    { "vpmaxsw_avx2", "_mm256_max_epi16" },
    { "vpmaxub_avx", "_mm_max_epu8" },
    { "vpmaxub_avx2", "_mm256_max_epu8" },
    { "vpmaxud_avx", "_mm_max_epu32" },
    { "vpmaxud_avx2", "_mm256_max_epu32" },
    { "vpmaxuw_avx", "_mm_max_epu16" },
    { "vpmaxuw_avx2", "_mm256_max_epu16" },
    { "vpminsb_avx", "_mm_min_epi8" },
    { "vpminsb_avx2", "_mm256_min_epi8" },
    { "vpminsd_avx", "_mm_min_epi32" },
    { "vpminsd_avx2", "_mm256_min_epi32" },
    { "vpminsw_avx", "_mm_min_epi16" },
    { "vpminsw_avx2", "_mm256_min_epi16" },
    { "vpminub_avx", "_mm_min_epu8" },
    { "vpminub_avx2", "_mm256_min_epu8" },
    { "vpminud_avx", "_mm_min_epu32" },
    { "vpminud_avx2", "_mm256_min_epu32" },
    { "vpminuw_avx", "_mm_min_epu16" },
    { "vpminuw_avx2", "_mm256_min_epu16" },
    { "vpmovsxbd_avx", "_mm_cvtepi8_epi32" },
    { "vpmovsxbd_avx2", "_mm256_cvtepi8_epi32" },
    { "vpmovsxbq_avx", "_mm_cvtepi8_epi64" },
    { "vpmovsxbq_avx2", "_mm256_cvtepi8_epi64" },
    { "vpmovsxbw_avx", "_mm_cvtepi8_epi16" },
    { "vpmovsxbw_avx2", "_mm256_cvtepi8_epi16" },
    { "vpmovsxdq_avx", "_mm_cvtepi32_epi64" },
    { "vpmovsxdq_avx2", "_mm256_cvtepi32_epi64" },
    { "vpmovsxwd_avx", "_mm_cvtepi16_epi32" },
    { "vpmovsxwd_avx2", "_mm256_cvtepi16_epi32" },
    { "vpmovsxwq_avx", "_mm_cvtepi16_epi64" },
    { "vpmovsxwq_avx2", "_mm256_cvtepi16_epi64" },
    { "vpmovzxbd_avx", "_mm_cvtepu8_epi32" },
    { "vpmovzxbd_avx2", "_mm256_cvtepu8_epi32" },
    { "vpmovzxbq_avx", "_mm_cvtepu8_epi64" },
    { "vpmovzxbq_avx2", "_mm256_cvtepu8_epi64" },
    { "vpmovzxbw_avx", "_mm_cvtepu8_epi16" },
    { "vpmovzxbw_avx2", "_mm256_cvtepu8_epi16" },
    { "vpmovzxdq_avx", "_mm_cvtepu32_epi64" },
    { "vpmovzxdq_avx2", "_mm256_cvtepu32_epi64" },
    { "vpmovzxwd_avx", "_mm_cvtepu16_epi32" },
    { "vpmovzxwd_avx2", "_mm256_cvtepu16_epi32" },
    { "vpmovzxwq_avx", "_mm_cvtepu16_epi64" },
    { "vpmovzxwq_avx2", "_mm256_cvtepu16_epi64" },
    { "vpmuldq_avx", "_mm_mul_epi32" },
    { "vpmuldq_avx2", "_mm256_mul_epi32" },
    { "vpmulhrsw_avx", "_mm_mulhrs_epi16" },
    { "vpmulhrsw_avx2", "_mm256_mulhrs_epi16" },
    { "vpmulhuw_avx", "_mm_mulhi_epu16" },
    { "vpmulhuw_avx2", "_mm256_mulhi_epu16" },
    { "vpmulhw_avx", "_mm_mulhi_epi16" },
    { "vpmulhw_avx2", "_mm256_mulhi_epi16" },
    { "vpmulld_avx", "_mm_mullo_epi32" },
    { "vpmulld_avx2", "_mm256_mullo_epi32" },
    { "vpmuludq_avx", "_mm_mul_epu32" },
    { "vpmuludq_avx2", "_mm256_mul_epu32" },
    { "vpor_avx", "_mm_or_si128" },
    { "vpor_avx2", "_mm256_or_si256" },
    { "vpsadbw_avx", "_mm_sad_epu8" },
    { "vpsadbw_avx2", "_mm256_sad_epu8" },
    { "vpshufb_avx", "_mm_shuffle_epi8" },
    { "vpshufb_avx2", "_mm256_shuffle_epi8" },
    { "vpshufd_avx", "_mm_shuffle_epi32" },
    { "vpshufd_avx2", "_mm256_shuffle_epi32" },
    { "vpshufhw_avx", "_mm_shufflehi_epi16" },
    { "vpshufhw_avx2", "_mm256_shufflehi_epi16" },
    { "vpshuflw_avx", "_mm_shufflelo_epi16" },
    { "vpshuflw_avx2", "_mm256_shufflelo_epi16" },
    { "vpsignb_avx", "_mm_sign_epi8" },
    { "vpsignb_avx2", "_mm256_sign_epi8" },
    { "vpsignd_avx", "_mm_sign_epi32" },
    { "vpsignd_avx2", "_mm256_sign_epi32" },
    { "vpsignw_avx", "_mm_sign_epi16" },
    { "vpsignw_avx2", "_mm256_sign_epi16" },
    { "vpslld_avx", "_mm_sll_epi32" },
    { "vpslld_avx2", "_mm256_sll_epi32" },
    { "vpslldq_avx", "_mm_sll_si128" },
    { "vpslldq_avx2", "_mm256_sll_si256" },
    { "vpsllq_avx", "_mm_sll_epi64" },
    { "vpsllq_avx2", "_mm256_sll_epi64" },
    { "vpsllvd_avx2", "_mm256_sllv_epi32" },
    { "vpsllvq_avx2", "_mm256_sllv_epi64" },
    { "vpsllw_avx", "_mm_sll_epi16" },
    { "vpsllw_avx2", "_mm256_sll_epi16" },
    { "vpsrad_avx", "_mm_sra_epi32" },
    { "vpsrad_avx2", "_mm256_sra_epi32" },
    { "vpsravd_avx2", "_mm256_srav_epi32" },
    { "vpsraw_avx", "_mm_sra_epi16" },
    { "vpsraw_avx2", "_mm256_sra_epi16" },
    { "vpsrld_avx", "_mm_srl_epi32" },
    { "vpsrld_avx2", "_mm256_srl_epi32" },
    { "vpsrldq_avx", "_mm_srl_si128" },
    { "vpsrldq_avx2", "_mm256_srl_si256" },
    { "vpsrlq_avx", "_mm_srl_epi64" },
    { "vpsrlq_avx2", "_mm256_srl_epi64" },
    { "vpsrlvd_avx2", "_mm256_srlv_epi32" },
    { "vpsrlvq_avx2", "_mm256_srlv_epi64" },
    { "vpsrlw_avx", "_mm_srl_epi16" },
    { "vpsrlw_avx2", "_mm256_srl_epi16" },
    { "vpsubb_avx", "_mm_sub_epi8" },
    { "vpsubb_avx2", "_mm256_sub_epi8" },
    { "vpsubd_avx", "_mm_sub_epi32" },
    { "vpsubd_avx2", "_mm256_sub_epi32" },
    { "vpsubq_avx", "_mm_sub_epi64" },
    { "vpsubq_avx2", "_mm256_sub_epi64" },
    { "vpsubsb_avx", "_mm_subs_epi8" },
    { "vpsubsb_avx2", "_mm256_subs_epi8" },
    { "vpsubsw_avx", "_mm_subs_epi16" },
    { "vpsubsw_avx2", "_mm256_subs_epi16" },
    { "vpsubusb_avx", "_mm_subs_epu8" },
    { "vpsubusb_avx2", "_mm256_subs_epu8" },
    { "vpsubusw_avx", "_mm_subs_epu16" },
    { "vpsubusw_avx2", "_mm256_subs_epu16" },
    { "vpsubw_avx", "_mm_sub_epi16" },
    { "vpsubw_avx2", "_mm256_sub_epi16" },
    { "vpternlogd_avx512f", "_mm512_ternarylogic_epi32" },
    { "vpternlogq_avx512f", "_mm512_ternarylogic_epi64" },
    { "vptest_avx", "_mm256_testz_si256" },
    { "vpunpckhbw_avx", "_mm_unpackhi_epi8" },
    { "vpunpckhbw_avx2", "_mm256_unpackhi_epi8" },
    { "vpunpckhdq_avx", "_mm_unpackhi_epi32" },
    { "vpunpckhdq_avx2", "_mm256_unpackhi_epi32" },
    { "vpunpckhqdq_avx", "_mm_unpackhi_epi64" },
    { "vpunpckhqdq_avx2", "_mm256_unpackhi_epi64" },
    { "vpunpckhwd_avx", "_mm_unpackhi_epi16" },
    { "vpunpckhwd_avx2", "_mm256_unpackhi_epi16" },
    { "vpunpcklbw_avx", "_mm_unpacklo_epi8" },
    { "vpunpcklbw_avx2", "_mm256_unpacklo_epi8" },
    { "vpunpckldq_avx", "_mm_unpacklo_epi32" },
    { "vpunpckldq_avx2", "_mm256_unpacklo_epi32" },
    { "vpunpcklqdq_avx", "_mm_unpacklo_epi64" },
    { "vpunpcklqdq_avx2", "_mm256_unpacklo_epi64" },
    { "vpunpcklwd_avx", "_mm_unpacklo_epi16" },
    { "vpunpcklwd_avx2", "_mm256_unpacklo_epi16" },
    { "vrcpps_avx", "_mm256_rcp_ps" },
    { "vrcpss_avx", "_mm_rcp_ss" },
    { "vroundpd_avx", "_mm256_round_pd" },
    { "vroundps_avx", "_mm256_round_ps" },
    { "vroundsd_avx", "_mm_round_sd" },
    { "vroundss_avx", "_mm_round_ss" },
    { "vrsqrtps_avx", "_mm256_rsqrt_ps" },
    { "vrsqrtss_avx", "_mm_rsqrt_ss" },
    { "vshufpd_avx", "_mm256_shuffle_pd" },
    { "vshufps_avx", "_mm256_shuffle_ps" },
    { "vsqrtpd_avx", "_mm256_sqrt_pd" },
    { "vsqrtps_avx", "_mm256_sqrt_ps" },
    { "vsqrtsd_avx", "_mm_sqrt_sd" },
    { "vsqrtss_avx", "_mm_sqrt_ss" },
    { "vstmxcsr_avx", "_mm_stmxcsr" },
    { "vsubpd_avx", "_mm256_sub_pd" },
    { "vsubps_avx", "_mm256_sub_ps" },
    { "vtestpd_avx", "_mm256_testz_pd" },
    { "vtestps_avx", "_mm256_testz_ps" },
    { "vunpckhpd_avx", "_mm256_unpackhi_pd" },
    { "vunpckhps_avx", "_mm256_unpackhi_ps" },
    { "vunpcklpd_avx", "_mm256_unpacklo_pd" },
    { "vunpcklps_avx", "_mm256_unpacklo_ps" },
};

constexpr bool simd_table_sorted()
{
    for (std::size_t i = 1; i < std::size(kSimdIntrinsics); ++i) {
        const char* a = kSimdIntrinsics[i - 1].pcodeop;
        const char* b = kSimdIntrinsics[i].pcodeop;
        std::size_t k = 0;
        while (a[k] != '\0' && a[k] == b[k])
            ++k;
        if (static_cast<unsigned char>(a[k]) >= static_cast<unsigned char>(b[k]))
            return false;
    }
    return true;
}

static_assert(simd_table_sorted(), "kSimdIntrinsics must be strictly sorted by pcodeop name");

const char* lookup_simd_intrinsic(const std::string_view pcodeop)
{
    std::size_t lo = 0;
    std::size_t hi = std::size(kSimdIntrinsics);
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        const std::string_view key(kSimdIntrinsics[mid].pcodeop);
        if (key < pcodeop)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < std::size(kSimdIntrinsics) && pcodeop == kSimdIntrinsics[lo].pcodeop)
        return kSimdIntrinsics[lo].intrinsic;
    return nullptr;
}

std::string resolve_callother_name(const ghidra::PcodeOp* operation,
                                   const ghidra::Funcdata& function)
{
    if (!operation || operation->numInput() < 1)
        return {};
    const auto* selector = operation->getIn(0);
    if (!selector || !selector->isConstant())
        return {};
    const auto* arch = function.getArch();
    if (!arch)
        return {};
    const auto index = selector->getOffset();
    if (index > (std::numeric_limits<ghidra::uint4>::max)())
        return {};
    const auto* userop = arch->userops.getOp(static_cast<ghidra::uint4>(index));
    if (!userop)
        return {};
    const auto raw = userop->getOperatorName(operation);
    if (raw.empty())
        return {};
    if (const char* intrinsic = lookup_simd_intrinsic(raw))
        return intrinsic;
    return bounded_utf8(raw);
}

bool transparent_forward_op(const std::uint16_t opcode) noexcept
{
    return opcode == ghidra::CPUI_COPY || opcode == ghidra::CPUI_CAST ||
        opcode == ghidra::CPUI_INT_ZEXT || opcode == ghidra::CPUI_INT_SEXT;
}

struct artifact_reader_t {
    const std::string& bytes;
    std::size_t offset = 0;

    bool u32(std::uint32_t& value) {
        if (offset > bytes.size() || bytes.size() - offset < sizeof(value))
            return false;
        value = 0;
        for (std::size_t index = 0; index < sizeof(value); ++index)
            value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset++])) << (index * 8U);
        return true;
    }

    bool string(std::string& value) {
        std::uint32_t size = 0;
        if (!u32(size) || size > k_artifact_max_bytes || offset > bytes.size() || bytes.size() - offset < size)
            return false;
        value.assign(bytes.data() + offset, size);
        offset += size;
        return true;
    }

    bool complete() const noexcept { return offset == bytes.size(); }
};

void append_u32(std::string& bytes, const std::uint32_t value)
{
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes.push_back(static_cast<char>(value >> (index * 8U)));
}

bool append_string(std::string& bytes, const std::string& value)
{
    if (value.size() > k_artifact_max_bytes || bytes.size() > k_artifact_max_bytes - sizeof(std::uint32_t) - value.size())
        return false;
    append_u32(bytes, static_cast<std::uint32_t>(value.size()));
    bytes.append(value);
    return true;
}

decompiler_diagnostic_t diagnostic(const decompiler_diagnostic_severity_t severity,
                                   const decompiler_diagnostic_code_t code,
                                   std::string key,
                                   const std::uint32_t ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = severity;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = ordinal;
    return result;
}

source_coordinate_t coordinate(const capture_request_t& request,
                               const decompiler_coordinate_layer_t layer,
                               const std::uint64_t address)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = request.workspace_generation;
    result.entity = request.entity;
    decompiler_address_range_t range;
    const auto* native = std::get_if<native_decompiler_entity_identity_t>(&request.entity.identity);
    range.begin = native ? native->entry : address_t{};
    range.end = range.begin;
    range.begin.value = address;
    range.end.value = address == (std::numeric_limits<std::uint64_t>::max)() ? address : address + 1U;
    result.address_range = range;
    return result;
}

provider_ir_opcode_t provider_opcode(const capture_value_t& value, bool& supported)
{
    supported = true;
    switch (value.kind) {
    case capture_value_kind_t::parameter:
        return provider_ir_opcode_t::parameter;
    case capture_value_kind_t::local:
        return provider_ir_opcode_t::local;
    case capture_value_kind_t::constant:
        return provider_ir_opcode_t::constant;
    case capture_value_kind_t::pcode:
        break;
    }
    switch (value.pcode_opcode) {
    case ghidra::CPUI_COPY:
        return provider_ir_opcode_t::copy;
    case ghidra::CPUI_LOAD:
        return provider_ir_opcode_t::load;
    case ghidra::CPUI_STORE:
        return provider_ir_opcode_t::store;
    case ghidra::CPUI_BRANCH:
        return provider_ir_opcode_t::branch;
    case ghidra::CPUI_CBRANCH:
        return provider_ir_opcode_t::conditional_branch;
    case ghidra::CPUI_BRANCHIND:
        return provider_ir_opcode_t::switch_branch;
    case ghidra::CPUI_CALL:
        return provider_ir_opcode_t::call;
    case ghidra::CPUI_CALLIND:
        return provider_ir_opcode_t::indirect_call;
    case ghidra::CPUI_RETURN:
        return provider_ir_opcode_t::return_value;
    case ghidra::CPUI_MULTIEQUAL:
        return provider_ir_opcode_t::phi;
    case ghidra::CPUI_CAST:
    case ghidra::CPUI_INT_ZEXT:
    case ghidra::CPUI_INT_SEXT:
    case ghidra::CPUI_SUBPIECE:
        return provider_ir_opcode_t::cast;
    case ghidra::CPUI_PTRADD:
        return provider_ir_opcode_t::array_load;
    case ghidra::CPUI_PTRSUB:
        return provider_ir_opcode_t::field_load;
    case ghidra::CPUI_INT_2COMP:
    case ghidra::CPUI_INT_NEGATE:
    case ghidra::CPUI_BOOL_NEGATE:
    case ghidra::CPUI_FLOAT_NEG:
    case ghidra::CPUI_FLOAT_ABS:
    case ghidra::CPUI_FLOAT_SQRT:
        return provider_ir_opcode_t::unary;
    case ghidra::CPUI_INT_EQUAL:
    case ghidra::CPUI_INT_NOTEQUAL:
    case ghidra::CPUI_INT_SLESS:
    case ghidra::CPUI_INT_SLESSEQUAL:
    case ghidra::CPUI_INT_LESS:
    case ghidra::CPUI_INT_LESSEQUAL:
    case ghidra::CPUI_INT_ADD:
    case ghidra::CPUI_INT_SUB:
    case ghidra::CPUI_INT_CARRY:
    case ghidra::CPUI_INT_SCARRY:
    case ghidra::CPUI_INT_SBORROW:
    case ghidra::CPUI_INT_XOR:
    case ghidra::CPUI_INT_AND:
    case ghidra::CPUI_INT_OR:
    case ghidra::CPUI_INT_LEFT:
    case ghidra::CPUI_INT_RIGHT:
    case ghidra::CPUI_INT_SRIGHT:
    case ghidra::CPUI_INT_MULT:
    case ghidra::CPUI_INT_DIV:
    case ghidra::CPUI_INT_SDIV:
    case ghidra::CPUI_INT_REM:
    case ghidra::CPUI_INT_SREM:
    case ghidra::CPUI_BOOL_XOR:
    case ghidra::CPUI_BOOL_AND:
    case ghidra::CPUI_BOOL_OR:
    case ghidra::CPUI_FLOAT_EQUAL:
    case ghidra::CPUI_FLOAT_NOTEQUAL:
    case ghidra::CPUI_FLOAT_LESS:
    case ghidra::CPUI_FLOAT_LESSEQUAL:
    case ghidra::CPUI_FLOAT_ADD:
    case ghidra::CPUI_FLOAT_DIV:
    case ghidra::CPUI_FLOAT_MULT:
    case ghidra::CPUI_FLOAT_SUB:
    case ghidra::CPUI_PIECE:
    case ghidra::CPUI_INSERT:
        return provider_ir_opcode_t::binary;
    default:
        supported = false;
        return provider_ir_opcode_t::unknown;
    }
}

hir_node_kind_t hir_kind(const provider_ir_opcode_t opcode)
{
    switch (opcode) {
    case provider_ir_opcode_t::parameter: return hir_node_kind_t::parameter;
    case provider_ir_opcode_t::local: return hir_node_kind_t::local;
    case provider_ir_opcode_t::constant: return hir_node_kind_t::literal;
    case provider_ir_opcode_t::copy: return hir_node_kind_t::assignment;
    case provider_ir_opcode_t::unary: return hir_node_kind_t::unary;
    case provider_ir_opcode_t::binary: return hir_node_kind_t::binary;
    case provider_ir_opcode_t::cast: return hir_node_kind_t::cast;
    case provider_ir_opcode_t::load: return hir_node_kind_t::load;
    case provider_ir_opcode_t::store: return hir_node_kind_t::store;
    case provider_ir_opcode_t::field_load:
    case provider_ir_opcode_t::field_store: return hir_node_kind_t::field;
    case provider_ir_opcode_t::array_load:
    case provider_ir_opcode_t::array_store: return hir_node_kind_t::index;
    case provider_ir_opcode_t::call:
    case provider_ir_opcode_t::indirect_call: return hir_node_kind_t::call;
    case provider_ir_opcode_t::phi: return hir_node_kind_t::phi;
    case provider_ir_opcode_t::branch: return hir_node_kind_t::branch;
    case provider_ir_opcode_t::conditional_branch: return hir_node_kind_t::conditional;
    case provider_ir_opcode_t::switch_branch: return hir_node_kind_t::switch_branch;
    case provider_ir_opcode_t::return_value: return hir_node_kind_t::return_value;
    case provider_ir_opcode_t::throw_value: return hir_node_kind_t::throw_value;
    default: return hir_node_kind_t::unknown;
    }
}

std::string value_text(const capture_value_t& value)
{
    if (!value.stable_symbol.empty())
        return value.stable_symbol;
    if (!value.stable_immediate.empty())
        return value.stable_immediate;
    if (value.kind == capture_value_kind_t::parameter)
        return "parameter_" + std::to_string(value.id);
    if (value.kind == capture_value_kind_t::local)
        return "local_" + std::to_string(value.id);
    if (value.kind == capture_value_kind_t::constant)
        return "constant_" + std::to_string(value.id);
    return ghidra::get_opname(static_cast<ghidra::OpCode>(value.pcode_opcode));
}

std::string binary_operator(const std::uint16_t opcode)
{
    switch (opcode) {
    case ghidra::CPUI_INT_EQUAL:
    case ghidra::CPUI_FLOAT_EQUAL: return "==";
    case ghidra::CPUI_INT_NOTEQUAL:
    case ghidra::CPUI_FLOAT_NOTEQUAL:
    case ghidra::CPUI_BOOL_XOR: return "!=";
    case ghidra::CPUI_INT_SLESS:
    case ghidra::CPUI_INT_LESS:
    case ghidra::CPUI_FLOAT_LESS: return "<";
    case ghidra::CPUI_INT_SLESSEQUAL:
    case ghidra::CPUI_INT_LESSEQUAL:
    case ghidra::CPUI_FLOAT_LESSEQUAL: return "<=";
    case ghidra::CPUI_INT_ADD:
    case ghidra::CPUI_FLOAT_ADD: return "+";
    case ghidra::CPUI_INT_SUB:
    case ghidra::CPUI_FLOAT_SUB: return "-";
    case ghidra::CPUI_INT_XOR: return "^";
    case ghidra::CPUI_INT_AND: return "&";
    case ghidra::CPUI_INT_OR: return "|";
    case ghidra::CPUI_INT_LEFT: return "<<";
    case ghidra::CPUI_INT_RIGHT:
    case ghidra::CPUI_INT_SRIGHT: return ">>";
    case ghidra::CPUI_INT_MULT:
    case ghidra::CPUI_FLOAT_MULT: return "*";
    case ghidra::CPUI_INT_DIV:
    case ghidra::CPUI_INT_SDIV:
    case ghidra::CPUI_FLOAT_DIV: return "/";
    case ghidra::CPUI_INT_REM:
    case ghidra::CPUI_INT_SREM: return "%";
    case ghidra::CPUI_BOOL_AND: return "&&";
    case ghidra::CPUI_BOOL_OR: return "||";
    default: return {};
    }
}

std::string unary_operator(const std::uint16_t opcode)
{
    switch (opcode) {
    case ghidra::CPUI_INT_2COMP:
    case ghidra::CPUI_FLOAT_NEG: return "-";
    case ghidra::CPUI_INT_NEGATE: return "~";
    case ghidra::CPUI_BOOL_NEGATE: return "!";
    default: return {};
    }
}

struct hir_semantics_t {
    hir_node_kind_t kind = hir_node_kind_t::unknown;
    std::vector<std::uint64_t> operands;
    std::string stable_value;
    bool supported = true;
};

hir_semantics_t hir_semantics(const capture_value_t& value,
                              const provider_ir_opcode_t opcode,
                              const bool provider_supported)
{
    hir_semantics_t result;
    result.kind = hir_kind(opcode);
    result.operands = value.operand_ids;
    result.stable_value = value_text(value);
    result.supported = provider_supported;
    if (value.kind != capture_value_kind_t::pcode) {
        if (value.kind == capture_value_kind_t::constant && !value.stable_symbol.empty())
            result.kind = hir_node_kind_t::reference;
        return result;
    }
    const auto select = [&result, &value](const std::initializer_list<std::size_t> indices) {
        std::vector<std::uint64_t> selected;
        selected.reserve(indices.size());
        for (const auto index : indices) {
            if (index >= value.operand_ids.size())
                return false;
            selected.push_back(value.operand_ids[index]);
        }
        result.operands = std::move(selected);
        return true;
    };
    switch (value.pcode_opcode) {
    case ghidra::CPUI_COPY:
        result.kind = hir_node_kind_t::cast;
        result.stable_value = "copy";
        result.supported = select({0}) && value.operand_ids.size() == 1;
        break;
    case ghidra::CPUI_LOAD:
        result.supported = select({1}) && value.operand_ids.size() == 2;
        break;
    case ghidra::CPUI_STORE:
        result.supported = select({1, 2}) && value.operand_ids.size() == 3;
        break;
    case ghidra::CPUI_BRANCH:
        result.operands.clear();
        result.supported = value.operand_ids.size() == 1;
        break;
    case ghidra::CPUI_CBRANCH:
        result.supported = select({1}) && value.operand_ids.size() == 2;
        break;
    case ghidra::CPUI_BRANCHIND:
        result.kind = hir_node_kind_t::switch_branch;
        result.stable_value = "switch";
        result.supported = select({0}) && value.operand_ids.size() == 1;
        break;
    case ghidra::CPUI_CALL:
    case ghidra::CPUI_CALLIND:
        result.operands.clear();
        if (value.operand_ids.size() > 1)
            result.operands.assign(value.operand_ids.begin() + 1, value.operand_ids.end());
        result.supported = !value.operand_ids.empty() && !value.stable_symbol.empty();
        break;
    case ghidra::CPUI_RETURN:
        result.operands.clear();
        if (value.operand_ids.size() > 1)
            result.operands.assign(value.operand_ids.begin() + 1, value.operand_ids.end());
        result.supported = result.operands.size() <= 1;
        break;
    case ghidra::CPUI_MULTIEQUAL:
        result.kind = hir_node_kind_t::phi;
        result.stable_value = "phi";
        result.supported = !value.operand_ids.empty();
        break;
    case ghidra::CPUI_CAST:
    case ghidra::CPUI_INT_ZEXT:
    case ghidra::CPUI_INT_SEXT:
        result.supported = select({0}) && value.operand_ids.size() == 1;
        break;
    case ghidra::CPUI_SUBPIECE:
        result.kind = hir_node_kind_t::cast;
        result.stable_value = "subpiece";
        result.supported = select({0}) && value.operand_ids.size() == 2;
        break;
    case ghidra::CPUI_PTRADD:
    case ghidra::CPUI_PTRSUB:
        result.kind = hir_node_kind_t::index;
        result.supported = select({0, 1}) &&
            (value.pcode_opcode == ghidra::CPUI_PTRSUB || value.operand_ids.size() == 3);
        break;
    default:
        if (result.kind == hir_node_kind_t::unary) {
            result.stable_value = unary_operator(value.pcode_opcode);
            result.supported = !result.stable_value.empty() && value.operand_ids.size() == 1;
        } else if (result.kind == hir_node_kind_t::binary) {
            result.stable_value = binary_operator(value.pcode_opcode);
            result.supported = !result.stable_value.empty() && value.operand_ids.size() == 2;
        }
        break;
    }
    if (!result.supported) {
        result.kind = hir_node_kind_t::unknown;
        result.operands.clear();
        if (value.pcode_opcode == ghidra::CPUI_CALLOTHER && !value.stable_symbol.empty()) {
            result.stable_value = value.stable_symbol;
        } else {
            result.stable_value = "unknown_pcode_" + std::to_string(value.pcode_opcode) +
                "_" + std::to_string(value.id);
        }
    }
    return result;
}

bool generated_local_name(const std::string_view value) noexcept
{
    constexpr std::string_view prefix = "local_";
    if (value.size() <= prefix.size() || value.substr(0, prefix.size()) != prefix)
        return false;
    for (std::size_t index = prefix.size(); index < value.size(); ++index) {
        if (value[index] < '0' || value[index] > '9')
            return false;
    }
    return true;
}

bool native_liveness_root(const capture_value_t& value,
                          const provider_ir_opcode_t opcode,
                          const bool exception_block) noexcept
{
    if (exception_block && value.kind == capture_value_kind_t::pcode) {
        switch (value.pcode_opcode) {
        case ghidra::CPUI_INT_DIV:
        case ghidra::CPUI_INT_SDIV:
        case ghidra::CPUI_INT_REM:
        case ghidra::CPUI_INT_SREM:
            return true;
        default:
            break;
        }
    }
    switch (opcode) {
    case provider_ir_opcode_t::parameter:
    case provider_ir_opcode_t::load:
    case provider_ir_opcode_t::store:
    case provider_ir_opcode_t::field_store:
    case provider_ir_opcode_t::array_store:
    case provider_ir_opcode_t::call:
    case provider_ir_opcode_t::indirect_call:
    case provider_ir_opcode_t::branch:
    case provider_ir_opcode_t::conditional_branch:
    case provider_ir_opcode_t::switch_branch:
    case provider_ir_opcode_t::return_value:
    case provider_ir_opcode_t::throw_value:
    case provider_ir_opcode_t::monitor_enter:
    case provider_ir_opcode_t::monitor_exit:
        return true;
    case provider_ir_opcode_t::local:
        return !value.stable_symbol.empty() && !generated_local_name(value.stable_symbol);
    case provider_ir_opcode_t::unknown:
        return value.kind == capture_value_kind_t::pcode &&
            (value.pcode_opcode == ghidra::CPUI_CALLOTHER ||
             value.pcode_opcode == ghidra::CPUI_INDIRECT ||
             value.pcode_opcode == ghidra::CPUI_NEW);
    case provider_ir_opcode_t::constant:
    case provider_ir_opcode_t::copy:
    case provider_ir_opcode_t::unary:
    case provider_ir_opcode_t::binary:
    case provider_ir_opcode_t::cast:
    case provider_ir_opcode_t::field_load:
    case provider_ir_opcode_t::array_load:
    case provider_ir_opcode_t::phi:
        return false;
    }
    return true;
}

std::unordered_set<std::uint64_t> native_live_value_ids(const capture_t& capture)
{
    std::unordered_map<std::uint64_t, const capture_value_t*> values;
    std::size_t value_count = 0;
    for (const auto& block : capture.blocks)
        value_count += block.values.size();
    values.reserve(value_count);
    for (const auto& block : capture.blocks) {
        for (const auto& value : block.values)
            values.emplace(value.id, &value);
    }

    std::unordered_set<std::uint64_t> live;
    live.reserve(value_count);
    std::vector<std::uint64_t> pending;
    pending.reserve(value_count);
    const auto seed = [&live, &pending](const std::uint64_t id) {
        if (id != 0 && live.insert(id).second)
            pending.push_back(id);
    };
    for (const auto& block : capture.blocks) {
        const bool exception_block = !block.exception_successor_ids.empty();
        bool has_root = false;
        std::uint64_t last_id = 0;
        for (const auto& value : block.values) {
            bool supported = false;
            const auto opcode = provider_opcode(value, supported);
            if (native_liveness_root(value, opcode, exception_block)) {
                seed(value.id);
                has_root = true;
            }
            last_id = (std::max)(last_id, value.id);
        }
        if (!has_root)
            seed(last_id);
    }
    while (!pending.empty()) {
        const auto id = pending.back();
        pending.pop_back();
        const auto value = values.find(id);
        if (value == values.end())
            continue;
        bool supported = false;
        const auto opcode = provider_opcode(*value->second, supported);
        const auto semantics = hir_semantics(*value->second, opcode, supported);
        if (!semantics.supported)
            continue;
        for (const auto operand : semantics.operands)
            seed(operand);
    }
    return live;
}

void retain_live_native_hir(const std::unordered_set<std::uint64_t>& live,
                            hir_function_t& hir)
{
    std::unordered_set<std::uint64_t> live_types;
    live_types.reserve(live.size() + hir.parameters.size() + 1U);
    live_types.insert(hir.return_type_id);
    for (const auto& parameter : hir.parameters)
        live_types.insert(parameter.type_id);
    for (auto& block : hir.blocks) {
        block.values.erase(std::remove_if(block.values.begin(), block.values.end(),
            [&live](const hir_value_t& value) {
                return live.find(value.id) == live.end();
            }), block.values.end());
        for (const auto& value : block.values)
            live_types.insert(value.type_id);
    }
    hir.locals.erase(std::remove_if(hir.locals.begin(), hir.locals.end(),
        [&live_types](const hir_variable_t& local) {
            return generated_local_name(local.stable_name) &&
                live_types.find(local.type_id) == live_types.end();
        }), hir.locals.end());
}

bool sorted_unique(std::vector<std::uint64_t>& ids)
{
    std::sort(ids.begin(), ids.end());
    return std::adjacent_find(ids.begin(), ids.end()) == ids.end();
}

decompiler_type_kind_t type_kind(const ghidra::Datatype* type)
{
    if (!type)
        return decompiler_type_kind_t::unknown;
    switch (type->getMetatype()) {
    case ghidra::TYPE_VOID: return decompiler_type_kind_t::void_type;
    case ghidra::TYPE_BOOL: return decompiler_type_kind_t::boolean;
    case ghidra::TYPE_INT: return decompiler_type_kind_t::signed_integer;
    case ghidra::TYPE_UINT: return decompiler_type_kind_t::unsigned_integer;
    case ghidra::TYPE_FLOAT: return decompiler_type_kind_t::floating_point;
    case ghidra::TYPE_PTR: return decompiler_type_kind_t::pointer;
    case ghidra::TYPE_ARRAY: return decompiler_type_kind_t::array;
    case ghidra::TYPE_STRUCT: return decompiler_type_kind_t::structure;
    case ghidra::TYPE_UNION: return decompiler_type_kind_t::union_type;
    case ghidra::TYPE_CODE: return decompiler_type_kind_t::function;
    default: return decompiler_type_kind_t::unknown;
    }
}

}

extraction_result_t normalize(const capture_t& capture)
{
    extraction_result_t result;
    std::uint32_t ordinal = 1;
    const auto fail = [&result, &ordinal](const decompiler_diagnostic_code_t code, const char* key) {
        result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error, code, key, ordinal++));
    };
    if (capture.request.workspace_generation == 0 || capture.request.type_graph_revision == 0 ||
        !std::holds_alternative<native_decompiler_entity_identity_t>(capture.request.entity.identity) ||
        !validate_decompiler_entity_key(capture.request.entity).valid() || capture.types.empty() ||
        capture.blocks.empty() || capture.entry_block_id == 0) {
        fail(decompiler_diagnostic_code_t::invalid_contract, "ghidra_ir.capture.header");
        return result;
    }

    std::vector<capture_type_t> types = capture.types;
    std::sort(types.begin(), types.end(), [](const auto& left, const auto& right) { return left.id < right.id; });
    std::unordered_map<std::uint64_t, std::uint64_t> type_ids;
    type_graph_t type_graph;
    type_graph.entity = capture.request.entity;
    type_graph.revision = capture.request.type_graph_revision;
    for (const auto& type : types) {
        if (type.id == 0 || type.confidence > 100 || type_ids.find(type.id) != type_ids.end()) {
            fail(decompiler_diagnostic_code_t::malformed_type_graph, "ghidra_ir.capture.type_id");
            return result;
        }
        const std::uint64_t normalized_id = static_cast<std::uint64_t>(type_ids.size() + 1U);
        type_ids.emplace(type.id, normalized_id);
        decompiler_type_node_t node;
        node.id = normalized_id;
        node.kind = type.kind;
        node.canonical_name = type.canonical_name.empty() ? "ghidra.type." + std::to_string(type.id) : type.canonical_name;
        node.display_name = type.display_name.empty() ? node.canonical_name : type.display_name;
        node.byte_size = type.byte_size;
        node.alignment = type.alignment == 0 ? 1U : type.alignment;
        node.is_signed = type.is_signed;
        node.confidence = type.kind == decompiler_type_kind_t::unknown
            ? (std::min)(type.confidence, std::uint8_t{50}) : type.confidence;
        node.provenance = type.provenance;
        node.coordinates.push_back(coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir,
            std::get<native_decompiler_entity_identity_t>(capture.request.entity.identity).entry.value));
        type_graph.nodes.push_back(std::move(node));
    }
    for (const auto& type : types) {
        if (type.kind != decompiler_type_kind_t::structure || !type.byte_size)
            continue;
        for (const auto& edge : type.edges) {
            if (edge.kind == decompiler_type_edge_kind_t::member && edge.byte_offset &&
                *edge.byte_offset >= *type.byte_size) {
                fail(decompiler_diagnostic_code_t::malformed_type_graph,
                    "ghidra_ir.capture.type_member_offset");
                return result;
            }
        }
    }
    std::uint32_t edge_ordinal = 1;
    for (const auto& type : types) {
        const auto source = type_ids.find(type.id);
        for (const auto& edge : type.edges) {
            const auto target = type_ids.find(edge.target_type_id);
            if (source == type_ids.end() || target == type_ids.end() || edge.confidence > 100) {
                fail(decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.capture.type_edge");
                return result;
            }
            decompiler_type_edge_t normalized;
            normalized.source_type_id = source->second;
            normalized.target_type_id = target->second;
            normalized.kind = edge.kind;
            normalized.stable_name = edge.stable_name.empty() ? "ghidra.type.edge." + std::to_string(edge_ordinal) : edge.stable_name;
            normalized.byte_offset = edge.byte_offset;
            normalized.ordinal = edge_ordinal++;
            normalized.confidence = edge.confidence;
            normalized.provenance = edge.provenance;
            type_graph.edges.push_back(std::move(normalized));
        }
    }
    const auto return_type = type_ids.find(capture.request.return_type_id);
    if (return_type == type_ids.end()) {
        fail(decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.capture.return_type");
        return result;
    }
    if (capture.request.function_type_id != 0) {
        const auto function_type = type_ids.find(capture.request.function_type_id);
        const auto source_type = std::find_if(types.begin(), types.end(), [&capture](const capture_type_t& type) {
            return type.id == capture.request.function_type_id;
        });
        if (function_type == type_ids.end() || source_type == types.end() ||
            source_type->kind != decompiler_type_kind_t::function) {
            fail(decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.capture.function_type");
            return result;
        }
    }

    std::vector<capture_block_t> blocks = capture.blocks;
    std::sort(blocks.begin(), blocks.end(), [](const auto& left, const auto& right) { return left.id < right.id; });
    std::set<std::uint64_t> block_ids;
    for (auto& block : blocks) {
        if (block.id == 0 || !block_ids.insert(block.id).second || block.values.empty()) {
            fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.block");
            return result;
        }
        if (!sorted_unique(block.predecessor_ids) || !sorted_unique(block.successor_ids) ||
            !sorted_unique(block.exception_successor_ids)) {
            fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.edge");
            return result;
        }
        std::sort(block.values.begin(), block.values.end(), [](const auto& left, const auto& right) {
            return left.id < right.id;
        });
    }
    if (block_ids.find(capture.entry_block_id) == block_ids.end()) {
        fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.entry");
        return result;
    }
    const auto live_native_values = native_live_value_ids(capture);

    provider_ir_t provider_ir;
    provider_ir.provider = capture.request.provider;
    provider_ir.language = capture.request.language;
    provider_ir.entity = capture.request.entity;
    provider_ir.entry_block_id = capture.entry_block_id;
    hir_function_t hir;
    hir.entity = capture.request.entity;
    hir.type_graph_revision = type_graph.revision;
    hir.return_type_id = return_type->second;
    std::uint64_t previous_value_id = 0;
    std::uint32_t provider_diagnostic_ordinal = 1;
    std::uint32_t hir_diagnostic_ordinal = 1;
    for (const auto& block : blocks) {
        provider_ir_block_t provider_block;
        provider_block.id = block.id;
        provider_block.predecessor_ids = block.predecessor_ids;
        provider_block.successor_ids = block.successor_ids;
        provider_block.exception_successor_ids = block.exception_successor_ids;
        provider_block.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir, block.address);
        hir_block_t hir_block;
        hir_block.id = block.id;
        hir_block.predecessor_ids = block.predecessor_ids;
        hir_block.successor_ids = block.successor_ids;
        hir_block.exception_successor_ids = block.exception_successor_ids;
        hir_block.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::hir, block.address);
        std::sort(provider_block.predecessor_ids.begin(), provider_block.predecessor_ids.end());
        std::sort(provider_block.successor_ids.begin(), provider_block.successor_ids.end());
        std::sort(provider_block.exception_successor_ids.begin(), provider_block.exception_successor_ids.end());
        std::sort(hir_block.predecessor_ids.begin(), hir_block.predecessor_ids.end());
        std::sort(hir_block.successor_ids.begin(), hir_block.successor_ids.end());
        std::sort(hir_block.exception_successor_ids.begin(), hir_block.exception_successor_ids.end());
        for (const auto& value : block.values) {
            if (value.id == 0 || value.id <= previous_value_id || value.confidence > 100 ||
                type_ids.find(value.type_id) == type_ids.end()) {
                fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.value");
                return result;
            }
            previous_value_id = value.id;
            bool supported = false;
            const auto opcode = provider_opcode(value, supported);
            provider_ir_value_t provider_value;
            provider_value.id = value.id;
            provider_value.opcode = opcode;
            provider_value.type_id = type_ids.at(value.type_id);
            provider_value.operand_ids = value.operand_ids;
            provider_value.stable_immediate = value.stable_immediate;
            provider_value.stable_symbol = value.stable_symbol;
            provider_value.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir, value.address);
            provider_value.confidence = supported ? value.confidence : (std::min)(value.confidence, std::uint8_t{50});
            provider_value.provenance = value.provenance;
            provider_block.values.push_back(provider_value);
            const auto semantics = hir_semantics(value, opcode, supported);
            const bool live_hir_value = live_native_values.find(value.id) != live_native_values.end();
            if (live_hir_value) {
                hir_value_t hir_value;
                hir_value.id = value.id;
                hir_value.kind = semantics.kind;
                hir_value.type_id = provider_value.type_id;
                hir_value.operand_ids = semantics.operands;
                hir_value.stable_value = semantics.stable_value;
                hir_value.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::hir, value.address);
                hir_value.confidence = semantics.supported ? provider_value.confidence : 0U;
                hir_value.provenance = provider_value.provenance;
                hir_block.values.push_back(std::move(hir_value));
            }
            if (!semantics.supported) {
                decompiler_unknown_t provider_unknown;
                provider_unknown.reason = decompiler_unknown_reason_t::unsupported_instruction;
                provider_unknown.stable_token = "ghidra.pcode." + std::to_string(value.pcode_opcode) + "." + std::to_string(value.id);
                provider_unknown.coordinate = provider_value.coordinate;
                provider_unknown.confidence = 0;
                provider_unknown.provenance = decompiler_fact_provenance_t::provider_semantics;
                provider_ir.unknowns.push_back(provider_unknown);
                provider_ir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unsupported_provider, "ghidra_ir.unsupported_pcode", provider_diagnostic_ordinal++));
                if (live_hir_value) {
                    decompiler_unknown_t hir_unknown = provider_unknown;
                    hir_unknown.coordinate.layer = decompiler_coordinate_layer_t::hir;
                    hir.unknowns.push_back(std::move(hir_unknown));
                    hir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                        decompiler_diagnostic_code_t::unsupported_provider, "ghidra_ir.unsupported_pcode", hir_diagnostic_ordinal++));
                }
            }
            if (value.unresolved_reference) {
                decompiler_unknown_t provider_unknown;
                provider_unknown.reason = decompiler_unknown_reason_t::unresolved_reference;
                provider_unknown.stable_token = "ghidra.call.unresolved." + std::to_string(value.id);
                provider_unknown.coordinate = provider_value.coordinate;
                provider_unknown.confidence = 0;
                provider_unknown.provenance = value.provenance;
                provider_ir.unknowns.push_back(provider_unknown);
                provider_ir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unresolved_symbol, "ghidra_ir.unresolved_call_target",
                    provider_diagnostic_ordinal++));
                if (live_hir_value) {
                    decompiler_unknown_t hir_unknown = provider_unknown;
                    hir_unknown.coordinate.layer = decompiler_coordinate_layer_t::hir;
                    hir.unknowns.push_back(std::move(hir_unknown));
                    hir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                        decompiler_diagnostic_code_t::unresolved_symbol, "ghidra_ir.unresolved_call_target",
                        hir_diagnostic_ordinal++));
                }
            }
        }
        provider_ir.source_coordinates.push_back(provider_block.coordinate);
        hir.source_coordinates.push_back(hir_block.coordinate);
        provider_ir.blocks.push_back(std::move(provider_block));
        hir.blocks.push_back(std::move(hir_block));
    }

    std::vector<capture_high_variable_t> highs = capture.high_variables;
    std::sort(highs.begin(), highs.end(), [](const auto& left, const auto& right) { return left.id < right.id; });
    std::uint64_t parameter_id = 1;
    std::uint64_t local_id = 1;
    for (const auto& high : highs) {
        const auto type = type_ids.find(high.type_id);
        if (high.id == 0 || high.confidence > 100 || type == type_ids.end()) {
            fail(decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.capture.high_variable");
            return result;
        }
        hir_variable_t variable;
        variable.id = high.parameter ? parameter_id++ : local_id++;
        variable.stable_name = high.stable_name.empty() ? "high_" + std::to_string(high.id) : high.stable_name;
        variable.type_id = type->second;
        variable.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::hir, high.address);
        variable.confidence = high.confidence;
        variable.provenance = high.provenance;
        if (high.parameter)
            hir.parameters.push_back(std::move(variable));
        else
            hir.locals.push_back(std::move(variable));
    }
    retain_live_native_hir(live_native_values, hir);
    hir.provider_ir_hash = stable_serialization_hash(provider_ir);

    const auto provider_validation = validate_provider_ir(provider_ir);
    const auto hir_validation = validate_hir_function(hir);
    const auto type_validation = validate_type_graph(type_graph);
    if (!provider_validation.valid() || !hir_validation.valid() || !type_validation.valid()) {
        result.diagnostics.insert(result.diagnostics.end(), provider_validation.diagnostics.begin(), provider_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), hir_validation.diagnostics.begin(), hir_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), type_validation.diagnostics.begin(), type_validation.diagnostics.end());
        return result;
    }
    result.artifacts = typed_artifacts_t{std::move(provider_ir), std::move(hir), std::move(type_graph)};
    return result;
}

extraction_result_t extract(const ghidra::Funcdata& function, const capture_request_t& request)
{
    capture_t capture;
    capture.request = request;
    if (auto* native = std::get_if<native_decompiler_entity_identity_t>(
            &capture.request.entity.identity)) {
        native->canonical_symbol = bounded_utf8(native->canonical_symbol);
        if (native->canonical_symbol.empty()) {
            native->canonical_symbol = bounded_utf8(function.getDisplayName());
            if (native->canonical_symbol.empty())
                native->canonical_symbol = bounded_utf8(function.getName());
            if (native->canonical_symbol.empty())
                native->canonical_symbol = address_symbol(native->entry.value);
        }
    }
    const auto* native_entity = std::get_if<native_decompiler_entity_identity_t>(
        &capture.request.entity.identity);
    const std::uint64_t runtime_entry = function.getAddress().getOffset();
    std::uint64_t coordinate_bias = 0;
    if (native_entity && native_entity->entry.space == address_space_id_t::relative_virtual) {
        if (runtime_entry < native_entity->entry.value) {
            extraction_result_t result;
            result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::source_map_rejected,
                "ghidra_ir.runtime_entry_bias", 1));
            return result;
        }
        coordinate_bias = runtime_entry - native_entity->entry.value;
    }
    const auto code_coordinate = [coordinate_bias, runtime_entry, native_entity](
            const std::uint64_t address) {
        if (!native_entity || native_entity->entry.space != address_space_id_t::relative_virtual)
            return address;
        if (address < coordinate_bias)
            return native_entity->entry.value;
        const auto normalized = address - coordinate_bias;
        return address < runtime_entry ? native_entity->entry.value : normalized;
    };
    std::map<const ghidra::Datatype*, std::uint64_t> types;
    std::uint64_t next_type_id = 1;
    std::function<std::uint64_t(const ghidra::Datatype*)> ensure_type;
    ensure_type = [&capture, &types, &next_type_id, &ensure_type](const ghidra::Datatype* type) {
        if (!type)
            return std::uint64_t{0};
        const auto found = types.find(type);
        if (found != types.end())
            return found->second;
        const auto id = next_type_id++;
        types.emplace(type, id);
        capture_type_t value;
        value.id = id;
        value.kind = type_kind(type);
        value.canonical_name = datatype_name(type);
        value.display_name = bounded_utf8(type->getDisplayName());
        if (value.display_name.empty())
            value.display_name = value.canonical_name;
        if (type->getSize() > 0)
            value.byte_size = static_cast<std::uint64_t>(type->getSize());
        value.alignment = type->getAlignment() > 0 ? static_cast<std::uint32_t>(type->getAlignment()) : 1U;
        value.is_signed = type->getMetatype() == ghidra::TYPE_INT;
        value.confidence = datatype_confidence(type);
        capture.types.push_back(std::move(value));
        const auto append_edge = [&](const ghidra::Datatype* target,
                                     const decompiler_type_edge_kind_t kind,
                                     std::string stable_name,
                                     std::optional<std::uint64_t> byte_offset = std::nullopt) {
            const auto target_id = ensure_type(target);
            if (target_id == 0 || target_id == id)
                return;
            auto& source = capture.types.at(static_cast<std::size_t>(id - 1U));
            const auto duplicate = std::find_if(source.edges.begin(), source.edges.end(),
                [&](const capture_type_edge_t& edge) {
                    return edge.target_type_id == target_id && edge.kind == kind &&
                        edge.stable_name == stable_name && edge.byte_offset == byte_offset;
                });
            if (duplicate == source.edges.end())
                source.edges.push_back({target_id, kind, std::move(stable_name), byte_offset});
        };
        if (const auto* alias = type->getTypedef(); alias && alias != type)
            append_edge(alias, decompiler_type_edge_kind_t::alias, "typedef");
        if (const auto* pointer = dynamic_cast<const ghidra::TypePointer*>(type)) {
            append_edge(pointer->getPtrTo(), decompiler_type_edge_kind_t::pointee, "pointee");
            return id;
        }
        if (const auto* array = dynamic_cast<const ghidra::TypeArray*>(type)) {
            append_edge(array->getBase(), decompiler_type_edge_kind_t::element, "element", 0U);
            return id;
        }
        if (const auto* structure = dynamic_cast<const ghidra::TypeStruct*>(type)) {
            std::uint32_t index = 0;
            for (auto field = structure->beginField(); field != structure->endField(); ++field, ++index) {
                const std::string name = field->name.empty()
                    ? "member." + std::to_string(index) : bounded_utf8(field->name);
                append_edge(field->type, decompiler_type_edge_kind_t::member, name,
                    field->offset >= 0 ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(field->offset)}
                                       : std::nullopt);
            }
            return id;
        }
        if (const auto* union_type = dynamic_cast<const ghidra::TypeUnion*>(type)) {
            for (ghidra::int4 index = 0; index < union_type->numDepend(); ++index) {
                const auto* field = union_type->getField(index);
                if (!field)
                    continue;
                const std::string name = field->name.empty()
                    ? "member." + std::to_string(index) : bounded_utf8(field->name);
                append_edge(field->type, decompiler_type_edge_kind_t::member, name,
                    field->offset >= 0 ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(field->offset)}
                                       : std::nullopt);
            }
            return id;
        }
        if (const auto* code = dynamic_cast<const ghidra::TypeCode*>(type)) {
            const auto* prototype = code->getPrototype();
            if (prototype) {
                append_edge(prototype->getOutputType(), decompiler_type_edge_kind_t::return_type, "return");
                std::string signature = datatype_name(prototype->getOutputType()) + "(";
                for (ghidra::int4 index = 0; index < prototype->numParams(); ++index) {
                    const auto* parameter = prototype->getParam(index);
                    append_edge(parameter ? parameter->getType() : nullptr,
                        decompiler_type_edge_kind_t::parameter, "parameter." + std::to_string(index));
                    if (index != 0)
                        signature.push_back(',');
                    signature += datatype_name(parameter ? parameter->getType() : nullptr);
                }
                if (prototype->isDotdotdot()) {
                    if (prototype->numParams() != 0)
                        signature.push_back(',');
                    signature += "...";
                }
                signature.push_back(')');
                auto& source = capture.types.at(static_cast<std::size_t>(id - 1U));
                if (source.canonical_name == "code" || source.canonical_name == "function") {
                    source.canonical_name = bounded_utf8(signature);
                    source.display_name = source.canonical_name;
                }
            }
            return id;
        }
        for (ghidra::int4 index = 0; index < type->numDepend(); ++index)
            append_edge(type->getDepend(index), decompiler_type_edge_kind_t::alias,
                "dependency." + std::to_string(index));
        return id;
    };
    std::map<std::string, std::uint64_t> prototype_types;
    const auto type_name_for_id = [&capture](const std::uint64_t id) {
        if (id == 0 || id > capture.types.size())
            return std::string{"unknown"};
        return capture.types.at(static_cast<std::size_t>(id - 1U)).canonical_name;
    };
    const auto append_prototype = [&capture, &ensure_type, &next_type_id, &prototype_types,
                                   &type_name_for_id](const ghidra::FuncProto& prototype,
                                                     std::string identity,
                                                     const ghidra::Datatype* output_override = nullptr) {
        const auto* output_type = output_override ? output_override : prototype.getOutputType();
        const auto return_type_id = ensure_type(output_type);
        if (return_type_id == 0)
            return std::uint64_t{0};
        std::vector<std::pair<std::uint64_t, std::string>> parameters;
        parameters.reserve(static_cast<std::size_t>((std::max)(prototype.numParams(), ghidra::int4{0})));
        std::uint8_t confidence = prototype.hasInputErrors() || prototype.hasOutputErrors()
            ? std::uint8_t{50} : std::uint8_t{100};
        confidence = (std::min)(confidence, datatype_confidence(output_type));
        std::string signature = type_name_for_id(return_type_id) + "(";
        for (ghidra::int4 index = 0; index < prototype.numParams(); ++index) {
            const auto* parameter = prototype.getParam(index);
            const auto* parameter_type = parameter ? parameter->getType() : nullptr;
            const auto parameter_type_id = ensure_type(parameter_type);
            confidence = (std::min)(confidence, datatype_confidence(parameter_type));
            if (index != 0)
                signature.push_back(',');
            signature += parameter_type_id == 0 ? "unknown" : type_name_for_id(parameter_type_id);
            if (parameter_type_id != 0) {
                auto name = parameter ? bounded_utf8(parameter->getName()) : std::string{};
                if (prototype.hasThisPointer() && parameter && parameter->isThisPointer())
                    name = "this";
                if (name.empty())
                    name = "parameter." + std::to_string(index);
                parameters.emplace_back(parameter_type_id, std::move(name));
            }
        }
        if (prototype.isDotdotdot()) {
            if (prototype.numParams() != 0)
                signature.push_back(',');
            signature += "...";
        }
        signature.push_back(')');
        identity = bounded_utf8(identity);
        if (identity.empty())
            identity = "function";
        const auto canonical_name = bounded_utf8(identity + ":" + signature);
        if (const auto found = prototype_types.find(canonical_name); found != prototype_types.end())
            return found->second;
        const auto id = next_type_id++;
        prototype_types.emplace(canonical_name, id);
        capture_type_t value;
        value.id = id;
        value.kind = decompiler_type_kind_t::function;
        value.canonical_name = canonical_name;
        value.display_name = bounded_utf8(identity + " " + signature);
        value.alignment = 1;
        value.confidence = confidence;
        value.provenance = decompiler_fact_provenance_t::call_signature;
        value.edges.push_back({return_type_id, decompiler_type_edge_kind_t::return_type, "return",
            std::nullopt, confidence, decompiler_fact_provenance_t::call_signature});
        for (std::size_t index = 0; index < parameters.size(); ++index) {
            value.edges.push_back({parameters[index].first, decompiler_type_edge_kind_t::parameter,
                parameters[index].second, std::nullopt, confidence,
                decompiler_fact_provenance_t::call_signature});
        }
        capture.types.push_back(std::move(value));
        return id;
    };
    const auto* recovered_return_type = function.getFuncProto().getOutputType();
    const auto* void_type = function.getArch() && function.getArch()->types
        ? function.getArch()->types->getTypeVoid() : nullptr;
    struct call_site_capture_t {
        std::string stable_symbol;
        const ghidra::Datatype* result_type = nullptr;
        std::uint8_t confidence = 50;
        bool unresolved_reference = true;
    };
    std::map<std::uint64_t, capture_block_t> blocks;
    std::map<const ghidra::PcodeOp*, std::uint64_t> operation_ids;
    std::map<std::uint64_t, std::vector<const ghidra::PcodeOp*>> operations_by_block;
    std::map<const ghidra::Varnode*, std::uint64_t> input_ids;
    std::map<const ghidra::Varnode*, std::string> input_symbols;
    std::map<const ghidra::Varnode*, const ghidra::Datatype*> input_types;
    std::map<const ghidra::Varnode*, std::vector<const ghidra::PcodeOp*>> input_consumers;
    std::map<const ghidra::PcodeOp*, call_site_capture_t> call_sites;
    std::map<const ghidra::Varnode*, std::uint64_t> defined_ids;
    std::map<const ghidra::HighVariable*, std::uint64_t> high_ids;
    std::map<std::uint64_t, std::set<std::uint64_t>> high_value_ids;
    std::map<std::uint64_t, std::pair<std::uint64_t, bool>> conditional_edges;
    std::uint64_t next_value_id = 1;
    const auto associated_high = [](const ghidra::Varnode* node)
        -> const ghidra::HighVariable* {
        if (!node || node->isAnnotation())
            return nullptr;
        return node->getHigh();
    };
    const auto value_type = [&associated_high](const ghidra::Varnode* node,
                                                const bool definition_facing)
        -> const ghidra::Datatype* {
        if (!node)
            return nullptr;
        const auto* high = associated_high(node);
        if (!high)
            return definition_facing ? node->getTypeDefFacing() : node->getType();
        return definition_facing ? node->getHighTypeDefFacing() : high->getType();
    };
    const auto read_type = [&associated_high, &value_type](const ghidra::Varnode* node,
                                                           const ghidra::PcodeOp* operation) {
        if (!node || node->isAnnotation() || !operation)
            return value_type(node, false);
        const auto* high = associated_high(node);
        const auto* facing = high ? node->getHighTypeReadFacing(operation)
                                  : node->getTypeReadFacing(operation);
        return stronger_datatype(value_type(node, false), facing);
    };
    const auto formal_parameter = [&function, &associated_high](const ghidra::Varnode* node)
        -> const ghidra::ProtoParameter* {
        if (!node)
            return nullptr;
        const auto* high = associated_high(node);
        const auto* input = high && high->isInput() ? high->getInputVarnode() :
            (node->isInput() ? node : nullptr);
        if (!input)
            return nullptr;
        const auto& prototype = function.getFuncProto();
        for (ghidra::int4 index = 0; index < prototype.numParams(); ++index) {
            const auto* parameter = prototype.getParam(index);
            if (parameter && parameter->getSize() == input->getSize() &&
                parameter->getAddress() == input->getAddr())
                return parameter;
        }
        return nullptr;
    };
    const auto& graph = function.getBasicBlocks();
    for (ghidra::int4 index = 0; index < graph.getSize(); ++index) {
        const auto* block = graph.getBlock(index);
        if (!block)
            continue;
        const auto id = static_cast<std::uint64_t>(block->getIndex() + 1);
        capture_block_t capture_block;
        capture_block.id = id;
        for (ghidra::int4 edge = 0; edge < block->sizeIn(); ++edge)
            capture_block.predecessor_ids.push_back(static_cast<std::uint64_t>(block->getIn(edge)->getIndex() + 1));
        for (ghidra::int4 edge = 0; edge < block->sizeOut(); ++edge)
            capture_block.successor_ids.push_back(static_cast<std::uint64_t>(block->getOut(edge)->getIndex() + 1));
        blocks.emplace(id, std::move(capture_block));
    }
    for (auto iterator = function.beginOpAll(); iterator != function.endOpAll(); ++iterator) {
        const auto* operation = (*iterator).second;
        if (!operation || !operation->getParent())
            continue;
        const auto block_id = static_cast<std::uint64_t>(operation->getParent()->getIndex() + 1);
        const auto block = blocks.find(block_id);
        if (block == blocks.end())
            continue;
        operation_ids.emplace(operation, 0);
        operations_by_block[block_id].push_back(operation);
        if ((operation->code() == ghidra::CPUI_CALL || operation->code() == ghidra::CPUI_CALLIND) &&
            operation->numInput() > 0) {
            const auto* target = operation->getIn(0);
            const auto* specification = function.getCallSpecs(operation);
            call_site_capture_t site;
            const bool direct = operation->code() == ghidra::CPUI_CALL;
            const auto target_symbol = varnode_symbol_name(target);
            if (specification) {
                site.result_type = specification->getOutputType();
                if (const auto* callee = specification->getFuncdata()) {
                    site.stable_symbol = bounded_utf8(callee->getDisplayName());
                    if (site.stable_symbol.empty())
                        site.stable_symbol = bounded_utf8(callee->getName());
                    site.unresolved_reference = false;
                }
                if (site.stable_symbol.empty())
                    site.stable_symbol = bounded_utf8(specification->getName());
                if (site.stable_symbol.empty() && !specification->getEntryAddress().isInvalid())
                    site.stable_symbol = address_symbol(specification->getEntryAddress().getOffset());
            }
            if (direct) {
                if (site.stable_symbol.empty() && !target_symbol.empty())
                    site.stable_symbol = target_symbol;
                if (site.stable_symbol.empty() && target && target->isConstant())
                    site.stable_symbol = address_symbol(target->getOffset());
                site.unresolved_reference = !target || site.stable_symbol.empty();
            } else if (site.unresolved_reference) {
                if (!target_symbol.empty())
                    site.stable_symbol = "*" + target_symbol;
                if (site.stable_symbol.empty())
                    site.stable_symbol = "indirect@" + address_symbol(
                        code_coordinate(operation->getSeqNum().getAddr().getOffset()));
            }
            site.confidence = site.unresolved_reference ? std::uint8_t{50} : std::uint8_t{100};
            if (site.result_type)
                site.confidence = (std::min)(site.confidence, datatype_confidence(site.result_type));
            if (specification)
                (void)append_prototype(*specification, site.stable_symbol);
            if (target) {
                if (!target_symbol.empty())
                    input_symbols[target] = target_symbol;
                else if (direct && !site.stable_symbol.empty())
                    input_symbols[target] = site.stable_symbol;
            }
            call_sites.emplace(operation, std::move(site));
        }
        if (operation->code() == ghidra::CPUI_RETURN && operation->numInput() > 1 &&
            !function.getFuncProto().isOutputLocked()) {
            recovered_return_type = stronger_datatype(recovered_return_type,
                read_type(operation->getIn(1), operation));
        }
        for (ghidra::int4 index = 0; index < operation->numInput(); ++index) {
            const auto* input = operation->getIn(index);
            if (!input || input->isAnnotation())
                continue;
            input_consumers[input].push_back(operation);
            const auto candidate = read_type(input, operation);
            const auto found = input_types.find(input);
            if (found == input_types.end())
                input_types.emplace(input, candidate);
            else
                found->second = stronger_datatype(found->second, candidate);
        }
    }
    if (operation_ids.empty()) {
        extraction_result_t result;
        result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::provider_failure, "ghidra_ir.empty_pcode", 1));
        return result;
    }
    capture.request.return_type_id = ensure_type(recovered_return_type);
    capture.request.function_type_id = append_prototype(function.getFuncProto(),
        native_entity ? native_entity->canonical_symbol : bounded_utf8(function.getDisplayName()),
        recovered_return_type);
    if (capture.request.return_type_id == 0 || capture.request.function_type_id == 0) {
        extraction_result_t result;
        result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.function_prototype", 1));
        return result;
    }
    const auto entry_block = operations_by_block.begin()->first;
    capture.entry_block_id = entry_block;
    auto entry = blocks.find(entry_block);
    for (const auto& entry_pair : operations_by_block) {
        for (const auto* operation : entry_pair.second) {
            for (ghidra::int4 index = 0; index < operation->numInput(); ++index) {
                const auto* input = operation->getIn(index);
                if (!input || input->getDef())
                    continue;
                if (input_ids.find(input) == input_ids.end())
                    input_ids.emplace(input, next_value_id++);
            }
        }
    }
    for (const auto& entry_pair : operations_by_block) {
        for (const auto* operation : entry_pair.second) {
            const auto operation_id = next_value_id++;
            operation_ids.at(operation) = operation_id;
            const auto* output = operation->getOut();
            if (output && !defined_ids.emplace(output, operation_id).second) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.duplicate_output_varnode", 1));
                return result;
            }
        }
    }
    const auto collect_high = [&capture, &high_ids, &high_value_ids, &ensure_type, &associated_high,
                               &formal_parameter, native_entity, &code_coordinate, runtime_entry,
                               &function](
                               const ghidra::Varnode* node,
                               const std::uint64_t value_id) {
        if (!node || node->isAnnotation() || node->isConstant())
            return true;
        const auto* high = associated_high(node);
        if (!high)
            return true;
        if (const auto found = high_ids.find(high); found != high_ids.end()) {
            high_value_ids[found->second].insert(value_id);
            return true;
        }
        const bool is_parameter = high->isInput();
        const auto* parameter = is_parameter ? formal_parameter(node) : nullptr;
        const auto* recovered_type = parameter ? parameter->getType() : high->getType();
        const auto type_id = ensure_type(recovered_type);
        if (type_id == 0)
            return false;
        const auto id = static_cast<std::uint64_t>(high_ids.size() + 1U);
        high_ids.emplace(high, id);
        high_value_ids[id].insert(value_id);
        capture_high_variable_t variable;
        variable.id = id;
        variable.parameter = is_parameter;
        variable.stable_name = symbol_name(high->getSymbol());
        if (variable.stable_name.empty() && parameter)
            variable.stable_name = bounded_utf8(parameter->getName());
        if (parameter && function.getFuncProto().hasThisPointer() && parameter->isThisPointer())
            variable.stable_name = "this";
        if (variable.stable_name.empty()) {
            variable.stable_name = (is_parameter ? "parameter_" : "local_") + std::to_string(id);
            variable.confidence = (std::min)(datatype_confidence(recovered_type), std::uint8_t{75});
        } else {
            variable.confidence = datatype_confidence(recovered_type);
        }
        variable.provenance = parameter ? decompiler_fact_provenance_t::call_signature
                                        : decompiler_fact_provenance_t::provider_semantics;
        variable.type_id = type_id;
        variable.address = native_entity ? native_entity->entry.value : code_coordinate(runtime_entry);
        capture.high_variables.push_back(std::move(variable));
        return true;
    };
    const auto resolve_equate_name = [&input_consumers, &call_sites](
            const ghidra::Varnode* input, const std::uint64_t constant_value) {
        std::string result;
        if (!input)
            return result;
        constexpr std::size_t k_max_hops = 3;
        std::vector<std::string> callees;
        std::vector<const ghidra::Varnode*> pending{input};
        std::set<const ghidra::Varnode*> visited;
        std::size_t hops = 0;
        while (!pending.empty() && hops <= k_max_hops) {
            std::vector<const ghidra::Varnode*> next;
            for (const auto* node : pending) {
                if (!visited.insert(node).second)
                    continue;
                const auto consumers = input_consumers.find(node);
                if (consumers == input_consumers.end())
                    continue;
                for (const auto* op : consumers->second) {
                    if (!op)
                        continue;
                    const auto code = op->code();
                    if (code == ghidra::CPUI_CALL || code == ghidra::CPUI_CALLIND) {
                        const auto site = call_sites.find(op);
                        if (site != call_sites.end() && !site->second.stable_symbol.empty() &&
                            std::find(callees.begin(), callees.end(), site->second.stable_symbol) ==
                                callees.end())
                            callees.push_back(site->second.stable_symbol);
                        continue;
                    }
                    if (!transparent_forward_op(static_cast<std::uint16_t>(code)))
                        continue;
                    const auto* out = op->getOut();
                    if (out && visited.find(out) == visited.end())
                        next.push_back(out);
                }
            }
            pending = std::move(next);
            ++hops;
        }
        builtin_typelib::equate_match_t match;
        for (const auto& callee : callees) {
            if (builtin_typelib::lookup_equate_affinity(callee, constant_value, match) && match.name)
                return std::string(match.name);
        }
        if (builtin_typelib::lookup_equate_shaped(constant_value, match) && match.name)
            result.assign(match.name);
        return result;
    };
    std::vector<std::pair<const ghidra::Varnode*, std::uint64_t>> ordered_inputs(input_ids.begin(), input_ids.end());
    std::sort(ordered_inputs.begin(), ordered_inputs.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    for (const auto& pair : ordered_inputs) {
        const auto* input = pair.first;
        capture_value_t value;
        value.id = pair.second;
        value.kind = input->isConstant() ? capture_value_kind_t::constant :
            (input->isInput() ? capture_value_kind_t::parameter : capture_value_kind_t::local);
        const auto* parameter = formal_parameter(input);
        const auto input_type = input_types.find(input);
        const ghidra::Datatype* recovered_type = parameter ? parameter->getType()
            : (input_type != input_types.end() ? input_type->second : value_type(input, false));
        value.type_id = ensure_type(recovered_type);
        if (value.type_id == 0) {
            recovered_type = input->getType();
            value.type_id = ensure_type(recovered_type);
        }
        value.address = native_entity ? native_entity->entry.value : code_coordinate(runtime_entry);
        value.stable_immediate = input->isConstant() ? std::to_string(input->getOffset()) : std::string{};
        if (const auto symbol = input_symbols.find(input); symbol != input_symbols.end()) {
            value.stable_symbol = symbol->second;
            value.provenance = decompiler_fact_provenance_t::call_signature;
        } else {
            value.stable_symbol = varnode_symbol_name(input);
            if (value.stable_symbol.empty() && parameter)
                value.stable_symbol = bounded_utf8(parameter->getName());
            value.provenance = parameter ? decompiler_fact_provenance_t::call_signature
                                         : decompiler_fact_provenance_t::provider_semantics;
        }
        if (value.stable_symbol.empty() && input->isConstant()) {
            auto equate = resolve_equate_name(input, input->getOffset());
            if (!equate.empty())
                value.stable_symbol = std::move(equate);
        }
        value.confidence = datatype_confidence(recovered_type);
        entry->second.values.push_back(std::move(value));
        if (!collect_high(input, pair.second)) {
            extraction_result_t result;
            result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.input_varnode_type", 1));
            return result;
        }
    }
    for (const auto& entry_pair : operations_by_block) {
        auto block = blocks.find(entry_pair.first);
        if (block == blocks.end())
            continue;
        for (const auto* operation : entry_pair.second) {
            const auto value_id = operation_ids.at(operation);
            capture_value_t value;
            value.id = value_id;
            value.kind = capture_value_kind_t::pcode;
            value.pcode_opcode = static_cast<std::uint16_t>(operation->code());
            const auto* output = operation->getOut();
            if (output && defined_ids.find(output) == defined_ids.end()) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.output_varnode_binding", 1));
                return result;
            }
            const auto call_site = call_sites.find(operation);
            const ghidra::Datatype* operation_type = output ? value_type(output, true) : nullptr;
            if (!operation_type && call_site != call_sites.end())
                operation_type = call_site->second.result_type;
            if (!operation_type && operation->code() == ghidra::CPUI_RETURN)
                operation_type = recovered_return_type;
            if (!operation_type)
                operation_type = void_type;
            value.type_id = ensure_type(operation_type);
            if (value.type_id == 0 && output)
                value.type_id = ensure_type(output->getTypeDefFacing());
            if (value.type_id == 0) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.output_varnode_type", 1));
                return result;
            }
            value.address = code_coordinate(operation->getSeqNum().getAddr().getOffset());
            if (operation->code() == ghidra::CPUI_CBRANCH && operation->getParent() &&
                operation->getParent()->sizeOut() == 2) {
                const auto true_id = static_cast<std::uint64_t>(
                    operation->getParent()->getTrueOut()->getIndex() + 1);
                const auto inserted = conditional_edges.emplace(
                    block->first, std::make_pair(true_id, operation->isBooleanFlip()));
                if (!inserted.second) {
                    extraction_result_t result;
                    result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::malformed_provider_ir,
                        "ghidra_ir.duplicate_conditional_edge", 1));
                    return result;
                }
                value.stable_symbol = "condition.true=" + std::to_string(true_id) +
                    ";negated=" + (operation->isBooleanFlip() ? "1" : "0");
            } else if (call_site != call_sites.end()) {
                value.stable_symbol = call_site->second.stable_symbol;
                value.confidence = call_site->second.confidence;
                value.provenance = decompiler_fact_provenance_t::call_signature;
                value.unresolved_reference = call_site->second.unresolved_reference;
            } else {
                if (operation->code() == ghidra::CPUI_CALLOTHER) {
                    value.stable_symbol = resolve_callother_name(operation, function);
                } else {
                    value.stable_symbol = ghidra::get_opname(operation->code());
                }
                value.confidence = datatype_confidence(operation_type);
            }
            for (ghidra::int4 index = 0; index < operation->numInput(); ++index) {
                const auto* input = operation->getIn(index);
                if (!input)
                    continue;
                std::uint64_t input_value_id = 0;
                if (const auto defined = defined_ids.find(input); defined != defined_ids.end()) {
                    input_value_id = defined->second;
                } else if (const auto input_id = input_ids.find(input); input_id != input_ids.end()) {
                    input_value_id = input_id->second;
                } else {
                    extraction_result_t result;
                    result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.input_varnode_binding", 1));
                    return result;
                }
                value.operand_ids.push_back(input_value_id);
                if (!collect_high(input, input_value_id)) {
                    extraction_result_t result;
                    result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.input_varnode_type", 1));
                    return result;
                }
            }
            if (!collect_high(output, value_id)) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.output_varnode_high_type", 1));
                return result;
            }
            block->second.values.push_back(std::move(value));
        }
    }
    std::set<std::uint64_t> populated_blocks;
    for (const auto& pair : blocks) {
        if (!pair.second.values.empty())
            populated_blocks.insert(pair.first);
    }
    const auto projected_targets = [&blocks, &populated_blocks](const std::uint64_t first) {
        std::set<std::uint64_t> targets;
        std::set<std::uint64_t> visited;
        std::vector<std::uint64_t> pending{first};
        while (!pending.empty()) {
            const auto current = pending.back();
            pending.pop_back();
            if (!visited.insert(current).second)
                continue;
            const auto found = blocks.find(current);
            if (found == blocks.end())
                continue;
            if (populated_blocks.find(current) != populated_blocks.end()) {
                targets.insert(current);
                continue;
            }
            pending.insert(pending.end(), found->second.successor_ids.begin(),
                found->second.successor_ids.end());
        }
        return std::vector<std::uint64_t>(targets.begin(), targets.end());
    };
    std::map<std::uint64_t, std::vector<std::uint64_t>> projected_successors;
    for (const auto block_id : populated_blocks) {
        std::set<std::uint64_t> targets;
        for (const auto successor : blocks.at(block_id).successor_ids) {
            const auto projected = projected_targets(successor);
            targets.insert(projected.begin(), projected.end());
        }
        projected_successors.emplace(block_id,
            std::vector<std::uint64_t>(targets.begin(), targets.end()));
    }
    for (const auto block_id : populated_blocks) {
        auto& block = blocks.at(block_id);
        block.predecessor_ids.clear();
        block.successor_ids = projected_successors.at(block_id);
    }
    for (const auto& source : projected_successors) {
        for (const auto target : source.second)
            blocks.at(target).predecessor_ids.push_back(source.first);
    }
    for (const auto& conditional : conditional_edges) {
        if (populated_blocks.find(conditional.first) == populated_blocks.end())
            continue;
        const auto targets = projected_targets(conditional.second.first);
        if (targets.size() != 1U ||
            !std::binary_search(projected_successors.at(conditional.first).begin(),
                projected_successors.at(conditional.first).end(), targets.front())) {
            extraction_result_t result;
            result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::malformed_provider_ir,
                "ghidra_ir.conditional_edge_projection", 1));
            return result;
        }
        const auto value = std::find_if(blocks.at(conditional.first).values.begin(),
            blocks.at(conditional.first).values.end(), [](const capture_value_t& candidate) {
                return candidate.kind == capture_value_kind_t::pcode &&
                    candidate.pcode_opcode == ghidra::CPUI_CBRANCH;
            });
        if (value == blocks.at(conditional.first).values.end()) {
            extraction_result_t result;
            result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::malformed_provider_ir,
                "ghidra_ir.conditional_edge_binding", 1));
            return result;
        }
        value->stable_symbol = "condition.true=" + std::to_string(targets.front()) +
            ";negated=" + (conditional.second.second ? "1" : "0");
    }
    for (const auto block_id : populated_blocks) {
        auto& block = blocks.at(block_id);
        block.address = block.values.front().address;
        capture.blocks.push_back(std::move(block));
    }
    if (std::none_of(capture.blocks.begin(), capture.blocks.end(), [&capture](const auto& block) { return block.id == capture.entry_block_id; }))
        capture.entry_block_id = capture.blocks.empty() ? 0 : capture.blocks.front().id;
    const auto live_values = native_live_value_ids(capture);
    capture.high_variables.erase(std::remove_if(
        capture.high_variables.begin(), capture.high_variables.end(),
        [&high_value_ids, &live_values](const capture_high_variable_t& variable) {
            if (variable.parameter || !generated_local_name(variable.stable_name))
                return false;
            const auto bindings = high_value_ids.find(variable.id);
            return bindings == high_value_ids.end() ||
                std::none_of(bindings->second.begin(), bindings->second.end(),
                    [&live_values](const std::uint64_t value_id) {
                        return live_values.find(value_id) != live_values.end();
                    });
        }), capture.high_variables.end());
    return normalize(capture);
}

std::string serialize_artifacts(const typed_artifacts_t& artifacts)
{
    if (!validate_provider_ir(artifacts.provider_ir).valid() || !validate_hir_function(artifacts.hir).valid() ||
        !validate_type_graph(artifacts.type_graph).valid() || !(artifacts.provider_ir.entity == artifacts.hir.entity) ||
        !(artifacts.provider_ir.entity == artifacts.type_graph.entity) ||
        artifacts.hir.provider_ir_hash != stable_serialization_hash(artifacts.provider_ir) ||
        artifacts.hir.type_graph_revision != artifacts.type_graph.revision)
        return {};
    try {
        std::string result;
        result.reserve(256);
        append_u32(result, k_artifact_magic);
        append_u32(result, k_artifact_version);
        if (!append_string(result, serialize_provider_ir(artifacts.provider_ir)) ||
            !append_string(result, serialize_hir_function(artifacts.hir)) ||
            !append_string(result, serialize_type_graph(artifacts.type_graph)))
            return {};
        return result;
    } catch (const std::exception&) {
        return {};
    }
}

std::optional<typed_artifacts_t> deserialize_artifacts(const std::string& bytes,
                                                       std::vector<decompiler_diagnostic_t>& diagnostics)
{
    diagnostics.clear();
    artifact_reader_t reader{bytes};
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::string provider_bytes;
    std::string hir_bytes;
    std::string type_bytes;
    if (bytes.size() > k_artifact_max_bytes || !reader.u32(magic) || magic != k_artifact_magic ||
        !reader.u32(version) || version != k_artifact_version || !reader.string(provider_bytes) ||
        !reader.string(hir_bytes) || !reader.string(type_bytes) || !reader.complete()) {
        diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization, "ghidra_ir.artifact.decode", 1));
        return std::nullopt;
    }
    const auto provider = deserialize_provider_ir(provider_bytes);
    const auto hir = deserialize_hir_function(hir_bytes);
    const auto types = deserialize_type_graph(type_bytes);
    if (!provider.valid() || !hir.valid() || !types.valid() || !provider.value || !hir.value || !types.value ||
        !(provider.value->entity == hir.value->entity) || !(provider.value->entity == types.value->entity) ||
        hir.value->provider_ir_hash != stable_serialization_hash(*provider.value) ||
        hir.value->type_graph_revision != types.value->revision) {
        diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization, "ghidra_ir.artifact.binding", 1));
        return std::nullopt;
    }
    return typed_artifacts_t{std::move(*provider.value), std::move(*hir.value), std::move(*types.value)};
}

}
