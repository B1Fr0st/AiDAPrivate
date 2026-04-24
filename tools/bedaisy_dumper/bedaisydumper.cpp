

#include "../../driver/comm.h"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


extern "C" long do_syscall_4(
    std::uint32_t, std::uint8_t*, std::uint64_t,
    std::uint64_t, std::uint64_t, std::uint64_t)
{
    return static_cast<long>(0xC0000002L);
}


typedef LONG(WINAPI* NtQuerySystemInformation_t)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

static constexpr ULONG SystemModuleInformation_Class = 11;

struct SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
};

struct SYSTEM_MODULE_INFORMATION {
    ULONG               NumberOfModules;
    SYSTEM_MODULE_ENTRY  Modules[1];
};


#pragma pack(push, 1)
struct DosHeader {
    std::uint16_t e_magic;
    std::uint8_t  pad[58];
    std::int32_t  e_lfanew;
};

struct FileHeader {
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
};

struct DataDirectory {
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
};

struct OptionalHeader64 {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve;
    std::uint64_t SizeOfStackCommit;
    std::uint64_t SizeOfHeapReserve;
    std::uint64_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[16];
};

struct NtHeaders64 {
    std::uint32_t    Signature;
    FileHeader       FileHeader;
    OptionalHeader64 OptionalHeader;
};

struct SectionHeader {
    char          Name[8];
    std::uint32_t VirtualSize;
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfRawData;
    std::uint32_t PointerToRawData;
    std::uint32_t PointerToRelocations;
    std::uint32_t PointerToLinenumbers;
    std::uint16_t NumberOfRelocations;
    std::uint16_t NumberOfLinenumbers;
    std::uint32_t Characteristics;
};


struct RuntimeFunction {
    std::uint32_t BeginAddress;
    std::uint32_t EndAddress;
    std::uint32_t UnwindInfoAddress;
};

struct UnwindInfo {
    std::uint8_t VersionAndFlags;
    std::uint8_t SizeOfProlog;
    std::uint8_t CountOfUnwindCodes;
    std::uint8_t FrameRegAndOffset;
};
#pragma pack(pop)


struct BasicBlock {
    std::uint64_t va;
    std::uint32_t rva;
    std::uint32_t size;
    std::uint64_t fallthrough_target;
    std::uint64_t branch_target;
    bool          is_unconditional_jmp;
    bool          is_conditional_jmp;
    bool          is_ret;
    bool          is_indirect;
    bool          is_call;


    bool          branch_resolved;
    bool          branch_taken;
};

struct RecoveredFunction {
    std::uint64_t entry_va;
    std::uint32_t entry_rva;
    std::vector<BasicBlock> blocks;
    std::uint32_t total_size;
    std::uint32_t max_rva_end;
    std::uint32_t min_rva;


    std::vector<std::uint8_t> clean_code;
    std::uint32_t clean_rva;
};


static std::string hex(std::uint64_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << v;
    return ss.str();
}

static std::string hex32(std::uint32_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << v;
    return ss.str();
}

static std::uint32_t align_up(std::uint32_t value, std::uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}


class Disassembler {
public:
    Disassembler() {
        ZydisDecoderInit(&dec_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&fmt_, ZYDIS_FORMATTER_STYLE_INTEL);
    }

    bool decode(const std::uint8_t* data, std::size_t len, std::uint64_t ip,
                ZydisDecodedInstruction& instr, ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]) {
        return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec_, data, len, &instr, ops));
    }

    bool is_jmp_rel(const ZydisDecodedInstruction& i) const {
        return i.mnemonic == ZYDIS_MNEMONIC_JMP && i.operand_count_visible >= 1 && i.raw.imm[0].is_relative;
    }

    bool is_jcc(const ZydisDecodedInstruction& i) const {
        switch (i.mnemonic) {
            case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_JCXZ:
            case ZYDIS_MNEMONIC_JECXZ: case ZYDIS_MNEMONIC_JKNZD: case ZYDIS_MNEMONIC_JKZD:
            case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_JNB:
            case ZYDIS_MNEMONIC_JNBE: case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_JNLE:
            case ZYDIS_MNEMONIC_JNO: case ZYDIS_MNEMONIC_JNP: case ZYDIS_MNEMONIC_JNS:
            case ZYDIS_MNEMONIC_JNZ: case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_JP:
            case ZYDIS_MNEMONIC_JRCXZ: case ZYDIS_MNEMONIC_JS: case ZYDIS_MNEMONIC_JZ:
                return true;
            default: return false;
        }
    }

    bool is_call(const ZydisDecodedInstruction& i) const { return i.mnemonic == ZYDIS_MNEMONIC_CALL; }

    bool is_ret(const ZydisDecodedInstruction& i) const { return i.mnemonic == ZYDIS_MNEMONIC_RET; }

    bool is_int3(const ZydisDecodedInstruction& i) const { return i.mnemonic == ZYDIS_MNEMONIC_INT3; }

    bool is_indirect_branch(const ZydisDecodedInstruction& i, const ZydisDecodedOperand ops[]) const {
        if (i.mnemonic == ZYDIS_MNEMONIC_JMP && i.operand_count_visible >= 1) {
            return ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER || ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY;
        }
        return false;
    }

    std::uint64_t calc_abs(std::uint64_t ip, const ZydisDecodedInstruction& i, const ZydisDecodedOperand& op) const {
        ZyanU64 r = 0;
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&i, &op, ip, &r))) return r;
        return 0;
    }

    std::string format(std::uint64_t ip, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand ops[]) {
        char buf[256];
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt_, &instr, ops, instr.operand_count_visible, buf, sizeof(buf), ip, nullptr)))
            return buf;
        return "<error>";
    }

private:
    ZydisDecoder dec_;
    ZydisFormatter fmt_;
};


class JunkDetector {
public:
    struct InsnInfo {
        std::uint64_t va;
        std::size_t   offset_in_section;
        std::uint8_t  length;
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
        bool is_junk;
    };

    std::uint32_t analyze(std::vector<InsnInfo>& insns) {
        const std::size_t n = insns.size();
        if (n < 2) return 0;
        std::uint32_t total_marked = 0;


        bool changed = true;
        while (changed) {
            changed = false;
            std::uint32_t before = count_junk(insns);

            pass_push_pop_pairs(insns);
            pass_dead_stores(insns);
            pass_standalone_nops(insns);
            pass_dead_flags(insns);
            pass_pushfq_popfq_pairs(insns);
            pass_dead_mov_imm_chains(insns);
            pass_opaque_arithmetic(insns);

            std::uint32_t after = count_junk(insns);
            if (after > before) changed = true;
        }

        for (const auto& ii : insns)
            if (ii.is_junk) total_marked++;
        return total_marked;
    }

private:
    static std::uint32_t count_junk(const std::vector<InsnInfo>& insns) {
        std::uint32_t c = 0;
        for (const auto& ii : insns)
            if (ii.is_junk) c++;
        return c;
    }


    void pass_push_pop_pairs(std::vector<InsnInfo>& insns) {
        const std::size_t n = insns.size();
        for (std::size_t i = 0; i + 1 < n; i++) {
            if (insns[i].is_junk) continue;
            if (insns[i].instr.mnemonic == ZYDIS_MNEMONIC_PUSH &&
                insns[i].ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {


                for (std::size_t j = i + 1; j < n && j <= i + 4; j++) {
                    if (insns[j].is_junk) continue;
                    if (insns[j].instr.mnemonic == ZYDIS_MNEMONIC_POP &&
                        insns[j].ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        insns[i].ops[0].reg.value == insns[j].ops[0].reg.value) {

                        bool safe = true;
                        for (std::size_t k = i + 1; k < j; k++) {
                            if (insns[k].is_junk) continue;
                            if (accesses_rsp(insns[k])) { safe = false; break; }
                        }
                        if (safe) {
                            insns[i].is_junk = true;
                            insns[j].is_junk = true;
                        }
                        break;
                    }

                    if (accesses_rsp(insns[j])) break;
                }
            }
        }
    }


    void pass_dead_stores(std::vector<InsnInfo>& insns) {
        const std::size_t n = insns.size();
        for (std::size_t i = 0; i < n; i++) {
            if (insns[i].is_junk) continue;
            if (insns[i].instr.mnemonic != ZYDIS_MNEMONIC_MOV) continue;
            if (insns[i].instr.operand_count_visible < 2) continue;
            if (insns[i].ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
            if (insns[i].ops[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;

            ZydisRegister target_reg = insns[i].ops[0].reg.value;
            ZydisRegister target_gpr = enclosing_gpr(target_reg);

            bool is_dead = false;
            std::size_t dead_end = i;
            for (std::size_t j = i + 1; j < n && j < i + 12; j++) {
                if (insns[j].is_junk) continue;

                bool writes_target = false, reads_target = false;
                for (int k = 0; k < insns[j].instr.operand_count_visible; k++) {
                    if (insns[j].ops[k].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        ZydisRegister r = insns[j].ops[k].reg.value;
                        if (enclosing_gpr(r) == target_gpr) {
                            if (insns[j].ops[k].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) writes_target = true;
                            if (insns[j].ops[k].actions & ZYDIS_OPERAND_ACTION_MASK_READ) reads_target = true;
                        }
                    }
                }

                if (!reads_target && writes_target) { is_dead = true; dead_end = j - 1; break; }
                if (reads_target && !is_arithmetic(insns[j].instr.mnemonic)) break;
                if (reads_target && is_arithmetic(insns[j].instr.mnemonic)) { dead_end = j; continue; }
            }
            if (is_dead) {
                for (std::size_t j = i; j <= dead_end; j++) insns[j].is_junk = true;
            }
        }
    }


    void pass_standalone_nops(std::vector<InsnInfo>& insns) {
        for (auto& ii : insns) {
            if (ii.instr.mnemonic == ZYDIS_MNEMONIC_NOP || ii.instr.mnemonic == ZYDIS_MNEMONIC_FNOP)
                ii.is_junk = true;
        }
    }


    void pass_dead_flags(std::vector<InsnInfo>& insns) {
        const std::size_t n = insns.size();
        for (std::size_t i = 0; i < n; i++) {
            if (insns[i].is_junk) continue;

            if (insns[i].instr.mnemonic == ZYDIS_MNEMONIC_CMP ||
                insns[i].instr.mnemonic == ZYDIS_MNEMONIC_TEST) {
                bool flags_used = false;
                for (std::size_t j = i + 1; j < n && j < i + 8; j++) {
                    if (insns[j].is_junk) continue;
                    if (reads_flags(insns[j].instr.mnemonic)) { flags_used = true; break; }
                    if (writes_flags(insns[j].instr.mnemonic)) break;
                }
                if (!flags_used) insns[i].is_junk = true;
            }
        }
    }


    void pass_pushfq_popfq_pairs(std::vector<InsnInfo>& insns) {
        const std::size_t n = insns.size();
        for (std::size_t i = 0; i + 1 < n; i++) {
            if (insns[i].is_junk) continue;
            if (insns[i].instr.mnemonic == ZYDIS_MNEMONIC_PUSHFQ) {
                for (std::size_t j = i + 1; j < n && j <= i + 6; j++) {
                    if (insns[j].is_junk) continue;
                    if (insns[j].instr.mnemonic == ZYDIS_MNEMONIC_POPFQ) {
                        insns[i].is_junk = true;
                        insns[j].is_junk = true;
                        break;
                    }
                    if (reads_flags(insns[j].instr.mnemonic)) break;
                }
            }
        }
    }


    void pass_dead_mov_imm_chains(std::vector<InsnInfo>& insns) {
        const std::size_t n = insns.size();
        for (std::size_t i = 0; i < n; i++) {
            if (insns[i].is_junk) continue;
            if (insns[i].instr.mnemonic != ZYDIS_MNEMONIC_MOV) continue;
            if (insns[i].ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
            if (insns[i].ops[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;

            std::uint64_t imm = insns[i].ops[1].imm.value.u;

            bool is_poison = (imm & 0xFFFF0000FFFF0000ULL) == 0xDEAD0000DEAD0000ULL ||
                             (imm >> 48) == 0xDEAD ||
                             (imm >> 32) == 0xDEADDEAD ||
                             imm == 0 ||
                             (imm > 0x100000000ULL && ((imm & 0xFF) == 0 || (imm & 0xFF) == 0xFF));

            if (!is_poison) continue;

            ZydisRegister target_gpr = enclosing_gpr(insns[i].ops[0].reg.value);
            std::size_t dead_end = i;
            for (std::size_t j = i + 1; j < n && j < i + 10; j++) {
                if (insns[j].is_junk) continue;
                bool uses = false, overwrites = false;
                for (int k = 0; k < insns[j].instr.operand_count_visible; k++) {
                    if (insns[j].ops[k].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        enclosing_gpr(insns[j].ops[k].reg.value) == target_gpr) {
                        if (insns[j].ops[k].actions & ZYDIS_OPERAND_ACTION_MASK_READ) uses = true;
                        if (insns[j].ops[k].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) overwrites = true;
                    }
                }
                if (uses && is_arithmetic(insns[j].instr.mnemonic)) { dead_end = j; continue; }
                if (!uses && overwrites) {
                    for (std::size_t k = i; k <= dead_end; k++) insns[k].is_junk = true;
                    break;
                }
                break;
            }
        }
    }


    void pass_opaque_arithmetic(std::vector<InsnInfo>& insns) {
        const std::size_t n = insns.size();
        for (std::size_t i = 0; i < n; i++) {
            if (insns[i].is_junk) continue;
            if (!is_unary_arithmetic(insns[i].instr.mnemonic)) continue;
            if (insns[i].ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;

            ZydisRegister target_gpr = enclosing_gpr(insns[i].ops[0].reg.value);


            bool result_used = false;
            for (std::size_t j = i + 1; j < n && j < i + 8; j++) {
                if (insns[j].is_junk) continue;
                bool reads = false, writes = false;
                for (int k = 0; k < insns[j].instr.operand_count_visible; k++) {
                    if (insns[j].ops[k].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        enclosing_gpr(insns[j].ops[k].reg.value) == target_gpr) {
                        if (insns[j].ops[k].actions & ZYDIS_OPERAND_ACTION_MASK_READ) reads = true;
                        if (insns[j].ops[k].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) writes = true;
                    }
                }
                if (reads && !is_arithmetic(insns[j].instr.mnemonic)) { result_used = true; break; }
                if (!reads && writes) break;
                if (reads) continue;
            }
            if (!result_used) insns[i].is_junk = true;
        }
    }

    static bool is_arithmetic(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_ADD: case ZYDIS_MNEMONIC_SUB: case ZYDIS_MNEMONIC_XOR:
            case ZYDIS_MNEMONIC_AND: case ZYDIS_MNEMONIC_OR:  case ZYDIS_MNEMONIC_NOT:
            case ZYDIS_MNEMONIC_NEG: case ZYDIS_MNEMONIC_SHL: case ZYDIS_MNEMONIC_SHR:
            case ZYDIS_MNEMONIC_SAR: case ZYDIS_MNEMONIC_ROL: case ZYDIS_MNEMONIC_ROR:
            case ZYDIS_MNEMONIC_BSWAP: case ZYDIS_MNEMONIC_INC: case ZYDIS_MNEMONIC_DEC:
            case ZYDIS_MNEMONIC_IMUL: case ZYDIS_MNEMONIC_MUL:
            case ZYDIS_MNEMONIC_BTC: case ZYDIS_MNEMONIC_BTS: case ZYDIS_MNEMONIC_BTR:
            case ZYDIS_MNEMONIC_SHLD: case ZYDIS_MNEMONIC_SHRD:
            case ZYDIS_MNEMONIC_CMOVB: case ZYDIS_MNEMONIC_CMOVBE: case ZYDIS_MNEMONIC_CMOVL:
            case ZYDIS_MNEMONIC_CMOVLE: case ZYDIS_MNEMONIC_CMOVNB: case ZYDIS_MNEMONIC_CMOVNBE:
            case ZYDIS_MNEMONIC_CMOVNL: case ZYDIS_MNEMONIC_CMOVNLE: case ZYDIS_MNEMONIC_CMOVNO:
            case ZYDIS_MNEMONIC_CMOVNP: case ZYDIS_MNEMONIC_CMOVNS: case ZYDIS_MNEMONIC_CMOVNZ:
            case ZYDIS_MNEMONIC_CMOVO: case ZYDIS_MNEMONIC_CMOVP: case ZYDIS_MNEMONIC_CMOVS:
            case ZYDIS_MNEMONIC_CMOVZ:
                return true;
            default: return false;
        }
    }

    static bool is_unary_arithmetic(ZydisMnemonic m) {
        return m == ZYDIS_MNEMONIC_NOT || m == ZYDIS_MNEMONIC_NEG ||
               m == ZYDIS_MNEMONIC_BSWAP || m == ZYDIS_MNEMONIC_INC ||
               m == ZYDIS_MNEMONIC_DEC;
    }

    static bool reads_flags(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_JL:
            case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_JNB: case ZYDIS_MNEMONIC_JNBE:
            case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_JNLE: case ZYDIS_MNEMONIC_JNO:
            case ZYDIS_MNEMONIC_JNP: case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_JNZ:
            case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_JP: case ZYDIS_MNEMONIC_JS:
            case ZYDIS_MNEMONIC_JZ:
            case ZYDIS_MNEMONIC_CMOVB: case ZYDIS_MNEMONIC_CMOVBE: case ZYDIS_MNEMONIC_CMOVL:
            case ZYDIS_MNEMONIC_CMOVLE: case ZYDIS_MNEMONIC_CMOVNB: case ZYDIS_MNEMONIC_CMOVNBE:
            case ZYDIS_MNEMONIC_CMOVNL: case ZYDIS_MNEMONIC_CMOVNLE: case ZYDIS_MNEMONIC_CMOVNO:
            case ZYDIS_MNEMONIC_CMOVNP: case ZYDIS_MNEMONIC_CMOVNS: case ZYDIS_MNEMONIC_CMOVNZ:
            case ZYDIS_MNEMONIC_CMOVO: case ZYDIS_MNEMONIC_CMOVP: case ZYDIS_MNEMONIC_CMOVS:
            case ZYDIS_MNEMONIC_CMOVZ:
            case ZYDIS_MNEMONIC_PUSHFQ: case ZYDIS_MNEMONIC_LAHF:
            case ZYDIS_MNEMONIC_ADC: case ZYDIS_MNEMONIC_SBB:
                return true;
            default: return false;
        }
    }

    static bool writes_flags(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_ADD: case ZYDIS_MNEMONIC_SUB: case ZYDIS_MNEMONIC_XOR:
            case ZYDIS_MNEMONIC_AND: case ZYDIS_MNEMONIC_OR:  case ZYDIS_MNEMONIC_CMP:
            case ZYDIS_MNEMONIC_TEST: case ZYDIS_MNEMONIC_NEG: case ZYDIS_MNEMONIC_INC:
            case ZYDIS_MNEMONIC_DEC: case ZYDIS_MNEMONIC_SHL: case ZYDIS_MNEMONIC_SHR:
            case ZYDIS_MNEMONIC_SAR: case ZYDIS_MNEMONIC_POPFQ:
            case ZYDIS_MNEMONIC_SAHF: case ZYDIS_MNEMONIC_ADC: case ZYDIS_MNEMONIC_SBB:
            case ZYDIS_MNEMONIC_IMUL: case ZYDIS_MNEMONIC_MUL:
                return true;
            default: return false;
        }
    }

    static bool accesses_rsp(const InsnInfo& ii) {
        for (int k = 0; k < ii.instr.operand_count_visible; k++) {
            if (ii.ops[k].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (ii.ops[k].reg.value == ZYDIS_REGISTER_RSP || ii.ops[k].reg.value == ZYDIS_REGISTER_ESP))
                return true;
            if (ii.ops[k].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                (ii.ops[k].mem.base == ZYDIS_REGISTER_RSP || ii.ops[k].mem.index == ZYDIS_REGISTER_RSP))
                return true;
        }
        return ii.instr.mnemonic == ZYDIS_MNEMONIC_PUSH || ii.instr.mnemonic == ZYDIS_MNEMONIC_POP ||
               ii.instr.mnemonic == ZYDIS_MNEMONIC_PUSHFQ || ii.instr.mnemonic == ZYDIS_MNEMONIC_POPFQ ||
               ii.instr.mnemonic == ZYDIS_MNEMONIC_CALL || ii.instr.mnemonic == ZYDIS_MNEMONIC_RET;
    }

    static ZydisRegister enclosing_gpr(ZydisRegister r) {
        if (r >= ZYDIS_REGISTER_AL  && r <= ZYDIS_REGISTER_R15B) return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (r - ZYDIS_REGISTER_AL));
        if (r >= ZYDIS_REGISTER_AX  && r <= ZYDIS_REGISTER_R15W) return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (r - ZYDIS_REGISTER_AX));
        if (r >= ZYDIS_REGISTER_EAX && r <= ZYDIS_REGISTER_R15D) return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (r - ZYDIS_REGISTER_EAX));
        if (r >= ZYDIS_REGISTER_RAX && r <= ZYDIS_REGISTER_R15) return r;
        return r;
    }
};


class BranchResolver {
public:
    struct ResolveResult {
        bool   resolved;
        bool   taken;
        std::uint64_t next_va;
    };

    BranchResolver() = default;


    bool init(std::uint64_t mod_base, const std::vector<std::uint8_t>& full_image, std::uint64_t image_size) {
        mod_base_ = mod_base;

        uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc_);
        if (err != UC_ERR_OK) {
            std::cerr << "    Unicorn init failed: " << uc_strerror(err) << "\n";
            return false;
        }


        std::uint64_t aligned_base = mod_base & ~0xFFFULL;
        std::uint64_t aligned_size = (image_size + 0xFFF) & ~0xFFFULL;
        err = uc_mem_map(uc_, aligned_base, static_cast<size_t>(aligned_size), UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            std::cerr << "    uc_mem_map module failed: " << uc_strerror(err) << "\n";
            uc_close(uc_); uc_ = nullptr;
            return false;
        }
        uc_mem_write(uc_, mod_base, full_image.data(), full_image.size());


        stack_base_ = 0x7FFE0000ULL;
        stack_size_ = 0x100000;
        err = uc_mem_map(uc_, stack_base_, stack_size_, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            std::cerr << "    uc_mem_map stack failed: " << uc_strerror(err) << "\n";
            uc_close(uc_); uc_ = nullptr;
            return false;
        }


        err = uc_mem_map(uc_, 0x10000, 0x10000, UC_PROT_ALL);
        if (err == UC_ERR_OK) {
            std::vector<std::uint8_t> zeros(0x10000, 0);
            uc_mem_write(uc_, 0x10000, zeros.data(), zeros.size());
        }


        uc_hook hh;
        uc_hook_add(uc_, &hh, UC_HOOK_MEM_UNMAPPED, (void*)hook_mem_unmapped, this, 1, 0);

        initialized_ = true;
        return true;
    }

    ~BranchResolver() {
        if (uc_) uc_close(uc_);
    }


    ResolveResult resolve(std::uint64_t block_va, std::uint32_t block_size,
                          std::uint64_t jcc_va, std::uint64_t taken_target,
                          std::uint64_t fallthrough_target) {
        ResolveResult result = {false, false, 0};
        if (!initialized_ || !uc_) return result;


        std::uint64_t rsp = stack_base_ + stack_size_ / 2;
        uc_reg_write(uc_, UC_X86_REG_RSP, &rsp);
        uc_reg_write(uc_, UC_X86_REG_RBP, &rsp);

        std::uint64_t zero = 0;
        uc_reg_write(uc_, UC_X86_REG_RAX, &zero);
        uc_reg_write(uc_, UC_X86_REG_RBX, &zero);
        uc_reg_write(uc_, UC_X86_REG_RCX, &zero);
        uc_reg_write(uc_, UC_X86_REG_RDX, &zero);
        uc_reg_write(uc_, UC_X86_REG_RSI, &zero);
        uc_reg_write(uc_, UC_X86_REG_RDI, &zero);
        uc_reg_write(uc_, UC_X86_REG_R8, &zero);
        uc_reg_write(uc_, UC_X86_REG_R9, &zero);
        uc_reg_write(uc_, UC_X86_REG_R10, &zero);
        uc_reg_write(uc_, UC_X86_REG_R11, &zero);
        uc_reg_write(uc_, UC_X86_REG_R12, &zero);
        uc_reg_write(uc_, UC_X86_REG_R13, &zero);
        uc_reg_write(uc_, UC_X86_REG_R14, &zero);
        uc_reg_write(uc_, UC_X86_REG_R15, &zero);


        std::vector<std::uint8_t> stk(0x1000, 0);
        uc_mem_write(uc_, rsp - 0x800, stk.data(), stk.size());


        resolve_mode_ = true;

        std::uint64_t stop_at = jcc_va;

        uc_err err = uc_emu_start(uc_, block_va, stop_at, 10 * 1000, 200);


        std::uint64_t rip = 0;
        uc_reg_read(uc_, UC_X86_REG_RIP, &rip);

        if (rip == jcc_va || err == UC_ERR_OK) {

            err = uc_emu_start(uc_, jcc_va, 0, 0, 1);
            uc_reg_read(uc_, UC_X86_REG_RIP, &rip);

            if (rip == taken_target) {
                result.resolved = true;
                result.taken = true;
                result.next_va = taken_target;
            } else if (rip == fallthrough_target) {
                result.resolved = true;
                result.taken = false;
                result.next_va = fallthrough_target;
            }

        }

        uc_emu_stop(uc_);
        resolve_mode_ = false;
        return result;
    }


    struct TracedBlock {
        std::uint64_t va;
        std::uint32_t size;
        std::vector<std::uint8_t> bytes;
    };

    std::vector<TracedBlock> trace_function(std::uint64_t entry_va, std::uint32_t max_insns = 5000) {
        std::vector<TracedBlock> result;
        if (!initialized_ || !uc_) return result;


        std::uint64_t rsp = stack_base_ + stack_size_ / 2;
        set_reg(UC_X86_REG_RSP, rsp);
        set_reg(UC_X86_REG_RBP, rsp);
        set_reg(UC_X86_REG_RAX, 0);
        set_reg(UC_X86_REG_RBX, 0);
        set_reg(UC_X86_REG_RCX, 0);
        set_reg(UC_X86_REG_RDX, 0);
        set_reg(UC_X86_REG_RSI, 0);
        set_reg(UC_X86_REG_RDI, 0);
        set_reg(UC_X86_REG_R8, 0);
        set_reg(UC_X86_REG_R9, 0);
        set_reg(UC_X86_REG_R10, 0);
        set_reg(UC_X86_REG_R11, 0);
        set_reg(UC_X86_REG_R12, 0);
        set_reg(UC_X86_REG_R13, 0);
        set_reg(UC_X86_REG_R14, 0);
        set_reg(UC_X86_REG_R15, 0);
        set_reg(UC_X86_REG_RFLAGS, 0x202);


        std::vector<std::uint8_t> stk(0x2000, 0);
        uc_mem_write(uc_, rsp - 0x1000, stk.data(), stk.size());


        std::uint64_t sentinel = 0xDEADC0DEDEADC0DEULL;
        uc_mem_write(uc_, rsp, &sentinel, 8);


        trace_ctx ctx;
        ctx.collected.reserve(max_insns);
        ctx.max_insns = max_insns;

        uc_hook hh;
        uc_hook_add(uc_, &hh, UC_HOOK_CODE, (void*)hook_code_trace, &ctx, 1, 0);

        uc_emu_start(uc_, entry_va, sentinel, 0, max_insns);

        uc_hook_del(uc_, hh);


        if (!ctx.collected.empty()) {
            TracedBlock current;
            current.va = ctx.collected[0].va;
            current.size = 0;
            current.bytes.clear();

            for (const auto& insn : ctx.collected) {
                if (!current.bytes.empty() && insn.va != current.va + current.size) {

                    result.push_back(std::move(current));
                    current.va = insn.va;
                    current.size = 0;
                    current.bytes.clear();
                }
                current.bytes.insert(current.bytes.end(), insn.bytes.begin(), insn.bytes.end());
                current.size += static_cast<std::uint32_t>(insn.bytes.size());
            }
            if (!current.bytes.empty())
                result.push_back(std::move(current));
        }

        return result;
    }

    void set_resolve_mode(bool resolve_mode) { resolve_mode_ = resolve_mode; }

private:
    uc_engine* uc_ = nullptr;
    bool initialized_ = false;
    bool resolve_mode_ = false;
    std::uint64_t mod_base_ = 0;
    std::uint64_t stack_base_ = 0;
    std::size_t stack_size_ = 0;

    void set_reg(int reg, std::uint64_t val) {
        uc_reg_write(uc_, reg, &val);
    }

    struct traced_insn {
        std::uint64_t va;
        std::vector<std::uint8_t> bytes;
    };

    struct trace_ctx {
        std::vector<traced_insn> collected;
        std::uint32_t max_insns;
    };

    static void hook_code_trace(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
        auto* ctx = static_cast<trace_ctx*>(user_data);
        if (ctx->collected.size() >= ctx->max_insns) {
            uc_emu_stop(uc);
            return;
        }

        traced_insn insn;
        insn.va = address;
        insn.bytes.resize(size);
        uc_mem_read(uc, address, insn.bytes.data(), size);
        ctx->collected.push_back(std::move(insn));
    }

    static bool hook_mem_unmapped(uc_engine* uc, uc_mem_type type,
                                  uint64_t address, int size,
                                  int64_t value, void* user_data) {
        (void)size; (void)value;
        auto* self = static_cast<BranchResolver*>(user_data);

        if (self && self->resolve_mode_) {
            uc_emu_stop(uc);
            return false;
        }

        std::uint64_t aligned = address & ~0xFFFULL;
        std::vector<std::uint8_t> zeros(0x2000, 0);
        uc_err err = uc_mem_map(uc, aligned, 0x2000, UC_PROT_ALL);
        if (err == UC_ERR_OK) {
            uc_mem_write(uc, aligned, zeros.data(), zeros.size());
        }
        return true;
    }
};


class BEDaisyDumper {
public:
    bool run(const std::string& output_path, const std::string& target_name) {
        std::cout << "[*] BEDaisy Dumper v4.0 - Deobfuscation + IAT Rebuild + Devirtualization\n";
        std::cout << "[*] Target: " << target_name << "\n\n";

        if (!connect_driver())              return false;
        if (!find_module(target_name))      return false;
        if (!read_headers())                return false;
        if (!read_sections())               return false;
        build_full_image();
        if (!init_emulator())               return false;
        analyze_dispatchers();
        recover_functions_deep();
        resolve_opaque_predicates();
        deobfuscate_inplace();
        reconstruct_iat();
        devirtualize_indirect_branches();
        linearize_functions();
        patch_section_flags();
        build_pdata();
        write_output(output_path);
        print_summary();
        return true;
    }

private:
    voyager::device_t dev_;
    Disassembler dis_;
    JunkDetector junk_;
    BranchResolver resolver_;


    std::uint64_t mod_base_ = 0;
    std::uint64_t mod_size_ = 0;
    std::string   mod_name_;


    std::vector<std::uint8_t> header_data_;
    std::vector<std::uint8_t> full_image_;
    NtHeaders64* nt_ = nullptr;
    std::vector<SectionHeader> secs_;
    std::vector<std::vector<std::uint8_t>> sec_data_;
    int text_idx_ = -1, be0_idx_ = -1, pdata_idx_ = -1;


    struct Dispatch { std::uint64_t text_va, target_va; bool conditional; };
    std::vector<Dispatch> dispatches_;
    std::set<std::uint64_t> be0_entries_;
    std::vector<RecoveredFunction> funcs_;
    std::uint32_t blocks_total_ = 0;


    std::uint32_t junk_insns_ = 0, junk_bytes_ = 0;
    std::uint32_t opaque_resolved_ = 0;
    std::uint32_t branches_patched_ = 0;
    std::uint32_t functions_linearized_ = 0;
    std::uint64_t linearized_bytes_ = 0;


    std::vector<std::uint8_t> pdata_blob_;
    std::uint32_t pdata_rva_ = 0;
    std::uint32_t pdata_func_count_ = 0;


    std::vector<std::uint8_t> clean_section_data_;
    std::uint32_t clean_section_rva_ = 0;


    struct ResolvedImport {
        std::string   name;
        std::uint64_t resolved_va;
        std::uint32_t iat_slot_rva;
        bool          is_flt;
    };
    std::vector<ResolvedImport> resolved_imports_;
    std::uint32_t iat_section_rva_ = 0;
    std::vector<std::uint8_t> iat_section_data_;
    std::uint32_t iat_refs_patched_ = 0;

    std::uint32_t indirect_resolved_ = 0;
    std::uint32_t indirect_total_ = 0;
    std::uint32_t skipped_junk_blocks_ = 0;


    bool connect_driver() {
        std::cout << "[1] Connecting to WhosWho driver...\n";
        if (!dev_.connect()) { std::cerr << "    FAIL: Cannot open device.\n"; return false; }
        if (!dev_.send_heartbeat()) { std::cerr << "    FAIL: Heartbeat rejected.\n"; return false; }
        dev_.solve_kernel_dtb();
        if (dev_.get_kernel_dtb() == 0) { std::cerr << "    FAIL: Kernel DTB not resolved.\n"; return false; }
        std::cout << "    OK - Kernel DTB: " << hex(dev_.get_kernel_dtb()) << "\n";
        return true;
    }


    bool find_module(const std::string& target) {
        std::cout << "[2] Enumerating kernel modules (NtQuerySystemInformation)...\n";

        auto NtQSI = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        if (!NtQSI) { std::cerr << "    FAIL: Cannot resolve NtQuerySystemInformation.\n"; return false; }

        ULONG needed = 0;
        NtQSI(SystemModuleInformation_Class, nullptr, 0, &needed);
        if (needed == 0) { std::cerr << "    FAIL: NtQuerySystemInformation returned 0 size.\n"; return false; }

        std::vector<std::uint8_t> buf(needed + 0x1000);
        LONG st = NtQSI(SystemModuleInformation_Class, buf.data(),
                        static_cast<ULONG>(buf.size()), &needed);
        if (st < 0) {
            std::cerr << "    FAIL: NtQuerySystemInformation status=0x" << std::hex << (unsigned long)st << "\n";
            return false;
        }

        auto* info = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(buf.data());
        std::cout << "    Found " << info->NumberOfModules << " kernel modules.\n";

        std::string target_lower = target;
        std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);

        for (ULONG i = 0; i < info->NumberOfModules; i++) {
            const auto& m = info->Modules[i];
            const char* full = reinterpret_cast<const char*>(m.FullPathName);
            const char* fname = full + m.OffsetToFileName;

            std::string name_lower = fname;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);

            if (name_lower == target_lower || name_lower.find(target_lower) != std::string::npos) {
                mod_base_ = reinterpret_cast<std::uint64_t>(m.ImageBase);
                mod_size_ = m.ImageSize;
                mod_name_ = fname;
                break;
            }
        }

        if (mod_base_ == 0) {
            std::cerr << "    FAIL: '" << target << "' not found.\n";
            for (ULONG i = 0; i < info->NumberOfModules && i < 20; i++) {
                const auto& m = info->Modules[i];
                const char* fname = reinterpret_cast<const char*>(m.FullPathName) + m.OffsetToFileName;
                std::cerr << "      " << fname << " @ " << hex(reinterpret_cast<std::uint64_t>(m.ImageBase))
                          << " size=" << hex32(m.ImageSize) << "\n";
            }
            return false;
        }

        std::cout << "    TARGET: " << mod_name_ << " @ " << hex(mod_base_)
                  << " size=" << hex(mod_size_) << "\n";
        return true;
    }


    bool read_headers() {
        std::cout << "[3] Reading PE headers...\n";
        header_data_.resize(0x1000);
        std::size_t got = dev_.read_kernel_raw(mod_base_, header_data_.data(), 0x1000);
        if (got < 0x200) { std::cerr << "    FAIL: Only read " << got << " header bytes.\n"; return false; }

        auto* dos = reinterpret_cast<DosHeader*>(header_data_.data());
        if (dos->e_magic != 0x5A4D) { std::cerr << "    FAIL: Bad DOS magic.\n"; return false; }
        if (dos->e_lfanew < 0 || (std::size_t)dos->e_lfanew + sizeof(NtHeaders64) > 0x1000)
            { std::cerr << "    FAIL: Bad e_lfanew.\n"; return false; }

        nt_ = reinterpret_cast<NtHeaders64*>(header_data_.data() + dos->e_lfanew);
        if (nt_->Signature != 0x4550)     { std::cerr << "    FAIL: Bad PE sig.\n"; return false; }
        if (nt_->FileHeader.Machine != 0x8664) { std::cerr << "    FAIL: Not AMD64.\n"; return false; }

        auto* sh = reinterpret_cast<SectionHeader*>(
            reinterpret_cast<std::uint8_t*>(&nt_->OptionalHeader) + nt_->FileHeader.SizeOfOptionalHeader);

        secs_.clear();
        for (int i = 0; i < nt_->FileHeader.NumberOfSections; i++) {
            secs_.push_back(sh[i]);
            char nm[9] = {}; std::memcpy(nm, sh[i].Name, 8);
            std::cout << "    [" << i << "] " << nm
                      << "  RVA=" << hex32(sh[i].VirtualAddress)
                      << "  VSize=" << hex32(sh[i].VirtualSize)
                      << "  Chars=" << hex32(sh[i].Characteristics) << "\n";
            std::string sname(nm);
            if (sname == ".text")  text_idx_  = i;
            if (sname == ".be0")   be0_idx_   = i;
            if (sname == ".pdata") pdata_idx_ = i;
        }
        return true;
    }


    bool read_sections() {
        std::cout << "[4] Reading sections from kernel memory (page-by-page)...\n";
        sec_data_.resize(secs_.size());

        for (std::size_t i = 0; i < secs_.size(); i++) {
            std::uint32_t vsize = secs_[i].VirtualSize;
            if (vsize == 0) { sec_data_[i].clear(); continue; }
            if (vsize > 0x1000000) vsize = 0x1000000;

            sec_data_[i].resize(vsize, 0);
            std::uint64_t va = mod_base_ + secs_[i].VirtualAddress;
            std::size_t total = 0;
            std::size_t failed_pages = 0;
            constexpr std::size_t PAGE = 0x1000;

            for (std::size_t off = 0; off < vsize; off += PAGE) {
                std::size_t want = std::min<std::size_t>(PAGE, vsize - off);
                std::size_t r = dev_.read_kernel_raw(va + off, sec_data_[i].data() + off, want);
                if (r > 0) {
                    total += r;
                } else {
                    failed_pages++;
                }
            }

            char nm[9] = {}; std::memcpy(nm, secs_[i].Name, 8);
            std::cout << "    " << nm << ": " << total << "/" << vsize << " bytes ("
                      << std::fixed << std::setprecision(1) << (vsize ? total*100.0/vsize : 0) << "%)";
            if (failed_pages > 0)
                std::cout << " [" << failed_pages << " pages failed, skipped]";
            std::cout << "\n";
        }
        return true;
    }


    void build_full_image() {
        std::cout << "[4.5] Building flat image for emulation engine...\n";
        full_image_.resize(static_cast<std::size_t>(mod_size_), 0);
        std::memcpy(full_image_.data(), header_data_.data(), std::min<std::size_t>(header_data_.size(), full_image_.size()));

        for (std::size_t i = 0; i < secs_.size(); i++) {
            std::uint32_t rva = secs_[i].VirtualAddress;
            if (rva < full_image_.size() && !sec_data_[i].empty()) {
                std::size_t copy_size = std::min<std::size_t>(sec_data_[i].size(), full_image_.size() - rva);
                std::memcpy(full_image_.data() + rva, sec_data_[i].data(), copy_size);
            }
        }
        std::cout << "    Flat image: " << full_image_.size() << " bytes\n";
    }


    bool init_emulator() {
        std::cout << "[4.6] Initializing Unicorn emulation engine...\n";
        if (!resolver_.init(mod_base_, full_image_, mod_size_)) {
            std::cerr << "    FAIL: Unicorn initialization failed.\n";
            return false;
        }
        std::cout << "    Unicorn ready: module mapped at " << hex(mod_base_) << "\n";
        return true;
    }


    void analyze_dispatchers() {
        if (text_idx_ < 0 || be0_idx_ < 0) { std::cout << "[5] Skip (no .text/.be0).\n"; return; }
        std::cout << "[5] Scanning .text dispatch stubs...\n";

        const auto& td = sec_data_[text_idx_];
        std::uint64_t tva = mod_base_ + secs_[text_idx_].VirtualAddress;
        std::uint64_t b0s = mod_base_ + secs_[be0_idx_].VirtualAddress;
        std::uint64_t b0e = b0s + secs_[be0_idx_].VirtualSize;

        std::size_t off = 0;
        while (off < td.size()) {
            std::uint64_t ip = tva + off;
            ZydisDecodedInstruction instr; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!dis_.decode(td.data() + off, td.size() - off, ip, instr, ops)) { off++; continue; }
            if ((dis_.is_jmp_rel(instr) || dis_.is_jcc(instr)) && instr.raw.imm[0].is_relative) {
                std::uint64_t tgt = dis_.calc_abs(ip, instr, ops[0]);
                if (tgt >= b0s && tgt < b0e) {
                    dispatches_.push_back({ip, tgt, dis_.is_jcc(instr)});
                    be0_entries_.insert(tgt);
                }
            }

            if (dis_.is_call(instr) && instr.raw.imm[0].is_relative) {
                std::uint64_t tgt = dis_.calc_abs(ip, instr, ops[0]);
                if (tgt >= b0s && tgt < b0e) {
                    be0_entries_.insert(tgt);
                }
            }
            off += instr.length;
        }


        const auto& bd = sec_data_[be0_idx_];
        off = 0;
        std::uint32_t internal_refs = 0;
        while (off < bd.size()) {
            std::uint64_t ip = b0s + off;
            ZydisDecodedInstruction instr; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!dis_.decode(bd.data() + off, bd.size() - off, ip, instr, ops)) { off++; continue; }
            if (dis_.is_call(instr) && instr.raw.imm[0].is_relative) {
                std::uint64_t tgt = dis_.calc_abs(ip, instr, ops[0]);
                if (tgt >= b0s && tgt < b0e) {
                    be0_entries_.insert(tgt);
                    internal_refs++;
                }
            }
            off += instr.length;
        }

        std::cout << "    " << dispatches_.size() << " branches -> .be0, "
                  << be0_entries_.size() << " unique entry points"
                  << " (" << internal_refs << " internal .be0 calls)\n";
    }


    void recover_functions_deep() {
        if (be0_idx_ < 0 || be0_entries_.empty()) { std::cout << "[6] Skip.\n"; return; }
        std::cout << "[6] Deep recursive block tracing...\n";


        if (text_idx_ >= 0) {
            const auto& td = sec_data_[text_idx_];
            std::uint64_t tva = mod_base_ + secs_[text_idx_].VirtualAddress;

            std::size_t off = 0;
            while (off < td.size()) {
                if (td[off] == 0xCC) { off++; continue; }

                std::uint64_t ip = tva + off;
                ZydisDecodedInstruction instr; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!dis_.decode(td.data() + off, td.size() - off, ip, instr, ops)) { off++; continue; }


                bool is_prologue = false;
                if (instr.mnemonic == ZYDIS_MNEMONIC_SUB && instr.operand_count_visible >= 2 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_RSP)
                    is_prologue = true;
                if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH && instr.operand_count_visible >= 1 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    auto r = ops[0].reg.value;
                    if (r == ZYDIS_REGISTER_RBP || r == ZYDIS_REGISTER_RBX || r == ZYDIS_REGISTER_RDI ||
                        r == ZYDIS_REGISTER_RSI || r == ZYDIS_REGISTER_R12 || r == ZYDIS_REGISTER_R13 ||
                        r == ZYDIS_REGISTER_R14 || r == ZYDIS_REGISTER_R15)
                        is_prologue = true;
                }
                if (off > 0 && td[off - 1] == 0xCC) is_prologue = true;

                off += instr.length;
            }
        }


        for (std::uint64_t entry : be0_entries_) {
            RecoveredFunction fn;
            fn.entry_va  = entry;
            fn.entry_rva = static_cast<std::uint32_t>(entry - mod_base_);
            fn.total_size = 0;
            fn.max_rva_end = fn.entry_rva;
            fn.min_rva = fn.entry_rva;


            std::queue<std::uint64_t> work;
            work.push(entry);
            std::set<std::uint64_t> visited;

            while (!work.empty()) {
                std::uint64_t bva = work.front(); work.pop();
                if (visited.count(bva)) continue;
                visited.insert(bva);

                int si = -1; std::uint64_t ss = 0; const std::uint8_t* sd = nullptr; std::size_t sz = 0;
                for (std::size_t s = 0; s < secs_.size(); s++) {
                    std::uint64_t a = mod_base_ + secs_[s].VirtualAddress;
                    if (bva >= a && bva < a + secs_[s].VirtualSize) {
                        si = (int)s; ss = a; sd = sec_data_[s].data(); sz = sec_data_[s].size(); break;
                    }
                }
                if (si < 0 || !sd) continue;
                std::size_t boff = (std::size_t)(bva - ss);
                if (boff >= sz) continue;

                BasicBlock bb{};
                bb.va = bva;
                bb.rva = (std::uint32_t)(bva - mod_base_);
                bb.branch_resolved = false;
                bb.branch_taken = false;
                bb.is_conditional_jmp = false;
                bb.is_call = false;
                bb.is_unconditional_jmp = false;
                bb.is_ret = false;
                bb.is_indirect = false;
                bb.fallthrough_target = 0;
                bb.branch_target = 0;

                std::size_t cur = boff;
                std::uint32_t bsz = 0;

                while (cur < sz && bsz < 0x2000) {
                    std::uint64_t ip = ss + cur;
                    ZydisDecodedInstruction instr; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                    if (!dis_.decode(sd + cur, sz - cur, ip, instr, ops)) break;
                    bsz += instr.length; cur += instr.length;

                    if (dis_.is_jmp_rel(instr)) {
                        std::uint64_t t = dis_.calc_abs(ip, instr, ops[0]);
                        bb.branch_target = t;
                        bb.is_unconditional_jmp = true;
                        if (!visited.count(t) && !be0_entries_.count(t)) work.push(t);
                        break;
                    }
                    if (dis_.is_jcc(instr)) {
                        std::uint64_t t = dis_.calc_abs(ip, instr, ops[0]);
                        bb.branch_target = t;
                        bb.fallthrough_target = ip + instr.length;
                        bb.is_conditional_jmp = true;
                        if (!visited.count(t)) work.push(t);
                        if (!visited.count(bb.fallthrough_target)) work.push(bb.fallthrough_target);
                        break;
                    }
                    if (dis_.is_ret(instr)) { bb.is_ret = true; break; }
                    if (dis_.is_indirect_branch(instr, ops)) { bb.is_indirect = true; break; }
                    if (dis_.is_int3(instr)) break;


                    if (dis_.is_call(instr) && instr.raw.imm[0].is_relative) {
                        std::uint64_t t = dis_.calc_abs(ip, instr, ops[0]);
                        bb.is_call = true;

                    }
                }
                bb.size = bsz;
                if (bsz > 0) {
                    fn.blocks.push_back(bb);
                    fn.total_size += bsz;
                    std::uint32_t end_rva = bb.rva + bsz;
                    if (end_rva > fn.max_rva_end) fn.max_rva_end = end_rva;
                    if (bb.rva < fn.min_rva) fn.min_rva = bb.rva;
                    blocks_total_++;
                }
            }
            if (!fn.blocks.empty()) funcs_.push_back(std::move(fn));
        }
        std::cout << "    " << funcs_.size() << " functions, " << blocks_total_ << " blocks\n";
    }


    void resolve_opaque_predicates() {
        std::cout << "[7] Resolving opaque predicates (static + emulation)...\n";

        std::uint32_t total_jcc = 0;
        std::uint32_t resolved_static = 0;
        std::uint32_t resolved_emu = 0;
        std::uint32_t processed = 0;


        for (const auto& fn : funcs_)
            for (const auto& bb : fn.blocks)
                if (bb.is_conditional_jmp && bb.branch_target != 0 && bb.fallthrough_target != 0)
                    total_jcc++;

        std::cout << "    " << total_jcc << " conditional branches to analyze...\n";


        const std::uint32_t max_emu_attempts = 500;
        std::uint32_t emu_attempts = 0;

        for (auto& fn : funcs_) {
            for (auto& bb : fn.blocks) {
                if (!bb.is_conditional_jmp) continue;
                if (bb.branch_target == 0 || bb.fallthrough_target == 0) continue;
                processed++;

                if (processed % 5000 == 0 || processed == total_jcc) {
                    std::cout << "    Progress: " << processed << "/" << total_jcc
                              << " (" << (resolved_static + resolved_emu) << " resolved)\r" << std::flush;
                }


                int si = -1; std::uint64_t ss = 0; const std::uint8_t* sd = nullptr; std::size_t sz = 0;
                for (std::size_t s = 0; s < secs_.size(); s++) {
                    std::uint64_t a = mod_base_ + secs_[s].VirtualAddress;
                    if (bb.va >= a && bb.va < a + secs_[s].VirtualSize) {
                        si = (int)s; ss = a; sd = sec_data_[s].data(); sz = sec_data_[s].size(); break;
                    }
                }
                if (si < 0 || !sd) continue;

                std::size_t boff = (std::size_t)(bb.va - ss);
                if (boff + bb.size > sz) continue;


                struct InsnEntry {
                    std::uint64_t va;
                    ZydisDecodedInstruction instr;
                    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                };
                std::vector<InsnEntry> insns;
                {
                    std::size_t cur = boff, end = boff + bb.size;
                    while (cur < end && cur < sz) {
                        InsnEntry e;
                        e.va = ss + cur;
                        if (!dis_.decode(sd + cur, end - cur, e.va, e.instr, e.ops)) break;
                        insns.push_back(e);
                        cur += e.instr.length;
                    }
                }
                if (insns.empty()) continue;


                int jcc_idx = -1;
                for (int i = (int)insns.size() - 1; i >= 0; i--) {
                    if (dis_.is_jcc(insns[i].instr)) { jcc_idx = i; break; }
                }
                if (jcc_idx < 0) continue;


                bool resolved = try_static_resolve(insns, jcc_idx, bb);
                if (resolved) {
                    resolved_static++;
                    continue;
                }


                if (emu_attempts < max_emu_attempts) {
                    emu_attempts++;
                    auto result = resolver_.resolve(bb.va, bb.size, insns[jcc_idx].va,
                                                    bb.branch_target, bb.fallthrough_target);
                    if (result.resolved) {
                        bb.branch_resolved = true;
                        bb.branch_taken = result.taken;
                        resolved_emu++;
                    }
                }
            }
        }

        opaque_resolved_ = resolved_static + resolved_emu;
        std::cout << "\n    " << opaque_resolved_ << "/" << total_jcc << " conditional branches resolved"
                  << " (" << resolved_static << " static, " << resolved_emu << " emulated)\n";
    }


    struct InsnEntry_t {
        std::uint64_t va;
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    };

    template<typename InsnEntry>
    bool try_static_resolve(const std::vector<InsnEntry>& insns, int jcc_idx, BasicBlock& bb) {
        if (jcc_idx < 2) return false;

        const auto& jcc = insns[jcc_idx];


        int test_idx = -1;
        for (int i = jcc_idx - 1; i >= 0; i--) {
            auto m = insns[i].instr.mnemonic;
            if (m == ZYDIS_MNEMONIC_NOP) continue;
            if (m == ZYDIS_MNEMONIC_TEST || m == ZYDIS_MNEMONIC_CMP ||
                m == ZYDIS_MNEMONIC_AND || m == ZYDIS_MNEMONIC_OR ||
                m == ZYDIS_MNEMONIC_ADD || m == ZYDIS_MNEMONIC_SUB ||
                m == ZYDIS_MNEMONIC_XOR || m == ZYDIS_MNEMONIC_NOT ||
                m == ZYDIS_MNEMONIC_NEG) {
                test_idx = i;
                break;
            }
            break;
        }
        if (test_idx < 0) return false;


        const auto& test_insn = insns[test_idx];
        ZydisRegister track_reg = ZYDIS_REGISTER_NONE;

        if (test_insn.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            track_reg = test_insn.ops[0].reg.value;
        } else {
            return false;
        }


        struct ChainOp {
            ZydisMnemonic mnemonic;
            std::int64_t imm;
            bool has_imm;
            ZydisRegister reg2;
            bool self_op;
        };

        std::vector<ChainOp> ops_chain;
        std::uint64_t init_value = 0;
        bool found_init = false;


        auto base_of = [](ZydisRegister r) -> int {

            if (r >= ZYDIS_REGISTER_AL && r <= ZYDIS_REGISTER_R15B) return (r - ZYDIS_REGISTER_AL);
            if (r >= ZYDIS_REGISTER_AH && r <= ZYDIS_REGISTER_BH) return (r - ZYDIS_REGISTER_AH);
            if (r >= ZYDIS_REGISTER_AX && r <= ZYDIS_REGISTER_R15W) return (r - ZYDIS_REGISTER_AX);
            if (r >= ZYDIS_REGISTER_EAX && r <= ZYDIS_REGISTER_R15D) return (r - ZYDIS_REGISTER_EAX);
            if (r >= ZYDIS_REGISTER_RAX && r <= ZYDIS_REGISTER_R15) return (r - ZYDIS_REGISTER_RAX);
            if (r >= ZYDIS_REGISTER_SPL && r <= ZYDIS_REGISTER_DIL) return (r - ZYDIS_REGISTER_SPL + 4);
            return -1;
        };

        int track_base = base_of(track_reg);
        if (track_base < 0) return false;

        auto same_reg = [&](ZydisRegister r) -> bool {
            return base_of(r) == track_base;
        };

        auto reg_bits = [](ZydisRegister r) -> int {
            if (r >= ZYDIS_REGISTER_AL && r <= ZYDIS_REGISTER_R15B) return 8;
            if (r >= ZYDIS_REGISTER_AH && r <= ZYDIS_REGISTER_BH) return 8;
            if (r >= ZYDIS_REGISTER_SPL && r <= ZYDIS_REGISTER_DIL) return 8;
            if (r >= ZYDIS_REGISTER_AX && r <= ZYDIS_REGISTER_R15W) return 16;
            if (r >= ZYDIS_REGISTER_EAX && r <= ZYDIS_REGISTER_R15D) return 32;
            if (r >= ZYDIS_REGISTER_RAX && r <= ZYDIS_REGISTER_R15) return 64;
            return 0;
        };


        {
            ChainOp cop;
            cop.mnemonic = test_insn.instr.mnemonic;
            cop.has_imm = (test_insn.instr.operand_count_visible >= 2 &&
                           test_insn.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);
            cop.imm = cop.has_imm ? test_insn.ops[1].imm.value.s : 0;
            cop.self_op = (test_insn.instr.operand_count_visible >= 2 &&
                           test_insn.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                           same_reg(test_insn.ops[1].reg.value));
            cop.reg2 = ZYDIS_REGISTER_NONE;
            ops_chain.push_back(cop);
        }


        for (int i = test_idx - 1; i >= 0; i--) {
            const auto& entry = insns[i];
            auto m = entry.instr.mnemonic;

            if (m == ZYDIS_MNEMONIC_NOP) continue;


            if (m == ZYDIS_MNEMONIC_MOV &&
                entry.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                same_reg(entry.ops[0].reg.value) &&
                entry.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {

                int bits = reg_bits(entry.ops[0].reg.value);
                std::uint64_t mask = (bits < 64) ? ((1ULL << bits) - 1) : ~0ULL;
                init_value = (std::uint64_t)entry.ops[1].imm.value.u & mask;
                found_init = true;
                break;
            }


            if ((m == ZYDIS_MNEMONIC_NOT || m == ZYDIS_MNEMONIC_NEG) &&
                entry.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                same_reg(entry.ops[0].reg.value)) {
                ChainOp cop;
                cop.mnemonic = m;
                cop.has_imm = false;
                cop.imm = 0;
                cop.self_op = false;
                cop.reg2 = ZYDIS_REGISTER_NONE;
                ops_chain.push_back(cop);
                continue;
            }


            if ((m == ZYDIS_MNEMONIC_SHL || m == ZYDIS_MNEMONIC_SHR || m == ZYDIS_MNEMONIC_SAR ||
                 m == ZYDIS_MNEMONIC_ROL || m == ZYDIS_MNEMONIC_ROR ||
                 m == ZYDIS_MNEMONIC_AND || m == ZYDIS_MNEMONIC_OR || m == ZYDIS_MNEMONIC_XOR ||
                 m == ZYDIS_MNEMONIC_ADD || m == ZYDIS_MNEMONIC_SUB) &&
                entry.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                same_reg(entry.ops[0].reg.value) &&
                entry.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                ChainOp cop;
                cop.mnemonic = m;
                cop.has_imm = true;
                cop.imm = entry.ops[1].imm.value.s;
                cop.self_op = false;
                cop.reg2 = ZYDIS_REGISTER_NONE;
                ops_chain.push_back(cop);
                continue;
            }


            if ((m == ZYDIS_MNEMONIC_AND || m == ZYDIS_MNEMONIC_OR || m == ZYDIS_MNEMONIC_XOR ||
                 m == ZYDIS_MNEMONIC_ADD || m == ZYDIS_MNEMONIC_SUB || m == ZYDIS_MNEMONIC_TEST) &&
                entry.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                same_reg(entry.ops[0].reg.value) &&
                entry.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                same_reg(entry.ops[1].reg.value)) {
                ChainOp cop;
                cop.mnemonic = m;
                cop.has_imm = false;
                cop.imm = 0;
                cop.self_op = true;
                cop.reg2 = ZYDIS_REGISTER_NONE;
                ops_chain.push_back(cop);
                continue;
            }


            bool writes_our_reg = false;
            if (entry.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                same_reg(entry.ops[0].reg.value)) {
                writes_our_reg = true;
            }
            if (writes_our_reg) return false;

            continue;
        }

        if (!found_init) return false;


        int bits = reg_bits(track_reg);
        if (bits == 0) bits = 64;
        std::uint64_t mask = (bits < 64) ? ((1ULL << bits) - 1) : ~0ULL;

        std::uint64_t val = init_value & mask;


        for (int i = (int)ops_chain.size() - 1; i > 0; i--) {
            const auto& op = ops_chain[i];
            switch (op.mnemonic) {
                case ZYDIS_MNEMONIC_NOT: val = ~val & mask; break;
                case ZYDIS_MNEMONIC_NEG: val = (std::uint64_t)(-(std::int64_t)val) & mask; break;
                case ZYDIS_MNEMONIC_SHL: val = (val << (op.imm & (bits - 1))) & mask; break;
                case ZYDIS_MNEMONIC_SHR: val = (val >> (op.imm & (bits - 1))) & mask; break;
                case ZYDIS_MNEMONIC_SAR: {
                    std::int64_t sv = (std::int64_t)(val << (64 - bits)) >> (64 - bits);
                    sv >>= (op.imm & (bits - 1));
                    val = (std::uint64_t)sv & mask;
                    break;
                }
                case ZYDIS_MNEMONIC_ROL: {
                    int s = op.imm & (bits - 1);
                    val = ((val << s) | (val >> (bits - s))) & mask;
                    break;
                }
                case ZYDIS_MNEMONIC_ROR: {
                    int s = op.imm & (bits - 1);
                    val = ((val >> s) | (val << (bits - s))) & mask;
                    break;
                }
                case ZYDIS_MNEMONIC_AND:
                    val = op.self_op ? (val & val) : (val & ((std::uint64_t)op.imm & mask));
                    val &= mask;
                    break;
                case ZYDIS_MNEMONIC_OR:
                    val = op.self_op ? (val | val) : (val | ((std::uint64_t)op.imm & mask));
                    val &= mask;
                    break;
                case ZYDIS_MNEMONIC_XOR:
                    val = op.self_op ? 0 : (val ^ ((std::uint64_t)op.imm & mask));
                    val &= mask;
                    break;
                case ZYDIS_MNEMONIC_ADD:
                    val = op.self_op ? (val + val) : (val + (std::uint64_t)op.imm);
                    val &= mask;
                    break;
                case ZYDIS_MNEMONIC_SUB:
                    val = op.self_op ? 0 : (val - (std::uint64_t)op.imm);
                    val &= mask;
                    break;
                case ZYDIS_MNEMONIC_TEST:

                    break;
                default: return false;
            }
        }


        const auto& flag_op = ops_chain[0];
        std::uint64_t result_val = 0;
        bool cf = false, zf = false, sf = false, of = false;

        switch (flag_op.mnemonic) {
            case ZYDIS_MNEMONIC_TEST: {
                std::uint64_t rhs = flag_op.has_imm ? ((std::uint64_t)flag_op.imm & mask) :
                                    flag_op.self_op ? val : 0;
                result_val = val & rhs;
                zf = (result_val & mask) == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                of = false;
                cf = false;
                break;
            }
            case ZYDIS_MNEMONIC_CMP: {
                std::uint64_t rhs = flag_op.has_imm ? ((std::uint64_t)flag_op.imm & mask) :
                                    flag_op.self_op ? val : 0;
                result_val = (val - rhs) & mask;
                zf = result_val == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                cf = val < rhs;

                bool s1 = ((val >> (bits - 1)) & 1) != 0;
                bool s2 = ((rhs >> (bits - 1)) & 1) != 0;
                bool sr = sf;
                of = (s1 != s2) && (sr != s1);
                break;
            }
            case ZYDIS_MNEMONIC_AND: {
                std::uint64_t rhs = flag_op.has_imm ? ((std::uint64_t)flag_op.imm & mask) :
                                    flag_op.self_op ? val : 0;
                result_val = val & rhs;
                zf = (result_val & mask) == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                of = false; cf = false;
                break;
            }
            case ZYDIS_MNEMONIC_OR: {
                std::uint64_t rhs = flag_op.has_imm ? ((std::uint64_t)flag_op.imm & mask) :
                                    flag_op.self_op ? val : 0;
                result_val = val | rhs;
                zf = (result_val & mask) == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                of = false; cf = false;
                break;
            }
            case ZYDIS_MNEMONIC_XOR: {
                std::uint64_t rhs = flag_op.has_imm ? ((std::uint64_t)flag_op.imm & mask) :
                                    flag_op.self_op ? val : 0;
                result_val = val ^ rhs;
                zf = (result_val & mask) == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                of = false; cf = false;
                break;
            }
            case ZYDIS_MNEMONIC_ADD: {
                std::uint64_t rhs = flag_op.has_imm ? ((std::uint64_t)flag_op.imm & mask) :
                                    flag_op.self_op ? val : 0;
                result_val = (val + rhs) & mask;
                zf = result_val == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                cf = (val + rhs) > mask;
                bool s1 = ((val >> (bits - 1)) & 1) != 0;
                bool s2 = ((rhs >> (bits - 1)) & 1) != 0;
                bool sr = sf;
                of = (s1 == s2) && (sr != s1);
                break;
            }
            case ZYDIS_MNEMONIC_SUB: {
                std::uint64_t rhs = flag_op.has_imm ? ((std::uint64_t)flag_op.imm & mask) :
                                    flag_op.self_op ? val : 0;
                result_val = (val - rhs) & mask;
                zf = result_val == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                cf = val < rhs;
                bool s1 = ((val >> (bits - 1)) & 1) != 0;
                bool s2 = ((rhs >> (bits - 1)) & 1) != 0;
                bool sr = sf;
                of = (s1 != s2) && (sr != s1);
                break;
            }
            case ZYDIS_MNEMONIC_NOT: {

                return false;
            }
            case ZYDIS_MNEMONIC_NEG: {
                result_val = ((~val) + 1) & mask;
                zf = result_val == 0;
                sf = ((result_val >> (bits - 1)) & 1) != 0;
                cf = val != 0;
                of = (val == (1ULL << (bits - 1)));
                break;
            }
            default: return false;
        }


        bool taken = false;
        switch (jcc.instr.mnemonic) {
            case ZYDIS_MNEMONIC_JZ:   taken = zf; break;
            case ZYDIS_MNEMONIC_JNZ:  taken = !zf; break;
            case ZYDIS_MNEMONIC_JS:   taken = sf; break;
            case ZYDIS_MNEMONIC_JNS:  taken = !sf; break;
            case ZYDIS_MNEMONIC_JO:   taken = of; break;
            case ZYDIS_MNEMONIC_JNO:  taken = !of; break;
            case ZYDIS_MNEMONIC_JB:   taken = cf; break;
            case ZYDIS_MNEMONIC_JNB:  taken = !cf; break;
            case ZYDIS_MNEMONIC_JBE:  taken = cf || zf; break;
            case ZYDIS_MNEMONIC_JNBE: taken = !cf && !zf; break;
            case ZYDIS_MNEMONIC_JL:   taken = sf != of; break;
            case ZYDIS_MNEMONIC_JNL:  taken = sf == of; break;
            case ZYDIS_MNEMONIC_JLE:  taken = zf || (sf != of); break;
            case ZYDIS_MNEMONIC_JNLE: taken = !zf && (sf == of); break;
            case ZYDIS_MNEMONIC_JP:   taken = false; break;
            case ZYDIS_MNEMONIC_JNP:  taken = true; break;
            default: return false;
        }

        bb.branch_resolved = true;
        bb.branch_taken = taken;
        return true;
    }


    void deobfuscate_inplace() {
        if (funcs_.empty()) { std::cout << "[8] Skip deobfuscation.\n"; return; }
        std::cout << "[8] Multi-pass junk elimination...\n";

        for (auto& fn : funcs_) {
            for (auto& bb : fn.blocks) {
                int si = -1; std::uint64_t ss = 0; std::uint8_t* sd = nullptr; std::size_t sz = 0;
                for (std::size_t s = 0; s < secs_.size(); s++) {
                    std::uint64_t a = mod_base_ + secs_[s].VirtualAddress;
                    if (bb.va >= a && bb.va < a + secs_[s].VirtualSize) {
                        si = (int)s; ss = a; sd = sec_data_[s].data(); sz = sec_data_[s].size(); break;
                    }
                }
                if (si < 0 || !sd) continue;
                std::size_t boff = (std::size_t)(bb.va - ss);
                if (boff + bb.size > sz) continue;

                std::vector<JunkDetector::InsnInfo> insns;
                std::size_t cur = boff, end = boff + bb.size;
                while (cur < end) {
                    JunkDetector::InsnInfo ii;
                    ii.va = ss + cur;
                    ii.offset_in_section = cur;
                    ii.is_junk = false;
                    if (!dis_.decode(sd + cur, end - cur, ii.va, ii.instr, ii.ops)) { cur++; continue; }
                    ii.length = static_cast<std::uint8_t>(ii.instr.length);
                    cur += ii.length;
                    insns.push_back(ii);
                }

                junk_.analyze(insns);

                for (const auto& ii : insns) {
                    if (ii.is_junk) {
                        std::memset(sd + ii.offset_in_section, 0x90, ii.length);
                        junk_insns_++;
                        junk_bytes_ += ii.length;
                    }
                }
            }
        }
        std::cout << "    Patched " << junk_insns_ << " junk instructions (" << junk_bytes_ << " bytes -> NOP)\n";
    }


    void reconstruct_iat() {
        std::cout << "[8.5] Reconstructing Import Address Table...\n";


        struct ApiNameEntry {
            std::string name;
            bool is_flt;
            std::uint64_t table_va;
        };
        std::vector<ApiNameEntry> api_names;


        int rdata_idx = -1;
        for (std::size_t i = 0; i < secs_.size(); i++) {
            char nm[9] = {}; std::memcpy(nm, secs_[i].Name, 8);
            if (std::string(nm) == ".rdata") { rdata_idx = (int)i; break; }
        }


        if (rdata_idx < 0) {
            std::cout << "    [!] No .rdata section found — cannot reconstruct IAT\n";
            return;
        }

        std::uint64_t iat_base_va = mod_base_ + secs_[rdata_idx].VirtualAddress;
        std::uint32_t iat_base_rva = secs_[rdata_idx].VirtualAddress;


        std::uint64_t name_table_va = iat_base_va + 0x50;
        std::uint32_t name_table_rva = iat_base_rva + 0x50;


        auto read_image = [&](std::uint64_t va, std::uint8_t* buf, std::size_t len) -> bool {
            std::uint32_t rva = (std::uint32_t)(va - mod_base_);
            if (rva + len > full_image_.size()) return false;
            std::memcpy(buf, full_image_.data() + rva, len);
            return true;
        };


        for (int i = 0; i < 8; i++) {
            std::uint8_t buf[16] = {};
            if (!read_image(name_table_va + i * 16, buf, 16)) continue;
            if (buf[0] == 0 || buf[0] == 0xFF) continue;

            std::string name(reinterpret_cast<char*>(buf), 16);

            while (!name.empty() && name.back() == '\0') name.pop_back();
            if (name.empty()) continue;

            bool is_flt = (name.substr(0, 3) == "Flt");
            api_names.push_back({name, is_flt, name_table_va + i * 16});
        }


        for (int i = 0; i < 8; i++) {
            std::uint8_t buf[16] = {};
            if (!read_image(name_table_va + 0x80 + i * 16, buf, 16)) continue;
            if (buf[0] == 0 || buf[0] == 0xFF) continue;


            char decoded[17] = {};
            bool valid = true;
            for (int b = 0; b < 16; b++) {
                decoded[b] = static_cast<char>(buf[b] ^ 0xFF);
                if (decoded[b] != 0 && (decoded[b] < 0x20 || decoded[b] > 0x7E)) { valid = false; break; }
            }
            if (!valid) continue;


            if (!(decoded[0] >= 'A' && decoded[0] <= 'Z' && decoded[1] >= 'a' && decoded[1] <= 'z'))
                continue;

            std::string name(decoded, 16);
            while (!name.empty() && name.back() == '\0') name.pop_back();
            if (name.empty()) continue;


            api_names.push_back({name, false, name_table_va + 0x80 + i * 16});
        }


        for (int i = 0; i < 5; i++) {
            std::uint8_t buf[16] = {};
            if (!read_image(name_table_va + 0x130 + i * 16, buf, 16)) continue;
            if (buf[0] == 0 || buf[0] == 0xFF) continue;


            if (buf[0] < 0x41 || buf[0] > 0x5A) continue;

            std::string name(reinterpret_cast<char*>(buf), 16);
            while (!name.empty() && name.back() == '\0') name.pop_back();
            if (name.empty()) continue;

            api_names.push_back({name, false, name_table_va + 0x130 + i * 16});
        }

        std::cout << "    Decoded " << api_names.size() << " dynamic API names from name table\n";


        static const std::pair<const char*, const char*> full_names[] = {
            {"FltGetRequestorP", "FltGetRequestorProcess"},
            {"FltReleaseFileNa", "FltReleaseFileNameInformation"},
            {"FltRegisterFilte", "FltRegisterFilter"},
            {"FltUnregisterFil", "FltUnregisterFilter"},
            {"NtReadVirtualMem", "NtReadVirtualMemory"},
            {"FltGetFileNameIn", "FltGetFileNameInformation"},
            {"FltStartFilterin", "FltStartFiltering"},
            {"FltQueryInformat", "FltQueryInformationFile"},
            {"HalPrivateDispat", "HalPrivateDispatchTable"},
            {"HalDispatchTable", "HalDispatchTable"},
            {"DxgCoreInterface", "DxgCoreInterface"},
            {"ZwSuspendThread",  "ZwSuspendThread"},
            {"NtWriteVirtualMe", "NtWriteVirtualMemory"},
            {"ZwGetContextThre", "ZwGetContextThread"},
            {"ZwProtectVirtual", "ZwProtectVirtualMemory"},
            {"NtDeviceIoContro", "NtDeviceIoControlFile"},
        };


        for (auto& api : api_names) {
            for (const auto& [prefix, full] : full_names) {
                if (api.name == prefix || api.name.find(prefix) == 0) {
                    api.name = full;
                    break;
                }
            }
        }

        for (const auto& api : api_names) {
            std::cout << "      " << (api.is_flt ? "[FLT] " : "[NT]  ") << api.name << "\n";
        }


        struct IatRef {
            std::uint64_t insn_va;
            std::uint32_t insn_rva;
            std::uint8_t  insn_len;
            std::uint64_t target_va;
            int           section_idx;
            std::size_t   offset_in_section;
            bool          is_call;
        };
        std::vector<IatRef> iat_refs;


        std::uint64_t static_iat_start = iat_base_va;
        std::uint64_t static_iat_end = iat_base_va + 0x40;


        for (std::size_t si = 0; si < secs_.size(); si++) {
            if (!(secs_[si].Characteristics & 0x20000000)) continue;
            const auto& sd = sec_data_[si];
            if (sd.empty()) continue;
            std::uint64_t sec_va = mod_base_ + secs_[si].VirtualAddress;

            std::size_t off = 0;
            while (off < sd.size()) {
                std::uint64_t ip = sec_va + off;
                ZydisDecodedInstruction instr;
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!dis_.decode(sd.data() + off, sd.size() - off, ip, instr, ops)) { off++; continue; }

                bool is_indirect_call = (instr.mnemonic == ZYDIS_MNEMONIC_CALL &&
                    instr.operand_count_visible >= 1 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    ops[0].mem.base == ZYDIS_REGISTER_RIP &&
                    ops[0].mem.index == ZYDIS_REGISTER_NONE);

                bool is_indirect_mov = (instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    instr.operand_count_visible >= 2 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    ops[1].mem.base == ZYDIS_REGISTER_RIP &&
                    ops[1].mem.index == ZYDIS_REGISTER_NONE);

                bool is_indirect_lea = (instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
                    instr.operand_count_visible >= 2 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    ops[1].mem.base == ZYDIS_REGISTER_RIP &&
                    ops[1].mem.index == ZYDIS_REGISTER_NONE);

                bool is_movdqa = ((instr.mnemonic == ZYDIS_MNEMONIC_MOVDQA ||
                    instr.mnemonic == ZYDIS_MNEMONIC_MOVDQU ||
                    instr.mnemonic == ZYDIS_MNEMONIC_MOVAPS ||
                    instr.mnemonic == ZYDIS_MNEMONIC_MOVUPS) &&
                    instr.operand_count_visible >= 2 &&
                    ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    ops[1].mem.base == ZYDIS_REGISTER_RIP &&
                    ops[1].mem.index == ZYDIS_REGISTER_NONE);

                if (is_indirect_call || is_indirect_mov || is_indirect_lea || is_movdqa) {
                    int op_idx = (is_indirect_call ? 0 : 1);
                    std::uint64_t target_va = dis_.calc_abs(ip, instr, ops[op_idx]);


                    if (target_va >= static_iat_start && target_va < static_iat_end + 0x200) {
                        IatRef ref;
                        ref.insn_va = ip;
                        ref.insn_rva = (std::uint32_t)(ip - mod_base_);
                        ref.insn_len = (std::uint8_t)instr.length;
                        ref.target_va = target_va;
                        ref.section_idx = (int)si;
                        ref.offset_in_section = off;
                        ref.is_call = is_indirect_call;
                        iat_refs.push_back(ref);
                    }
                }

                off += instr.length;
            }
        }

        std::cout << "    Found " << iat_refs.size() << " IAT/import references in code\n";


        std::size_t total_iat_slots = 6 + api_names.size();
        std::size_t iat_data_size = total_iat_slots * 8;
        std::size_t names_offset = (iat_data_size + 15) & ~15;


        std::size_t names_total = 0;
        for (const auto& api : api_names) {
            names_total += api.name.size() + 1;
        }
        names_total = (names_total + 15) & ~15;

        iat_section_data_.resize(names_offset + names_total, 0);


        if (iat_base_rva > 0 && iat_base_rva < full_image_.size()) {

            std::size_t copy_len = std::min<std::size_t>(56, full_image_.size() - iat_base_rva);
            std::memcpy(iat_section_data_.data(), full_image_.data() + iat_base_rva, copy_len);
        }


        for (std::size_t i = 0; i < api_names.size(); i++) {
            ResolvedImport imp;
            imp.name = api_names[i].name;
            imp.resolved_va = 0;
            imp.iat_slot_rva = 0;
            imp.is_flt = api_names[i].is_flt;
            resolved_imports_.push_back(imp);
        }


        std::size_t name_cursor = names_offset;
        for (std::size_t i = 0; i < api_names.size(); i++) {
            std::memcpy(iat_section_data_.data() + name_cursor, api_names[i].name.c_str(), api_names[i].name.size());
            iat_section_data_[name_cursor + api_names[i].name.size()] = 0;
            name_cursor += api_names[i].name.size() + 1;
        }


        static const char* static_iat_names[] = {
            "FltGetRoutineAddress", nullptr, "MmGetSystemRoutineAddress",
            "__C_specific_handler", "__chkstk", "MmMapLockedPagesSpecifyCache",
            "KeBugCheckEx"
        };

        for (const auto& ref : iat_refs) {
            if (ref.target_va >= static_iat_start && ref.target_va < static_iat_end) {
                std::uint32_t slot = (std::uint32_t)(ref.target_va - static_iat_start) / 8;
                if (slot < 7 && static_iat_names[slot]) {
                    iat_refs_patched_++;
                }
            }
        }


        std::uint32_t name_table_refs = 0;
        for (const auto& ref : iat_refs) {
            if (ref.target_va >= name_table_va && ref.target_va < name_table_va + 0x1C0) {
                name_table_refs++;
            }
        }

        std::cout << "    Static IAT refs: " << iat_refs_patched_ << "\n";
        std::cout << "    Dynamic name table refs: " << name_table_refs << "\n";
        std::cout << "    " << resolved_imports_.size() << " dynamic imports identified for IAT rebuild\n";
    }


    void devirtualize_indirect_branches() {
        std::cout << "[8.6] Devirtualizing indirect branches...\n";


        constexpr std::uint32_t MAX_EMU_ATTEMPTS = 200;
        std::uint32_t emu_attempts = 0;
        std::uint32_t skipped_unreachable = 0;
        std::uint32_t skipped_dead = 0;
        std::uint32_t static_resolved = 0;

        for (auto& fn : funcs_) {

            std::unordered_map<std::uint64_t, BasicBlock*> bmap;
            for (auto& b : fn.blocks) bmap[b.va] = &b;


            std::unordered_set<std::uint64_t> reachable;
            {
                std::queue<std::uint64_t> q;
                if (!fn.blocks.empty()) q.push(fn.blocks[0].va);
                while (!q.empty()) {
                    auto va = q.front(); q.pop();
                    if (reachable.count(va)) continue;
                    reachable.insert(va);
                    auto it = bmap.find(va);
                    if (it == bmap.end()) continue;
                    const auto* b = it->second;
                    if (b->is_unconditional_jmp && b->branch_target)
                        q.push(b->branch_target);
                    if (b->is_conditional_jmp) {
                        if (b->branch_resolved) {

                            std::uint64_t target = b->branch_taken ? b->branch_target : b->fallthrough_target;
                            if (target) q.push(target);
                        }

                    }

                }
            }

            for (auto& bb : fn.blocks) {
                if (!bb.is_indirect) continue;


                if (!reachable.count(bb.va)) {
                    skipped_unreachable++;
                    bb.is_indirect = false;
                    continue;
                }


                const std::uint8_t* block_data = nullptr;
                std::size_t block_data_size = 0;
                int si = -1;
                for (std::size_t s = 0; s < secs_.size(); s++) {
                    std::uint64_t a = mod_base_ + secs_[s].VirtualAddress;
                    if (bb.va >= a && bb.va < a + secs_[s].VirtualSize) {
                        si = (int)s;
                        std::size_t boff = (std::size_t)(bb.va - a);
                        block_data = sec_data_[s].data() + boff;
                        block_data_size = std::min<std::size_t>(bb.size, sec_data_[s].size() - boff);
                        break;
                    }
                }
                if (!block_data || block_data_size == 0) continue;


                std::uint64_t indirect_va = 0;
                std::uint8_t indirect_len = 0;
                std::uint8_t* indirect_ptr = nullptr;
                bool dead_indirect = false;
                {
                    std::size_t scan = 0;
                    while (scan < block_data_size) {
                        ZydisDecodedInstruction instr;
                        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                        std::uint64_t ip = bb.va + scan;
                        if (!dis_.decode(block_data + scan, block_data_size - scan, ip, instr, ops)) { scan++; continue; }


                        if (instr.mnemonic == ZYDIS_MNEMONIC_NOP) { scan += instr.length; continue; }


                        bool is_direct_jmp = (instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
                            instr.operand_count_visible >= 1 &&
                            (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                             (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[0].mem.base == ZYDIS_REGISTER_RIP)));

                        bool is_jcc = (instr.meta.category == ZYDIS_CATEGORY_COND_BR);

                        bool is_ret = (instr.mnemonic == ZYDIS_MNEMONIC_RET);

                        bool is_indirect_jmp = (instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
                            instr.operand_count_visible >= 1 &&
                            (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER ||
                             (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[0].mem.base != ZYDIS_REGISTER_RIP)));

                        if (is_direct_jmp || is_jcc || is_ret) {


                            dead_indirect = true;
                            break;
                        }

                        if (is_indirect_jmp) {
                            indirect_va = ip;
                            indirect_len = (std::uint8_t)instr.length;
                            for (std::size_t s = 0; s < secs_.size(); s++) {
                                std::uint64_t a = mod_base_ + secs_[s].VirtualAddress;
                                if (ip >= a && ip < a + secs_[s].VirtualSize) {
                                    indirect_ptr = sec_data_[s].data() + (std::size_t)(ip - a);
                                    break;
                                }
                            }
                            break;
                        }

                        scan += instr.length;
                    }
                }

                if (dead_indirect) { skipped_dead++; bb.is_indirect = false; continue; }
                if (indirect_va == 0 || !indirect_ptr) continue;

                indirect_total_++;


                std::uint64_t static_target = 0;
                {

                    ZydisDecodedInstruction jmp_instr;
                    ZydisDecodedOperand jmp_ops[ZYDIS_MAX_OPERAND_COUNT];
                    if (dis_.decode(indirect_ptr, indirect_len, indirect_va, jmp_instr, jmp_ops) &&
                        jmp_ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        ZydisRegister target_reg = jmp_ops[0].reg.value;

                        ZydisRegister base_reg = target_reg;


                        ZydisRegister reg64 = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, target_reg);


                        std::size_t scan = 0;
                        std::uint64_t last_mov_imm = 0;
                        bool found_mov = false;
                        while (scan < block_data_size) {
                            ZydisDecodedInstruction instr;
                            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                            std::uint64_t ip = bb.va + scan;
                            if (!dis_.decode(block_data + scan, block_data_size - scan, ip, instr, ops)) { scan++; continue; }

                            if (ip == indirect_va) break;


                            if (instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                                instr.operand_count_visible >= 2 &&
                                ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                                ZydisRegister mov_reg64 = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[0].reg.value);
                                if (mov_reg64 == reg64) {
                                    last_mov_imm = ops[1].imm.value.u;

                                    if (ops[0].size == 32) {
                                        last_mov_imm &= 0xFFFFFFFF;
                                    }
                                    found_mov = true;
                                }
                            }

                            else if (instr.operand_count_visible >= 1 &&
                                     ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                     ops[0].actions & ZYDIS_OPERAND_ACTION_WRITE) {
                                ZydisRegister wr_reg64 = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[0].reg.value);
                                if (wr_reg64 == reg64 && instr.mnemonic != ZYDIS_MNEMONIC_MOV) {
                                    found_mov = false;
                                }
                            }

                            scan += instr.length;
                        }

                        if (found_mov && last_mov_imm >= mod_base_ && last_mov_imm < mod_base_ + mod_size_) {
                            static_target = last_mov_imm;
                        }
                    }
                }

                std::uint64_t resolved_target = static_target;


                if (resolved_target == 0 && emu_attempts < MAX_EMU_ATTEMPTS) {
                    emu_attempts++;
                    auto traced = resolver_.trace_function(bb.va, 200);
                    if (traced.size() >= 2) {
                        std::uint64_t last = traced.back().va;
                        if (last >= mod_base_ && last < mod_base_ + mod_size_) {
                            resolved_target = last;
                        }
                    }
                }

                if (resolved_target == 0) continue;
                if (static_target != 0) static_resolved++;


                if (indirect_len >= 5) {
                    std::int64_t rel = (std::int64_t)resolved_target - (std::int64_t)(indirect_va + 5);
                    if (rel >= INT32_MIN && rel <= INT32_MAX) {
                        indirect_ptr[0] = 0xE9;
                        std::int32_t rel32 = (std::int32_t)rel;
                        std::memcpy(indirect_ptr + 1, &rel32, 4);
                        for (std::uint8_t n = 5; n < indirect_len; n++)
                            indirect_ptr[n] = 0x90;

                        bb.is_indirect = false;
                        bb.is_unconditional_jmp = true;
                        bb.branch_target = resolved_target;
                        indirect_resolved_++;

                        be0_entries_.insert(resolved_target);
                    }
                }
            }
        }

        skipped_junk_blocks_ = skipped_unreachable + skipped_dead;
        std::cout << "    Skipped " << skipped_unreachable << " unreachable junk-path blocks\n";
        std::cout << "    Skipped " << skipped_dead << " dead-code indirect branches (after direct JMP/Jcc/RET)\n";
        std::cout << "    " << indirect_resolved_ << "/" << indirect_total_
                  << " reachable indirect branches devirtualized"
                  << " (" << static_resolved << " static, "
                  << std::min(emu_attempts, MAX_EMU_ATTEMPTS) << " emulated)\n";
    }


    void linearize_functions() {
        std::cout << "[9] Linearizing " << funcs_.size() << " recovered functions (post-devirt)...\n";


        std::uint32_t sec_align = 0x1000;
        if (nt_) sec_align = nt_->OptionalHeader.SectionAlignment;
        if (sec_align == 0) sec_align = 0x1000;

        std::uint32_t last_end = 0;
        for (const auto& s : secs_) {
            std::uint32_t e = s.VirtualAddress + align_up(s.VirtualSize, sec_align);
            if (e > last_end) last_end = e;
        }

        clean_section_rva_ = last_end;

        std::uint32_t write_offset = 0;
        clean_section_data_.clear();
        clean_section_data_.reserve(0x200000);

        for (auto& fn : funcs_) {
            if (fn.blocks.empty()) continue;


            std::unordered_map<std::uint64_t, std::size_t> block_map;
            for (std::size_t i = 0; i < fn.blocks.size(); i++)
                block_map[fn.blocks[i].va] = i;


            std::vector<std::size_t> order;
            std::set<std::size_t> emitted;
            std::queue<std::size_t> bfs;


            if (block_map.count(fn.entry_va)) {
                bfs.push(block_map[fn.entry_va]);
            }

            while (!bfs.empty()) {
                std::size_t idx = bfs.front(); bfs.pop();
                if (emitted.count(idx)) continue;
                emitted.insert(idx);
                order.push_back(idx);

                const auto& bb = fn.blocks[idx];

                if (bb.is_conditional_jmp && bb.branch_resolved) {

                    std::uint64_t next = bb.branch_taken ? bb.branch_target : bb.fallthrough_target;
                    if (block_map.count(next)) bfs.push(block_map[next]);

                    std::uint64_t other = bb.branch_taken ? bb.fallthrough_target : bb.branch_target;
                    if (block_map.count(other)) bfs.push(block_map[other]);
                } else if (bb.is_unconditional_jmp) {
                    if (block_map.count(bb.branch_target)) bfs.push(block_map[bb.branch_target]);
                } else if (bb.fallthrough_target && !bb.is_ret && !bb.is_indirect) {
                    if (block_map.count(bb.fallthrough_target)) bfs.push(block_map[bb.fallthrough_target]);
                }
            }


            for (std::size_t i = 0; i < fn.blocks.size(); i++) {
                if (!emitted.count(i)) {
                    order.push_back(i);
                    emitted.insert(i);
                }
            }


            fn.clean_rva = clean_section_rva_ + write_offset;
            fn.clean_code.clear();

            for (std::size_t oi = 0; oi < order.size(); oi++) {
                auto& bb = fn.blocks[order[oi]];


                const std::uint8_t* block_data = nullptr;
                std::size_t block_data_size = 0;
                for (std::size_t s = 0; s < secs_.size(); s++) {
                    std::uint64_t a = mod_base_ + secs_[s].VirtualAddress;
                    if (bb.va >= a && bb.va < a + secs_[s].VirtualSize) {
                        std::size_t boff = (std::size_t)(bb.va - a);
                        block_data = sec_data_[s].data() + boff;
                        block_data_size = std::min<std::size_t>(bb.size, sec_data_[s].size() - boff);
                        break;
                    }
                }
                if (!block_data || block_data_size == 0) continue;

                std::vector<std::uint8_t> block_bytes(block_data, block_data + block_data_size);


                if (bb.is_conditional_jmp && bb.branch_resolved) {

                    std::uint64_t resolved_target = bb.branch_taken ? bb.branch_target : bb.fallthrough_target;


                    bool next_is_target = false;
                    if (oi + 1 < order.size()) {
                        next_is_target = (fn.blocks[order[oi + 1]].va == resolved_target);
                    }


                    std::size_t jcc_offset = 0;
                    std::uint8_t jcc_len = 0;
                    {
                        std::size_t scan = 0;
                        while (scan < block_bytes.size()) {
                            ZydisDecodedInstruction instr; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                            if (!dis_.decode(block_bytes.data() + scan, block_bytes.size() - scan,
                                           bb.va + scan, instr, ops)) { scan++; continue; }
                            if (dis_.is_jcc(instr)) {
                                jcc_offset = scan;
                                jcc_len = static_cast<std::uint8_t>(instr.length);
                            }
                            scan += instr.length;
                        }
                    }

                    if (jcc_len > 0) {
                        if (next_is_target) {

                            std::memset(block_bytes.data() + jcc_offset, 0x90, jcc_len);
                            branches_patched_++;
                        } else {


                            std::memset(block_bytes.data() + jcc_offset, 0x90, jcc_len);
                            branches_patched_++;
                        }
                    }
                }


                if (bb.is_unconditional_jmp && oi + 1 < order.size()) {
                    if (fn.blocks[order[oi + 1]].va == bb.branch_target) {

                        std::size_t scan = 0, jmp_off = 0;
                        std::uint8_t jmp_len = 0;
                        while (scan < block_bytes.size()) {
                            ZydisDecodedInstruction instr; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                            if (!dis_.decode(block_bytes.data() + scan, block_bytes.size() - scan,
                                           bb.va + scan, instr, ops)) { scan++; continue; }
                            if (dis_.is_jmp_rel(instr)) {
                                jmp_off = scan;
                                jmp_len = static_cast<std::uint8_t>(instr.length);
                            }
                            scan += instr.length;
                        }
                        if (jmp_len > 0) {
                            std::memset(block_bytes.data() + jmp_off, 0x90, jmp_len);
                        }
                    }
                }

                fn.clean_code.insert(fn.clean_code.end(), block_bytes.begin(), block_bytes.end());
            }

            if (!fn.clean_code.empty()) {

                std::size_t aligned_size = (fn.clean_code.size() + 15) & ~15;
                fn.clean_code.resize(aligned_size, 0xCC);

                clean_section_data_.insert(clean_section_data_.end(),
                                          fn.clean_code.begin(), fn.clean_code.end());
                write_offset += static_cast<std::uint32_t>(fn.clean_code.size());
                linearized_bytes_ += fn.clean_code.size();
                functions_linearized_++;
            }
        }

        std::cout << "    Linearized " << functions_linearized_ << " functions, "
                  << linearized_bytes_ << " bytes clean code\n";
        std::cout << "    Branches patched: " << branches_patched_ << "\n";
    }


    void patch_section_flags() {
        std::cout << "[10] Patching section characteristics...\n";


        if (be0_idx_ >= 0) {
            secs_[be0_idx_].Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
            secs_[be0_idx_].Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
            std::cout << "    .be0 -> +CODE +EXECUTE +READ\n";
        }
    }


    void build_pdata() {
        std::cout << "[11] Building .pdata (RUNTIME_FUNCTION table)...\n";

        struct FuncBounds { std::uint32_t begin_rva; std::uint32_t end_rva; };
        std::vector<FuncBounds> entries;


        if (text_idx_ >= 0) {
            const auto& td = sec_data_[text_idx_];
            std::uint64_t tva = mod_base_ + secs_[text_idx_].VirtualAddress;
            std::uint32_t text_rva = secs_[text_idx_].VirtualAddress;
            std::uint32_t text_end_rva = text_rva + secs_[text_idx_].VirtualSize;

            std::set<std::uint32_t> text_func_rvas;
            for (std::size_t off = 0; off + 4 < td.size(); ) {
                if (td[off] == 0xCC) { off++; continue; }

                std::uint64_t ip = tva + off;
                ZydisDecodedInstruction instr; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!dis_.decode(td.data()+off, td.size()-off, ip, instr, ops)) { off++; continue; }

                bool is_prologue = false;
                if (instr.mnemonic == ZYDIS_MNEMONIC_SUB && instr.operand_count_visible >= 2 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_RSP)
                    is_prologue = true;
                if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH && instr.operand_count_visible >= 1 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    auto r = ops[0].reg.value;
                    if (r == ZYDIS_REGISTER_RBP || r == ZYDIS_REGISTER_RBX || r == ZYDIS_REGISTER_RDI ||
                        r == ZYDIS_REGISTER_RSI || r == ZYDIS_REGISTER_R12 || r == ZYDIS_REGISTER_R13 ||
                        r == ZYDIS_REGISTER_R14 || r == ZYDIS_REGISTER_R15)
                        is_prologue = true;
                }
                if (instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operand_count_visible >= 2 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (ops[0].reg.value == ZYDIS_REGISTER_RAX || ops[0].reg.value == ZYDIS_REGISTER_R11) &&
                    ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].reg.value == ZYDIS_REGISTER_RSP)
                    is_prologue = true;
                if (off > 0 && td[off - 1] == 0xCC) is_prologue = true;

                if (is_prologue) text_func_rvas.insert(text_rva + (std::uint32_t)off);
                off += instr.length;
            }

            std::vector<std::uint32_t> sorted_starts(text_func_rvas.begin(), text_func_rvas.end());
            std::sort(sorted_starts.begin(), sorted_starts.end());
            for (std::size_t i = 0; i < sorted_starts.size(); i++) {
                std::uint32_t end = (i + 1 < sorted_starts.size()) ? sorted_starts[i+1] : text_end_rva;
                entries.push_back({sorted_starts[i], end});
            }
            std::cout << "    .text: " << sorted_starts.size() << " function entries\n";
        }


        for (const auto& fn : funcs_) {
            entries.push_back({fn.entry_rva, fn.max_rva_end});
        }


        for (const auto& fn : funcs_) {
            if (!fn.clean_code.empty()) {
                std::uint32_t clean_end = fn.clean_rva + static_cast<std::uint32_t>(fn.clean_code.size());
                entries.push_back({fn.clean_rva, clean_end});
            }
        }

        if (entries.empty()) { std::cout << "    No functions.\n"; return; }

        std::sort(entries.begin(), entries.end(),
                  [](const FuncBounds& a, const FuncBounds& b) { return a.begin_rva < b.begin_rva; });
        entries.erase(std::unique(entries.begin(), entries.end(),
                      [](const FuncBounds& a, const FuncBounds& b) { return a.begin_rva == b.begin_rva; }),
                      entries.end());

        pdata_func_count_ = static_cast<std::uint32_t>(entries.size());


        std::uint32_t sec_align = 0x1000;
        if (nt_) sec_align = nt_->OptionalHeader.SectionAlignment;
        if (sec_align == 0) sec_align = 0x1000;

        pdata_rva_ = clean_section_rva_ + align_up(static_cast<std::uint32_t>(clean_section_data_.size()), sec_align);

        std::uint32_t rt_array_size = pdata_func_count_ * sizeof(RuntimeFunction);
        std::uint32_t unwind_offset = rt_array_size;
        if (unwind_offset % 4 != 0) unwind_offset += 4 - (unwind_offset % 4);
        std::uint32_t unwind_rva = pdata_rva_ + unwind_offset;
        std::uint32_t blob_size = unwind_offset + sizeof(UnwindInfo);

        pdata_blob_.resize(blob_size, 0);

        auto* rt = reinterpret_cast<RuntimeFunction*>(pdata_blob_.data());
        for (std::uint32_t i = 0; i < pdata_func_count_; i++) {
            rt[i].BeginAddress    = entries[i].begin_rva;
            rt[i].EndAddress      = entries[i].end_rva;
            rt[i].UnwindInfoAddress = unwind_rva;
        }

        auto* uw = reinterpret_cast<UnwindInfo*>(pdata_blob_.data() + unwind_offset);
        uw->VersionAndFlags   = 0x01;
        uw->SizeOfProlog      = 0;
        uw->CountOfUnwindCodes = 0;
        uw->FrameRegAndOffset = 0;

        std::cout << "    .pdata: " << pdata_func_count_ << " entries @ RVA " << hex32(pdata_rva_)
                  << ", blob=" << blob_size << " bytes\n";
    }


    void write_output(const std::string& output_path) {
        std::cout << "[12] Writing output: " << output_path << "\n";

        std::uint32_t file_align = 0x200;
        std::uint32_t sec_align = 0x1000;
        if (nt_) {
            file_align = nt_->OptionalHeader.FileAlignment;
            sec_align = nt_->OptionalHeader.SectionAlignment;
        }
        if (file_align == 0) file_align = 0x200;
        if (sec_align == 0) sec_align = 0x1000;


        int extra_sections = 0;
        bool add_clean = !clean_section_data_.empty();
        bool add_pdata = pdata_func_count_ > 0;
        bool add_iat = !iat_section_data_.empty();
        if (add_clean) extra_sections++;
        if (add_pdata) extra_sections++;
        if (add_iat) extra_sections++;


        if (add_iat) {
            std::uint32_t after_pdata = pdata_rva_ + align_up(static_cast<std::uint32_t>(pdata_blob_.size()), sec_align);
            iat_section_rva_ = after_pdata;

            for (std::size_t i = 0; i < resolved_imports_.size(); i++) {
                resolved_imports_[i].iat_slot_rva = iat_section_rva_ + (6 + (std::uint32_t)i) * 8;
            }
        }

        int output_num_sections = (int)secs_.size() + extra_sections;

        auto* dos = reinterpret_cast<DosHeader*>(header_data_.data());
        std::uint32_t sh_start = dos->e_lfanew + sizeof(NtHeaders64);
        std::uint32_t sh_end = sh_start + output_num_sections * sizeof(SectionHeader);
        if (sh_end > 0x1000) {
            std::cerr << "    WARNING: Not enough header space for new sections.\n";
            add_clean = false;
            add_pdata = false;
            add_iat = false;
            output_num_sections = (int)secs_.size();
        }

        std::uint32_t headers_size = align_up(sh_end, file_align);


        std::vector<std::uint32_t> raw_off(secs_.size());
        std::uint32_t cursor = headers_size;
        for (std::size_t i = 0; i < secs_.size(); i++) {
            raw_off[i] = cursor;
            cursor += align_up(static_cast<std::uint32_t>(sec_data_[i].size()), file_align);
        }

        std::uint32_t clean_raw_off = 0;
        if (add_clean && !clean_section_data_.empty()) {
            clean_raw_off = cursor;
            cursor += align_up(static_cast<std::uint32_t>(clean_section_data_.size()), file_align);
        }

        std::uint32_t pdata_raw_off = 0;
        if (add_pdata && !pdata_blob_.empty()) {
            pdata_raw_off = cursor;
            cursor += align_up(static_cast<std::uint32_t>(pdata_blob_.size()), file_align);
        }

        std::uint32_t iat_raw_off = 0;
        if (add_iat && !iat_section_data_.empty()) {
            iat_raw_off = cursor;
            cursor += align_up(static_cast<std::uint32_t>(iat_section_data_.size()), file_align);
        }

        std::uint32_t total_file = cursor;

        std::vector<std::uint8_t> out(total_file, 0);
        std::memcpy(out.data(), header_data_.data(), std::min<std::size_t>(header_data_.size(), headers_size));

        auto* o_dos = reinterpret_cast<DosHeader*>(out.data());
        auto* o_nt  = reinterpret_cast<NtHeaders64*>(out.data() + o_dos->e_lfanew);
        auto* o_sh  = reinterpret_cast<SectionHeader*>(
            reinterpret_cast<std::uint8_t*>(&o_nt->OptionalHeader) + o_nt->FileHeader.SizeOfOptionalHeader);

        o_nt->FileHeader.NumberOfSections = static_cast<std::uint16_t>(output_num_sections);


        for (std::size_t i = 0; i < secs_.size(); i++) {
            o_sh[i] = secs_[i];
            o_sh[i].PointerToRawData = raw_off[i];
            o_sh[i].SizeOfRawData = align_up(static_cast<std::uint32_t>(sec_data_[i].size()), file_align);
            if (!sec_data_[i].empty())
                std::memcpy(out.data() + raw_off[i], sec_data_[i].data(), sec_data_[i].size());
        }

        int next_sec_idx = (int)secs_.size();


        if (add_clean && !clean_section_data_.empty()) {
            auto& ch = o_sh[next_sec_idx];
            std::memset(&ch, 0, sizeof(SectionHeader));
            std::memcpy(ch.Name, ".clean", 7);
            ch.VirtualSize    = static_cast<std::uint32_t>(clean_section_data_.size());
            ch.VirtualAddress = clean_section_rva_;
            ch.SizeOfRawData  = align_up(static_cast<std::uint32_t>(clean_section_data_.size()), file_align);
            ch.PointerToRawData = clean_raw_off;
            ch.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
            std::memcpy(out.data() + clean_raw_off, clean_section_data_.data(), clean_section_data_.size());
            next_sec_idx++;
        }


        if (add_pdata && !pdata_blob_.empty()) {
            auto& ph = o_sh[next_sec_idx];
            std::memset(&ph, 0, sizeof(SectionHeader));
            std::memcpy(ph.Name, ".pdata", 7);
            ph.VirtualSize    = static_cast<std::uint32_t>(pdata_blob_.size());
            ph.VirtualAddress = pdata_rva_;
            ph.SizeOfRawData  = align_up(static_cast<std::uint32_t>(pdata_blob_.size()), file_align);
            ph.PointerToRawData = pdata_raw_off;
            ph.Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
            std::memcpy(out.data() + pdata_raw_off, pdata_blob_.data(), pdata_blob_.size());

            if (o_nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
                o_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = pdata_rva_;
                o_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size =
                    pdata_func_count_ * sizeof(RuntimeFunction);
            }
            next_sec_idx++;
        }


        if (add_iat && !iat_section_data_.empty()) {
            auto& ih = o_sh[next_sec_idx];
            std::memset(&ih, 0, sizeof(SectionHeader));
            std::memcpy(ih.Name, ".iat", 5);
            ih.VirtualSize    = static_cast<std::uint32_t>(iat_section_data_.size());
            ih.VirtualAddress = iat_section_rva_;
            ih.SizeOfRawData  = align_up(static_cast<std::uint32_t>(iat_section_data_.size()), file_align);
            ih.PointerToRawData = iat_raw_off;
            ih.Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
            std::memcpy(out.data() + iat_raw_off, iat_section_data_.data(), iat_section_data_.size());

            if (o_nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT) {
                o_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = iat_section_rva_;
                o_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size =
                    static_cast<std::uint32_t>(resolved_imports_.size() * 8);
            }
            next_sec_idx++;
        }


        std::uint32_t max_end = 0;
        for (int i = 0; i < output_num_sections; i++) {
            std::uint32_t e = o_sh[i].VirtualAddress + align_up(o_sh[i].VirtualSize, sec_align);
            if (e > max_end) max_end = e;
        }
        o_nt->OptionalHeader.SizeOfImage = max_end;
        o_nt->OptionalHeader.ImageBase = mod_base_;
        o_nt->OptionalHeader.CheckSum = 0;

        std::ofstream ofs(output_path, std::ios::binary);
        if (!ofs) { std::cerr << "    FAIL: Cannot create " << output_path << "\n"; return; }
        ofs.write(reinterpret_cast<const char*>(out.data()), out.size());
        ofs.close();
        std::cout << "    Written " << total_file << " bytes (" << hex32(total_file) << ")\n";
    }

    void print_summary() {
        std::cout << "\n========== DUMP SUMMARY (v4.0) ==========\n";
        std::cout << "Module:                " << mod_name_ << "\n";
        std::cout << "Base VA:               " << hex(mod_base_) << "\n";
        std::cout << "Size:                  " << hex(mod_size_) << "\n";
        std::cout << "Sections (original):   " << secs_.size() << "\n";
        std::cout << "Dispatch stubs:        " << dispatches_.size() << "\n";
        std::cout << "Unique .be0 entries:   " << be0_entries_.size() << "\n";
        std::cout << "Functions recovered:   " << funcs_.size() << "\n";
        std::cout << "Blocks recovered:      " << blocks_total_ << "\n";
        std::cout << "--- Deobfuscation ---\n";
        std::cout << "Opaque predicates:     " << opaque_resolved_ << " resolved\n";
        std::cout << "Junk NOPped:           " << junk_insns_ << " insns (" << junk_bytes_ << " bytes)\n";
        std::cout << "Branches patched:      " << branches_patched_ << "\n";
        std::cout << "--- IAT Reconstruction ---\n";
        std::cout << "Dynamic imports:       " << resolved_imports_.size() << "\n";
        std::cout << "Static IAT refs:       " << iat_refs_patched_ << "\n";
        if (!iat_section_data_.empty())
            std::cout << ".iat section:          " << iat_section_data_.size() << " bytes @ RVA " << hex32(iat_section_rva_) << "\n";
        std::cout << "--- Devirtualization ---\n";
        std::cout << "Junk-path blocks:      " << (indirect_total_ + indirect_resolved_ + skipped_junk_blocks_)
                  << " pruned (" << skipped_junk_blocks_ << " unreachable)\n";
        std::cout << "Indirect branches:     " << indirect_total_ << " remaining (obfuscation dispatch), "
                  << indirect_resolved_ << " resolved\n";
        std::cout << "--- Linearization ---\n";
        std::cout << "Functions linearized:  " << functions_linearized_ << "\n";
        std::cout << "Clean code output:     " << linearized_bytes_ << " bytes\n";
        std::cout << ".pdata entries:        " << pdata_func_count_ << "\n";
        std::cout << "--- Output Sections ---\n";
        std::cout << ".text:   original code + NOP-patched junk\n";
        std::cout << ".be0:    original scattered blocks (NOP-patched)\n";
        std::cout << ".clean:  linearized deobfuscated functions\n";
        std::cout << ".pdata:  synthetic RUNTIME_FUNCTION table\n";
        if (!iat_section_data_.empty())
            std::cout << ".iat:    reconstructed import address table\n";
        std::cout << "==========================================\n";
        std::cout << "\nOpen in IDA Pro. Functions auto-discovered via .pdata.\n";
        std::cout << "The .clean section contains linearized, deobfuscated code.\n";
        std::cout << "Original .text + .be0 also cleaned (junk NOPped).\n";
        std::cout << ".iat provides reconstructed import names for analysis.\n";
    }
};


int main(int argc, char* argv[]) {
    std::string output_path = "BEDaisy_clean.sys";
    std::string target_name = "BEDaisy.sys";

    std::vector<std::string> positional;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if ((a == "-o" || a == "--output") && i + 1 < argc) { output_path = argv[++i]; continue; }
        if ((a == "-t" || a == "--target") && i + 1 < argc) { target_name = argv[++i]; continue; }
        if (a == "-h" || a == "--help") {
            std::cout << "Usage: BEDaisyDumper [output.sys] [target_name]\n"
                      << "       BEDaisyDumper -o <output> -t <target>\n\n"
                      << "Defaults: output=BEDaisy_clean.sys  target=BEDaisy.sys\n";
            return 0;
        }
        positional.push_back(a);
    }
    if (positional.size() >= 1) output_path = positional[0];
    if (positional.size() >= 2) target_name = positional[1];

    BEDaisyDumper dumper;
    if (!dumper.run(output_path, target_name)) {
        std::cerr << "\n[!] Dump FAILED.\n";
        return 1;
    }
    std::cout << "\n[+] Done. Output: " << output_path << "\n";
    return 0;
}
