#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unordered_set>
#include <queue>

#include <asmjit/asmjit.h>

#include "stub.hpp"
#include "stub_polymorphic.hpp"

#include <Zydis/Zydis.h>

namespace {

struct linear_decode_t {
    uint32_t offset;
    uint32_t length;
    char text[128];
};

bool linear_disassemble(const uint8_t* code,
                        size_t code_size,
                        std::vector<linear_decode_t>& out_decodes,
                        std::unordered_set<uint32_t>& out_offsets)
{
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        std::fprintf(stderr, "[ERR] ZydisDecoderInit failed (linear)\n");
        return false;
    }
    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        std::fprintf(stderr, "[ERR] ZydisFormatterInit failed (linear)\n");
        return false;
    }

    uint32_t cursor = 0;
    while (cursor < static_cast<uint32_t>(code_size)) {
        ZydisDecodedInstruction instr{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder,
            code + cursor,
            code_size - cursor,
            &instr,
            operands);
        if (!ZYAN_SUCCESS(status)) {
            cursor++;
            continue;
        }
        linear_decode_t d{};
        d.offset = cursor;
        d.length = instr.length;
        ZydisFormatterFormatInstruction(
            &formatter,
            &instr,
            operands,
            instr.operand_count_visible,
            d.text,
            sizeof(d.text),
            cursor,
            ZYAN_NULL);
        out_decodes.push_back(d);
        out_offsets.insert(cursor);
        cursor += instr.length;
    }
    return true;
}

bool recursive_disassemble(const uint8_t* code,
                            size_t code_size,
                            uint32_t entry_offset,
                            std::unordered_set<uint32_t>& out_offsets)
{
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        std::fprintf(stderr, "[ERR] ZydisDecoderInit failed (recursive)\n");
        return false;
    }

    std::queue<uint32_t> work;
    work.push(entry_offset);

    while (!work.empty()) {
        uint32_t addr = work.front();
        work.pop();
        if (addr >= code_size) continue;
        if (out_offsets.count(addr) > 0) continue;

        ZydisDecodedInstruction instr{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder,
            code + addr,
            code_size - addr,
            &instr,
            operands);
        if (!ZYAN_SUCCESS(status)) {
            continue;
        }

        out_offsets.insert(addr);
        uint32_t next = addr + instr.length;

        bool is_uncond_branch = false;
        bool is_branch = false;
        bool is_terminator = false;
        int64_t branch_target = -1;

        if (instr.mnemonic == ZYDIS_MNEMONIC_RET ||
            instr.mnemonic == ZYDIS_MNEMONIC_INT3 ||
            instr.mnemonic == ZYDIS_MNEMONIC_INT) {
            is_terminator = true;
        }

        if (instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
            is_uncond_branch = true;
            is_branch = true;
        } else if (instr.mnemonic == ZYDIS_MNEMONIC_JZ ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNZ ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JB ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JBE ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNB ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNBE ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JL ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JLE ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNL ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNLE ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JS ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNS ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JO ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNO ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JP ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JNP ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JCXZ ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JECXZ ||
                    instr.mnemonic == ZYDIS_MNEMONIC_JRCXZ ||
                    instr.mnemonic == ZYDIS_MNEMONIC_LOOP ||
                    instr.mnemonic == ZYDIS_MNEMONIC_LOOPE ||
                    instr.mnemonic == ZYDIS_MNEMONIC_LOOPNE) {
            is_branch = true;
        } else if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
            is_branch = true;
        }

        if (is_branch) {
            for (uint32_t i = 0; i < instr.operand_count_visible; ++i) {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    if (operands[i].imm.is_relative) {
                        int64_t signed_off = operands[i].imm.value.s;
                        branch_target = static_cast<int64_t>(addr) + static_cast<int64_t>(instr.length) + signed_off;
                    } else {
                        branch_target = static_cast<int64_t>(operands[i].imm.value.u);
                    }
                    break;
                }
            }
        }

        if (branch_target >= 0 && branch_target < static_cast<int64_t>(code_size)) {
            work.push(static_cast<uint32_t>(branch_target));
        }

        if (!is_uncond_branch && !is_terminator) {
            if (next < code_size) {
                work.push(next);
            }
        }
    }
    return true;
}

}

static int seh_call_pattern_fn(void* mem, uint64_t* out_result)
{
    using fn_t = uint64_t (*)();
    fn_t fn = reinterpret_cast<fn_t>(mem);
    __try {
        *out_result = fn();
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static int seh_call_void_fn(void* mem)
{
    using fn_t = void (*)();
    fn_t fn = reinterpret_cast<fn_t>(mem);
    __try {
        fn();
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

bool emit_isolated_pattern_bytes(uint32_t pattern_id,
                                 uint64_t seed,
                                 std::vector<uint8_t>& out_bytes)
{
    using namespace asmjit;
    CodeHolder code;
    Environment env;
    env.set_arch(Arch::kX64);
    if (code.init(env) != kErrorOk) {
        std::fprintf(stderr, "[FAIL] CodeHolder init failed for pattern %u\n", pattern_id);
        return false;
    }
    x86::Assembler a(&code);

    a.push(x86::rbx);
    a.push(x86::rsi);
    a.push(x86::rdi);
    a.push(x86::rbp);
    a.sub(x86::rsp, 0x28);

    a.mov(x86::rax, static_cast<int64_t>(0xDEADBEEFCAFEBABEULL));

    stub_poly::poly_rng_t rng(seed);
    if (pattern_id == 0u) {
        stub_poly::emit_overlap_pattern_a(a, rng);
    } else if (pattern_id == 1u) {
        stub_poly::emit_overlap_pattern_b(a, rng);
    } else {
        stub_poly::emit_overlap_pattern_c(a, rng);
    }

    a.mov(x86::rcx, x86::rax);

    a.add(x86::rsp, 0x28);
    a.pop(x86::rbp);
    a.pop(x86::rdi);
    a.pop(x86::rsi);
    a.pop(x86::rbx);
    a.ret();

    if (code.flatten() != kErrorOk) return false;
    if (code.resolve_cross_section_fixups() != kErrorOk) return false;

    size_t sz = code.code_size();
    out_bytes.resize(sz, 0);
    if (code.copy_flattened_data(out_bytes.data(), sz, CopySectionFlags::kNone) != kErrorOk) {
        return false;
    }
    return true;
}

bool test_isolated_overlap_pattern(uint32_t pattern_id, uint64_t seed)
{
    std::vector<uint8_t> stub_bytes;
    if (!emit_isolated_pattern_bytes(pattern_id, seed, stub_bytes)) {
        return false;
    }
    if (stub_bytes.empty()) {
        std::fprintf(stderr, "[FAIL] Pattern %u emitted zero bytes\n", pattern_id);
        return false;
    }
    void* mem = VirtualAlloc(nullptr, stub_bytes.size(),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        std::fprintf(stderr, "[FAIL] VirtualAlloc failed for pattern %u (gle=%lu)\n",
                     pattern_id, GetLastError());
        return false;
    }
    std::memcpy(mem, stub_bytes.data(), stub_bytes.size());
    FlushInstructionCache(GetCurrentProcess(), mem, stub_bytes.size());

    uint64_t result = 0;
    int seh_ok = seh_call_pattern_fn(mem, &result);

    SecureZeroMemory(mem, stub_bytes.size());
    VirtualFree(mem, 0, MEM_RELEASE);

    if (seh_ok == 0) {
        std::fprintf(stderr, "[FAIL] Pattern %u SEH exception during execute\n", pattern_id);
        return false;
    }
    if (result != 0xDEADBEEFCAFEBABEULL) {
        std::fprintf(stderr, "[FAIL] Pattern %u clobbered RAX (got %016llX, expected DEADBEEFCAFEBABE)\n",
                     pattern_id, static_cast<unsigned long long>(result));
        return false;
    }
    std::printf("[OK] Pattern %u executed flow-neutrally (RAX preserved)\n", pattern_id);
    return true;
}

int main()
{
    std::printf("[OVERLAP_TEST] Begin Phase 4 verification\n");

    if (!test_isolated_overlap_pattern(0u, 0xA5A5A5A5DEADBEEFULL)) return 100;
    if (!test_isolated_overlap_pattern(1u, 0x5A5A5A5ABEEFDEADULL)) return 101;
    if (!test_isolated_overlap_pattern(2u, 0x1234567890ABCDEFULL)) return 102;
    for (uint64_t s = 1u; s <= 6u; ++s) {
        if (!test_isolated_overlap_pattern(static_cast<uint32_t>(s % 3u),
                                            s * 0x9E3779B97F4A7C15ULL)) {
            return 110 + static_cast<int>(s);
        }
    }


    stub::stub_config_t cfg{};
    cfg.packed_section_rva = 0x10000u;
    cfg.original_entry_rva = 0x1000u;
    cfg.section_count = 4u;
    cfg.import_count = 8u;
    cfg.string_fixup_count = 0u;
    cfg.resource_fixup_count = 0u;
    cfg.is_dll = false;
    cfg.has_existing_tls = true;
    cfg.exception_dir_rva = 0u;
    cfg.exception_dir_size = 0u;
    cfg.reloc_dir_rva = 0u;
    cfg.reloc_dir_size = 0u;
    cfg.preferred_image_base = 0x140000000ULL;
    std::memset(cfg.obfuscated_master_key, 0xA5, 32);
    std::memset(cfg.key_obfuscation_mask, 0x5A, 32);
    cfg.original_timestamp = 0xDEADBEEFu;
    cfg.original_size_of_code = 0x4000u;
    cfg.section_table_offset = 0u;
    cfg.import_table_offset = 0u;
    cfg.string_table_offset = 0u;
    cfg.resource_table_offset = 0u;
    cfg.master_key_offset = 0u;
    cfg.seed = 0x1234567890ABCDEFULL;
    cfg.polymorphic = true;

    stub::generated_stub_t out = stub_poly::generate(cfg);
    if (out.main_stub.empty()) {
        std::fprintf(stderr, "[FAIL] Generated stub is empty\n");
        return 1;
    }

    std::printf("[OVERLAP_TEST] Stub generated: %zu bytes, build_nonce=%016llX, sig_tag=%08X\n",
                out.main_stub.size(),
                static_cast<unsigned long long>(out.build_nonce),
                out.stub_signature_tag);

    std::vector<linear_decode_t> linear_decodes;
    std::unordered_set<uint32_t> linear_offsets;
    if (!linear_disassemble(out.main_stub.data(), out.main_stub.size(), linear_decodes, linear_offsets)) {
        std::fprintf(stderr, "[FAIL] Linear disassembly failed\n");
        return 2;
    }

    std::unordered_set<uint32_t> recursive_offsets;
    if (!recursive_disassemble(out.main_stub.data(), out.main_stub.size(),
                                out.main_stub_entry_offset, recursive_offsets)) {
        std::fprintf(stderr, "[FAIL] Recursive disassembly failed\n");
        return 3;
    }

    uint32_t overlap_islands = 0u;
    for (const auto& d : linear_decodes) {
        if (recursive_offsets.count(d.offset) == 0u) {
            ++overlap_islands;
        }
    }

    std::printf("[OVERLAP_TEST] linear_count=%zu recursive_count=%zu overlap_islands=%u\n",
                linear_decodes.size(),
                recursive_offsets.size(),
                overlap_islands);

    if (overlap_islands < 3u) {
        std::fprintf(stderr, "[FAIL] overlap_islands < 3 (got %u). Linear/recursive sets too similar.\n",
                     overlap_islands);
        return 4;
    }

    void* exec_mem = VirtualAlloc(nullptr,
                                   out.main_stub.size() + 16u,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        std::fprintf(stderr, "[FAIL] VirtualAlloc failed (gle=%lu)\n", GetLastError());
        return 5;
    }

    std::memcpy(exec_mem, out.main_stub.data(), out.main_stub.size());
    uint8_t* exec_bytes = reinterpret_cast<uint8_t*>(exec_mem);
    exec_bytes[out.main_stub_entry_offset] = 0xC3u;

    FlushInstructionCache(GetCurrentProcess(),
                           exec_mem,
                           out.main_stub.size() + 16u);

    int execute_ok = seh_call_void_fn(exec_bytes + out.main_stub_entry_offset);

    SecureZeroMemory(exec_mem, out.main_stub.size() + 16u);
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    if (execute_ok == 0) {
        std::fprintf(stderr, "[FAIL] Direct execution of patched entry stub raised SEH exception\n");
        return 7;
    }

    std::printf("OVERLAP_TEST_PASSED linear_count=%zu recursive_count=%zu overlap_islands=%u\n",
                linear_decodes.size(),
                recursive_offsets.size(),
                overlap_islands);
    return 0;
}
