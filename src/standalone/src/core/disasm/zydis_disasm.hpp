
#pragma once
#include <windows.h>
#include "work_queue.hpp"
#include <commdlg.h>

#include <Zydis/Zydis.h>

#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <thread>
#include <algorithm>
#include <mutex>

#include "standalone_driver.hpp"
#include "../analysis/pe_parser.hpp"
#include "../../helpers/diag_log.hpp"


struct mem_op_snapshot_t
{
    uint16_t base_reg     = 0;
    uint16_t index_reg    = 0;
    uint8_t  scale        = 0;
    int64_t  disp         = 0;
    uint16_t size         = 0;
    uint8_t  segment      = 0;
    bool     has_disp     = false;
};

struct AsmInstr
{
    uint64_t addr           = 0;
    uint8_t  raw[16]        = {};
    int      len            = 1;
    char     mnem[32]       = {};
    char     ops[128]       = {};
    bool     is_branch      = false;
    bool     is_call        = false;
    bool     is_ret         = false;
    bool     is_nop         = false;
    bool     is_priv        = false;
    uint64_t branch_target  = 0;
    int64_t  imm_signed     = 0;
    uint64_t imm_unsigned   = 0;
    bool     has_imm        = false;
    uint8_t  imm_op_index   = 0xFF;
    bool     has_mem_op     = false;
    mem_op_snapshot_t mem_op{};
};


struct PESection
{
    uint64_t             va = 0;
    std::vector<uint8_t> bytes;
    bool                 is_executable = true;
};


struct DisasmFile
{
    std::string            path;
    std::string            filename;
    uint64_t               image_base = 0;
    uint64_t               entry_point = 0;
    uint64_t               text_va    = 0;
    std::vector<PESection> sections;
    std::vector<AsmInstr>  instrs;
    bool                   loaded = false;
    bool                   decoding = false;
    std::string            err;
};


struct DisasmState
{
    DisasmFile file;
    int  ctx_row   = -1;
    bool show_ctx  = false;


    bool     live_mode       = false;
    uint32_t live_pid        = 0;
    uint64_t live_base       = 0;
    uint64_t live_size       = 0;
    uint64_t live_floor_va   = 0;
    uint64_t live_view_addr  = 0;
    uint64_t live_window     = 0x4000;
    std::string live_module;
    float    live_refresh_timer = 0.f;
    float    live_refresh_interval = 2.0f;
    bool     live_paused     = false;
    bool     live_needs_refresh = false;
    std::atomic<bool> live_decoding{false};
    std::atomic<bool> live_decode_failed{false};
    std::atomic<int>  live_fail_count{0};
    std::vector<AsmInstr> live_pending_instrs;
    uint64_t live_pending_va = 0;
    std::atomic<bool> live_pending_ready{false};
	uint64_t goto_address = 0;
	bool has_new_goto = false;
	bool last_swap_was_live = false;
};

namespace static_analysis
{
    inline bool read_bytes_from_pe(const DisasmFile& file, uint64_t va, size_t len, std::vector<uint8_t>& out)
    {
        out.clear();
        if (!file.loaded || file.sections.empty() || len == 0) return false;

        out.resize(len, 0);
        size_t filled = 0;

        for (auto& sec : file.sections) {
            uint64_t sec_start = sec.va;
            uint64_t sec_end   = sec_start + sec.bytes.size();
            if (va + len <= sec_start || va >= sec_end) continue;

            uint64_t overlap_start = (va > sec_start) ? va : sec_start;
            uint64_t overlap_end   = (va + len < sec_end) ? va + len : sec_end;
            size_t src_off = static_cast<size_t>(overlap_start - sec_start);
            size_t dst_off = static_cast<size_t>(overlap_start - va);
            size_t copy_sz = static_cast<size_t>(overlap_end - overlap_start);
            std::memcpy(out.data() + dst_off, sec.bytes.data() + src_off, copy_sz);
            filled += copy_sz;
        }
        if (filled == 0) {
            out.clear();
            return false;
        }
        if (filled < len) out.resize(filled);
        return true;
    }

    inline uint64_t total_image_size(const DisasmFile& file)
    {
        uint64_t max_end = 0;
        for (auto& sec : file.sections) {
            uint64_t end = sec.va + sec.bytes.size();
            if (end > max_end) max_end = end;
        }
        if (max_end <= file.image_base) return 0;
        return max_end - file.image_base;
    }
}

namespace zydis_detail
{
    inline ZydisDecoder&   decoder()   { static ZydisDecoder   d; return d; }
    inline ZydisFormatter& formatter() { static ZydisFormatter f; return f; }
    inline bool&           ready()     { static bool r = false; return r; }
    inline std::once_flag& flag()      { static std::once_flag f; return f; }

    inline void ensure_init()
    {
        std::call_once(flag(), []() {
            ZydisDecoderInit(&decoder(), ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            ZydisFormatterInit(&formatter(), ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterSetProperty(&formatter(), ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_FALSE);
            ZydisFormatterSetProperty(&formatter(), ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_FALSE);
            ready() = true;
        });
    }
}


inline AsmInstr zydis_decode_one(const uint8_t* code, int avail, uint64_t va)
{
    zydis_detail::ensure_init();

    AsmInstr ins;
    ins.addr = va;

    if (!code || avail <= 0) {
        snprintf(ins.mnem, sizeof(ins.mnem), "db");
        snprintf(ins.ops, sizeof(ins.ops), "??");
        return ins;
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &zydis_detail::decoder(), code, avail, &instruction, operands)))
    {
        ins.len = 1;
        snprintf(ins.mnem, sizeof(ins.mnem), "db");
        snprintf(ins.ops, sizeof(ins.ops), "0x%02X", code[0]);
        ins.raw[0] = code[0];
        return ins;
    }

    ins.len = static_cast<int>(instruction.length);
    const int copy_len = (ins.len < 16) ? ins.len : 16;
    memcpy(ins.raw, code, static_cast<size_t>(copy_len));


    char full[256] = {};
    ZydisFormatterFormatInstruction(
        &zydis_detail::formatter(), &instruction, operands,
        instruction.operand_count_visible,
        full, sizeof(full), va, ZYAN_NULL);

    const char* mnemonic_str = ZydisMnemonicGetString(instruction.mnemonic);
    if (mnemonic_str)
        snprintf(ins.mnem, sizeof(ins.mnem), "%s", mnemonic_str);


    const char* space = strchr(full, ' ');
    if (space)
        snprintf(ins.ops, sizeof(ins.ops), "%s", space + 1);


    switch (instruction.meta.category) {
    case ZYDIS_CATEGORY_CALL:      ins.is_call   = true; break;
    case ZYDIS_CATEGORY_RET:       ins.is_ret    = true; break;
    case ZYDIS_CATEGORY_COND_BR:
    case ZYDIS_CATEGORY_UNCOND_BR: ins.is_branch = true; break;
    case ZYDIS_CATEGORY_NOP:       ins.is_nop    = true; break;
    default: break;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_SYSTEM ||
        instruction.meta.category == ZYDIS_CATEGORY_INTERRUPT)
        ins.is_priv = true;

    if (ins.is_branch || ins.is_call) {
        for (uint8_t oi = 0; oi < instruction.operand_count_visible; ++oi) {
            const auto& op = operands[oi];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                uint64_t abs_addr = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, va, &abs_addr))) {
                    ins.branch_target = abs_addr;
                    break;
                }
            }
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !op.imm.is_relative) {
                ins.branch_target = static_cast<uint64_t>(op.imm.value.u);
                break;
            }
        }
    }

    for (uint8_t oi = 0; oi < instruction.operand_count_visible; ++oi) {
        const auto& op = operands[oi];
        if (!ins.has_imm && op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !op.imm.is_relative) {
            ins.has_imm = true;
            ins.imm_op_index = oi;
            ins.imm_unsigned = static_cast<uint64_t>(op.imm.value.u);
            ins.imm_signed = static_cast<int64_t>(op.imm.value.s);
        }
        if (!ins.has_mem_op && op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            ins.has_mem_op = true;
            ins.mem_op.base_reg = static_cast<uint16_t>(op.mem.base);
            ins.mem_op.index_reg = static_cast<uint16_t>(op.mem.index);
            ins.mem_op.scale = static_cast<uint8_t>(op.mem.scale);
            ins.mem_op.disp = static_cast<int64_t>(op.mem.disp.value);
            ins.mem_op.size = static_cast<uint16_t>(op.size);
            ins.mem_op.segment = static_cast<uint8_t>(op.mem.segment);
            ins.mem_op.has_disp = (op.mem.disp.size != 0);
        }
        if (ins.has_imm && ins.has_mem_op)
            break;
    }

    return ins;
}


namespace disasm
{
    inline std::string open_file_dialog(HWND owner)
    {
        char buf[MAX_PATH] = {};
        OPENFILENAMEA ofn   = {};
        ofn.lStructSize     = sizeof(ofn);
        ofn.hwndOwner       = owner;
        ofn.lpstrFile       = buf;
        ofn.nMaxFile        = MAX_PATH;
        ofn.lpstrFilter     = "PE Files\0*.exe;*.dll;*.sys\0All Files\0*.*\0\0";
        ofn.nFilterIndex    = 1;
        ofn.Flags           = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
        if (GetOpenFileNameA(&ofn))
            return std::string(buf);
        return {};
    }

    inline bool load_pe(const std::string& path, DisasmFile& out)
    {
        out = {};
        out.path = path;
        size_t sl = path.find_last_of("/\\");
        out.filename = (sl != std::string::npos) ? path.substr(sl + 1) : path;

        HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) { out.err = "Cannot open file"; return false; }

        DWORD fsz = GetFileSize(hf, nullptr);
        if (fsz == INVALID_FILE_SIZE || fsz < sizeof(IMAGE_DOS_HEADER)) {
            CloseHandle(hf); out.err = "File too small"; return false;
        }

        std::vector<uint8_t> raw(fsz);
        DWORD read = 0;
        if (!ReadFile(hf, raw.data(), fsz, &read, nullptr) || read != fsz) {
            CloseHandle(hf); out.err = "Read error"; return false;
        }
        CloseHandle(hf);

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { out.err = "Not a PE file"; return false; }
        if (static_cast<DWORD>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > fsz) {
            out.err = "Corrupt PE"; return false;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { out.err = "Not a PE file"; return false; }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            out.err = "Not x64 PE"; return false;
        }

        out.image_base  = nt->OptionalHeader.ImageBase;
        out.entry_point = out.image_base + nt->OptionalHeader.AddressOfEntryPoint;

        const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(nt)
            + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
            + nt->FileHeader.SizeOfOptionalHeader);
        WORD nsec = nt->FileHeader.NumberOfSections;

        bool any_exec_loaded = false;
        for (WORD i = 0; i < nsec; i++) {
            bool is_exec = (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                           (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
            if (!is_exec) continue;
            DWORD off = sec[i].PointerToRawData;
            DWORD sz  = sec[i].SizeOfRawData;
            if (sec[i].Misc.VirtualSize && sec[i].Misc.VirtualSize < sz)
                sz = sec[i].Misc.VirtualSize;
            if (sz == 0 || static_cast<uint64_t>(off) + sz > fsz) continue;
            PESection ps;
            ps.va = out.image_base + sec[i].VirtualAddress;
            ps.bytes.assign(raw.data() + off, raw.data() + off + sz);
            ps.is_executable = true;
            if (!any_exec_loaded) {
                out.text_va = ps.va;
                any_exec_loaded = true;
            }
            out.sections.push_back(std::move(ps));
        }
        if (!any_exec_loaded) { out.err = "No executable section found"; return false; }

        for (WORD i = 0; i < nsec; i++) {
            bool is_exec = (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                           (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
            if (is_exec) continue;
            bool is_readable = (sec[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
            bool has_raw     = (sec[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == 0;
            if (!is_readable || !has_raw) continue;
            DWORD off = sec[i].PointerToRawData;
            DWORD sz  = sec[i].SizeOfRawData;
            if (sec[i].Misc.VirtualSize && sec[i].Misc.VirtualSize < sz)
                sz = sec[i].Misc.VirtualSize;
            if (sz == 0 || static_cast<uint64_t>(off) + sz > fsz) continue;
            PESection ps;
            ps.va = out.image_base + sec[i].VirtualAddress;
            ps.bytes.assign(raw.data() + off, raw.data() + off + sz);
            ps.is_executable = false;
            out.sections.push_back(std::move(ps));
        }

        out.loaded  = true;
        return true;
    }


    inline void decode_section(DisasmFile& file)
    {
        file.instrs.clear();
        if (file.sections.empty()) return;

        size_t total_bytes = 0;
        for (auto& s : file.sections) {
            if (!s.is_executable) continue;
            total_bytes += s.bytes.size();
        }
        file.instrs.reserve(total_bytes / 4);

        constexpr size_t kYieldEveryN = 16384;
        size_t since_yield = 0;

        for (auto& section : file.sections) {
            if (!section.is_executable) continue;
            const uint8_t* data = section.bytes.data();
            int             sz   = static_cast<int>(section.bytes.size());
            int             off  = 0;
            uint64_t        va   = section.va;

            while (off < sz) {
                const int remaining = sz - off;
                const int avail = (remaining < 15) ? remaining : 15;
                AsmInstr ins = zydis_decode_one(data + off, avail, va + off);
                const int raw_len = (ins.len < 15) ? ins.len : 15;
                memcpy(ins.raw, data + off, static_cast<size_t>(raw_len));
                file.instrs.push_back(ins);
                off += ins.len;
                if (++since_yield >= kYieldEveryN) {
                    since_yield = 0;
                    std::this_thread::yield();
                }
            }
        }


        if (file.instrs.size() > 4) {
            int last_real = static_cast<int>(file.instrs.size()) - 1;
            while (last_real > 0 && (file.instrs[last_real].is_nop ||
                   (file.instrs[last_real].is_priv &&
                    file.instrs[last_real].raw[0] == 0xCC &&
                    file.instrs[last_real].len == 1))) {
                --last_real;
            }
            const int keep = last_real + 1 + 3;
            if (keep < static_cast<int>(file.instrs.size()))
                file.instrs.resize(keep);
        }

        file.instrs.shrink_to_fit();
    }


    inline void decode_section_async(DisasmFile& file)
    {
        if (file.decoding) return;
        file.decoding = true;
        work_queue::post([&file]() {
            decode_section(file);
            file.decoding = false;
        });
    }


    inline void request_live_decode(DisasmState& state)
    {
        diag::log_tagged_critical_fmt("disasm", "request_live_decode_enter pid=%u base=0x%llX size=0x%llX view=0x%llX",
            state.live_pid,
            static_cast<unsigned long long>(state.live_base),
            static_cast<unsigned long long>(state.live_size),
            static_cast<unsigned long long>(state.live_view_addr));
        bool expected = false;
        if (!state.live_decoding.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            diag::log_tagged_critical("disasm", "request_live_decode_SKIPPED_already_decoding");
            static int s_skip_log = 0;
            if (s_skip_log++ < 5)
                driver_bridge::debug_log("request_live_decode: SKIPPED (already decoding)\n");
            return;
        }
        if (!state.live_mode || state.live_base == 0 || state.live_size == 0) {
            diag::log_tagged_critical_fmt("disasm", "request_live_decode_SKIPPED_invalid_state mode=%d base=0x%llX size=0x%llX",
                state.live_mode ? 1 : 0,
                static_cast<unsigned long long>(state.live_base),
                static_cast<unsigned long long>(state.live_size));
            driver_bridge::debug_log("request_live_decode: SKIPPED (mode=%d base=0x%llX size=0x%llX)\n",
                state.live_mode ? 1 : 0,
                static_cast<unsigned long long>(state.live_base),
                static_cast<unsigned long long>(state.live_size));
            state.live_decoding.store(false, std::memory_order_release);
            return;
        }

        uint64_t half = state.live_window / 2;
        uint64_t win_start = state.live_view_addr;
        uint64_t effective_floor = state.live_base;
        if (state.live_floor_va != 0 &&
            state.live_floor_va >= state.live_base &&
            state.live_floor_va < state.live_base + state.live_size &&
            state.live_view_addr >= state.live_floor_va)
            effective_floor = state.live_floor_va;
        if (win_start > half && (win_start - half) >= effective_floor)
            win_start -= half;
        else
            win_start = effective_floor;

        uint64_t mod_end = state.live_base + state.live_size;
        uint64_t win_end = win_start + state.live_window;
        if (win_end > mod_end) win_end = mod_end;
        uint64_t read_sz = win_end - win_start;
        if (read_sz == 0) {
            driver_bridge::debug_log("request_live_decode: read_sz == 0, aborting\n");
            state.live_decoding.store(false, std::memory_order_release);
            return;
        }

        driver_bridge::debug_log("request_live_decode: win_start=0x%llX read_sz=%llu pid=%u\n",
            static_cast<unsigned long long>(win_start),
            static_cast<unsigned long long>(read_sz),
            state.live_pid);
        diag::log_tagged_critical_fmt("disasm",
            "request_live_decode_posting_to_work_queue win_start=0x%llX read_sz=%llu pid=%u",
            static_cast<unsigned long long>(win_start),
            static_cast<unsigned long long>(read_sz),
            state.live_pid);

        uint32_t pid = state.live_pid;
        DisasmState* state_ptr = &state;

        work_queue::post([state_ptr, pid, win_start, read_sz]() {
            diag::log_tagged_critical_fmt("disasm",
                "live_decode_worker_enter pid=%u win_start=0x%llX read_sz=%llu tid=%lu",
                pid,
                static_cast<unsigned long long>(win_start),
                static_cast<unsigned long long>(read_sz),
                GetCurrentThreadId());
            std::vector<uint8_t> mem;
            if (driver_bridge::is_loaded() &&
                driver_bridge::attached_pid() == pid) {
                diag::log_tagged_critical("disasm", "live_decode_worker_pre_read_memory");
                driver_bridge::read_memory(win_start, static_cast<size_t>(read_sz), mem);
                diag::log_tagged_critical_fmt("disasm",
                    "live_decode_worker_post_read_memory bytes=%llu",
                    (unsigned long long)mem.size());
            }

            std::vector<AsmInstr> instrs;
            if (!mem.empty()) {
                instrs.reserve(mem.size() / 4);
                const uint8_t* data = mem.data();
                int sz = static_cast<int>(mem.size());
                int off = 0;
                size_t since_yield = 0;
                while (off < sz) {
                    int remaining = sz - off;
                    int avail = (remaining < 15) ? remaining : 15;
                    AsmInstr ins = zydis_decode_one(data + off, avail, win_start + off);
                    int raw_len = (ins.len < 15) ? ins.len : 15;
                    memcpy(ins.raw, data + off, static_cast<size_t>(raw_len));
                    instrs.push_back(ins);
                    off += ins.len;
                    if (++since_yield >= 16384) {
                        since_yield = 0;
                        std::this_thread::yield();
                    }
                }
            }

            if (instrs.empty()) {
                state_ptr->live_decode_failed.store(true, std::memory_order_release);
                state_ptr->live_fail_count.fetch_add(1, std::memory_order_acq_rel);
            } else {
                state_ptr->live_decode_failed.store(false, std::memory_order_release);
                state_ptr->live_fail_count.store(0, std::memory_order_release);
            }

            state_ptr->live_pending_instrs = std::move(instrs);
            state_ptr->live_pending_va = win_start;
            state_ptr->live_pending_ready.store(true, std::memory_order_release);
            state_ptr->live_decoding.store(false, std::memory_order_release);
            diag::log_tagged_critical_fmt("disasm",
                "live_decode_worker_exit pid=%u win_start=0x%llX",
                pid,
                static_cast<unsigned long long>(win_start));
        });
    }


    inline bool start_live(DisasmState& state, uint32_t pid,
                           uint64_t base, uint64_t size,
                           const std::string& module_name)
    {
        diag::log_tagged_critical_fmt("disasm", "start_live_enter pid=%u base=0x%llX size=0x%llX module=%s tid=%lu",
            pid,
            static_cast<unsigned long long>(base),
            static_cast<unsigned long long>(size),
            module_name.c_str(),
            GetCurrentThreadId());
        driver_bridge::debug_log("start_live: pid=%u base=0x%llX size=0x%llX module=%s\n",
            pid,
            static_cast<unsigned long long>(base),
            static_cast<unsigned long long>(size),
            module_name.c_str());

        state.live_mode   = true;
        state.live_pid    = pid;
        state.live_base   = base;
        state.live_size   = size;
        state.live_floor_va = 0;
        state.live_view_addr = base;

        std::vector<PESection> snapshot_sections;
        {
            diag::log_tagged_critical("disasm", "start_live_pre_pe_parse_sections_only");
            pe_parser::pe_info_t pe;
            if (pe_parser::parse(base, pe, false)) {
                diag::log_tagged_critical_fmt("disasm",
                    "start_live_post_pe_parse sections=%llu",
                    (unsigned long long)pe.sections.size());
                constexpr uint32_t kCntCode = 0x00000020u;
                constexpr uint32_t kMemExec = 0x20000000u;
                constexpr uint32_t kMemRead = 0x40000000u;
                constexpr uint32_t kCntUData = 0x00000080u;
                constexpr size_t kMaxSnapshotBytes = 64ull * 1024ull * 1024ull;
                uint64_t first_exec_va = 0;
                size_t snapshot_total = 0;
                for (const auto& s : pe.sections) {
                    bool is_exec = (s.characteristics & kCntCode) || (s.characteristics & kMemExec);
                    if (!is_exec) continue;
                    if (first_exec_va == 0)
                        first_exec_va = base + static_cast<uint64_t>(s.virtual_address);
                    uint32_t sec_size = (s.virtual_size > 0) ? s.virtual_size : s.raw_size;
                    if (sec_size == 0) continue;
                    if (snapshot_total >= kMaxSnapshotBytes) continue;
                    size_t remaining_budget = kMaxSnapshotBytes - snapshot_total;
                    size_t read_size = (sec_size <= remaining_budget) ? sec_size : remaining_budget;
                    uint64_t sec_va = base + static_cast<uint64_t>(s.virtual_address);
                    std::vector<uint8_t> sec_bytes;
                    if (driver_bridge::read_memory(sec_va, read_size, sec_bytes) && !sec_bytes.empty()) {
                        PESection ps;
                        ps.va = sec_va;
                        ps.bytes = std::move(sec_bytes);
                        ps.is_executable = true;
                        snapshot_total += ps.bytes.size();
                        snapshot_sections.push_back(std::move(ps));
                    }
                }
                for (const auto& s : pe.sections) {
                    bool is_exec = (s.characteristics & kCntCode) || (s.characteristics & kMemExec);
                    if (is_exec) continue;
                    bool is_readable = (s.characteristics & kMemRead) != 0;
                    bool has_raw     = (s.characteristics & kCntUData) == 0;
                    if (!is_readable || !has_raw) continue;
                    uint32_t sec_size = (s.virtual_size > 0) ? s.virtual_size : s.raw_size;
                    if (sec_size == 0) continue;
                    if (snapshot_total >= kMaxSnapshotBytes) continue;
                    size_t remaining_budget = kMaxSnapshotBytes - snapshot_total;
                    size_t read_size = (sec_size <= remaining_budget) ? sec_size : remaining_budget;
                    uint64_t sec_va = base + static_cast<uint64_t>(s.virtual_address);
                    std::vector<uint8_t> sec_bytes;
                    if (driver_bridge::read_memory(sec_va, read_size, sec_bytes) && !sec_bytes.empty()) {
                        PESection ps;
                        ps.va = sec_va;
                        ps.bytes = std::move(sec_bytes);
                        ps.is_executable = false;
                        snapshot_total += ps.bytes.size();
                        snapshot_sections.push_back(std::move(ps));
                    }
                }
                if (first_exec_va != 0 && first_exec_va >= base && first_exec_va < base + size) {
                    state.live_view_addr = first_exec_va;
                    state.live_floor_va  = first_exec_va;
                }
                diag::log_tagged_critical_fmt("disasm",
                    "start_live_snapshot sections=%llu bytes=%llu",
                    (unsigned long long)snapshot_sections.size(),
                    (unsigned long long)snapshot_total);
            } else {
                diag::log_tagged_critical("disasm", "start_live_pe_parse_FAILED");
            }
        }
        state.live_module = module_name;
        state.live_paused = false;
        state.live_decoding.store(false, std::memory_order_release);
        state.live_decode_failed.store(false, std::memory_order_release);
        state.live_fail_count.store(0, std::memory_order_release);
        state.live_pending_ready.store(false);
        state.live_refresh_timer = 0.f;
        state.live_needs_refresh = true;

        state.file = DisasmFile{};
        state.file.filename = module_name + " [LIVE]";
        state.file.path     = "live://" + std::to_string(pid) + "/" + module_name;
        state.file.image_base = base;
        state.file.text_va    = state.live_view_addr;
        state.file.sections   = std::move(snapshot_sections);
        state.file.loaded     = true;

        diag::log_tagged_critical("disasm", "start_live_pre_request_live_decode");
        request_live_decode(state);
        diag::log_tagged_critical("disasm", "start_live_exit");
        return true;
    }


    inline void stop_live(DisasmState& state)
    {
        state.live_mode   = false;
        state.live_pid    = 0;
        state.live_base   = 0;
        state.live_size   = 0;
        state.live_floor_va = 0;
        state.live_view_addr = 0;
        state.live_module.clear();
        state.live_paused = false;
        state.live_decoding.store(false, std::memory_order_release);
        state.live_decode_failed.store(false, std::memory_order_release);
        state.live_fail_count.store(0, std::memory_order_release);
        state.live_pending_ready.store(false);
        state.live_pending_instrs.clear();
    }
}
