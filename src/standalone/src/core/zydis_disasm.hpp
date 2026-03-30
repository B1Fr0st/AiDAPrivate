
#pragma once
#include <windows.h>
#include <commdlg.h>

#include <Zydis/Zydis.h>

#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <mutex>


struct AsmInstr
{
    uint64_t addr       = 0;
    uint8_t  raw[16]    = {};
    int      len        = 1;
    char     mnem[32]   = {};
    char     ops[128]   = {};
    bool     is_branch  = false;
    bool     is_call    = false;
    bool     is_ret     = false;
    bool     is_nop     = false;
    bool     is_priv    = false;
};


struct PESection
{
    uint64_t             va = 0;
    std::vector<uint8_t> bytes;
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
    std::string            err;
};


struct DisasmState
{
    DisasmFile file;
    int  ctx_row   = -1;
    bool show_ctx  = false;
};


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

        auto* dos = (IMAGE_DOS_HEADER*)raw.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { out.err = "Not a PE file"; return false; }
        if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fsz) {
            out.err = "Corrupt PE"; return false;
        }

        auto* nt = (IMAGE_NT_HEADERS64*)(raw.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { out.err = "Not a PE file"; return false; }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            out.err = "Not x64 PE"; return false;
        }

        out.image_base  = nt->OptionalHeader.ImageBase;
        out.entry_point = out.image_base + nt->OptionalHeader.AddressOfEntryPoint;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        WORD nsec = nt->FileHeader.NumberOfSections;

        for (WORD i = 0; i < nsec; i++) {
            bool is_exec = (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                           (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
            if (!is_exec) continue;
            DWORD off = sec[i].PointerToRawData;
            DWORD sz  = sec[i].SizeOfRawData;
            if (sec[i].Misc.VirtualSize && sec[i].Misc.VirtualSize < sz)
                sz = sec[i].Misc.VirtualSize;
            if (sz == 0 || (uint64_t)off + sz > fsz) continue;
            PESection ps;
            ps.va = out.image_base + sec[i].VirtualAddress;
            ps.bytes.assign(raw.data() + off, raw.data() + off + sz);
            out.sections.push_back(std::move(ps));
        }
        if (out.sections.empty()) { out.err = "No executable section found"; return false; }
        out.text_va = out.sections[0].va;
        out.loaded  = true;
        return true;
    }


    static constexpr int MAX_INSTRS = 250000;


    inline void decode_section(DisasmFile& file)
    {
        file.instrs.clear();
        if (file.sections.empty()) return;
        const int reserve_count = static_cast<int>(file.sections[0].bytes.size() / 3);
        file.instrs.reserve(static_cast<size_t>((reserve_count < MAX_INSTRS) ? reserve_count : MAX_INSTRS));

        for (auto& section : file.sections) {
            const uint8_t* data = section.bytes.data();
            int             sz   = (int)section.bytes.size();
            int             off  = 0;
            uint64_t        va   = section.va;

            while (off < sz) {
                if ((int)file.instrs.size() >= MAX_INSTRS) {
                    AsmInstr cap{};
                    cap.addr = va + off;
                    snprintf(cap.mnem, sizeof(cap.mnem), "...");
                    snprintf(cap.ops,  sizeof(cap.ops),
                             "output capped at %d instructions", MAX_INSTRS);
                    file.instrs.push_back(cap);
                    return;
                }

                const int remaining = sz - off;
                const int avail = (remaining < 15) ? remaining : 15;
                AsmInstr ins = zydis_decode_one(data + off, avail, va + off);
                const int raw_len = (ins.len < 15) ? ins.len : 15;
                memcpy(ins.raw, data + off, static_cast<size_t>(raw_len));
                file.instrs.push_back(ins);
                off += ins.len;
            }
        }
    }
}
