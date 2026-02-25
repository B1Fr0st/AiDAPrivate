#pragma once

#include <cstdint>
#include <cstring>

namespace anti_re {

static constexpr uint16_t kDosSignature       = 0x5A4D;
static constexpr uint32_t kPePtrOffset        = 0x3C;

static constexpr uint32_t kCoffMachineOff     = 4;
static constexpr uint32_t kCoffNumSectionsOff = 6;
static constexpr uint32_t kCoffOptHdrSizeOff  = 20;

static constexpr uint16_t kPe32Magic          = 0x10B;
static constexpr uint16_t kPe32PlusMagic      = 0x20B;

static constexpr uint32_t kDirBaseReloc       = 5;
static constexpr uint32_t kDirDebug           = 6;
static constexpr uint32_t kDirLoadConfig      = 10;

static constexpr uint32_t kDebugTypeCodeView  = 2;


struct pe_layout_t
{
    ea_t image_base;
    ea_t pe_sig_ea;
    ea_t coff_ea;
    ea_t opt_ea;
    ea_t datadir_ea;
    ea_t sections_ea;
    uint16_t num_sections;
    uint16_t opt_hdr_size;
    bool is_pe64;
    uint32_t num_data_dirs;
    bool valid;

    pe_layout_t() : image_base(0), pe_sig_ea(0), coff_ea(0), opt_ea(0),
                    datadir_ea(0), sections_ea(0), num_sections(0),
                    opt_hdr_size(0), is_pe64(false), num_data_dirs(0),
                    valid(false) {}
};

inline pe_layout_t locate_pe_header()
{
    pe_layout_t layout;

    int nseg = get_segm_qty();
    for (int i = 0; i < nseg; ++i)
    {
        segment_t *seg = getnseg(i);
        if (seg == nullptr)
            continue;

        ea_t base = seg->start_ea;
        if (!is_mapped(base) || !is_loaded(base))
            continue;

        uint16_t dos_sig = get_word(base);
        if (dos_sig != kDosSignature)
            continue;

        ea_t pe_ptr_ea = base + kPePtrOffset;
        if (!is_loaded(pe_ptr_ea))
            continue;

        uint32_t pe_offset = get_dword(pe_ptr_ea);
        ea_t pe_sig_ea = base + pe_offset;
        if (!is_loaded(pe_sig_ea))
            continue;

        uint32_t pe_sig = get_dword(pe_sig_ea);
        if (pe_sig != 0x00004550)
            continue;

        layout.image_base = base;
        layout.pe_sig_ea = pe_sig_ea;
        layout.coff_ea = pe_sig_ea + 4;
        layout.num_sections = get_word(layout.coff_ea + 2);
        layout.opt_hdr_size = get_word(layout.coff_ea + 16);
        layout.opt_ea = layout.coff_ea + 20;

        uint16_t opt_magic = get_word(layout.opt_ea);
        layout.is_pe64 = (opt_magic == kPe32PlusMagic);

        if (layout.is_pe64)
        {
            layout.num_data_dirs = get_dword(layout.opt_ea + 108);
            layout.datadir_ea = layout.opt_ea + 112;
        }
        else
        {
            layout.num_data_dirs = get_dword(layout.opt_ea + 92);
            layout.datadir_ea = layout.opt_ea + 96;
        }

        layout.sections_ea = layout.opt_ea + layout.opt_hdr_size;
        layout.valid = true;
        break;
    }

    return layout;
}

inline bool get_datadir(const pe_layout_t &pe, uint32_t index,
                        uint32_t &out_rva, uint32_t &out_size)
{
    if (index >= pe.num_data_dirs)
    {
        out_rva = 0;
        out_size = 0;
        return false;
    }
    ea_t off = pe.datadir_ea + index * 8;
    out_rva = get_dword(off);
    out_size = get_dword(off + 4);
    return (out_rva != 0);
}

inline void set_datadir(const pe_layout_t &pe, uint32_t index,
                        uint32_t rva, uint32_t size)
{
    ea_t off = pe.datadir_ea + index * 8;
    put_dword(off, rva);
    put_dword(off + 4, size);
}

inline bool apply_vuln1_load_config(const pe_layout_t &pe)
{
    if (!pe.valid)
        return false;

    uint32_t lc_rva = 0, lc_size = 0;
    if (!get_datadir(pe, kDirLoadConfig, lc_rva, lc_size))
    {
        for (int i = 0; i < pe.num_sections; ++i)
        {
            ea_t sec_hdr = pe.sections_ea + i * 40;
            uint32_t sec_va = get_dword(sec_hdr + 12);
            uint32_t sec_vs = get_dword(sec_hdr + 8);
            uint32_t sec_chars = get_dword(sec_hdr + 36);

            if ((sec_chars & 0x00000040) == 0)
                continue;

            ea_t sec_start = pe.image_base + sec_va;
            ea_t sec_end = sec_start + sec_vs;

            if (is_loaded(sec_start))
            {
                put_dword(sec_start, 0xFFFFFFFF);

                set_datadir(pe, kDirLoadConfig, sec_va, 0x100);
                return true;
            }
        }
        return false;
    }

    ea_t lc_ea = pe.image_base + lc_rva;
    if (!is_loaded(lc_ea))
        return false;

    put_dword(lc_ea, 0xFFFFFFFF);

    return true;
}

inline bool apply_vuln2_reloc_desync(const pe_layout_t &pe)
{
    if (!pe.valid)
        return false;

    uint32_t reloc_rva = 0, reloc_size = 0;
    if (!get_datadir(pe, kDirBaseReloc, reloc_rva, reloc_size))
    {
        for (int i = 0; i < pe.num_sections; ++i)
        {
            ea_t sec_hdr = pe.sections_ea + i * 40;
            uint32_t sec_va = get_dword(sec_hdr + 12);
            uint32_t sec_vs = get_dword(sec_hdr + 8);

            ea_t sec_start = pe.image_base + sec_va;
            if (!is_loaded(sec_start) || sec_vs < 1024)
                continue;

            uint32_t inject_offset = sec_vs - 1024;
            ea_t inject_ea = sec_start + inject_offset;
            if (!is_loaded(inject_ea))
                continue;

            uint32_t num_blocks = 1024 / 8;
            for (uint32_t b = 0; b < num_blocks; ++b)
            {
                ea_t block_ea = inject_ea + b * 8;
                uint32_t page_rva = 0x1000 + (b % 256) * 0x1000;
                put_dword(block_ea, page_rva);
                put_dword(block_ea + 4, 4);
            }

            set_datadir(pe, kDirBaseReloc, sec_va + inject_offset, 1024);
            return true;
        }
        return false;
    }

    ea_t reloc_ea = pe.image_base + reloc_rva;
    if (!is_loaded(reloc_ea))
        return false;

    uint32_t num_blocks = reloc_size / 8;
    if (num_blocks > 10000)
        num_blocks = 10000;

    for (uint32_t b = 0; b < num_blocks; ++b)
    {
        ea_t block_ea = reloc_ea + b * 8;
        if (!is_loaded(block_ea))
            break;

        uint32_t page_rva = 0x1000 + (b % 256) * 0x1000;
        put_dword(block_ea, page_rva);
        put_dword(block_ea + 4, 4);
    }

    set_datadir(pe, kDirBaseReloc, reloc_rva, num_blocks * 8);

    return true;
}

inline bool apply_vuln3_sections_overflow(const pe_layout_t &pe)
{
    if (!pe.valid)
        return false;

    ea_t num_sections_ea = pe.coff_ea + 2;
    if (!is_loaded(num_sections_ea))
        return false;

    put_word(num_sections_ea, 0xFFFF);

    return true;
}

inline bool apply_vuln4_debug_dir(const pe_layout_t &pe)
{
    if (!pe.valid)
        return false;

    uint32_t dbg_rva = 0, dbg_size = 0;
    if (!get_datadir(pe, kDirDebug, dbg_rva, dbg_size))
    {
        for (int i = 0; i < pe.num_sections; ++i)
        {
            ea_t sec_hdr = pe.sections_ea + i * 40;
            uint32_t sec_va = get_dword(sec_hdr + 12);
            uint32_t sec_vs = get_dword(sec_hdr + 8);
            uint32_t sec_chars = get_dword(sec_hdr + 36);

            if ((sec_chars & 0x00000040) == 0)
                continue;

            ea_t sec_start = pe.image_base + sec_va;
            if (!is_loaded(sec_start) || sec_vs < 56)
                continue;

            ea_t dbg_ea = sec_start + 28;
            if (!is_loaded(dbg_ea))
                continue;

            put_dword(dbg_ea + 0, 0);
            put_dword(dbg_ea + 4, 0x5F3759DF);
            put_word(dbg_ea + 8, 0);
            put_word(dbg_ea + 10, 0);
            put_dword(dbg_ea + 12, kDebugTypeCodeView);
            put_dword(dbg_ea + 16, 0xFFFFFFFF);
            put_dword(dbg_ea + 20, 0x7FFE0000);
            put_dword(dbg_ea + 24, 0);

            set_datadir(pe, kDirDebug, sec_va + 28, 28);
            return true;
        }
        return false;
    }

    ea_t dbg_ea = pe.image_base + dbg_rva;
    if (!is_loaded(dbg_ea))
        return false;

    put_dword(dbg_ea + 12, kDebugTypeCodeView);

    put_dword(dbg_ea + 16, 0xFFFFFFFF);

    put_dword(dbg_ea + 20, 0x7FFE0000);

    put_dword(dbg_ea + 24, 0);

    return true;
}

inline uint32_t apply_all_pe_protections()
{
    pe_layout_t pe = locate_pe_header();
    if (!pe.valid)
        return 0;

    uint32_t result = 0;

    if (apply_vuln1_load_config(pe))
        result |= (1u << 0);

    if (apply_vuln2_reloc_desync(pe))
        result |= (1u << 1);

    if (apply_vuln4_debug_dir(pe))
        result |= (1u << 3);

    if (apply_vuln3_sections_overflow(pe))
        result |= (1u << 2);

    return result;
}

inline uint32_t apply_pe_protections(uint32_t vuln_mask)
{
    pe_layout_t pe = locate_pe_header();
    if (!pe.valid)
        return 0;

    uint32_t result = 0;

    if (vuln_mask & (1u << 0))
    {
        if (apply_vuln1_load_config(pe))
            result |= (1u << 0);
    }

    if (vuln_mask & (1u << 1))
    {
        if (apply_vuln2_reloc_desync(pe))
            result |= (1u << 1);
    }

    if (vuln_mask & (1u << 3))
    {
        if (apply_vuln4_debug_dir(pe))
            result |= (1u << 3);
    }

    if (vuln_mask & (1u << 2))
    {
        if (apply_vuln3_sections_overflow(pe))
            result |= (1u << 2);
    }

    return result;
}

}