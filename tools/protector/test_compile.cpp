#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "transforms.hpp"
#include "stub.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

namespace {

pe_file::pe_image_t make_synthetic() {
    pe_file::pe_image_t pe{};
    pe.optional_header.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    pe.optional_header.FileAlignment = 0x200u;
    pe.optional_header.SectionAlignment = 0x1000u;
    pe.optional_header.SizeOfHeaders = 0x400u;
    pe.optional_header.SizeOfCode = 0x200u;
    pe.optional_header.AddressOfEntryPoint = 0x1000u;
    pe.optional_header.ImageBase = 0x140000000ull;
    pe.optional_header.NumberOfRvaAndSizes = 16;
    pe.file_header.TimeDateStamp = 0x60000000u;
    pe.has_rich_header = false;
    pe.has_tls = false;
    pe.is_dll = false;

    pe_file::section_t s{};
    const char nm[8] = { '.','t','e','x','t',0,0,0 };
    std::memcpy(s.name, nm, 8);
    s.virtual_address = 0x1000u;
    s.virtual_size = 0x200u;
    s.raw_offset = 0x400u;
    s.raw_size = 0x200u;
    s.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    s.data.assign(0x200u, 0);
    for (size_t i = 0; i < s.data.size(); ++i) {
        s.data[i] = static_cast<uint8_t>((i * 7u + 1u) & 0xFFu);
    }
    pe.sections.push_back(std::move(s));

    pe_file::section_t r{};
    const char rn[8] = { '.','r','d','a','t','a',0,0 };
    std::memcpy(r.name, rn, 8);
    r.virtual_address = 0x2000u;
    r.virtual_size = 0x200u;
    r.raw_offset = 0x600u;
    r.raw_size = 0x200u;
    r.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    r.data.assign(0x200u, 0);
    const char sample[] = "HelloWorldStringSample";
    std::memcpy(r.data.data() + 0x10, sample, sizeof(sample));
    pe.sections.push_back(std::move(r));
    return pe;
}

}

int main() {
    protector::import_hash_entry_t ihe{};
    ihe.dll_hash = 0xDEADBEEFu;
    ihe.func_hash = 0xFEEDFACEu;
    ihe.iat_rva = 0x3000u;
    ihe.ordinal = 1u;
    ihe.flags = protector::kImportFlagByOrdinal;
    (void)ihe;

    protector::string_fixup_t sf{};
    sf.rva = 0x2010u;
    sf.length = 10u;
    sf.xor_key = 0x42u;
    sf.is_wide = 0u;
    sf.reserved = 0u;
    (void)sf;

    protector::resource_fixup_t rf{};
    rf.rva = 0x4000u;
    rf.size = 0x100u;
    rf.rolling_key = 0x123456789ABCDEF0ull;
    (void)rf;

    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>(i * 11u + 3u);
    }

    uint64_t ik = protector::derive_import_key(master);
    uint64_t sk = protector::derive_string_key(master);
    uint64_t rk = protector::derive_resource_key(master);
    (void)ik; (void)sk; (void)rk;

    protector::rng_state_t rng = protector::make_rng(0xCAFEBABEDEADBEEFull);
    (void)rng.next_u64();
    uint8_t bb[16];
    rng.next_bytes(bb, 16);
    (void)rng.next_u32_in_range(10u, 14u);

    pe_file::pe_image_t pe = make_synthetic();
    protector::import_hash_table_t iht = protector::destroy_imports(pe, master);
    protector::string_fixup_table_t sft = protector::encrypt_strings(pe, master);
    protector::resource_fixup_table_t rft = protector::encrypt_resources(pe, master);
    protector::mangle_header(pe, rng);
    protector::randomize_section_names(pe, rng);
    (void)iht; (void)sft; (void)rft;

    protector::protect_options_t opt{};
    opt.seed = 0x1122334455667788ull;
    opt.seed_provided = true;
    opt.pack_sections = false;
    opt.encrypt_imports = false;
    opt.encrypt_strings = false;
    opt.encrypt_resources = false;
    opt.mangle_headers = false;
    opt.randomize_section_names = false;

    pe_file::pe_image_t pe2 = make_synthetic();
    protector::transform_result_t tr = protector::protect_pe(pe2, opt);
    if (!tr.success) {
        std::fprintf(stderr, "protect_pe failed: %s\n", tr.error.c_str());
        return 1;
    }
    if (tr.original_entry_point != 0x1000u) {
        std::fprintf(stderr, "original_entry_point mismatch: 0x%X\n", tr.original_entry_point);
        return 1;
    }
    if (pe2.optional_header.AddressOfEntryPoint != 0x1000u) {
        std::fprintf(stderr, "entry point must not be redirected in phase 5\n");
        return 1;
    }

    stub::stub_config_t cfg_default{};
    cfg_default.packed_section_rva = 0x10000u;
    cfg_default.original_entry_rva = 0x1000u;
    cfg_default.section_count = 0u;
    cfg_default.import_count = 0u;
    cfg_default.string_fixup_count = 0u;
    cfg_default.resource_fixup_count = 0u;
    cfg_default.is_dll = false;
    cfg_default.has_existing_tls = false;
    cfg_default.exception_dir_rva = 0u;
    cfg_default.exception_dir_size = 0u;
    cfg_default.reloc_dir_rva = 0u;
    cfg_default.reloc_dir_size = 0u;
    cfg_default.preferred_image_base = 0x140000000ull;
    for (int i = 0; i < 32; ++i) {
        cfg_default.obfuscated_master_key[i] = 0u;
        cfg_default.key_obfuscation_mask[i] = 0u;
    }
    cfg_default.original_timestamp = 0u;
    cfg_default.original_size_of_code = 0u;
    cfg_default.section_table_offset = 56u;
    cfg_default.import_table_offset = 0x100u;
    cfg_default.string_table_offset = 0x200u;
    cfg_default.resource_table_offset = 0x300u;
    cfg_default.master_key_offset = 0x400u;
    cfg_default.seed = 0xCAFEF00DDEADBEEFull;

    stub::generated_stub_t gs = stub::generate(cfg_default);
    if (gs.main_stub.empty() || gs.main_stub.size() >= 65536u) {
        std::fprintf(stderr, "stub main size out of range: %zu\n", gs.main_stub.size());
        return 1;
    }

    std::printf("ALL CHECKS PASSED\n");
    return 0;
}
