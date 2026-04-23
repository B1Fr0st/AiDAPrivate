#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#pragma pack(push, 1)
struct coff_file_header_t {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct coff_section_header_t {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct coff_relocation_t {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
};

struct coff_symbol_t {
    union {
        uint8_t ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } LongName;
    } N;
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
};
#pragma pack(pop)

static std::vector<uint8_t> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        return {};
    }
    auto sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> v(static_cast<size_t>(sz));
    if (sz > 0) {
        f.read(reinterpret_cast<char*>(v.data()), sz);
    }
    return v;
}

static std::string symbol_name(const coff_symbol_t& sym, const uint8_t* string_table) {
    if (sym.N.LongName.Zeroes == 0) {
        const char* p = reinterpret_cast<const char*>(string_table + sym.N.LongName.Offset);
        return std::string(p);
    }
    char buf[9] = { 0 };
    std::memcpy(buf, sym.N.ShortName, 8);
    return std::string(buf);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: %s input.obj output.hpp array_name\n", argv[0]);
        return 1;
    }
    const char* input = argv[1];
    const char* output = argv[2];
    const char* array_name = argv[3];
    const char* entry_symbol = "aida_unpack";

    auto data = read_file(input);
    if (data.size() < sizeof(coff_file_header_t)) {
        std::fprintf(stderr, "file too small\n");
        return 1;
    }
    coff_file_header_t fh{};
    std::memcpy(&fh, data.data(), sizeof(fh));
    if (fh.Machine != 0x8664) {
        std::fprintf(stderr, "not amd64 object: machine=0x%X\n", fh.Machine);
        return 1;
    }
    const uint8_t* base = data.data();
    const coff_section_header_t* sections = reinterpret_cast<const coff_section_header_t*>(
        base + sizeof(coff_file_header_t) + fh.SizeOfOptionalHeader);

    int payload_section_index = -1;
    for (int i = 0; i < fh.NumberOfSections; ++i) {
        char nm[9] = { 0 };
        std::memcpy(nm, sections[i].Name, 8);
        if (std::strncmp(nm, ".payload", 8) == 0) {
            payload_section_index = i;
            break;
        }
    }
    if (payload_section_index < 0) {
        std::fprintf(stderr, "no .payload section found\n");
        return 1;
    }
    const coff_section_header_t& ps = sections[payload_section_index];
    int payload_one_based = payload_section_index + 1;

    std::vector<uint8_t> payload(ps.SizeOfRawData);
    if (ps.SizeOfRawData > 0) {
        std::memcpy(payload.data(), base + ps.PointerToRawData, ps.SizeOfRawData);
    }

    const coff_symbol_t* symtab = reinterpret_cast<const coff_symbol_t*>(base + fh.PointerToSymbolTable);
    const uint8_t* string_table = base + fh.PointerToSymbolTable + fh.NumberOfSymbols * sizeof(coff_symbol_t);

    uint32_t entry_offset = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < fh.NumberOfSymbols; ) {
        const coff_symbol_t& s = symtab[i];
        std::string nm = symbol_name(s, string_table);
        if (nm == entry_symbol && s.SectionNumber == payload_one_based) {
            entry_offset = s.Value;
            break;
        }
        i += 1u + static_cast<uint32_t>(s.NumberOfAuxSymbols);
    }
    if (entry_offset == 0xFFFFFFFFu) {
        std::fprintf(stderr, "symbol '%s' not found in .payload section\n", entry_symbol);
        return 1;
    }

    uint32_t patched = 0;
    if (ps.NumberOfRelocations > 0) {
        const coff_relocation_t* relocs = reinterpret_cast<const coff_relocation_t*>(
            base + ps.PointerToRelocations);
        for (uint16_t i = 0; i < ps.NumberOfRelocations; ++i) {
            const coff_relocation_t& rel = relocs[i];
            const coff_symbol_t& sym = symtab[rel.SymbolTableIndex];
            uint32_t adjust = 0;
            switch (rel.Type) {
                case 4: adjust = 0; break;
                case 5: adjust = 1; break;
                case 6: adjust = 2; break;
                case 7: adjust = 3; break;
                case 8: adjust = 4; break;
                case 9: adjust = 5; break;
                case 1:
                    std::fprintf(stderr, "ADDR64 reloc at 0x%X to symbol '%s' is not supported\n",
                                 rel.VirtualAddress, symbol_name(sym, string_table).c_str());
                    return 1;
                case 2:
                    std::fprintf(stderr, "ADDR32 reloc at 0x%X to symbol '%s' is not supported\n",
                                 rel.VirtualAddress, symbol_name(sym, string_table).c_str());
                    return 1;
                case 3:
                    std::fprintf(stderr, "ADDR32NB reloc at 0x%X to symbol '%s' is not supported\n",
                                 rel.VirtualAddress, symbol_name(sym, string_table).c_str());
                    return 1;
                default:
                    std::fprintf(stderr, "unsupported reloc type %u at 0x%X to symbol '%s'\n",
                                 rel.Type, rel.VirtualAddress, symbol_name(sym, string_table).c_str());
                    return 1;
            }
            if (sym.SectionNumber != payload_one_based) {
                std::fprintf(stderr,
                    "external reloc at 0x%X to symbol '%s' (section %d) is not supported\n",
                    rel.VirtualAddress, symbol_name(sym, string_table).c_str(), sym.SectionNumber);
                return 1;
            }
            uint32_t target_offset = sym.Value;
            int32_t disp = static_cast<int32_t>(target_offset)
                         - static_cast<int32_t>(rel.VirtualAddress + 4 + adjust);
            if (rel.VirtualAddress + 4 > payload.size()) {
                std::fprintf(stderr, "reloc out of range at 0x%X\n", rel.VirtualAddress);
                return 1;
            }
            std::memcpy(payload.data() + rel.VirtualAddress, &disp, 4);
            ++patched;
        }
    }

    std::ofstream out(output, std::ios::binary);
    if (!out) {
        std::fprintf(stderr, "cannot open output %s\n", output);
        return 1;
    }
    out << "#pragma once\n";
    out << "#include <cstdint>\n";
    out << "#include <cstddef>\n";
    out << "namespace aida_payload {\n";
    out << "constexpr std::size_t kBlobSize = " << payload.size() << ";\n";
    out << "constexpr std::uint32_t kEntryOffset = " << entry_offset << "u;\n";
    out << "alignas(16) constexpr std::uint8_t " << array_name << "[kBlobSize] = {\n";
    char buf[8];
    for (size_t i = 0; i < payload.size(); ++i) {
        if ((i % 16u) == 0u) {
            out << "    ";
        }
        std::snprintf(buf, sizeof(buf), "0x%02X", payload[i]);
        out << buf;
        if (i + 1 != payload.size()) {
            out << ",";
        }
        if (((i + 1) % 16u) == 0u || i + 1 == payload.size()) {
            out << "\n";
        } else {
            out << " ";
        }
    }
    out << "};\n";
    out << "}\n";
    out.close();

    std::fprintf(stdout, "extracted %zu bytes, entry=0x%X, patched=%u relocs\n",
                 payload.size(), entry_offset, patched);
    (void)input;
    return 0;
}
