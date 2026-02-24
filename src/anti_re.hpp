#pragma once

#include <string>
#include <cstring>
#include <cctype>
#include <algorithm>

#ifdef __NT__
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <delayimp.h>
#pragma comment(lib, "ntdll.lib")
#endif

#ifdef __NT__
#pragma section(".aida0", read, execute)
#pragma section(".aida1", read, execute)
#pragma section(".aida2", read, execute)

__declspec(allocate(".aida0"))
static const unsigned char s_anti_disasm_0[4096] = {
    0x48, 0x89, 0x5C, 0x24, 0x08,
    0xEB, 0x03,
    0x0F, 0x0B, 0xCC,
    0x48, 0x83, 0xEC, 0x20,
    0xEB, 0xFE,
    0xE8, 0x00, 0x10, 0x00, 0x00,
    0xE8, 0xFF, 0x0F, 0x00, 0x00,
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC0, 0x41, 0x69, 0x44, 0x41,
    0xEB, 0x01,
    0xE8,
    0x48, 0x89, 0x5C, 0x24, 0x10,
    0xC3,
    0xCC, 0xCC, 0xCC, 0xCC,

    0xFF, 0x24, 0xC5, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
};

__declspec(allocate(".aida1"))
static const unsigned char s_anti_disasm_1[32768] = {
    0xEB, 0x0E,  0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x20, 0xCC,
    0xEB, 0x0E,  0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x0F, 0x0B,
    0xEB, 0x0E,  0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57, 0x41, 0x56, 0x48, 0x8D, 0x6C, 0x24, 0xCC,
    0xEB, 0x0E,  0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x33, 0xC9, 0xFF, 0x15, 0xCC,

    0xE8, 0x00, 0x20, 0x00, 0x00,
    0xE8, 0x00, 0x40, 0x00, 0x00,
    0xE8, 0x00, 0x60, 0x00, 0x00,
    0xFF, 0x15, 0x00, 0x10, 0x00, 0x00,
    0xFF, 0x25, 0x00, 0x20, 0x00, 0x00,
};

__declspec(allocate(".aida2"))
static const unsigned char s_anti_disasm_2[16384] = {
    0x48, 0x89, 0x5C, 0x24, 0x08,
    0x48, 0x83, 0xEC, 0x28,
    0xE8, 0xF1, 0xFF, 0xFF, 0xFF,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,

    0x40, 0x55, 0x48, 0x8D, 0x6C, 0x24, 0xE1,
    0x48, 0x81, 0xEC, 0xF0, 0x00, 0x00, 0x00,
    0xE8, 0xE0, 0xFF, 0xFF, 0xFF,
    0x0F, 0x0B,
};

#pragma section(".aida3", read, execute)
#pragma section(".aida4", read, execute)
#pragma section(".aida5", read, execute)
#pragma section(".aida6", read, execute)

#define AIDA_HOSTILE_A  \
    0x48,0x89,0x5C,0x24,0x08, 0xEB,0x03, 0x0F,0x0B,0xCC, \
    0x48,0x83,0xEC,0x20, 0xC3,0xCC

#define AIDA_HOSTILE_B  \
    0xE8,0x00,0x10,0x00,0x00, 0xE8,0x00,0x40,0x00,0x00, \
    0xFF,0x25,0x00,0x00,0x00,0x00

#define AIDA_HOSTILE_C  \
    0xE8,0xF1,0xFF,0xFF,0xFF, 0x48,0x83,0xC4,0x28, 0xC3, \
    0xFF,0x24,0xC5,0x00,0x00,0x00

#define AIDA_HOSTILE_256A  \
    AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A, \
    AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A, \
    AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A, \
    AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A, AIDA_HOSTILE_A

#define AIDA_HOSTILE_256B  \
    AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B, \
    AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B, \
    AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B, \
    AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B, AIDA_HOSTILE_B

#define AIDA_HOSTILE_256C  \
    AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C, \
    AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C, \
    AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C, \
    AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C, AIDA_HOSTILE_C

#define AIDA_HOSTILE_4K  \
    AIDA_HOSTILE_256A, AIDA_HOSTILE_256B, AIDA_HOSTILE_256C, AIDA_HOSTILE_256A, \
    AIDA_HOSTILE_256B, AIDA_HOSTILE_256C, AIDA_HOSTILE_256A, AIDA_HOSTILE_256B, \
    AIDA_HOSTILE_256C, AIDA_HOSTILE_256A, AIDA_HOSTILE_256B, AIDA_HOSTILE_256C, \
    AIDA_HOSTILE_256A, AIDA_HOSTILE_256B, AIDA_HOSTILE_256C, AIDA_HOSTILE_256A

#define AIDA_HOSTILE_64K  \
    AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, \
    AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, \
    AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, \
    AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K, AIDA_HOSTILE_4K

__declspec(allocate(".aida3"))
static const unsigned char s_anti_disasm_3[262144] = {
    AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K
};

__declspec(allocate(".aida4"))
static const unsigned char s_anti_disasm_4[262144] = {
    AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K
};

__declspec(allocate(".aida5"))
static const unsigned char s_anti_disasm_5[262144] = {
    AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K
};

__declspec(allocate(".aida6"))
static const unsigned char s_anti_disasm_6[262144] = {
    AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K, AIDA_HOSTILE_64K
};

#define AIDA_CRASH_DOS_HDR                                              \
    0x4D,0x5A,0x90,0x00, 0x03,0x00,0x00,0x00,                         \
    0x04,0x00,0x00,0x00, 0xFF,0xFF,0x00,0x00,                         \
    0xB8,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,                         \
    0x40,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,                         \
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,                         \
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,                         \
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,                         \
    0x00,0x00,0x00,0x00, 0x40,0x00,0x00,0x00

#define AIDA_CRASH_PE_SIG  0x50,0x45,0x00,0x00

#define AIDA_CRASH_COFF_A                                               \
    0x64,0x86,              /* Machine = IMAGE_FILE_MACHINE_AMD64    */ \
    0xFF,0xFF,              /* NumberOfSections = 65535 (CRASH)      */ \
    0x00,0x00,0x00,0x00,    /* TimeDateStamp                        */ \
    0x00,0x00,0x00,0x00,    /* PointerToSymbolTable                 */ \
    0x00,0x00,0x00,0x00,    /* NumberOfSymbols                      */ \
    0xFF,0xFF,              /* SizeOfOptionalHeader = 65535 (CRASH)  */ \
    0x22,0x00               /* Characteristics (EXEC|LARGE_ADDR)    */

#define AIDA_CRASH_COFF_B                                               \
    0x4C,0x01,              /* Machine = IMAGE_FILE_MACHINE_I386    */  \
    0xFE,0xFF,              /* NumberOfSections = 65534              */ \
    0x00,0x00,0x00,0x00,    /* TimeDateStamp                        */ \
    0x00,0x00,0x00,0x00,    /* PointerToSymbolTable                 */ \
    0x00,0x00,0x00,0x00,    /* NumberOfSymbols                      */ \
    0x00,0x80,              /* SizeOfOptionalHeader = 32768          */ \
    0x02,0x01               /* Characteristics (EXEC|NO_RELOCS)     */

#define AIDA_CRASH_COFF_C                                               \
    0x64,0xAA,              /* Machine = IMAGE_FILE_MACHINE_ARM64   */  \
    0x00,0xFF,              /* NumberOfSections = 0xFF00             */ \
    0x00,0x00,0x00,0x00,    /* TimeDateStamp                        */ \
    0x00,0x00,0x00,0x00,    /* PointerToSymbolTable                 */ \
    0x00,0x00,0x00,0x00,    /* NumberOfSymbols                      */ \
    0xFF,0xFF,              /* SizeOfOptionalHeader = 65535          */ \
    0x22,0x00               /* Characteristics                      */

#define AIDA_CRASH_COFF_D                                               \
    0xFF,0xFF,              /* Machine = UNKNOWN (triggers TIL crash)*/ \
    0xFF,0xFF,              /* NumberOfSections = 65535              */ \
    0x00,0x00,0x00,0x00,    /* TimeDateStamp                        */ \
    0x00,0x00,0x00,0x00,    /* PointerToSymbolTable                 */ \
    0x00,0x00,0x00,0x00,    /* NumberOfSymbols                      */ \
    0xFF,0xFF,              /* SizeOfOptionalHeader = 65535          */ \
    0x00,0x00               /* Characteristics = 0                  */

#define AIDA_CRASH_COFF_E                                               \
    0x66,0x01,              /* Machine = IMAGE_FILE_MACHINE_R4000    */ \
    0xFF,0xFF,              /* NumberOfSections = 65535              */ \
    0x00,0x00,0x00,0x00,    /* TimeDateStamp                        */ \
    0x00,0x00,0x00,0x00,    /* PointerToSymbolTable                 */ \
    0x00,0x00,0x00,0x00,    /* NumberOfSymbols                      */ \
    0xFF,0xFF,              /* SizeOfOptionalHeader = 65535          */ \
    0x23,0x00               /* Characteristics (EXEC|LARGE|NO_RELOC) */

#define AIDA_CRASH_COFF_F                                               \
    0xF0,0x01,              /* Machine = IMAGE_FILE_MACHINE_POWERPC  */ \
    0x00,0x80,              /* NumberOfSections = 32768              */ \
    0x00,0x00,0x00,0x00,    /* TimeDateStamp                        */ \
    0xFF,0xFF,0xFF,0x7F,    /* PointerToSymbolTable = 0x7FFFFFFF     */ \
    0xFF,0xFF,0xFF,0x7F,    /* NumberOfSymbols = 0x7FFFFFFF          */ \
    0x00,0xF0,              /* SizeOfOptionalHeader = 0xF000         */ \
    0x22,0x00               /* Characteristics                      */

#define AIDA_CRASH_COFF_G                                               \
    0x66,0x01,              /* Machine = IMAGE_FILE_MACHINE_SH4      */ \
    0xFE,0x7F,              /* NumberOfSections = 32766              */ \
    0x00,0x00,0x00,0x00,    /* TimeDateStamp                        */ \
    0x00,0x00,0x00,0x00,    /* PointerToSymbolTable                 */ \
    0x00,0x00,0x00,0x00,    /* NumberOfSymbols                      */ \
    0xFE,0xFF,              /* SizeOfOptionalHeader = 0xFFFE         */ \
    0x02,0x01               /* Characteristics                      */

#define AIDA_CRASH_COFF_H                                               \
    0x00,0x02,              /* Machine = IMAGE_FILE_MACHINE_IA64     */ \
    0xFF,0x7F,              /* NumberOfSections = 32767              */ \
    0xDE,0xAD,0xBE,0xEF,    /* TimeDateStamp = 0xDEADBEEF            */ \
    0xFF,0xFF,0xFF,0xFF,    /* PointerToSymbolTable = -1 (invalid)   */ \
    0xFF,0xFF,0xFF,0xFF,    /* NumberOfSymbols = -1 (invalid)        */ \
    0xFF,0x7F,              /* SizeOfOptionalHeader = 32767          */ \
    0x22,0x00               /* Characteristics                      */

#define AIDA_PE_CRASH_E  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_E
#define AIDA_PE_CRASH_F  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_F
#define AIDA_PE_CRASH_G  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_G
#define AIDA_PE_CRASH_H  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_H

#define AIDA_PE_CRASH_A  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_A
#define AIDA_PE_CRASH_B  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_B
#define AIDA_PE_CRASH_C  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_C
#define AIDA_PE_CRASH_D  AIDA_CRASH_DOS_HDR, AIDA_CRASH_PE_SIG, AIDA_CRASH_COFF_D

#define AIDA_PE_STUB_PAD  0xCC,0xCC,0xCC,0xCC, 0xCC,0xCC,0xCC,0xCC

#define AIDA_PE_CRASH_QUAD                                              \
    AIDA_PE_CRASH_A, AIDA_PE_STUB_PAD,                                 \
    AIDA_PE_CRASH_B, AIDA_PE_STUB_PAD,                                 \
    AIDA_PE_CRASH_C, AIDA_PE_STUB_PAD,                                 \
    AIDA_PE_CRASH_D, AIDA_PE_STUB_PAD

#define AIDA_PE_CRASH_QUAD_EXT                                          \
    AIDA_PE_CRASH_E, AIDA_PE_STUB_PAD,                                 \
    AIDA_PE_CRASH_F, AIDA_PE_STUB_PAD,                                 \
    AIDA_PE_CRASH_G, AIDA_PE_STUB_PAD,                                 \
    AIDA_PE_CRASH_H, AIDA_PE_STUB_PAD

#pragma section(".aida7", read, execute)
#pragma section(".aida8", read, execute)
#pragma section(".aida9", read, execute)
#pragma section(".aidaA", read, execute)

__declspec(allocate(".aida7"))
static const unsigned char s_anti_ida_crash_stubs[4096] = {
    AIDA_PE_CRASH_QUAD, AIDA_PE_CRASH_QUAD,
    AIDA_PE_CRASH_QUAD, AIDA_PE_CRASH_QUAD,
    AIDA_PE_CRASH_QUAD, AIDA_PE_CRASH_QUAD,
    AIDA_PE_CRASH_QUAD, AIDA_PE_CRASH_QUAD,
    AIDA_PE_CRASH_QUAD, AIDA_PE_CRASH_QUAD,
};

__declspec(allocate(".aida8"))
static const unsigned char s_anti_ida_aligned_stubs[4096] = {
    AIDA_PE_CRASH_A, AIDA_HOSTILE_A,
    AIDA_PE_CRASH_B, AIDA_HOSTILE_B,
    AIDA_PE_CRASH_C, AIDA_HOSTILE_C,
    AIDA_PE_CRASH_D, AIDA_HOSTILE_A,
    AIDA_PE_CRASH_A, AIDA_HOSTILE_B,
    AIDA_PE_CRASH_B, AIDA_HOSTILE_C,
    AIDA_PE_CRASH_C, AIDA_HOSTILE_A,
    AIDA_PE_CRASH_D, AIDA_HOSTILE_B,
};

__declspec(allocate(".aida9"))
static const unsigned char s_anti_ida_exotic_stubs[4096] = {
    AIDA_PE_CRASH_QUAD_EXT, AIDA_PE_CRASH_QUAD_EXT,
    AIDA_PE_CRASH_QUAD_EXT, AIDA_PE_CRASH_QUAD_EXT,
    AIDA_PE_CRASH_QUAD_EXT, AIDA_PE_CRASH_QUAD_EXT,
    AIDA_PE_CRASH_QUAD_EXT, AIDA_PE_CRASH_QUAD_EXT,
    AIDA_PE_CRASH_QUAD_EXT, AIDA_PE_CRASH_QUAD_EXT,
};

__declspec(allocate(".aidaA"))
static const unsigned char s_anti_ida_mixed_stubs[4096] = {
    AIDA_PE_CRASH_A, AIDA_HOSTILE_A,
    AIDA_PE_CRASH_E, AIDA_HOSTILE_B,
    AIDA_PE_CRASH_B, AIDA_HOSTILE_C,
    AIDA_PE_CRASH_F, AIDA_HOSTILE_A,
    AIDA_PE_CRASH_C, AIDA_HOSTILE_B,
    AIDA_PE_CRASH_G, AIDA_HOSTILE_C,
    AIDA_PE_CRASH_D, AIDA_HOSTILE_A,
    AIDA_PE_CRASH_H, AIDA_HOSTILE_B,
};

#define AIDA_TIL_MAGIC  0x49,0x44,0x41,0x01

#define AIDA_TIL_CRASH_A                                                \
    AIDA_TIL_MAGIC,                                                     \
    0x00,0x0E,              /* format = 14                            */\
    0x01,                   /* flags                                  */\
    0x00,                   /* compiler                               */\
    0xFF,0xFF,0xFF,0x7F,    /* title_len = 0x7FFFFFFF (OOB read)     */\
    0x41,0x42,0x43,0x44,    /* partial title bytes                    */\
    0xFF,0xFF,0xFF,0xFF,    /* base_count = -1 signed (overflow)     */\
    0xFF,0xFF,0xFF,0xFF     /* type_count = -1 signed (overflow)     */

#define AIDA_TIL_CRASH_B                                                \
    AIDA_TIL_MAGIC,                                                     \
    0x00,0x0D,              /* format = 13                            */\
    0x00,                   /* flags                                  */\
    0x00,                   /* compiler                               */\
    0x00,0x00,0x00,0x00,    /* title_len = 0                          */\
    0xFF,0xFF,0x00,0x00,    /* base_count = 65535                     */\
    0xFF,0xFF,0xFF,0x3F,    /* type_count = 0x3FFFFFFF (huge alloc)  */\
    0xFF,0xFF,0xFF,0x3F     /* field_count = 0x3FFFFFFF               */

#define AIDA_TIL_CRASH_C                                                \
    AIDA_TIL_MAGIC,                                                     \
    0xFF,0xFF,              /* format = 65535 (unsupported version)   */\
    0xFF,                   /* flags = all bits set                   */\
    0xFF,                   /* compiler = invalid                     */\
    0xFF,0xFF,0xFF,0xFF,    /* title_len = UINT32_MAX (massive OOB)  */\
    0xFF,0xFF,0xFF,0xFF,    /* all fields max                        */\
    0xFF,0xFF,0xFF,0xFF,                                                \
    0xFF,0xFF,0xFF,0xFF

#define AIDA_TIL_CRASH_TRIPLE                                           \
    AIDA_TIL_CRASH_A, 0xCC,0xCC,0xCC,0xCC,                             \
    AIDA_TIL_CRASH_B, 0xCC,0xCC,0xCC,0xCC,                             \
    AIDA_TIL_CRASH_C, 0xCC,0xCC,0xCC,0xCC

#pragma section(".aidaB", read, execute)

__declspec(allocate(".aidaB"))
static const unsigned char s_anti_ida_til_stubs[4096] = {
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
    AIDA_TIL_CRASH_TRIPLE, AIDA_TIL_CRASH_TRIPLE,
};

inline void deploy_crash_pe_to_temp()
{
#ifdef __NT__
    VMP_VIRT("deploy_crash_pe");

    alignas(16) unsigned char crash_pe[84] = {};

    crash_pe[0] = 0x4D; crash_pe[1] = 0x5A;   /* e_magic = 'MZ' */
    crash_pe[60] = 0x40; /* e_lfanew = 64 */

    crash_pe[64] = 0x50; crash_pe[65] = 0x45;  /* 'PE\0\0' */
    crash_pe[66] = 0x00; crash_pe[67] = 0x00;

    crash_pe[68] = 0x64; crash_pe[69] = 0x86;  /* Machine = AMD64 */
    crash_pe[70] = 0xFF; crash_pe[71] = 0xFF;  /* NumberOfSections = 65535 */

    crash_pe[80] = 0xFF; crash_pe[81] = 0xFF;  /* SizeOfOptionalHeader = 65535 */
    crash_pe[82] = 0x22; crash_pe[83] = 0x00;  /* Characteristics */

    wchar_t temp_dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_dir);

    LARGE_INTEGER perf = {};
    QueryPerformanceCounter(&perf);
    uint64_t seed = static_cast<uint64_t>(perf.QuadPart)
                  ^ static_cast<uint64_t>(GetCurrentProcessId());

    wchar_t fname[MAX_PATH] = {};
    wsprintfW(fname, L"%s\\~ida_cache_%llX.tmp", temp_dir,
              static_cast<unsigned long long>(seed));

    HANDLE hf = CreateFileW(fname, GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (hf != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(hf, crash_pe, sizeof(crash_pe), &written, nullptr);
        CloseHandle(hf);
    }

    crash_pe[68] = 0xFF; crash_pe[69] = 0xFF;  /* Machine = UNKNOWN */
    crash_pe[82] = 0x00; crash_pe[83] = 0x00;  /* Characteristics = 0 */

    seed ^= 0xDEADFACECAFEBEEFULL;
    wsprintfW(fname, L"%s\\~ida_til_%llX.tmp", temp_dir,
              static_cast<unsigned long long>(seed));

    hf = CreateFileW(fname, GENERIC_WRITE, 0, nullptr,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (hf != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(hf, crash_pe, sizeof(crash_pe), &written, nullptr);
        CloseHandle(hf);
    }

    VMP_END;
#endif
}

#endif /* __NT__ */

namespace anti_re {
namespace detail {

#ifdef __NT__

#define CRASH_HARD() do { \
    const unsigned int _crash_tag = \
        (static_cast<unsigned int>(__LINE__) ^ 0xA5B4C3D2u); \
    \
    /* Method 1: NtTerminateProcess (dynamic resolve — survives IAT hooks) */ \
    { \
        using _fn_nttp = LONG (NTAPI*)(HANDLE, LONG); \
        HMODULE _nt = GetModuleHandleW(L"ntdll.dll"); \
        if (_nt) { \
            _fn_nttp _pfn = reinterpret_cast<_fn_nttp>( \
                GetProcAddress(_nt, "NtTerminateProcess")); \
            if (_pfn) \
                _pfn(GetCurrentProcess(), static_cast<LONG>(_crash_tag)); \
        } \
    } \
    \
    /* Method 2: TerminateProcess (user-land fallback) */ \
    TerminateProcess(GetCurrentProcess(), _crash_tag); \
    \
    /* Method 3: __fastfail — unhookable (generates int 0x29).           */ \
    /*   Cannot be intercepted by user-mode hooks or SEH.               */ \
    __fastfail(FAST_FAIL_FATAL_APP_EXIT); \
    \
    /* Method 4: null-pointer write with unique tag (absolute last resort) */ \
    { \
        volatile int* _p = nullptr; \
        *_p = static_cast<int>(_crash_tag); \
    } \
    \
    __assume(0); \
} while (0)

[[noreturn]] __declspec(noinline) inline void crash_hard()
{
    CRASH_HARD();
}

#else /* !__NT__ */

#define CRASH_HARD() do { _exit(1); abort(); } while (0)

[[noreturn]] inline void crash_hard()
{
    _exit(1);
    abort();
}

#endif

#ifdef __NT__
using fn_IsDebuggerPresent   = BOOL (WINAPI*)();
using fn_GetThreadContext     = BOOL (WINAPI*)(HANDLE, LPCONTEXT);
using fn_QPC                 = BOOL (WINAPI*)(LARGE_INTEGER*);
using fn_QPF                 = BOOL (WINAPI*)(LARGE_INTEGER*);
using fn_GetModuleHandleExW  = BOOL (WINAPI*)(DWORD, LPCWSTR, HMODULE*);
using fn_GetModuleFileNameW  = DWORD (WINAPI*)(HMODULE, LPWSTR, DWORD);
using fn_TerminateProcess    = BOOL (WINAPI*)(HANDLE, UINT);
using fn_NtQueryInformationProcess = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using fn_CheckRemoteDebuggerPresent = BOOL (WINAPI*)(HANDLE, PBOOL);
using fn_NtSetInformationThread = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG);

struct resolved_apis_t
{
    fn_IsDebuggerPresent   pIsDebuggerPresent   = nullptr;
    fn_GetThreadContext     pGetThreadContext     = nullptr;
    fn_QPC                 pQPC                  = nullptr;
    fn_QPF                 pQPF                  = nullptr;
    fn_GetModuleHandleExW  pGetModuleHandleExW   = nullptr;
    fn_GetModuleFileNameW  pGetModuleFileNameW   = nullptr;
    fn_TerminateProcess    pTerminateProcess     = nullptr;
    fn_NtQueryInformationProcess   pNtQueryInformationProcess   = nullptr;
    fn_CheckRemoteDebuggerPresent  pCheckRemoteDebuggerPresent  = nullptr;
    fn_NtSetInformationThread      pNtSetInformationThread      = nullptr;
    bool resolved = false;

    void resolve()
    {
        if (resolved) return;
        HMODULE k32  = GetModuleHandleA(OBFSTR_C("kernel32.dll"));
        HMODULE nt   = GetModuleHandleA(OBFSTR_C("ntdll.dll"));
        if (k32)
        {
            pIsDebuggerPresent  = (fn_IsDebuggerPresent) GetProcAddress(k32, OBFSTR_C("IsDebuggerPresent"));
            pGetThreadContext    = (fn_GetThreadContext)   GetProcAddress(k32, OBFSTR_C("GetThreadContext"));
            pQPC                 = (fn_QPC)                GetProcAddress(k32, OBFSTR_C("QueryPerformanceCounter"));
            pQPF                 = (fn_QPF)                GetProcAddress(k32, OBFSTR_C("QueryPerformanceFrequency"));
            pGetModuleHandleExW  = (fn_GetModuleHandleExW) GetProcAddress(k32, OBFSTR_C("GetModuleHandleExW"));
            pGetModuleFileNameW  = (fn_GetModuleFileNameW) GetProcAddress(k32, OBFSTR_C("GetModuleFileNameW"));
            pTerminateProcess    = (fn_TerminateProcess)   GetProcAddress(k32, OBFSTR_C("TerminateProcess"));
            pCheckRemoteDebuggerPresent = (fn_CheckRemoteDebuggerPresent) GetProcAddress(k32, OBFSTR_C("CheckRemoteDebuggerPresent"));
        }
        if (nt)
        {
            pNtQueryInformationProcess = (fn_NtQueryInformationProcess) GetProcAddress(nt, OBFSTR_C("NtQueryInformationProcess"));
            pNtSetInformationThread    = (fn_NtSetInformationThread)    GetProcAddress(nt, OBFSTR_C("NtSetInformationThread"));
        }
        resolved = true;
    }
};

inline resolved_apis_t& apis()
{
    static resolved_apis_t inst;
    return inst;
}
#endif

} // namespace detail

inline bool is_ida_host_process()
{
#ifdef __NT__
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    const wchar_t* filename = wcsrchr(path, L'\\');
    filename = filename ? filename + 1 : path;

    wchar_t lower[MAX_PATH] = {};
    for (size_t i = 0; filename[i] && i < MAX_PATH - 1; ++i)
        lower[i] = static_cast<wchar_t>(towlower(filename[i]));

    if (wcscmp(lower, WOBFSTR_C(L"ida.exe")) == 0
     || wcscmp(lower, WOBFSTR_C(L"ida64.exe")) == 0
     || wcscmp(lower, WOBFSTR_C(L"idat.exe")) == 0
     || wcscmp(lower, WOBFSTR_C(L"idat64.exe")) == 0
     || wcscmp(lower, WOBFSTR_C(L"idaq.exe")) == 0
     || wcscmp(lower, WOBFSTR_C(L"idaq64.exe")) == 0
     || wcscmp(lower, WOBFSTR_C(L"idaw.exe")) == 0
     || wcscmp(lower, WOBFSTR_C(L"idaw64.exe")) == 0)
        return true;

    return false;
#else
    return true;
#endif
}

inline bool is_blocked_analysis_tool()
{
#ifdef __NT__
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    const wchar_t* filename = wcsrchr(path, L'\\');
    filename = filename ? filename + 1 : path;

    wchar_t lower[MAX_PATH] = {};
    for (size_t i = 0; filename[i] && i < MAX_PATH - 1; ++i)
        lower[i] = static_cast<wchar_t>(towlower(filename[i]));

    auto blocked = [&](const wchar_t* pat) { return wcsstr(lower, pat) != nullptr; };
    if (blocked(WOBFSTR_C(L"x64dbg"))      || blocked(WOBFSTR_C(L"x32dbg"))
     || blocked(WOBFSTR_C(L"ollydbg"))     || blocked(WOBFSTR_C(L"windbg"))
     || blocked(WOBFSTR_C(L"windbgx"))     || blocked(WOBFSTR_C(L"binaryninja"))
     || blocked(WOBFSTR_C(L"binja"))       || blocked(WOBFSTR_C(L"radare2"))
     || blocked(WOBFSTR_C(L"cutter"))      || blocked(WOBFSTR_C(L"r2agent"))
     || blocked(WOBFSTR_C(L"iaito"))       || blocked(WOBFSTR_C(L"pestudio"))
     || blocked(WOBFSTR_C(L"pe-bear"))     || blocked(WOBFSTR_C(L"cffexplor"))
     || blocked(WOBFSTR_C(L"hiew32"))      || blocked(WOBFSTR_C(L"hiew"))
     || blocked(WOBFSTR_C(L"010editor"))   || blocked(WOBFSTR_C(L"processhacker"))
     || blocked(WOBFSTR_C(L"procmon"))     || blocked(WOBFSTR_C(L"apimonitor"))
     || blocked(WOBFSTR_C(L"scylla"))      || blocked(WOBFSTR_C(L"importrec"))
     || blocked(WOBFSTR_C(L"ghidrarun"))   || blocked(WOBFSTR_C(L"analyzeheadless"))
     || blocked(WOBFSTR_C(L"dnspy"))       || blocked(WOBFSTR_C(L"de4dot"))
     || blocked(WOBFSTR_C(L"ilspy"))       || blocked(WOBFSTR_C(L"dotpeek"))
     || blocked(WOBFSTR_C(L"immunitydebugger")) || blocked(WOBFSTR_C(L"cheatengine"))
     || blocked(WOBFSTR_C(L"fiddler"))     || blocked(WOBFSTR_C(L"wireshark"))
     || blocked(WOBFSTR_C(L"charles")))
        return true;

    wchar_t full_lower[MAX_PATH] = {};
    for (size_t i = 0; path[i] && i < MAX_PATH - 1; ++i)
        full_lower[i] = static_cast<wchar_t>(towlower(path[i]));

    auto in_dir = [&](const wchar_t* pat) { return wcsstr(full_lower, pat) != nullptr; };
    if (in_dir(WOBFSTR_C(L"\\ghidra\\"))         || in_dir(WOBFSTR_C(L"\\binary ninja\\"))
     || in_dir(WOBFSTR_C(L"\\binja\\"))          || in_dir(WOBFSTR_C(L"\\x64dbg\\"))
     || in_dir(WOBFSTR_C(L"\\x32dbg\\"))         || in_dir(WOBFSTR_C(L"\\ollydbg\\"))
     || in_dir(WOBFSTR_C(L"\\radare2\\"))        || in_dir(WOBFSTR_C(L"\\cutter\\"))
     || in_dir(WOBFSTR_C(L"\\ghidra_scripts\\")) || in_dir(WOBFSTR_C(L"\\nsight\\")))
        return true;

    return false;
#else
    return false;
#endif
}

inline void erase_pe_header()
{
#ifdef __NT__
    auto& api = detail::apis();
    api.resolve();

    HMODULE hModule = nullptr;
    if (api.pGetModuleHandleExW)
    {
        api.pGetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&erase_pe_header),
            &hModule);
    }
    if (!hModule)
        return;

    size_t wipe_size = 0x1000;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dos->e_magic == IMAGE_DOS_SIGNATURE
        && dos->e_lfanew > 0
        && static_cast<DWORD>(dos->e_lfanew) < 0x1000)
    {
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(hModule) + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE
            && nt->OptionalHeader.SizeOfHeaders > wipe_size
            && nt->OptionalHeader.SizeOfHeaders <= 0x10000)
        {
            wipe_size = nt->OptionalHeader.SizeOfHeaders;
        }
    }

    DWORD old_protect = 0;
    if (VirtualProtect(hModule, wipe_size, PAGE_READWRITE, &old_protect))
    {
        SecureZeroMemory(hModule, wipe_size);
        DWORD ignored = 0;
        VirtualProtect(hModule, wipe_size, old_protect, &ignored);
    }
#endif
}

inline void hide_thread_from_debugger()
{
#ifdef __NT__
    VMP_VIRT("hide_thread");
    auto& api = detail::apis();
    api.resolve();
    if (api.pNtSetInformationThread)
    {
        api.pNtSetInformationThread(
            GetCurrentThread(),
            0x11,
            nullptr,
            0);
    }
    VMP_END;
#endif
}

inline void unlink_module_from_peb()
{
#ifdef __NT__
    VMP_VIRT("unlink_peb");

    HMODULE hModule = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&unlink_module_from_peb),
        &hModule);
    if (!hModule) { VMP_END; return; }

#ifdef _WIN64
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

    if (!peb || !peb->Ldr) { VMP_END; return; }

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    while (current != head)
    {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase == hModule)
        {
            current->Flink->Blink = current->Blink;
            current->Blink->Flink = current->Flink;
            break;
        }
        current = current->Flink;
    }

    VMP_END;
#endif
}

inline bool detect_debugger()
{
#ifdef __NT__
    VMP_ULTRA("detect_debugger");
    auto& api = detail::apis();
    api.resolve();

    if (VMP_IS_DEBUGGER(true))
    {
        VMP_END;
        return true;
    }

    if (api.pIsDebuggerPresent && api.pIsDebuggerPresent())
    {
        VMP_END;
        return true;
    }

    if (api.pNtQueryInformationProcess)
    {
        DWORD_PTR debug_port = 0;
        LONG status = api.pNtQueryInformationProcess(
            GetCurrentProcess(),
            7,
            &debug_port, sizeof(debug_port), nullptr);
        if (status == 0 && debug_port != 0)
        {
            VMP_END;
            return true;
        }

        HANDLE debug_object = nullptr;
        status = api.pNtQueryInformationProcess(
            GetCurrentProcess(),
            0x1E,
            &debug_object, sizeof(debug_object), nullptr);
        if (status == 0 && debug_object != nullptr)
        {
            VMP_END;
            return true;
        }
    }

    if (api.pCheckRemoteDebuggerPresent)
    {
        BOOL remote_present = FALSE;
        api.pCheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_present);
        if (remote_present)
        {
            VMP_END;
            return true;
        }
    }

    {
#ifdef _WIN64
        constexpr size_t kNtGlobalFlagOffset = 0xBC;
#else
        constexpr size_t kNtGlobalFlagOffset = 0x68;
#endif
        PPEB peb = nullptr;
#ifdef _WIN64
        peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
        peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
        if (peb)
        {
            ULONG flags = *reinterpret_cast<ULONG*>(
                reinterpret_cast<BYTE*>(peb) + kNtGlobalFlagOffset);
            if (flags & 0x70)
                return true;
        }
    }

    if (api.pGetThreadContext)
    {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (api.pGetThreadContext(GetCurrentThread(), &ctx))
        {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
                return true;
        }
    }

    if (api.pQPC && api.pQPF)
    {
        LARGE_INTEGER freq = {}, t0 = {}, t1 = {};
        api.pQPF(&freq);
        api.pQPC(&t0);

        volatile unsigned x = 0;
        for (unsigned i = 0; i < 1000; ++i)
            x += i;

        api.pQPC(&t1);
        double elapsed_ms = static_cast<double>(t1.QuadPart - t0.QuadPart)
                          / static_cast<double>(freq.QuadPart) * 1000.0;
        if (elapsed_ms > 100.0)
        {
            VMP_END;
            return true;
        }
    }

    {
        if (FindWindowW(nullptr, WOBFSTR_C(L"x64dbg"))
         || FindWindowW(nullptr, WOBFSTR_C(L"x32dbg"))
         || FindWindowW(nullptr, WOBFSTR_C(L"OllyDbg"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Cheat Engine"))
         || FindWindowW(nullptr, WOBFSTR_C(L"IDENT_WIRESHARK"))
         || FindWindowW(nullptr, WOBFSTR_C(L"WinDbgFrameClass"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Immunity Debugger - [CPU"))
         || FindWindowW(nullptr, WOBFSTR_C(L"The Wireshark Network Analyzer"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Scylla"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Import Reconstructor"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Binary Ninja"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Cutter"))
         || FindWindowW(nullptr, WOBFSTR_C(L"PE-bear"))
         || FindWindowW(nullptr, WOBFSTR_C(L"pestudio"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Process Hacker"))
         || FindWindowW(nullptr, WOBFSTR_C(L"API Monitor"))
         || FindWindowW(nullptr, WOBFSTR_C(L"Fiddler"))
         || FindWindowW(nullptr, WOBFSTR_C(L"dnSpy")))
            return true;

        if (FindWindowW(WOBFSTR_C(L"WinDbgFrameClass"), nullptr)
         || FindWindowW(WOBFSTR_C(L"OllyDbg"), nullptr)
         || FindWindowW(WOBFSTR_C(L"PROCEXPL"), nullptr)
         || FindWindowW(WOBFSTR_C(L"ProcessHacker"), nullptr)
         || FindWindowW(WOBFSTR_C(L"Zeta Debugger"), nullptr))
        {
            VMP_END;
            return true;
        }
    }

    VMP_END;
    return false;
#else
    return false;
#endif
}

inline bool is_self_analysis()
{
    VMP_VIRT("is_self_analysis");

    auto has_pattern = [](const std::string& text,
                          const std::vector<std::string>& pats) -> bool
    {
        for (const auto& p : pats)
            if (text.find(p) != std::string::npos)
                return true;
        return false;
    };

    auto is_native_module = [](const std::string& s) -> bool
    {
        return s.find(OBFSTR(".dll"))   != std::string::npos
            || s.find(OBFSTR(".so"))    != std::string::npos
            || s.find(OBFSTR(".dylib")) != std::string::npos;
    };

    static const std::vector<std::string> suspicious = {
        OBFSTR("aida"), OBFSTR("a1da"), OBFSTR("a_ida"),
        OBFSTR("ai_da"), OBFSTR("aid_a"), OBFSTR("ai-da"),
        OBFSTR("a-ida"), OBFSTR("aiida"), OBFSTR("aidda"),
        OBFSTR("a.i.d.a"), OBFSTR("a i d a"), OBFSTR("41d4"),
        OBFSTR("a!da"), OBFSTR("@ida"), OBFSTR("ai_assistant"),
    };

    char name_buf[1024] = {};
    get_root_filename(name_buf, sizeof(name_buf));

    std::string name(name_buf);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (has_pattern(name, suspicious) && is_native_module(name))
    {
        VMP_END;
        return true;
    }

    char path_buf[4096] = {};
    get_input_file_path(path_buf, sizeof(path_buf));

    std::string full(path_buf);
    std::transform(full.begin(), full.end(), full.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (has_pattern(full, suspicious) && is_native_module(full))
    {
        VMP_END;
        return true;
    }

    if (is_native_module(name) || is_native_module(full))
    {
        size_t entry_count = get_entry_qty();
        bool has_compare2 = false;
        bool has_equals = false;

        bool has_plugin_export = false;
        bool has_init_export   = false;

        for (size_t i = 0; i < entry_count && i < 1000; ++i)
        {
            uval_t ord = get_entry_ordinal(i);
            qstring ename;
            if (get_entry_name(&ename, ord) > 0 && !ename.empty())
            {
                if (strstr(ename.c_str(),
                           OBFSTR_C("simpleline_place_t__compare2")) != nullptr)
                    has_compare2 = true;
                if (strstr(ename.c_str(),
                           OBFSTR_C("simpleline_place_t__equals")) != nullptr)
                    has_equals = true;
                if (strstr(ename.c_str(),
                           OBFSTR_C("PLUGIN")) != nullptr)
                    has_plugin_export = true;
            }
        }
        if (has_compare2 && has_equals)
        {
            VMP_END;
            return true;
        }
        if (has_plugin_export && (has_compare2 || has_equals))
        {
            VMP_END;
            return true;
        }
    }

    {
        int seg_count = get_segm_qty();
        int aida_section_hits = 0;
        for (int i = 0; i < seg_count; ++i)
        {
            segment_t* seg = getnseg(i);
            if (!seg) continue;
            qstring sname;
            if (get_segm_name(&sname, seg) > 0)
            {
                std::string sn(sname.c_str());
                std::transform(sn.begin(), sn.end(), sn.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (sn.find(OBFSTR(".aida")) != std::string::npos)
                    ++aida_section_hits;
            }
        }
        if (aida_section_hits >= 2)
        {
            VMP_END;
            return true;
        }
    }

    {
        size_t str_count = get_strlist_qty();
        int aida_string_hits = 0;
        static const std::vector<std::string> str_fingerprints = {
            OBFSTR("aida mcp"),
            OBFSTR("agent tools"),
            OBFSTR("ai_assistant.cfg"),
            OBFSTR("license_validated_at"),
            OBFSTR("copilot-api@latest"),
        };
        for (size_t i = 0; i < str_count && i < 5000; ++i)
        {
            string_info_t si;
            if (!get_strlist_item(&si, i))
                continue;
            if (si.length > 4096 || si.length == 0)
                continue;
            qstring qbuf;
            if (get_strlit_contents(&qbuf, si.ea, si.length, si.type) <= 0)
                continue;
            std::string s(qbuf.c_str());
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            for (const auto& fp : str_fingerprints)
            {
                if (s.find(fp) != std::string::npos)
                {
                    ++aida_string_hits;
                    break;
                }
            }
            if (aida_string_hits >= 2)
            {
                VMP_END;
                return true;
            }
        }
    }

    VMP_END;
    return false;
}

inline bool verify_code_integrity()
{
#ifdef __NT__
    VMP_VIRT("code_integrity");
    static const BYTE* cached_text_start = nullptr;
    static DWORD       cached_text_size  = 0;

    if (!cached_text_start)
    {
        auto& api = detail::apis();
        api.resolve();

        HMODULE hModule = nullptr;
        if (api.pGetModuleHandleExW)
        {
            api.pGetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&verify_code_integrity),
                &hModule);
        }
        if (!hModule)
            return true;

        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(hModule) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        std::string text_sec = OBFSTR(".text");
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        {
            if (std::memcmp(sec->Name, text_sec.c_str(), text_sec.size()) == 0)
            {
                cached_text_start = reinterpret_cast<BYTE*>(hModule)
                                  + sec->VirtualAddress;
                cached_text_size  = sec->Misc.VirtualSize;
                break;
            }
        }
    }

    if (!cached_text_start || cached_text_size == 0)
        return true;

    uint64_t hash = 14695981039346656037ULL;
    for (DWORD j = 0; j < cached_text_size; ++j)
    {
        hash ^= cached_text_start[j];
        hash *= 1099511628211ULL;
    }

    static volatile LONG64 expected_hash = 0;
    LONG64 current = InterlockedCompareExchange64(&expected_hash, 0, 0);
    if (current == 0)
    {
        InterlockedExchange64(&expected_hash, static_cast<LONG64>(hash));
        VMP_END;
        return true;
    }
    bool ok = static_cast<uint64_t>(current) == hash;
    VMP_END;
    return ok;
#else
    return true;
#endif
}

inline bool detect_analysis_modules()
{
#ifdef __NT__
    VMP_VIRT("detect_modules");

    const std::wstring suspicious[] = {
        WOBFSTR(L"ScyllaHide32.dll"),
        WOBFSTR(L"ScyllaHide64.dll"),
        WOBFSTR(L"HookLibraryx64.dll"),
        WOBFSTR(L"HookLibraryx86.dll"),
        WOBFSTR(L"TitanHide.dll"),
        WOBFSTR(L"SharpOD_x64.dll"),
        WOBFSTR(L"SharpOD_x86.dll"),
        WOBFSTR(L"PhantOm.dll"),
        WOBFSTR(L"vehdebug.dll"),
        WOBFSTR(L"dbghelp_custom.dll"),
        WOBFSTR(L"SbieDll.dll"),
        WOBFSTR(L"snxhk.dll"),
        WOBFSTR(L"cmdvrt64.dll"),
    };

    for (const auto& name : suspicious)
    {
        if (GetModuleHandleW(name.c_str()) != nullptr)
        {
            VMP_END;
            return true;
        }
    }

    VMP_END;
    return false;
#else
    return false;
#endif
}

inline int idaapi protection_timer_cb(void* /*ud*/)
{
    VMP_MUT("protection_timer");

    if (detect_debugger())
    {
        deploy_crash_pe_to_temp();
        CRASH_HARD();
    }

    if (!verify_code_integrity())
    {
        deploy_crash_pe_to_temp();
        CRASH_HARD();
    }

    if (VMP_IS_DEBUGGER(false))
    {
        deploy_crash_pe_to_temp();
        CRASH_HARD();
    }

    if (is_self_analysis())
    {
        deploy_crash_pe_to_temp();
        CRASH_HARD();
    }

    if (detect_analysis_modules())
    {
        CRASH_HARD();
    }

    VMP_END;
    return 15000;
}

inline void start_protection_timer()
{
    verify_code_integrity();
    register_timer(15000, protection_timer_cb, nullptr);
}

#ifdef __NT__
inline void dllmain_guard()
{
    VMP_ULTRA("dllmain_guard");

    {
        volatile unsigned char sink = 0;
        sink ^= s_anti_disasm_0[0];
        sink ^= s_anti_disasm_1[0];
        sink ^= s_anti_disasm_2[0];
        sink ^= s_anti_disasm_3[0];
        sink ^= s_anti_disasm_4[0];
        sink ^= s_anti_disasm_5[0];
        sink ^= s_anti_disasm_6[0];
        sink ^= s_anti_ida_crash_stubs[0];
        sink ^= s_anti_ida_aligned_stubs[0];
        sink ^= s_anti_ida_exotic_stubs[0];
        sink ^= s_anti_ida_mixed_stubs[0];
        sink ^= s_anti_ida_til_stubs[0];
        (void)sink;
    }

    if (!is_ida_host_process())
    {
        CRASH_HARD();
    }

    if (is_blocked_analysis_tool())
    {
        CRASH_HARD();
    }

    if (detail::apis().pIsDebuggerPresent == nullptr)
        detail::apis().resolve();

    if (detect_debugger())
    {
        CRASH_HARD();
    }

    hide_thread_from_debugger();

    VMP_END;
}
#endif

inline void init_guard()
{
    VMP_ULTRA("init_guard");

    if (is_self_analysis())
    {
        deploy_crash_pe_to_temp();
        CRASH_HARD();
    }

    if (detect_debugger())
    {
        deploy_crash_pe_to_temp();
        CRASH_HARD();
    }

    if (detect_analysis_modules())
    {
        CRASH_HARD();
    }

    hide_thread_from_debugger();

    start_protection_timer();

#ifdef AIDA_USE_VMP
    __try {
        __HrLoadAllImportsForDll("VMProtectSDK64.dll");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
#endif

    erase_pe_header();

    unlink_module_from_peb();

    VMP_END;
}

} // namespace anti_re
