#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <cstdint>

#pragma section(".aidx", read, execute)

#pragma comment(linker, "/SECTION:.aidx,ER")

#pragma code_seg(".aidx")

static constexpr uint64_t AIDA_ENCRYPT_SEED = 0xA1DAC0DEDEADBEEFULL;

__declspec(noinline)
void NTAPI aida_section_decrypt_callback(
    PVOID  dll_handle,
    DWORD  reason,
    PVOID  /*reserved*/)
{
    if (reason != DLL_PROCESS_ATTACH)
        return;

    BYTE* base = static_cast<BYTE*>(dll_handle);

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    uint64_t seed = AIDA_ENCRYPT_SEED;

#ifdef _WIN64
    auto* peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto* peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

    if (peb)
    {
        if (peb->BeingDebugged)
            seed ^= 0xFFFFFFFFFFFFFFFFULL;

#ifdef _WIN64
        constexpr size_t kNtGlobalFlagOff = 0xBC;
#else
        constexpr size_t kNtGlobalFlagOff = 0x68;
#endif
        ULONG gflags = *reinterpret_cast<ULONG*>(
            reinterpret_cast<BYTE*>(peb) + kNtGlobalFlagOff);
        if (gflags & 0x70u)
            seed ^= 0xFFFFFFFFFFFFFFFFULL;
    }

    BYTE key[256];
    {
        uint64_t state = seed;
        for (int i = 0; i < 256; ++i)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            key[i] = static_cast<BYTE>(state >> 56);
        }
    }

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        if (sec->Name[0] == '.'  && sec->Name[1] == 't' &&
            sec->Name[2] == 'e'  && sec->Name[3] == 'x' &&
            sec->Name[4] == 't'  && sec->Name[5] == '\0')
        {
            BYTE* code      = base + sec->VirtualAddress;
            DWORD code_size = sec->Misc.VirtualSize;

            DWORD old_prot = 0;
            VirtualProtect(code, code_size, PAGE_EXECUTE_READWRITE, &old_prot);

            for (DWORD j = 0; j < code_size; ++j)
                code[j] ^= key[j % 256];

            DWORD ignored = 0;
            VirtualProtect(code, code_size, old_prot, &ignored);

            FlushInstructionCache(GetCurrentProcess(), code, code_size);

            volatile BYTE* vk = key;
            for (int k = 0; k < 256; ++k)
                vk[k] = 0;

            break;
        }
    }

    {
        static constexpr uint64_t RDATA_SEED_BASE = 0xD4A7B3C2E1F05896ULL;
        uint64_t rseed = RDATA_SEED_BASE;

        if (peb)
        {
            if (peb->BeingDebugged)
                rseed ^= 0xFFFFFFFFFFFFFFFFULL;

#ifdef _WIN64
            constexpr size_t kRdGFlagOff = 0xBC;
#else
            constexpr size_t kRdGFlagOff = 0x68;
#endif
            ULONG rg = *reinterpret_cast<ULONG*>(
                reinterpret_cast<BYTE*>(peb) + kRdGFlagOff);
            if (rg & 0x70u)
                rseed ^= 0xFFFFFFFFFFFFFFFFULL;
        }

        BYTE rkey[256];
        {
            uint64_t st = rseed;
            for (int i = 0; i < 256; ++i)
            {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                rkey[i] = static_cast<BYTE>(st >> 56);
            }
        }

        auto* rsec = IMAGE_FIRST_SECTION(nt);
        for (WORD ri = 0; ri < nt->FileHeader.NumberOfSections; ++ri, ++rsec)
        {
            if (rsec->Name[0] == '.'  && rsec->Name[1] == 'r' &&
                rsec->Name[2] == 'd'  && rsec->Name[3] == 'a' &&
                rsec->Name[4] == 't'  && rsec->Name[5] == 'a')
            {
                BYTE* rd      = base + rsec->VirtualAddress;
                DWORD rd_size = rsec->Misc.VirtualSize;
                DWORD rd_rva  = rsec->VirtualAddress;
                DWORD rd_end  = rd_rva + rd_size;

                DWORD reloc_rva = 0, reloc_sz = 0;
                if (nt->OptionalHeader.NumberOfRvaAndSizes > 5)
                {
                    reloc_rva = nt->OptionalHeader.DataDirectory[5].VirtualAddress;
                    reloc_sz  = nt->OptionalHeader.DataDirectory[5].Size;
                }

                struct { DWORD lo, hi; } crit[1024];
                int n_crit = 0;

                auto add_crit = [&](DWORD rva, DWORD size) {
                    if (rva == 0 || size == 0)         return;
                    if (rva + size <= rd_rva)           return;
                    if (rva >= rd_end)                  return;
                    if (n_crit >= 1024)                 return;
                    crit[n_crit].lo = rva;
                    crit[n_crit].hi = rva + size;
                    ++n_crit;
                };

                auto skip_str = [&](DWORD rva) {
                    if (rva < rd_rva || rva >= rd_end) return;
                    DWORD p = rva;
                    while (p < rd_end && (base + p)[0] != 0)
                        ++p;
                    add_crit(rva, p - rva + 1u);
                };

                DWORD n_rvas = nt->OptionalHeader.NumberOfRvaAndSizes;
#                ifdef _WIN64
                auto crit_dir = [&](DWORD idx) -> const IMAGE_DATA_DIRECTORY* {
                    if (idx >= n_rvas) return nullptr;
                    return &nt->OptionalHeader.DataDirectory[idx];
                };
#                else
                auto crit_dir = [&](DWORD idx) -> const IMAGE_DATA_DIRECTORY* {
                    if (idx >= n_rvas) return nullptr;
                    return &nt->OptionalHeader.DataDirectory[idx];
                };
#                endif

                auto add_dir = [&](DWORD idx) {
                    auto* d = crit_dir(idx);
                    if (d) add_crit(d->VirtualAddress, d->Size);
                };

                add_dir(0);
                if (n_rvas > 0 && crit_dir(0) && crit_dir(0)->VirtualAddress)
                {
                    DWORD e_rva = crit_dir(0)->VirtualAddress;
                    if (rd_rva <= e_rva && e_rva + 40 <= rd_end)
                    {
                        BYTE* ed = base + e_rva;
                        DWORD n_names   = *reinterpret_cast<DWORD*>(ed + 24);
                        DWORD nptr_rva  = *reinterpret_cast<DWORD*>(ed + 32);
                        DWORD ord_rva   = *reinterpret_cast<DWORD*>(ed + 36);
                        add_crit(nptr_rva, n_names * 4u);
                        add_crit(ord_rva,  n_names * 2u);
                    }
                }

                add_dir(1);
                if (n_rvas > 1 && crit_dir(1) && crit_dir(1)->VirtualAddress)
                {
                    DWORD imp_rva = crit_dir(1)->VirtualAddress;
                    for (DWORD di = 0; ; ++di)
                    {
                        DWORD drva = imp_rva + di * 20u;
                        if (drva + 20u > rd_end) break;
                        BYTE* desc = base + drva;
                        DWORD orig_thunk = *reinterpret_cast<DWORD*>(desc +  0);
                        DWORD name_rva2  = *reinterpret_cast<DWORD*>(desc + 12);
                        DWORD iat_rva2   = *reinterpret_cast<DWORD*>(desc + 16);
                        if (orig_thunk == 0 && name_rva2 == 0 && iat_rva2 == 0) break;

                        skip_str(name_rva2);

                        DWORD ilt_rva = orig_thunk ? orig_thunk : iat_rva2;
#                        ifdef _WIN64
                        DWORD thunk_sz = 8;
                        DWORD ord_flag = 0x80000000u;
#                        else
                        DWORD thunk_sz = 4;
                        DWORD ord_flag = 0x80000000u;
#                        endif
                        if (ilt_rva)
                        {
                            for (DWORD ti = 0; ; ++ti)
                            {
                                DWORD t_rva = ilt_rva + ti * thunk_sz;
                                if (t_rva + thunk_sz > rd_end + (rd_end - rd_rva)) break;
                                add_crit(t_rva, thunk_sz);
                                if (t_rva < rd_rva || t_rva + thunk_sz > rd_end) break;
                                DWORD tv32 = *reinterpret_cast<DWORD*>(base + t_rva);
                                if (tv32 == 0) break;
                                if (!(tv32 & ord_flag))
                                {
                                    DWORD ibn_rva = tv32 & 0x7FFFFFFFu;
                                    if (ibn_rva >= rd_rva && ibn_rva < rd_end)
                                    {
                                        add_crit(ibn_rva, 2);
                                        skip_str(ibn_rva + 2u);
                                    }
                                }
                            }
                        }
                    }
                }

                add_dir(9);

                add_dir(10);

                add_dir(12);

                add_dir(13);
                if (n_rvas > 13 && crit_dir(13) && crit_dir(13)->VirtualAddress)
                {
                    DWORD drva2 = crit_dir(13)->VirtualAddress;
                    for (DWORD di = 0; ; ++di)
                    {
                        DWORD d2rva = drva2 + di * 32u;
                        if (d2rva + 32u > rd_end + (rd_end - rd_rva)) break;
                        if (d2rva < rd_rva || d2rva + 32u > rd_end) break;
                        BYTE*  d2   = base + d2rva;
                        DWORD dns   = *reinterpret_cast<DWORD*>(d2 +  4);
                        DWORD diat  = *reinterpret_cast<DWORD*>(d2 + 12);
                        DWORD dint  = *reinterpret_cast<DWORD*>(d2 + 16);
                        if (dns == 0 && diat == 0) break;
                        skip_str(dns);
                        add_crit(diat, 0x200u);
                        add_crit(dint, 0x200u);
                    }
                }

                for (int si = 1; si < n_crit; ++si)
                {
                    auto tmp = crit[si];
                    int sj = si - 1;
                    while (sj >= 0 && crit[sj].lo > tmp.lo)
                    {
                        crit[sj + 1] = crit[sj];
                        --sj;
                    }
                    crit[sj + 1] = tmp;
                }

                auto is_crit = [&](DWORD rva) -> bool {
                    int lo2 = 0, hi2 = n_crit - 1;
                    while (lo2 <= hi2)
                    {
                        int mid = lo2 + (hi2 - lo2) / 2;
                        if (crit[mid].hi <= rva)
                            lo2 = mid + 1;
                        else if (crit[mid].lo > rva)
                            hi2 = mid - 1;
                        else
                            return true;
                    }
                    return false;
                };

                DWORD rprot = 0;
                VirtualProtect(rd, rd_size, PAGE_READWRITE, &rprot);

                for (DWORD pg = rd_rva & ~0xFFFu; pg < rd_end; pg += 0x1000)
                {
                    BYTE skip2[512];
                    for (int z = 0; z < 512; ++z)
                        skip2[z] = 0;

                    if (reloc_rva != 0 && reloc_sz != 0)
                    {
                        BYTE* rp = base + reloc_rva;
                        BYTE* re = rp + reloc_sz;
                        while (rp + 8 <= re)
                        {
                            auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(rp);
                            if (blk->SizeOfBlock < 8)
                                break;
                            if (blk->VirtualAddress == pg)
                            {
                                DWORD cnt = (blk->SizeOfBlock - 8) / 2;
                                WORD* ent = reinterpret_cast<WORD*>(rp + 8);
                                for (DWORD e = 0; e < cnt; ++e)
                                {
                                    WORD ty  = ent[e] >> 12;
                                    WORD off = ent[e] & 0xFFF;
                                    int msz = (ty == 10) ? 8
                                            : (ty == 3)  ? 4 : 0;
                                    for (int b = 0; b < msz; ++b)
                                    {
                                        WORD pos = off + static_cast<WORD>(b);
                                        if (pos < 0x1000)
                                            skip2[pos >> 3] |=
                                                static_cast<BYTE>(1u << (pos & 7));
                                    }
                                }
                                break;
                            }
                            rp += blk->SizeOfBlock;
                        }
                    }

                    DWORD pg_lo = (pg >= rd_rva) ? 0 : (rd_rva - pg);
                    DWORD pg_hi = ((pg + 0x1000) <= rd_end)
                                ? 0x1000 : (rd_end - pg);
                    for (DWORD j = pg_lo; j < pg_hi; ++j)
                    {
                        if (skip2[j >> 3] & (1u << (j & 7)))
                            continue;
                        DWORD soff = (pg - rd_rva) + j;
                        if (is_crit(rd_rva + soff))
                            continue;
                        rd[soff] ^= rkey[soff % 256];
                    }
                }

                DWORD rign = 0;
                VirtualProtect(rd, rd_size, rprot, &rign);
                break;
            }
        }

        volatile BYTE* vrk = rkey;
        for (int k = 0; k < 256; ++k)
            vrk[k] = 0;
    }

    {
        static constexpr uint64_t AIDAB_SEED_BASE = 0xB7E2A1D4F3C65089ULL;
        uint64_t abseed = AIDAB_SEED_BASE;

        if (peb)
        {
            if (peb->BeingDebugged)
                abseed ^= 0xFFFFFFFFFFFFFFFFULL;

#ifdef _WIN64
            constexpr size_t kAbGFlagOff = 0xBC;
#else
            constexpr size_t kAbGFlagOff = 0x68;
#endif
            ULONG abg = *reinterpret_cast<ULONG*>(
                reinterpret_cast<BYTE*>(peb) + kAbGFlagOff);
            if (abg & 0x70u)
                abseed ^= 0xFFFFFFFFFFFFFFFFULL;
        }

        BYTE abkey[256];
        {
            uint64_t st = abseed;
            for (int i = 0; i < 256; ++i)
            {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                abkey[i] = static_cast<BYTE>(st >> 56);
            }
        }

        auto* absec = IMAGE_FIRST_SECTION(nt);
        for (WORD abi = 0; abi < nt->FileHeader.NumberOfSections; ++abi, ++absec)
        {
            if (absec->Name[0] == '.'  && absec->Name[1] == 'a' &&
                absec->Name[2] == 'i'  && absec->Name[3] == 'd' &&
                absec->Name[4] == 'a'  && absec->Name[5] == 'B')
            {
                BYTE* ab      = base + absec->VirtualAddress;
                DWORD ab_size = absec->Misc.VirtualSize;

                DWORD abprot = 0;
                VirtualProtect(ab, ab_size, PAGE_READWRITE, &abprot);

                for (DWORD j = 0; j < ab_size; ++j)
                    ab[j] ^= abkey[j % 256];

                DWORD abign = 0;
                VirtualProtect(ab, ab_size, abprot, &abign);
                break;
            }
        }

        volatile BYTE* vab = abkey;
        for (int k = 0; k < 256; ++k)
            vab[k] = 0;
    }
}

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

#pragma section(".CRT$XLA", read)
__declspec(allocate(".CRT$XLA"))
PIMAGE_TLS_CALLBACK p_aida_decrypt_tls_cb =
    reinterpret_cast<PIMAGE_TLS_CALLBACK>(aida_section_decrypt_callback);

#pragma code_seg()

#endif // _WIN32
