#pragma once

#include <ntddk.h>
#include <bcrypt.h>

namespace kernel_crypto
{
    __forceinline NTSTATUS hmac_sha256(
        const UINT8* key, ULONG key_len,
        const UINT8* data, ULONG data_len,
        UINT8 hash_out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!NT_SUCCESS(status)) return status;

        BCRYPT_HASH_HANDLE hh = nullptr;
        status = BCryptCreateHash(alg, &hh, nullptr, 0,
            const_cast<UINT8*>(key), key_len, 0);
        if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return status; }

        status = BCryptHashData(hh, const_cast<UINT8*>(data), data_len, 0);
        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hh, hash_out, 32, 0);

        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

    __forceinline NTSTATUS sha256(
        const UINT8* data, ULONG data_len,
        UINT8 hash_out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return status;

        BCRYPT_HASH_HANDLE hh = nullptr;
        status = BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0);
        if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return status; }

        status = BCryptHashData(hh, const_cast<UINT8*>(data), data_len, 0);
        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hh, hash_out, 32, 0);

        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

    __forceinline NTSTATUS gen_random(UINT8* buf, ULONG len)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return status;

        status = BCryptGenRandom(alg, buf, len, 0);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }
}
