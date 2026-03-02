#include "EmbeddedDriver.h"
#include "P2CDriverBytes.h"
#include <Windows.h>
#include <intrin.h>

unsigned char* g_P2CDriverData = nullptr;
size_t g_P2CDriverSize = 0;

static constexpr unsigned char XOR_KEY[] = {
    0x7A, 0xC3, 0x91, 0xE5, 0x3D, 0xF8, 0x46, 0xAB,
    0x1F, 0x82, 0xD7, 0x54, 0x69, 0xBE, 0x03, 0xC6
};

BOOL InitializeDriverData() {
    if (rawDataSize < 2) {
        return FALSE;
    }

    g_P2CDriverData = (unsigned char*)VirtualAlloc(
        nullptr, rawDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!g_P2CDriverData) {
        return FALSE;
    }

    for (size_t i = 0; i < rawDataSize; i++) {
        g_P2CDriverData[i] = rawData[i] ^ XOR_KEY[i % sizeof(XOR_KEY)];
    }

    if (g_P2CDriverData[0] != 'M' || g_P2CDriverData[1] != 'Z') {
        SecureZeroMemory(g_P2CDriverData, rawDataSize);
        VirtualFree(g_P2CDriverData, 0, MEM_RELEASE);
        g_P2CDriverData = nullptr;
        return FALSE;
    }

    g_P2CDriverSize = rawDataSize;
    return TRUE;
}

void ReleaseDriverData() {
    if (g_P2CDriverData) {
        SecureZeroMemory(g_P2CDriverData, g_P2CDriverSize);
        VirtualFree(g_P2CDriverData, 0, MEM_RELEASE);
        g_P2CDriverData = nullptr;
        g_P2CDriverSize = 0;
    }
}
