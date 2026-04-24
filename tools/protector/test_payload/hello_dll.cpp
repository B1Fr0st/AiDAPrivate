#include <cstdio>
#include <windows.h>

thread_local int g_dll_tls = 0;

extern "C" __declspec(dllexport) int aida_hello_add(int a, int b) {
    ++g_dll_tls;
    return a + b + g_dll_tls;
}

extern "C" __declspec(dllexport) const char* aida_hello_greeting() {
    return "hello from protected dll";
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE h = CreateFileW(L"aida_hello_dll_attach.log",
                               GENERIC_WRITE, FILE_SHARE_READ,
                               nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            const char msg[] = "DLL_PROCESS_ATTACH ok\r\n";
            DWORD w = 0;
            WriteFile(h, msg, sizeof(msg) - 1, &w, nullptr);
            CloseHandle(h);
        }
    }
    return TRUE;
}
