#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: load_test <dll>\n"); return 1; }
    HMODULE h = LoadLibraryExA(argv[1], NULL, 0);
    DWORD err = GetLastError();
    printf("LoadLibraryExA(0): h=%p err=%lu (0x%lX)\n", (void*)h, err, err);
    if (h) FreeLibrary(h);

    h = LoadLibraryExA(argv[1], NULL, DONT_RESOLVE_DLL_REFERENCES);
    err = GetLastError();
    printf("LoadLibraryExA(DONT_RESOLVE): h=%p err=%lu (0x%lX)\n", (void*)h, err, err);
    if (h) FreeLibrary(h);

    h = LoadLibraryExA(argv[1], NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    err = GetLastError();
    printf("LoadLibraryExA(AS_IMAGE_RESOURCE): h=%p err=%lu (0x%lX)\n", (void*)h, err, err);
    if (h) FreeLibrary(h);
    return 0;
}
