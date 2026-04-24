#include <cstdio>
#include <windows.h>

typedef int  (*pfn_add_t)(int, int);
typedef const char* (*pfn_greet_t)();

int main() {
    HMODULE h = LoadLibraryW(L"aida_hello_dll.dll");
    if (h == nullptr) {
        std::fprintf(stderr, "LoadLibrary failed: %lu\n",
                     static_cast<unsigned long>(GetLastError()));
        return 1;
    }
    auto add_fn = reinterpret_cast<pfn_add_t>(
        GetProcAddress(h, "aida_hello_add"));
    auto greet_fn = reinterpret_cast<pfn_greet_t>(
        GetProcAddress(h, "aida_hello_greeting"));
    if (add_fn == nullptr || greet_fn == nullptr) {
        std::fprintf(stderr, "GetProcAddress failed\n");
        return 2;
    }
    int sum = add_fn(40, 2);
    const char* g = greet_fn();
    std::printf("dll loaded: greeting='%s' sum=%d\n",
                g != nullptr ? g : "(null)", sum);
    return sum;
}
