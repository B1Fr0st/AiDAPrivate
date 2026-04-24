#include <cstdio>
#include <cstdlib>
#include <windows.h>

thread_local int g_tls_counter = 0;

int main() {
    std::printf("aida_hello_loop: start pid=%lu\n",
                static_cast<unsigned long>(GetCurrentProcessId()));
    std::fflush(stdout);

    for (;;) {
        ++g_tls_counter;
        std::printf("hello world %d\n", g_tls_counter);
        std::fflush(stdout);
        Sleep(500);
    }

    return 0;
}
