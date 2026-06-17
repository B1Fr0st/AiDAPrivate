#include <stdio.h>
#include <windows.h>

int main(void) {
    printf("AIDA_PROTECTOR_DIAG_START pid=%lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);
    Sleep(250);
    printf("AIDA_PROTECTOR_DIAG_PASS\n");
    fflush(stdout);
    return 37;
}
