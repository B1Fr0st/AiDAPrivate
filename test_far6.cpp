#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef far
#ifdef FAR
#pragma message("FAR is still defined after undef far")
#else
#pragma message("FAR is GONE after undef far")
#endif
int main() { return 0; }
