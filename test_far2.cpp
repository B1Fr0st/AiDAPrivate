#define __NT__
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#ifdef far
int far_is_lowercase = 1;
#else
int far_is_lowercase = 0;
#endif
#ifdef FAR
int FAR_is_uppercase = 1;
#else
int FAR_is_uppercase = 0;
#endif
#include <zlib.h>
int main() { return 0; }
