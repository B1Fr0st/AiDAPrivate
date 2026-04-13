#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef far
#undef FAR
#define FAR
typedef unsigned char Byte;
typedef Byte FAR Bytef;
int main() { return 0; }
