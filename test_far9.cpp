#define __NT__
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#  undef small
#endif
#ifdef near
#  undef near
#endif
#ifdef far
#  undef far
#endif
#ifdef FAR
#  undef FAR
#  define FAR
#endif
#ifdef NEAR
#  undef NEAR
#  define NEAR
#endif
#ifdef pascal
#  undef pascal
#endif
#ifdef cdecl
#  undef cdecl
#endif

#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "architecture.hh"
#include "action.hh"
#include "funcdata.hh"
#include "printc.hh"
#pragma warning(pop)

#include <zlib.h>
int main() { return 0; }
