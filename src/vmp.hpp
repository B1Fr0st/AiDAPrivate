#pragma once

#ifdef AIDA_USE_VMP

#include <VMProtectSDK.h>

#define VMP_ULTRA(name)       VMProtectBeginUltra(name)
#define VMP_VIRT(name)        VMProtectBeginVirtualization(name)
#define VMP_MUT(name)         VMProtectBeginMutation(name)
#define VMP_ULTRA_LOCK(name)  VMProtectBeginUltraLockByKey(name)
#define VMP_END               VMProtectEnd()

#define VMP_IS_DEBUGGER(check_kernel)  (VMProtectIsDebuggerPresent(check_kernel) != 0)
#define VMP_IS_VIRTUAL_MACHINE         (VMProtectIsVirtualMachinePresent() != 0)
#define VMP_IS_PROTECTED               (VMProtectIsProtected() != 0)

#define VMP_STR_A(s)    VMProtectDecryptStringA(s)
#define VMP_STR_W(s)    VMProtectDecryptStringW(s)
#define VMP_FREE_STR(s) VMProtectFreeString(s)

#define VMP_GET_HWID(buf, size) VMProtectGetCurrentHWID(buf, size)

#else // !AIDA_USE_VMP

#define VMP_ULTRA(name)       ((void)0)
#define VMP_VIRT(name)        ((void)0)
#define VMP_MUT(name)         ((void)0)
#define VMP_ULTRA_LOCK(name)  ((void)0)
#define VMP_END               ((void)0)

#define VMP_IS_DEBUGGER(check_kernel)  (false)
#define VMP_IS_VIRTUAL_MACHINE         (false)
#define VMP_IS_PROTECTED               (false)

#define VMP_STR_A(s)    (s)
#define VMP_STR_W(s)    (s)
#define VMP_FREE_STR(s) ((void)0)

#define VMP_GET_HWID(buf, size) (0)

#endif // AIDA_USE_VMP
