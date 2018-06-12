#include "qemu/osdep.h"
#include "qemu-common.h"

/* Win32 has its own inline stub */
#if !defined _WIN32 && !defined __SWITCH__
bool is_daemonized(void)
{
    return false;
}
#endif
