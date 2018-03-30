#include "qemu/osdep.h"
#include "qemu-common.h"

/* Win32 has its own inline stub */
#if !defined _WIN32 && !defined SWITCH
bool is_daemonized(void)
{
    return false;
}
#endif
