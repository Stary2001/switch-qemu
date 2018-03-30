/*
 * event notifier support
 *
 * Copyright Red Hat, Inc. 2010
 *
 * Authors:
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/cutils.h"
#include "qemu/event_notifier.h"
#include "qemu/main-loop.h"

/*
 * Initialize @e with existing file descriptor @fd.
 * @fd must be a genuine eventfd object, emulation with pipe won't do.
 */
void event_notifier_init_fd(EventNotifier *e, int fd)
{
}

int event_notifier_init(EventNotifier *e, int active)
{
    errno = ENOSYS;
    return -1;
}

void event_notifier_cleanup(EventNotifier *e)
{
}

int event_notifier_get_fd(const EventNotifier *e)
{
    return 0;
}

int event_notifier_set(EventNotifier *e)
{
    return 0;
}

int event_notifier_test_and_clear(EventNotifier *e)
{
    return 0;
}