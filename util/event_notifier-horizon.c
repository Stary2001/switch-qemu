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

#include "switch_wrapper.h"

int event_notifier_init(EventNotifier *e, int active)
{
	e->event = malloc(sizeof(struct UEvent));
	ueventCreate(e->event, false);
	return 0;
}

void event_notifier_cleanup(EventNotifier *e)
{
	free(e->event);
}

int event_notifier_set(EventNotifier *e)
{
    ueventSignal(e->event);
    return 0;
}

int event_notifier_test_and_clear(EventNotifier *e)
{
    Result rc = waitSingle(waiterForUEvent(e->event), -1);
    if(rc != 0xea01)
    {
        ueventClear(e->event);
        return true;
    }
    return false;
}

void* event_notifier_get_event(EventNotifier *e)
{
    return e->event;
}