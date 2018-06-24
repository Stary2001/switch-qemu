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

int event_notifier_init(EventNotifier *e, int active)
{
    Result rc;
    rc = svcCreateEvent(&e->sig_handle, &e->wait_handle);
    if(R_FAILED(rc))
    {
    	return -1;
    }
    else
    {
    	return 0;
    }
}

void event_notifier_cleanup(EventNotifier *e)
{
    svcCloseHandle(e->sig_handle);
    svcCloseHandle(e->wait_handle);
    e->sig_handle = 0;
    e->wait_handle = 0;
}

int event_notifier_set(EventNotifier *e)
{
    svcSignalEvent(e->sig_handle);
    return 0;
}

int event_notifier_test_and_clear(EventNotifier *e)
{
	s32 dummy;
    Result rc;
    rc = svcWaitSynchronization(&dummy, &e->wait_handle, 1, -1);
    if (rc != 0xea01) { // timeout
        svcResetSignal(e->wait_handle);
        return true;
    }
    return false;
}
