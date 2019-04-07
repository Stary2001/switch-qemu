/*
 * QEMU aio implementation
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "block/block.h"
#include "qemu/rcu_queue.h"
#include "qemu/sockets.h"
#include "qemu/cutils.h"
#include "trace.h"

#include "switch_wrapper.h"

struct AioHandler {
    EventNotifier *e;
    IOHandler *io_read;
    IOHandler *io_write;
    EventNotifierHandler *io_notify;
    GPollFD pfd;
    int deleted;
    void *opaque;
    bool is_external;
    QLIST_ENTRY(AioHandler) node;
};

void aio_set_fd_handler(AioContext *ctx,
                        int fd,
                        bool is_external,
                        IOHandler *io_read,
                        IOHandler *io_write,
                        AioPollFn *io_poll,
                        void *opaque)
{
    printf("aio_set_fd_handler unimplemented\n");
    abort();
}

void aio_set_fd_poll(AioContext *ctx, int fd,
                     IOHandler *io_poll_begin,
                     IOHandler *io_poll_end)
{
    /* Not implemented */
}

void aio_set_event_notifier(AioContext *ctx,
                            EventNotifier *e,
                            bool is_external,
                            EventNotifierHandler *io_notify,
                            AioPollFn *io_poll)
{
    AioHandler *node;

    qemu_lockcnt_lock(&ctx->list_lock);
    QLIST_FOREACH(node, &ctx->aio_handlers, node) {
        if (node->e == e && !node->deleted) {
            break;
        }
    }

    /* Are we deleting the fd handler? */
    if (!io_notify) {
        if (node) {
            g_source_remove_poll(&ctx->source, &node->pfd);

            /* aio_poll is in progress, just mark the node as deleted */
            if (qemu_lockcnt_count(&ctx->list_lock)) {
                node->deleted = 1;
                node->pfd.revents = 0;
            } else {
                /* Otherwise, delete it for real.  We can't just mark it as
                 * deleted because deleted nodes are only cleaned up after
                 * releasing the list_lock.
                 */
                QLIST_REMOVE(node, node);
                g_free(node);
            }
        }
    } else {
        if (node == NULL) {
            /* Alloc and insert if it's not already there */
            node = g_new0(AioHandler, 1);
            node->e = e;
            node->pfd.fd = (uintptr_t)event_notifier_get_event(e);
            node->pfd.events = G_IO_IN;
            node->is_external = is_external;
            QLIST_INSERT_HEAD_RCU(&ctx->aio_handlers, node, node);

            g_source_add_poll(&ctx->source, &node->pfd);
        }
        /* Update handler with latest information */
        node->io_notify = io_notify;
    }

    qemu_lockcnt_unlock(&ctx->list_lock);
    aio_notify(ctx);
}

void aio_set_event_notifier_poll(AioContext *ctx,
                                 EventNotifier *notifier,
                                 EventNotifierHandler *io_poll_begin,
                                 EventNotifierHandler *io_poll_end)
{
    /* Not implemented */
}

bool aio_prepare(AioContext *ctx)
{
    return true;
}

bool aio_pending(AioContext *ctx)
{
    AioHandler *node;
    bool result = false;

    /*
     * We have to walk very carefully in case aio_set_fd_handler is
     * called while we're walking.
     */
    qemu_lockcnt_inc(&ctx->list_lock);
    QLIST_FOREACH_RCU(node, &ctx->aio_handlers, node) {
        if (node->pfd.revents && node->io_notify) {
            result = true;
            break;
        }

        if ((node->pfd.revents & G_IO_IN) && node->io_read) {
            result = true;
            break;
        }
        if ((node->pfd.revents & G_IO_OUT) && node->io_write) {
            result = true;
            break;
        }
    }

    qemu_lockcnt_dec(&ctx->list_lock);
    return result;
}

static bool aio_dispatch_handlers(AioContext *ctx, UEvent *event)
{
    AioHandler *node;
    bool progress = false;
    AioHandler *tmp;

    /*
     * We have to walk very carefully in case aio_set_fd_handler is
     * called while we're walking.
     */
    QLIST_FOREACH_SAFE_RCU(node, &ctx->aio_handlers, node, tmp) {
        int revents = node->pfd.revents;

        if (!node->deleted &&
            (revents || event_notifier_get_event(node->e) == event) &&
            node->io_notify) {
            node->pfd.revents = 0;
            node->io_notify(node->e);

            /* aio_notify() does not count as progress */
            if (node->e != &ctx->notifier) {
                progress = true;
            }
        }

        if (!node->deleted &&
            (node->io_read || node->io_write)) {
            node->pfd.revents = 0;
            if ((revents & G_IO_IN) && node->io_read) {
                node->io_read(node->opaque);
                progress = true;
            }
            if ((revents & G_IO_OUT) && node->io_write) {
                node->io_write(node->opaque);
                progress = true;
            }
        }

        if (node->deleted) {
            if (qemu_lockcnt_dec_if_lock(&ctx->list_lock)) {
                QLIST_REMOVE(node, node);
                g_free(node);
                qemu_lockcnt_inc_and_unlock(&ctx->list_lock);
            }
        }
    }

    return progress;
}

void aio_dispatch(AioContext *ctx)
{
    qemu_lockcnt_inc(&ctx->list_lock);
    aio_bh_poll(ctx);
    aio_dispatch_handlers(ctx, NULL);
    qemu_lockcnt_dec(&ctx->list_lock);
    timerlistgroup_run_timers(&ctx->tlg);
}

bool aio_poll(AioContext *ctx, bool blocking)
{
    AioHandler *node;
    UEvent *events[MAX_WAIT_OBJECTS]; // originally MAXIMUM_WAIT_OBJECTS on windows lol
    Waiter waiters[MAX_WAIT_OBJECTS];
    bool progress, have_select_revents, first;
    int count;
    uint64_t timeout;

    progress = false;

    /* aio_notify can avoid the expensive event_notifier_set if
     * everything (file descriptors, bottom halves, timers) will
     * be re-evaluated before the next blocking poll().  This is
     * already true when aio_poll is called with blocking == false;
     * if blocking == true, it is only true after poll() returns,
     * so disable the optimization now.
     */
    if (blocking) {
        atomic_add(&ctx->notify_me, 2);
    }

    qemu_lockcnt_inc(&ctx->list_lock);
    aio_prepare(ctx);

    /* fill fd sets */
    count = 0;
    QLIST_FOREACH_RCU(node, &ctx->aio_handlers, node) {
        if (!node->deleted && node->io_notify
            && aio_node_check(ctx, node->is_external)) {
            events[count] = event_notifier_get_event(node->e);
            waiters[count] = waiterForUEvent(events[count]);
            count++;
        }
    }

    first = true;

    /* ctx->notifier is always registered.  */
    assert(count > 0);

    /* Multiple iterations, all of them non-blocking except the first,
     * may be necessary to process all pending events.  After the first
     * WaitForMultipleObjects call ctx->notify_me will be decremented.
     */
    do {
        UEvent *event;
        int ret;

        timeout = blocking ? aio_compute_timeout(ctx) : 0;
        Result res = waitObjects(&ret, waiters, count, timeout);

        if (blocking) {
            assert(first);
            atomic_sub(&ctx->notify_me, 2);
        }

        if (first) {
            aio_notify_accept(ctx);
            progress |= aio_bh_poll(ctx);
            first = false;
        }

        // Very important to fail AFTER bh_poll.
        if(R_FAILED(res))
        {
            break;
        }

        /* if we have any signaled events, dispatch event */
        event = NULL;
        if (ret < count) {
            event = events[ret];
            events[ret] = events[--count];
        }

        blocking = false;

        progress |= aio_dispatch_handlers(ctx, event);
    } while (count > 0);

    qemu_lockcnt_dec(&ctx->list_lock);

    progress |= timerlistgroup_run_timers(&ctx->tlg);
    return progress;
}

void aio_context_setup(AioContext *ctx)
{
}

void aio_context_set_poll_params(AioContext *ctx, int64_t max_ns,
                                 int64_t grow, int64_t shrink, Error **errp)
{
    error_setg(errp, "AioContext polling is not implemented on Horizon");
}
