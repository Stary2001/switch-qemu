/*
 * Wrappers around mutex/cond/thread functions
 *
 * Copyright Red Hat, Inc. 2009
 *
 * Author:
 *  Marcelo Tosatti <mtosatti@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/atomic.h"
#include "qemu/notify.h"
#include "trace.h"

static bool name_threads;

void qemu_thread_naming(bool enable)
{
    name_threads = enable;

#ifndef CONFIG_THREAD_SETNAME_BYTHREAD
    /* This is a debugging option, not fatal */
    if (enable) {
        fprintf(stderr, "qemu: thread naming not supported on this host\n");
    }
#endif
}

static void error_exit(int err, const char *msg)
{
    fprintf(stderr, "qemu: %s: %s\n", msg, strerror(err));
    abort();
}

void qemu_mutex_init(QemuMutex *mutex)
{
    int err;
    mutex->initialized = true;
}

void qemu_mutex_destroy(QemuMutex *mutex)
{
    assert(mutex->initialized);
    mutex->initialized = false;
}

void qemu_mutex_lock(QemuMutex *mutex)
{
    assert(mutex->initialized);


    trace_qemu_mutex_locked(mutex);
}

int qemu_mutex_trylock(QemuMutex *mutex)
{
    assert(mutex->initialized);
    return 0;
}

void qemu_mutex_unlock(QemuMutex *mutex)
{
    assert(mutex->initialized);
    trace_qemu_mutex_unlocked(mutex);
}

void qemu_rec_mutex_init(QemuRecMutex *mutex)
{
    mutex->initialized = true;
}

void qemu_rec_mutex_destroy(QemuRecMutex *mutex)
{
    assert(mutex->initialized);
    mutex->initialized = false;
}

void qemu_rec_mutex_lock(QemuRecMutex *mutex)
{
    assert(mutex->initialized);
}

int qemu_rec_mutex_trylock(QemuRecMutex *mutex)
{
    assert(mutex->initialized);
}

void qemu_rec_mutex_unlock(QemuRecMutex *mutex)
{
    assert(mutex->initialized);
}

void qemu_cond_init(QemuCond *cond)
{
    cond->initialized = true;
}

void qemu_cond_destroy(QemuCond *cond)
{
    assert(cond->initialized);
    cond->initialized = false;
}

void qemu_cond_signal(QemuCond *cond)
{
    assert(cond->initialized);
}

void qemu_cond_broadcast(QemuCond *cond)
{
    assert(cond->initialized);
}

void qemu_cond_wait(QemuCond *cond, QemuMutex *mutex)
{
    assert(cond->initialized);
    trace_qemu_mutex_unlocked(mutex);

    trace_qemu_mutex_locked(mutex);
}

void qemu_sem_init(QemuSemaphore *sem, int init)
{
    sem->initialized = true;
}

void qemu_sem_destroy(QemuSemaphore *sem)
{
    assert(sem->initialized);
    sem->initialized = false;
}

void qemu_sem_post(QemuSemaphore *sem)
{
    assert(sem->initialized);
}

static void compute_abs_deadline(struct timespec *ts, int ms)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts->tv_nsec = tv.tv_usec * 1000 + (ms % 1000) * 1000000;
    ts->tv_sec = tv.tv_sec + ms / 1000;
    if (ts->tv_nsec >= 1000000000) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000;
    }
}

int qemu_sem_timedwait(QemuSemaphore *sem, int ms)
{
    assert(sem->initialized);
    return 0;
}

void qemu_sem_wait(QemuSemaphore *sem)
{
    assert(sem->initialized);
}


/* Valid transitions:
 * - free->set, when setting the event
 * - busy->set, when setting the event, followed by qemu_futex_wake
 * - set->free, when resetting the event
 * - free->busy, when waiting
 *
 * set->busy does not happen (it can be observed from the outside but
 * it really is set->free->busy).
 *
 * busy->free provably cannot happen; to enforce it, the set->free transition
 * is done with an OR, which becomes a no-op if the event has concurrently
 * transitioned to free or busy.
 */

#define EV_SET         0
#define EV_FREE        1
#define EV_BUSY       -1

void qemu_event_init(QemuEvent *ev, bool init)
{
    ev->value = (init ? EV_SET : EV_FREE);
    ev->initialized = true;
}

void qemu_event_destroy(QemuEvent *ev)
{
    assert(ev->initialized);
    ev->initialized = false;
}

void qemu_event_set(QemuEvent *ev)
{
    /* qemu_event_set has release semantics, but because it *loads*
     * ev->value we need a full memory barrier here.
     */
    assert(ev->initialized);
    smp_mb();
    if (atomic_read(&ev->value) != EV_SET) {
        if (atomic_xchg(&ev->value, EV_SET) == EV_BUSY) {
            /* There were waiters, wake them up.  */
        }
    }
}

void qemu_event_reset(QemuEvent *ev)
{
    unsigned value;

    assert(ev->initialized);
    value = atomic_read(&ev->value);
    smp_mb_acquire();
    if (value == EV_SET) {
        /*
         * If there was a concurrent reset (or even reset+wait),
         * do nothing.  Otherwise change EV_SET->EV_FREE.
         */
        atomic_or(&ev->value, EV_FREE);
    }
}

void qemu_event_wait(QemuEvent *ev)
{
    unsigned value;

    assert(ev->initialized);
    value = atomic_read(&ev->value);
    smp_mb_acquire();
    if (value != EV_SET) {
        if (value == EV_FREE) {
            /*
             * Leave the event reset and tell qemu_event_set that there
             * are waiters.  No need to retry, because there cannot be
             * a concurrent busy->free transition.  After the CAS, the
             * event will be either set or busy.
             */
            if (atomic_cmpxchg(&ev->value, EV_FREE, EV_BUSY) == EV_SET) {
                return;
            }
        }
    }
}

//static pthread_key_t exit_key;

union NotifierThreadData {
    void *ptr;
    NotifierList list;
};
QEMU_BUILD_BUG_ON(sizeof(union NotifierThreadData) != sizeof(void *));

void qemu_thread_atexit_add(Notifier *notifier)
{
    union NotifierThreadData ntd;
    //ntd.ptr = pthread_getspecific(exit_key);
    //notifier_list_add(&ntd.list, notifier);
    //pthread_setspecific(exit_key, ntd.ptr);
}

void qemu_thread_atexit_remove(Notifier *notifier)
{
    union NotifierThreadData ntd;
    ///ntd.ptr = pthread_getspecific(exit_key);
    ///notifier_remove(notifier);
    ///pthread_setspecific(exit_key, ntd.ptr);
}

static void qemu_thread_atexit_run(void *arg)
{
    union NotifierThreadData ntd = { .ptr = arg };
    notifier_list_notify(&ntd.list, NULL);
}

/*
static void __attribute__((constructor)) qemu_thread_atexit_init(void)
{
    pthread_key_create(&exit_key, qemu_thread_atexit_run);
}
*/

/* Attempt to set the threads name; note that this is for debug, so
 * we're not going to fail if we can't set it.
 */
static void qemu_thread_set_name(QemuThread *thread, const char *name)
{
}

void qemu_thread_create(QemuThread *thread, const char *name,
                       void *(*start_routine)(void*),
                       void *arg, int mode)
{
    /*
    sigset_t set, oldset;
    int err;
    pthread_attr_t attr;

    err = pthread_attr_init(&attr);
    if (err) {
        error_exit(err, __func__);
    }

    /* Leave signal handling to the iothread.  */
    /*sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);
    err = pthread_create(&thread->thread, &attr, start_routine, arg);
    if (err)
        error_exit(err, __func__);

    if (name_threads) {
        qemu_thread_set_name(thread, name);
    }

    if (mode == QEMU_THREAD_DETACHED) {
        err = pthread_detach(thread->thread);
        if (err) {
            error_exit(err, __func__);
        }
    }
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);

    pthread_attr_destroy(&attr);*/
}

void qemu_thread_get_self(QemuThread *thread)
{
    //thread->thread = pthread_self();
}

bool qemu_thread_is_self(QemuThread *thread)
{/*
   return pthread_equal(pthread_self(), thread->thread);
*/
return false;
}

void qemu_thread_exit(void *retval)
{
    //pthread_exit(retval);
}

void *qemu_thread_join(QemuThread *thread)
{
    /*int err;
    void *ret;

    err = pthread_join(thread->thread, &ret);
    if (err) {
        error_exit(err, __func__);
    }
    return ret;*/

    return NULL;
}
