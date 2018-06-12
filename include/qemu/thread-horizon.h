#ifndef QEMU_THREAD_HORIZON_H
#define QEMU_THREAD_HORIZON_H

#ifndef __SWITCH___H_INCLUDED
#define SWITCH_H_INCLUDED
#ifdef __SWITCH__
#undef BIT
#endif
#include <switch.h>
#endif

struct QemuMutex {
    Mutex lock;
    bool initialized;
};

typedef struct QemuRecMutex QemuRecMutex;
struct QemuRecMutex {
    RMutex lock;
    bool initialized;
};

void qemu_rec_mutex_destroy(QemuRecMutex *mutex);
void qemu_rec_mutex_lock(QemuRecMutex *mutex);
int qemu_rec_mutex_trylock(QemuRecMutex *mutex);
void qemu_rec_mutex_unlock(QemuRecMutex *mutex);

struct QemuCond {
    CondVar var;
    bool initialized;
};

struct QemuSemaphore {
    int sema;
    bool initialized;
};

struct QemuEvent {
    int value;
    Handle event;
    bool initialized;
};

typedef struct QemuThreadData QemuThreadData;
struct QemuThread {
    QemuThreadData *data;
    unsigned tid;
};

/* Only valid for joinable threads.  */
Thread* qemu_thread_get_handle(QemuThread *thread);

#endif
