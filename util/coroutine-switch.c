/*
 * sigaltstack coroutine initialization code
 *
 * Copyright (C) 2006  Anthony Liguori <anthony@codemonkey.ws>
 * Copyright (C) 2011  Kevin Wolf <kwolf@redhat.com>
 * Copyright (C) 2012  Alex Barcelo <abarcelo@ac.upc.edu>
** This file is partly based on pth_mctx.c, from the GNU Portable Threads
**  Copyright (c) 1999-2006 Ralf S. Engelschall <rse@engelschall.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/coroutine_int.h"

typedef struct {
    Coroutine base;
    void *stack;
    size_t stack_size;
    uint64_t context[10];
    uint64_t sp;
    uint64_t lr;
    uint64_t initial_x0;
    CoroutineAction action;
} CoroutineSwitch;

static void coroutine_trampoline(void *co_)
{
    printf("Hello from the coroutine trampoline! we are %p\n", co_);
    Coroutine *co = co_;

    while (true) {
        co->entry(co->entry_arg);
        qemu_coroutine_switch(co, co->caller, COROUTINE_TERMINATE);
    }
}

Coroutine *qemu_coroutine_new(void)
{
    CoroutineSwitch *co = g_malloc0(sizeof(CoroutineSwitch));
    co->stack_size = COROUTINE_STACK_SIZE;
    co->stack = qemu_alloc_stack(&co->stack_size);

    co->initial_x0 = co;
    co->sp = co->stack + co->stack_size;
    co->lr = coroutine_trampoline;

    printf("new coroutine (%p) with sp=%p pc=%p\n", co, co->sp, co->lr);

    return &co->base;
}

void qemu_coroutine_delete(Coroutine *co_)
{
    CoroutineSwitch *co = DO_UPCAST(CoroutineSwitch, base, co_);
    qemu_free_stack(co->stack, co->stack_size);
    g_free(co);
}

static __thread CoroutineSwitch leader;
static __thread Coroutine *current;

void bad_coroutine_switch(uint64_t *context_from, uint64_t *context_to);
CoroutineAction qemu_coroutine_switch(Coroutine *from_, Coroutine *to_,
                                      CoroutineAction action)
{
    CoroutineSwitch *from = DO_UPCAST(CoroutineSwitch, base, from_);
    CoroutineSwitch *to = DO_UPCAST(CoroutineSwitch, base, to_);

    current = to_;

    to->action = action;

    printf("we are switching to coroutine %p from %p\n", to, from);
    printf("coro has stack %p and pc %p\n", to->sp, to->lr - (uint64_t)&qemu_coroutine_switch);
    fflush(stdout);
        
    uint64_t sp;
    asm volatile ("mov %0, sp" : "=r"(sp));
    printf("sp before call = %p\n", sp);

    bad_coroutine_switch(from->context, to->context);
    printf("out of the coroutine switch! from->action is %i\n", from->action);
    fflush(stdout);

    return from->action;
}

Coroutine *qemu_coroutine_self(void)
{
    if (!current) {
        current = &leader.base;
        printf("ah shit we made a coroutine %p\n", current);
        fflush(stdout);
    }
    return current;
}

bool qemu_in_coroutine(void)
{
    return current && current->caller;
}
