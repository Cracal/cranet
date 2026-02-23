/**
 * @file cra_loop.h
 * @author Cracal
 * @brief event loop
 * @version 0.1
 * @date 2024-12-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __CRA_LOOP_H__
#define __CRA_LOOP_H__
#include "collections/cra_alist.h"
#include "collections/cra_deque.h"
#include "collections/cra_dict.h"
#include "cra_event.h"

#if 1 // lock

// #include "threads/cra_lock.h"
// #define __CRA_LOOP_LOCK_T cra_mutex_t

#define __CRA_LOOP_LOCK_T cra_spinlock_t

#ifdef __CRA_LOOP_LOCK

// #define __CRA_LOOP_LOCK_INIT   cra_mutex_init
// #define __CRA_LOOP_LOCK_UNINIT cra_mutex_destroy
// #define __CRA_LOOP_LOCK_LOCK   cra_mutex_lock
// #define __CRA_LOOP_LOCK_UNLOCK cra_mutex_unlock

#define __CRA_LOOP_LOCK_INIT   cra_spinlock_init
#define __CRA_LOOP_LOCK_UNINIT cra_spinlock_uninit
#define __CRA_LOOP_LOCK_LOCK   cra_spinlock_lock
#define __CRA_LOOP_LOCK_UNLOCK cra_spinlock_unlock

#endif

#endif // end lock

typedef void (*cra_functor_fn)(void *);

typedef struct _CraPollerCtx CraPollerCtx;
typedef struct _CraRefcnt    CraRefcnt;
typedef struct _CraLoop      CraLoop;
#ifdef CRA_OS_WIN
typedef HANDLE cra_timerfd_t;
#else
#endif

struct _CraLoop
{
    bool              looping;             // loop flag
    bool              handling_pending;    // is handling pending things
    unsigned long     current_ms;          // current time(ms)
    cra_socket_t      awakepipe[2];        // awake loop pipe
    CraIO             awakepipe_read_end;  // awake loop pipe[read-end]
    CraDeque         *pending_things;      // Deque<CraFunctor>
    CraDeque         *pending_things_free; // Deque<CraFunctor>
    __CRA_LOOP_LOCK_T pending_lock;        // lock
    CraPollerCtx     *pollerctx;           // poller context
    CraAList          active_ios;          // List<CraEvent *>
    CraTimewheel     *timewheel;           // time wheel
    cra_timerfd_t     timerevent;          // timer event
    unsigned int      ntimers;
    unsigned int      nios;
};

#undef __CRA_LOOP_LOCK_T

#define cra_loop_ntimers(loop) (loop)->ntimers
#define cra_loop_nios(loop)    (loop)->nios

// returns: if the current thread has a loop, return the loop, otherwise return NULL
CRA_NET_API CraLoop *
cra_loop_get_current_loop(void);

CRA_NET_API bool
cra_loop_is_in_thread(CraLoop *loop);

CRA_NET_API void
cra_loop_assert_in_thread(CraLoop *loop);

CRA_NET_API void
cra_loop_init(CraLoop *loop);

CRA_NET_API void
cra_loop_uninit(CraLoop *loop);

CRA_NET_API void
cra_loop_loop_once(CraLoop *loop, int timeout_ms);

CRA_NET_API void
cra_loop_loop(CraLoop *loop);

CRA_NET_API void
cra_loop_stop_safe(CraLoop *loop);

CRA_NET_API void
cra_loop_functor_to_queue(CraLoop *loop, cra_functor_fn func, void *arg, CraRefcnt *ref);

CRA_NET_API void
cra_loop_run_in_loop(CraLoop *loop, cra_functor_fn func, void *arg, CraRefcnt *ref);

CRA_NET_API void
cra_loop_enable_timewheel(CraLoop *loop, int tick_ms, uint32_t timewheel_buckets);

CRA_NET_API bool
cra_loop_add_io(CraIO *io);

CRA_NET_API bool
cra_loop_del_io(CraIO *io);

CRA_NET_API bool
cra_loop_mod_io(CraIO *io);

CRA_NET_API bool
cra_loop_add_timer(CraTimer *timer);

CRA_NET_API bool
cra_loop_del_timer(CraTimer *timer);

#endif