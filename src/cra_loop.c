#define __CRA_LOOP_LOCK
#include "cra_loop.h"
#include "cra_assert.h"
#include "cra_log.h"
#include "cra_malloc.h"
#include "cra_poller.h"
#include "cra_refcnt.h"
#include "cra_time.h"
#include "threads/cra_thread.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-Loop"

#define Loop loop

typedef struct _CraFunctor
{
    void          *arg;
    CraRefcnt     *ref;
    cra_functor_fn func;
} CraFunctor;

static cra_thrd_local CraLoop *st_loop = NULL;

#define CRA_LOOP_SET(_loop)              st_loop = _loop
#define CRA_LOOP_CLR(_loop)              st_loop = NULL
#define CRA_LOOP_ASSERT_NULL()           assert_always(st_loop == NULL)
#define CRA_LOOP_IS_IN_THREAD(_loop)     ((_loop) == st_loop)
#define CRA_LOOP_ASSERT_IN_THREAD(_loop) assert_always(CRA_LOOP_IS_IN_THREAD(_loop))

static inline void
cra_loop_do_pending(CraDeque *deque)
{
    CraFunctor functor = { 0 };
    while (cra_deque_pop_left(deque, &functor))
    {
        assert(functor.func);
        functor.func(functor.arg);
        if (functor.ref)
            cra_refcnt_unref(functor.ref);
    }
    assert(cra_deque_get_count(deque) == 0);
}

bool
cra_loop_is_in_thread(CraLoop *loop)
{
    return CRA_LOOP_IS_IN_THREAD(loop);
}

void
cra_loop_assert_in_thread(CraLoop *loop)
{
    CRA_LOOP_ASSERT_IN_THREAD(loop);
}

static void
cra_awake_handle_read(CraIO *io)
{
    int  n;
    char buf[128];
    while ((n = cra_socket_recv(io->fd, buf, sizeof(buf))) == sizeof(buf))
        ;
    // #undef Loop
    // #define Loop io->loop
    //     CRA_LOG(trace,
    //             Loop,
    //             "Wake-up loop: pipe %d -> %d, read %d bytes.",
    //             (int)Loop->awakepipe[0],
    //             (int)Loop->awakepipe[1],
    //             n);
    // #undef Loop
    // #define Loop loop
}

#define cra_awake_wakeup(_loop) cra_socket_send((_loop)->awakepipe[1], "A", 1)

static inline void
cra_awake_init(CraLoop *loop)
{
    assert(loop->pollerctx != NULL);
    assert_always(cra_socket_pair(loop->awakepipe));
    cra_socketopt_set_nonblocking(loop->awakepipe[0], true);
    cra_socketopt_set_nonblocking(loop->awakepipe[1], true);
    // cra_socketopt_set_tcp_no_delay(loop->awakepipe[0], true);
    // cra_socketopt_set_tcp_no_delay(loop->awakepipe[1], true);
    cra_socketopt_set_close_on_execute(loop->awakepipe[0], true);
    cra_socketopt_set_close_on_execute(loop->awakepipe[1], true);
    cra_io_init(&loop->awakepipe_read_end, loop, loop->awakepipe[0], CRA_IO_READ, cra_awake_handle_read);
    cra_poller_add(loop->pollerctx, &loop->awakepipe_read_end);

    CRA_LOG(trace, Loop, "Open awake pipe: %d -> %d.", (int)loop->awakepipe[0], (int)loop->awakepipe[1]);
}

static inline void
cra_awake_uninit(CraLoop *loop)
{
    CRA_LOG(trace, Loop, "Close awake pipe: %d -> %d.", (int)loop->awakepipe[0], (int)loop->awakepipe[1]);

    cra_poller_del(loop->pollerctx, &loop->awakepipe_read_end);
    cra_socket_close(loop->awakepipe[0]); // close read-end fd
    cra_socket_close(loop->awakepipe[1]); // close write-end fd
    cra_io_uninit(loop->awakepipe_read_end);
}

CraLoop *
cra_loop_get_current_loop(void)
{
    return st_loop;
}

#ifdef CRA_OS_WIN

static void
cra_loop_tick_timewheel(CraLoop *loop)
{
    // CRA_LOOP_ASSERT_IN_THREAD(loop);
    if (loop->looping)
    {
        assert(loop->timewheel);
        cra_timewheel_tick(loop->timewheel);
    }
}

static VOID CALLBACK
cra_loop_win_timer_cb(PVOID loop, BOOLEAN timerOrWaitFired)
{
    CRA_UNUSED_VALUE(timerOrWaitFired);
    cra_loop_functor_to_queue((CraLoop *)loop, (cra_functor_fn)cra_loop_tick_timewheel, loop, NULL);
}

#define CRA_LOOP_OPEN_TIMER(_loop)                                                                            \
    do                                                                                                        \
    {                                                                                                         \
        DWORD tick = (DWORD)(_loop)->timewheel->tick_ms;                                                      \
        if (!CreateTimerQueueTimer(                                                                           \
              &(_loop)->timerevent, NULL, cra_loop_win_timer_cb, _loop, tick, tick, WT_EXECUTEINTIMERTHREAD)) \
        {                                                                                                     \
            CRA_LOG(fatal, Loop, "CreateTimerQueueTimer() failed. error: %d.", cra_get_last_error());         \
            assert_always(false);                                                                             \
        }                                                                                                     \
    } while (0)

#define CRA_LOOP_CLOSE_TIMER(_loop)                        \
    if ((_loop)->timerevent)                               \
    DeleteTimerQueueTimer(NULL, (_loop)->timerevent, NULL)

#else

// TODO: Linux(timer)
#define CRA_LOOP_OPEN_TIMER(_loop)
#define CRA_LOOP_CLOSE_TIMER(_loop)

#endif

void
cra_loop_init(CraLoop *loop)
{
    CRA_LOOP_ASSERT_NULL();
    CRA_LOOP_SET(loop);

    bzero(loop, sizeof(*loop));
    loop->pending_things = cra_alloc(CraDeque);
    if (!loop->pending_things)
    {
        CRA_LOG(fatal, Loop, "Failed to create pending deque.");
        exit(EXIT_FAILURE);
    }
    loop->pending_things_free = cra_alloc(CraDeque);
    if (!loop->pending_things_free)
    {
        CRA_LOG(fatal, Loop, "Failed to create pending backup deque.");
        cra_dealloc(loop->pending_things);
        exit(EXIT_FAILURE);
    }
    if (!cra_deque_init0(CraFunctor, loop->pending_things, CRA_DEQUE_INFINITE, true))
    {
        CRA_LOG(fatal, Loop, "Failed to init pending deque.");
        cra_dealloc(loop->pending_things_free);
        cra_dealloc(loop->pending_things);
        exit(EXIT_FAILURE);
    }
    if (!cra_deque_init0(CraFunctor, loop->pending_things_free, CRA_DEQUE_INFINITE, true))
    {
        CRA_LOG(fatal, Loop, "Failed to init pending backup deque.");
        cra_deque_uninit(loop->pending_things);
        cra_dealloc(loop->pending_things_free);
        cra_dealloc(loop->pending_things);
        exit(EXIT_FAILURE);
    }
    loop->pollerctx = cra_poller_create_ctx();
    if (!loop->pollerctx)
    {
        CRA_LOG(fatal, Loop, "Failed to create poller context.");
        cra_deque_uninit(loop->pending_things_free);
        cra_deque_uninit(loop->pending_things);
        cra_dealloc(loop->pending_things_free);
        cra_dealloc(loop->pending_things);
        exit(EXIT_FAILURE);
    }
    if (!cra_alist_init_size0(CraIO *, &loop->active_ios, 64, false))
    {
        CRA_LOG(fatal, Loop, "Failed to init active ios.");
        cra_poller_destroy_ctx(loop->pollerctx);
        cra_deque_uninit(loop->pending_things_free);
        cra_deque_uninit(loop->pending_things);
        cra_dealloc(loop->pending_things_free);
        cra_dealloc(loop->pending_things);
        exit(EXIT_FAILURE);
    }
    __CRA_LOOP_LOCK_INIT(&loop->pending_lock);
    cra_awake_init(loop);

    CRA_LOG(trace, Loop, "Initialized.");
}

void
cra_loop_uninit(CraLoop *loop)
{
    assert_always(!loop->looping);
    CRA_LOOP_ASSERT_IN_THREAD(loop);

    CRA_LOOP_CLOSE_TIMER(loop);

    // 保证在loop退出时清空所有待办的事件，
    // 防止在refcnt有ref（在调用run_in_loop前调用）而没有unref（在->func后调用）导致内存泄漏
    cra_loop_do_pending(loop->pending_things);

    cra_awake_uninit(loop);
    cra_deque_uninit(loop->pending_things);
    cra_deque_uninit(loop->pending_things_free);
    cra_dealloc(loop->pending_things);
    cra_dealloc(loop->pending_things_free);
    __CRA_LOOP_LOCK_UNINIT(&loop->pending_lock);
    cra_poller_destroy_ctx(loop->pollerctx);
    cra_alist_uninit(&loop->active_ios);
    if (loop->timewheel)
    {
        cra_timewheel_uninit(loop->timewheel);
        cra_dealloc(loop->timewheel);
    }

    bzero(loop, sizeof(*loop));

    CRA_LOOP_CLR(loop);

    CRA_LOG(trace, Loop, "Uninitialized.");
}

static void
handle_pending_things(CraLoop *loop)
{
    loop->handling_pending = true;

    __CRA_LOOP_LOCK_LOCK(&loop->pending_lock);
    cra_swap_ptr((void **)&loop->pending_things, (void **)&loop->pending_things_free);
    __CRA_LOOP_LOCK_UNLOCK(&loop->pending_lock);

    cra_loop_do_pending(loop->pending_things_free);

    loop->handling_pending = false;
}

static inline void
__cra_loop_loop_once(CraLoop *loop, int timeout_ms)
{
    int n;

    cra_alist_clear(&loop->active_ios);
    n = cra_poller_poll(loop->pollerctx, &loop->active_ios, timeout_ms);
    loop->current_ms = cra_tick_ms();
    // handle IO & Timer
    if (n > 0)
    {
        CraAListIter it;
        CraIO      **ioptr;
        for (cra_alist_iter_init(&loop->active_ios, &it); cra_alist_iter_next(&it, (void **)&ioptr);)
            (*ioptr)->on_events(*ioptr);
    }
    // handle poller error
    else if (n < 0)
    {
        int err = cra_get_last_error();
        if (err != CRA_EINTR)
        {
            CRA_LOG(fatal, Loop, "Poll error: %d.", err);
            exit(EXIT_FAILURE);
        }
    }

    // pending things
    handle_pending_things(loop);
}

void
cra_loop_loop_once(CraLoop *loop, int timeout_ms)
{
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    __cra_loop_loop_once(loop, timeout_ms);
}

void
cra_loop_loop(CraLoop *loop)
{
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    if (loop->looping)
        return;

    CRA_LOG(trace, Loop, "Starting...");

    loop->looping = true;
    while (loop->looping)
    {
        __cra_loop_loop_once(loop, -1);
    }

    CRA_LOG(trace, Loop, "Stopped.");
}

void
cra_loop_stop_safe(CraLoop *loop)
{
    if (!loop->looping)
        return;

    CRA_LOG(trace, Loop, "Stopping...");

    loop->looping = false;
    if (!CRA_LOOP_IS_IN_THREAD(loop))
        cra_awake_wakeup(loop);
}

void
cra_loop_functor_to_queue(CraLoop *loop, cra_functor_fn func, void *arg, CraRefcnt *ref)
{
    assert(func);

    CraFunctor functor = { .arg = arg, .ref = ref, .func = func };

    if (ref)
        cra_refcnt_ref(ref);

    __CRA_LOOP_LOCK_LOCK(&loop->pending_lock);
    cra_deque_push(loop->pending_things, &functor);
    __CRA_LOOP_LOCK_UNLOCK(&loop->pending_lock);

    if (!CRA_LOOP_IS_IN_THREAD(loop) || loop->handling_pending)
        cra_awake_wakeup(loop);
}

void
cra_loop_run_in_loop(CraLoop *loop, cra_functor_fn func, void *arg, CraRefcnt *ref)
{
    if (CRA_LOOP_IS_IN_THREAD(loop))
        func(arg);
    else
        cra_loop_functor_to_queue(loop, func, arg, ref);
}

void
cra_loop_enable_timewheel(CraLoop *loop, int tick_ms, uint32_t timewheel_buckets)
{
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    assert_always(!loop->looping);
    assert_always(loop->timewheel == NULL);
    assert_always(tick_ms > 0 && timewheel_buckets > 0);
    loop->timewheel = cra_alloc(CraTimewheel);
    if (!loop->timewheel)
    {
        CRA_LOG(fatal, Loop, "Failed to create timewheel.");
        exit(EXIT_FAILURE);
    }
    if (!cra_timewheel_init(loop->timewheel, (uint32_t)tick_ms, timewheel_buckets))
    {
        CRA_LOG(fatal, Loop, "Failed to init timewheel.");
        cra_dealloc(loop->timewheel);
        exit(EXIT_FAILURE);
    }

    CRA_LOOP_OPEN_TIMER(loop);

    CRA_LOG(trace, Loop, "Enabled timing wheel: tick=%dms, bucket_size=%u.", tick_ms, timewheel_buckets);
}

bool
cra_loop_add_io(CraIO *io)
{
    CraLoop *loop = io->loop;
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    if (cra_poller_add(loop->pollerctx, io))
    {
        CRA_LOG(trace, Loop, "IO event added: fd=%d, events=%d.", (int)io->fd, io->events);
        ++loop->nios;
        return true;
    }
    CRA_LOG(error, Loop, "Failed to add IO event: fd=%d, events=%d.", (int)io->fd, io->events);
    return false;
}

bool
cra_loop_del_io(CraIO *io)
{
    CraLoop *loop = io->loop;
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    if (cra_poller_del(loop->pollerctx, io))
    {
        CRA_LOG(trace, Loop, "IO event deleted: fd=%d, events=%d.", (int)io->fd, io->events);
        --loop->nios;
        return true;
    }
    CRA_LOG(error, Loop, "Failed to delete IO event: fd=%d, events=%d.", (int)io->fd, io->events);
    return false;
}

bool
cra_loop_mod_io(CraIO *io)
{
    CraLoop *loop = io->loop;
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    if (cra_poller_mod(loop->pollerctx, io))
    {
        CRA_LOG(trace, Loop, "IO event modified: fd=%d, events=%d.", (int)io->fd, io->events);
        return true;
    }
    CRA_LOG(error, Loop, "Failed to modify IO event: fd=%d, events=%d.", (int)io->fd, io->events);
    return false;
}

bool
cra_loop_add_timer(CraTimer *timer)
{
    CraLoop *loop = timer->loop;
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    assert(loop->timewheel);
    if (cra_timewheel_add(loop->timewheel, &timer->base))
    {
        CRA_LOG(trace, Loop, "Timer event added: timeout=%ums, repeat=%u.", timer->base.timeout_ms, timer->base.repeat);
        ++loop->ntimers;
        return true;
    }
    CRA_LOG(
      error, Loop, "Failed to add Timer event: timeout=%ums, repeat=%u.", timer->base.timeout_ms, timer->base.repeat);
    if (timer->base.on_remove_timer)
        timer->base.on_remove_timer(&timer->base);
    return false;
}

bool
cra_loop_del_timer(CraTimer *timer)
{
    CraLoop *loop = timer->loop;
    CRA_LOOP_ASSERT_IN_THREAD(loop);
    assert(loop->timewheel);
    // cancel一个timer必然成功(仅标记失活)
    cra_timer_base_cancel(&timer->base);
    CRA_LOG(trace, Loop, "Timer event deleted: timeout=%ums, repeat=%u.", timer->base.timeout_ms, timer->base.repeat);
    --loop->ntimers;
    return true;
}
