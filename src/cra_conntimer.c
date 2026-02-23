#include "cra_conntimer.h"
#include "cra_conn.h"
#include "cra_log.h"
#include "cra_loop.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-ConnTimer"

#define ConnTimer timer

struct _CraConnTimer
{
    CraTimer         base;
    CraConn         *conn;
    int              refcnt; // for self
    bool             updated;
    bool             callonce;
    bool             canupdate;
    cra_conntimer_fn on_timeout;
};

static void
cra_conntimer_on_timeout(CraTimer *base)
{
    CraConnTimer *timer = container_of(base, CraConnTimer, base);
    if (!timer->updated)
    {
        timer->canupdate = false;
        timer->on_timeout(timer->conn);
        if (timer->callonce)
            cra_loop_del_timer(&timer->base);
    }
    else
    {
        timer->updated = false;
    }
}

static void
cra_conntimer_on_removed(CraTimer *base)
{
    CraConnTimer *timer = container_of(base, CraConnTimer, base);

    cra_conn_unref(timer->conn);

    CRA_LOG(trace, ConnTimer, "Removed{%ums, %d}.", timer->base.base.timeout_ms, timer->refcnt);

    if (--timer->refcnt == 0)
    {
        cra_timer_uninit(&timer->base);
        cra_dealloc(timer);
    }
}

CraConnTimer *
cra_conntimer_open_safe(CraLoop *loop, CraConn *conn, bool call_once, uint32_t timeout_ms, cra_conntimer_fn on_timeout)
{
    assert(loop);
    assert(conn);
    assert(timeout_ms > 0);
    assert(on_timeout);

    CraConnTimer *timer = cra_alloc(CraConnTimer);
    if (!timer)
    {
        CRA_LOG(error, ConnTimer, "Failed to alloc timer{%ums}.", timeout_ms);
        return NULL;
    }

    cra_timer_init(
      &timer->base, loop, CRA_TIMER_INFINITE, timeout_ms, cra_conntimer_on_timeout, cra_conntimer_on_removed);
    timer->conn = conn;
    timer->on_timeout = on_timeout;
    timer->updated = false;
    timer->callonce = call_once;
    timer->canupdate = true;
    timer->refcnt = 2;

    cra_conn_ref(conn);

    cra_loop_run_in_loop(timer->base.loop, (cra_functor_fn)cra_loop_add_timer, &timer->base, NULL);

    CRA_LOG(trace, ConnTimer, "Opened{%ums, %d}.", timeout_ms, timer->refcnt);

    return timer;
}

static void
cra_conntimer_close_in_loop(CraConnTimer *timer)
{
    CRA_LOG(trace, ConnTimer, "Closed{%ums, %d}.", timer->base.base.timeout_ms, timer->refcnt);

    cra_loop_del_timer(&timer->base);

    if (--timer->refcnt == 0)
    {
        cra_timer_uninit(&timer->base);
        cra_dealloc(timer);
    }
}

void
cra_conntimer_close_safe(CraConnTimer **ptimer)
{
    cra_loop_run_in_loop((*ptimer)->base.loop, (cra_functor_fn)cra_conntimer_close_in_loop, *ptimer, NULL);
    *ptimer = NULL;
}

void
cra_conntimer_update(CraConnTimer *timer)
{
    if (timer->canupdate)
        timer->updated = true;
    else
        timer->canupdate = true;
}
