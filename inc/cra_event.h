/**
 * @file cra_event.h
 * @author Cracal
 * @brief events
 * @version 0.1
 * @date 2024-12-12
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __CRA_EVENT_H__
#define __CRA_EVENT_H__
#include "cra_socket.h"
#include "cra_timewheel.h"

typedef struct _CraTimer CraTimer;
typedef struct _CraLoop  CraLoop;
typedef struct _CraIO    CraIO;

typedef void (*cra_io_fn)(CraIO *io);
typedef void (*cra_timer_fn)(CraTimer *timer);

#define CRA_IO_NONE 0
#define CRA_IO_READ 1
#define CRA_IO_WRIT 2
#define CRA_IO_BOTH (CRA_IO_READ | CRA_IO_WRIT)

struct _CraIO
{
    int          events;
    int          revents;
    int          index;
    cra_socket_t fd;
    CraLoop     *loop;
    cra_io_fn    on_events;
};

struct _CraTimer
{
    CraTimer_base base;
    CraLoop      *loop;
};

static inline void
cra_io_init(CraIO *io, CraLoop *loop, cra_socket_t fd, int events, cra_io_fn on_events)
{
    io->events = events;
    io->revents = CRA_IO_NONE;
    io->index = -1;
    io->fd = fd;
    io->loop = loop;
    io->on_events = on_events;
}

#define cra_io_uninit(_io) CRA_UNUSED_VALUE(_io)

static inline void
cra_timer_init(CraTimer    *timer,
               CraLoop     *loop,
               uint32_t     repeat,
               uint32_t     timeout_ms,
               cra_timer_fn on_timeout,
               cra_timer_fn on_removed)
{
    cra_timer_base_init(&timer->base, repeat, timeout_ms, (cra_timer_base_fn)on_timeout, (cra_timer_base_fn)on_removed);
    timer->loop = loop;
}

#define cra_timer_uninit(_timer) CRA_UNUSED_VALUE(_timer)

#endif