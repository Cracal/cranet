/**
 * @file cra_conn.h
 * @author Cracal
 * @brief connection
 * @version 0.1
 * @date 2026-01-03
 *
 * @copyright Copyright (c) 2026
 *
 */
#ifndef __CRA_CONN_H__
#define __CRA_CONN_H__
#include "cra_conntimer.h"
#include "cra_loop.h"
#include "cra_malloc.h"
#include "cra_refcnt.h"
#include "cra_trans_i.h"

typedef struct _CraConnBuffConn CraConnBuffConn;
typedef struct _CraConnBuf      CraConnBuf;
typedef struct _CraServer       CraServer;
typedef struct _CraClient       CraClient;
typedef struct _CraConn         CraConn;

typedef void (*cra_conn_fn)(CraConn *conn);
typedef void (*cra_conn_read_fn)(CraConn *conn, CraBuffer *buf);
typedef void (*cra_conn_writ_fn)(CraConn *conn, int n);

typedef enum
{
    CRA_CONN_STATE_CONNECTING = 0,
    CRA_CONN_STATE_CONNECTED,
    CRA_CONN_STATE_DISCONNECTING,
    CRA_CONN_STATE_DISCONNECTED,
} CraConnState_e;

struct _CraConnBuf
{
    cra_atomic_int32_t refcnt;
    int                len;
    char               buf[];
};

static inline CraConnBuf *
cra_conn_buf_create(int len, int refcnt)
{
    CraConnBuf *connbuf = (CraConnBuf *)cra_malloc(sizeof(CraConnBuf) + len);
    if (connbuf)
    {
        connbuf->refcnt = refcnt;
        connbuf->len = len;
    }
    return connbuf;
}

static inline void
cra_conn_buf_ref(CraConnBuf *connbuf)
{
    cra_atomic_inc32(&connbuf->refcnt);
}

static inline void
cra_conn_buf_unref(CraConnBuf *connbuf)
{
    if (cra_atomic_dec32(&connbuf->refcnt) == 1)
        cra_dealloc(connbuf);
}

// =========================

struct _CraConn
{
    CraIO            io;
    CraRefcnt        ref;
    CraTrans_i     **trans;
    CraConnState_e   state;
    CraSocketAddress peeraddr;
    CraSocketAddress localaddr;
    CraBuffer       *inputbuf;
    CraBuffer       *outputbuf;
    int              bufsize;
    int              write_high_water_mark;

    void *user; // for user
    union
    {
        CraServer *srv; // for server
        CraClient *cli; // for client
    };

    CraConnTimer *closetimer;
    CraConnTimer *heartbeattimer;

    cra_conn_fn      on_conn; // for client/server
    cra_conn_read_fn on_read;
    cra_conn_writ_fn on_write_completed;
    cra_conn_writ_fn on_write_high_water_mark;
};

#define cra_conn_fd(conn)        (conn)->io.fd
#define cra_conn_state(conn)     (conn)->state
#define cra_conn_peeraddr(conn)  (&(conn)->peeraddr)
#define cra_conn_localaddr(conn) (&(conn)->localaddr)
#define cra_conn_user(conn)      (conn)->user

CRA_NET_API void
cra_conn_init(CraConn              *conn,
              cra_socket_t          fd,
              CraLoop              *loop,
              int                   events,
              int                   bufsize,
              cra_refcnt_release_fn handle_destroy);

CRA_NET_API void
cra_conn_uninit(CraConn *conn);

static inline void
cra_conn_ref(CraConn *conn)
{
    cra_refcnt_ref(&conn->ref);
}

static inline void
cra_conn_unref(CraConn *conn)
{
    cra_refcnt_unref(&conn->ref);
}

static inline bool
cra_conn_is_connected(CraConn *conn)
{
    return conn->state == CRA_CONN_STATE_CONNECTED;
}

#ifndef __CRA_CONN_NO_ASSERT_IN_LOOP
#define __CRA_CONN_ASSERT_IN_LOOP(_conn) cra_loop_assert_in_thread((_conn)->io.loop)
#else
#define __CRA_CONN_ASSERT_IN_LOOP(_conn) CRA_UNUSED_VALUE(_conn)
#endif

static inline void
cra_conn_enable_read(CraConn *conn)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    if (!(conn->io.events & CRA_IO_READ))
    {
        conn->io.events |= CRA_IO_READ;
        cra_loop_mod_io(&conn->io);
    }
}

static inline void
cra_conn_disable_read(CraConn *conn)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    if (conn->io.events & CRA_IO_READ)
    {
        conn->io.events &= ~CRA_IO_READ;
        cra_loop_mod_io(&conn->io);
    }
}

static inline void
cra_conn_set_conn_cb(CraConn *conn, cra_conn_fn cb)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    conn->on_conn = cb;
}

static inline void
cra_conn_set_read_cb(CraConn *conn, cra_conn_read_fn cb)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    conn->on_read = cb;
}

static inline void
cra_conn_set_write_completed_cb(CraConn *conn, cra_conn_writ_fn cb)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    conn->on_write_completed = cb;
}

static inline void
cra_conn_set_write_high_water_mark_cb(CraConn *conn, int mark, cra_conn_writ_fn cb)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    conn->write_high_water_mark = mark;
    conn->on_write_high_water_mark = cb;
}

static inline void
cra_conn_disable_close_timer(CraConn *conn)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    if (conn->closetimer)
        cra_conntimer_close_safe(&conn->closetimer);
}

static inline void
cra_conn_enable_close_timer(CraConn *conn, CraLoop *tmloop, uint32_t timeout_ms, cra_conntimer_fn cb)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    cra_conn_disable_close_timer(conn);
    conn->closetimer = cra_conntimer_open_safe(tmloop, conn, true, timeout_ms, cb);
}

static inline void
cra_conn_disable_heartbeat_timer(CraConn *conn)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    if (conn->heartbeattimer)
        cra_conntimer_close_safe(&conn->heartbeattimer);
}

static inline void
cra_conn_enable_heartbeat_timer(CraConn *conn, CraLoop *tmloop, uint32_t interval_ms, cra_conntimer_fn cb)
{
    __CRA_CONN_ASSERT_IN_LOOP(conn);
    cra_conn_disable_heartbeat_timer(conn);
    conn->heartbeattimer = cra_conntimer_open_safe(tmloop, conn, false, interval_ms, cb);
}

CRA_NET_API void
cra_conn_shutdown(CraConn *conn);

static inline void
cra_conn_shutdown_safe(CraConn *conn)
{
    cra_loop_run_in_loop(conn->io.loop, (cra_functor_fn)cra_conn_shutdown, conn, &conn->ref);
}

CRA_NET_API void
cra_conn_close(CraConn *conn);

static inline void
cra_conn_close_safe(CraConn *conn)
{
    cra_loop_run_in_loop(conn->io.loop, (cra_functor_fn)cra_conn_close, conn, &conn->ref);
}

CRA_NET_API void
cra_conn_send(CraConn *conn, const void *buf, int len);

CRA_NET_API void
cra_conn_send_safe0(CraConn *conn, const void *buf, int len);

CRA_NET_API void
cra_conn_send_safe1(CraConn *conn, CraConnBuf *buf);

#undef __CRA_CONN_ASSERT_IN_LOOP

// ========================

#ifdef __CRA_CONN_INNER

struct _CraConnBuffConn
{
    CraConn  *conn;
    CraBuffer buff;
};

static inline CraConnBuffConn *
cra_conn_buff_conn_create(int bufsize)
{
    CraConnBuffConn *buffconn = cra_alloc(CraConnBuffConn);
    if (!buffconn)
        return NULL;
    if (!cra_buffer_init(&buffconn->buff, bufsize))
    {
        cra_dealloc(buffconn);
        return NULL;
    }
    buffconn->conn = NULL;
    return buffconn;
}

static inline void
cra_conn_buff_conn_destroy(CraConnBuffConn *buffconn)
{
    cra_buffer_uninit(&buffconn->buff);
    cra_dealloc(buffconn);
}

void
cra_conn_establish(CraConn *conn);
void
cra_conn_terminate(CraConn *conn);
void
cra_conn_call_read_cb(CraConnBuffConn *buffconn);

#endif

#endif