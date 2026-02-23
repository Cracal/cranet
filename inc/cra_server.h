/**
 * @file cra_server.h
 * @author Cracal
 * @brief server
 * @version 0.1
 * @date 2025-12-05
 *
 * @copyright Copyright (c) 2025
 *
 */
#ifndef __CRA_SERVER_H__
#define __CRA_SERVER_H__
#include "collections/cra_dict.h"
#include "cra_conn.h"

typedef struct _CraThrdPool CraThrdPool;

struct _CraServer
{
    bool             started;
    CraIO            listenio;
    CraSocketAddress listenaddr;
    CraTrans_i     **listentrans;
    void            *trans_ctx;
    CraLoop         *mainloop;
    CraLoop         *subloops; // Array<CraLoop>
    unsigned int     nextloop;
    unsigned int     nsubloops;
    CraThrdPool     *loop_pool;
    CraConn         *tempconn;
    CraConnBuffConn *tempbuff;
    CraDict          conns; // Dict<cra_socket_t, CraConn *>

    // for connections
    cra_conn_fn      on_conn;
    cra_conn_read_fn on_read;
    cra_conn_writ_fn on_write_completed;
    cra_conn_writ_fn on_write_high_water_mark;
    int              write_high_water_mark;
    int              bufsize;
    uint32_t         ct_timeout;
    uint32_t         hb_interval;
    cra_conntimer_fn ct_on_timeout;
    cra_conntimer_fn hb_on_heartbeat;
};

CRA_NET_API void
cra_server_init(CraServer *srv, const char *host, int port, CraLoop *loop, unsigned int nsubloops, int bufsize);

CRA_NET_API void
cra_server_uninit(CraServer *srv);

CRA_NET_API void
cra_server_start(CraServer *srv, const CraTrans_i *trans_i, void *trans_ctx, bool ipv6only);

CRA_NET_API void
cra_server_stop(CraServer *srv);

static inline void
cra_server_set_conn_cb(CraServer *srv, cra_conn_fn cb)
{
    srv->on_conn = cb;
}

static inline void
cra_server_set_read_cb(CraServer *srv, cra_conn_read_fn cb)
{
    srv->on_read = cb;
}

static inline void
cra_server_set_write_completed_cb(CraServer *srv, cra_conn_writ_fn cb)
{
    srv->on_write_completed = cb;
}

static inline void
cra_server_set_write_high_water_mark_cb(CraServer *srv, int mark, cra_conn_writ_fn cb)
{
    srv->write_high_water_mark = mark;
    srv->on_write_high_water_mark = cb;
}

static inline void
cra_server_enable_close_timer(CraServer *srv, uint32_t timeout_ms, cra_conntimer_fn cb)
{
    assert(!srv->started);
    srv->ct_timeout = timeout_ms;
    srv->ct_on_timeout = cb;
}

static inline void
cra_server_enable_heartbeat_timer(CraServer *srv, uint32_t interval_ms, cra_conntimer_fn cb)
{
    assert(!srv->started);
    srv->hb_interval = interval_ms;
    srv->hb_on_heartbeat = cb;
}

#endif