/**
 * @file cra_client.h
 * @author Cracal
 * @brief client
 * @version 0.1
 * @date 2025-06-21
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __CRA_CLIENT_H__
#define __CRA_CLIENT_H__
#include "cra_conn.h"

typedef struct _CraClientTimer CraClientTimer;

typedef enum
{
    CRA_CLIENT_STATE_DISCONNECTED,
    CRA_CLIENT_STATE_CONNECTING,
    CRA_CLIENT_STATE_TIME_WAIT,
    CRA_CLIENT_STATE_CONNECTED,
} CraClientState_e;

struct _CraClient
{
    CraClientState_e  state;
    bool              retry;
    CraIO             io;
    CraTrans_i      **trans;
    const CraTrans_i *trans_i;
    void             *trans_ctx;
    CraConn          *conn;
    CraClientTimer   *timer;
    uint32_t          retry_ms;
    uint32_t          retry_max_ms;
    CraSocketAddress  remoteaddr;

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

#define CRA_CLIENT_RETRY_MS     200
#define CRA_CLIENT_RETRY_MAX_MS (5 * 60 * 1000)

CRA_NET_API void
cra_client_init(CraClient *cli, const char *host, int port, CraLoop *loop, int bufsize);

CRA_NET_API void
cra_client_uninit(CraClient *cli);

CRA_NET_API void
cra_client_connect(CraClient *cli, const CraTrans_i *trans_i, void *trans_ctx, bool reconnect);

CRA_NET_API void
cra_client_reconnect(CraClient *cli);

CRA_NET_API void
cra_client_disconnect(CraClient *cli);

static inline void
cra_client_set_conn_cb(CraClient *cli, cra_conn_fn cb)
{
    cli->on_conn = cb;
}

static inline void
cra_client_set_read_cb(CraClient *cli, cra_conn_read_fn cb)
{
    cli->on_read = cb;
}

static inline void
cra_client_set_write_completed_cb(CraClient *cli, cra_conn_writ_fn cb)
{
    cli->on_write_completed = cb;
}

static inline void
cra_client_set_write_high_water_mark_cb(CraClient *cli, int mark, cra_conn_writ_fn cb)
{
    cli->write_high_water_mark = mark;
    cli->on_write_high_water_mark = cb;
}

static inline void
cra_client_enable_close_timer(CraClient *cli, uint32_t timeout_ms, cra_conntimer_fn cb)
{
    assert(cli->state == CRA_CLIENT_STATE_DISCONNECTED);
    cli->ct_timeout = timeout_ms;
    cli->ct_on_timeout = cb;
}

static inline void
cra_client_enable_heartbeat_timer(CraClient *cli, uint32_t interval_ms, cra_conntimer_fn cb)
{
    assert(cli->state == CRA_CLIENT_STATE_DISCONNECTED);
    cli->hb_interval = interval_ms;
    cli->hb_on_heartbeat = cb;
}

#endif