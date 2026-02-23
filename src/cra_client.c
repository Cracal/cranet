#define __CRA_CONN_INNER
#include "cra_client.h"
#include "cra_log.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-Client"

#define Client cli

struct _CraClientTimer
{
    CraTimer   base;
    CraClient *cli;
};

static void
__cra_client_connect(CraClient *cli);
static void
cra_client_retry(CraClient *cli, int err);

static void
cra_client_release_conn(CraRefcnt *ref)
{
    CraConn *conn = container_of(ref, CraConn, ref);
    cra_conn_uninit(conn);
    cra_dealloc(conn);
}

static void
cra_client_handle_conn(CraConn *conn)
{
    assert(conn->cli);

    cra_conn_ref(conn);

    if (!cra_conn_is_connected(conn))
    {
        conn->cli->state = CRA_CLIENT_STATE_DISCONNECTED;
        conn->cli->conn = NULL;
        cra_conn_unref(conn);
    }

    if (conn->cli->on_conn)
        conn->cli->on_conn(conn);

    cra_conn_unref(conn);
}

static void
cra_client_handle_connect(CraIO *io)
{
    int          err;
    CraClient   *cli;
    CraTrans_i **trans;

    cli = container_of(io, CraClient, io);
    assert(!cli->conn);

    if (cli->state != CRA_CLIENT_STATE_CONNECTING)
        return;

    cra_loop_del_io(&cli->io);

    trans = cli->trans;
    cli->trans = NULL;
    err = cra_socketopt_get_socket_error(cli->io.fd);
    if (err == 0)
    {
        cli->state = CRA_CLIENT_STATE_CONNECTED;
        cli->conn = cra_alloc(CraConn);
        if (!cli->conn)
        {
            CRA_LOG(fatal, Client, "Failed to alloc conn.");
            exit(EXIT_FAILURE);
        }

        cra_conn_init(cli->conn, cli->io.fd, cli->io.loop, CRA_IO_READ, cli->bufsize, cra_client_release_conn);
        cli->conn->cli = cli;
        cli->conn->trans = trans;
        cli->retry_ms = CRA_CLIENT_RETRY_MS;
        cra_conn_set_conn_cb(cli->conn, cra_client_handle_conn);
        cra_conn_set_read_cb(cli->conn, cli->on_read);
        cra_conn_set_write_completed_cb(cli->conn, cli->on_write_completed);
        cra_conn_set_write_high_water_mark_cb(cli->conn, cli->write_high_water_mark, cli->on_write_high_water_mark);
        if (cli->ct_on_timeout)
            cra_conn_enable_close_timer(cli->conn, cli->io.loop, cli->ct_timeout, cli->ct_on_timeout);
        if (cli->hb_on_heartbeat)
            cra_conn_enable_heartbeat_timer(cli->conn, cli->io.loop, cli->hb_interval, cli->hb_on_heartbeat);
        memcpy(&cli->conn->peeraddr, &cli->remoteaddr, sizeof(cli->remoteaddr));
        cra_socket_get_local_address(cli->io.fd, &cli->conn->localaddr);

        char ipport[CRA_IPPORTSTR_MAX];
        cra_socket_address_get_ipport(&cli->conn->peeraddr, ipport, sizeof(ipport));
        CRA_LOG(debug, Client, "Connected to %s.", ipport);

        cra_conn_establish(cli->conn);
    }
    else
    {
        cra_trans_shutdown(trans, true);
        cra_trans_release(trans);
        cra_client_retry(cli, err);
    }
}

static void
cra_client_on_timeout(CraTimer *t)
{
    CraClientTimer *timer = container_of(t, CraClientTimer, base);
    CraClient      *cli = timer->cli;
    cli->timer = NULL;
    if (cli->state == CRA_CLIENT_STATE_TIME_WAIT)
        __cra_client_connect(cli);
}

static void
cra_client_on_removed(CraTimer *t)
{
    CraClientTimer *timer = container_of(t, CraClientTimer, base);
    cra_dealloc(timer);
}

static void
cra_client_retry(CraClient *cli, int err)
{
    assert(!cli->timer);

    if (cli->retry)
    {
        cli->timer = cra_alloc(CraClientTimer);
        if (!cli->timer)
        {
            CRA_LOG(fatal, Client, "Failed to alloc timer.");
            exit(EXIT_FAILURE);
        }

        cli->timer->cli = cli;
        cli->state = CRA_CLIENT_STATE_TIME_WAIT;
        cra_timer_init(&cli->timer->base,
                       cli->io.loop,
                       1,
                       cli->retry_ms,
                       (cra_timer_fn)cra_client_on_timeout,
                       (cra_timer_fn)cra_client_on_removed);

        CRA_LOG(error, Client, "Connect error: %d, retry in %d ms.", err, cli->retry_ms);

        cli->retry_ms = cli->retry_ms * 2;
        if (cli->retry_ms > cli->retry_max_ms)
        {
            cli->retry_ms = cli->retry_max_ms;
        }

        cra_loop_add_timer(&cli->timer->base);
    }
    else
    {
        cli->state = CRA_CLIENT_STATE_DISCONNECTED;
        CRA_LOG(error, Client, "Connect error: %d.", err);
    }
}

static void
__cra_client_connect(CraClient *cli)
{
    int  err;
    char ipport[CRA_IPPORTSTR_MAX];

    assert(!cli->conn);
    assert(!cli->trans);
    assert(!cli->timer);

    cra_socket_address_get_ipport(&cli->remoteaddr, ipport, sizeof(ipport));
    CRA_LOG(debug, Client, "Connecting to %s.", ipport);

    cli->state = CRA_CLIENT_STATE_CONNECTING;
    cli->trans = cra_trans_connect(cli->trans_i, cli->trans_ctx, &cli->remoteaddr, &cli->io.fd, &err);
    switch (err)
    {
        case 0:
        case CRA_EWOULDBLOCK:
        case CRA_EINPROGRESS:
            assert_always(cli->trans);
            cra_loop_add_io(&cli->io);
            break;

        default:
            if (cli->trans)
            {
                cra_trans_shutdown(cli->trans, true);
                cra_trans_release(cli->trans);
            }
            cra_client_retry(cli, err);
            break;
    }
}

void
cra_client_init(CraClient *cli, const char *host, int port, CraLoop *loop, int bufsize)
{
    assert(cli);
    assert(host);
    assert(loop);
    assert(bufsize > 0);
    assert(port > 0 && port < 65536);

    bzero(cli, sizeof(*cli));
    cli->bufsize = bufsize;
    cli->retry_ms = CRA_CLIENT_RETRY_MS;
    cli->retry_max_ms = CRA_CLIENT_RETRY_MAX_MS;
    cra_io_init(&cli->io, loop, CRA_SOCKET_INVALID, CRA_IO_WRIT, cra_client_handle_connect);
    if (!cra_socket_address_init(&cli->remoteaddr, host, (unsigned short)port))
    {
        CRA_LOG(fatal, Client, "Invalid host or port: %s:%d", host, port);
        exit(EXIT_FAILURE);
    }

    CRA_LOG(trace, Client, "Initialized.");
}

void
cra_client_uninit(CraClient *cli)
{
    assert(cli);
    assert(!cli->conn);
    assert(!cli->trans);
    assert(!cli->timer);
    assert(cli->state == CRA_CLIENT_STATE_DISCONNECTED);
    cra_loop_assert_in_thread(cli->io.loop);

    cra_io_uninit(&cli->io);

    CRA_LOG(trace, Client, "Uninitialized.");
}

void
cra_client_connect(CraClient *cli, const CraTrans_i *trans_i, void *trans_ctx, bool reconnect)
{
    assert(cli);
    assert(trans_i);
    assert(cli->state == CRA_CLIENT_STATE_DISCONNECTED);
    cra_loop_assert_in_thread(cli->io.loop);

    cli->retry = reconnect;
    cli->trans_i = trans_i;
    cli->trans_ctx = trans_ctx;

    __cra_client_connect(cli);
}

void
cra_client_reconnect(CraClient *cli)
{
    assert(cli);
    assert(cli->trans_i);
    cra_loop_assert_in_thread(cli->io.loop);

    if (cli->state == CRA_CLIENT_STATE_CONNECTED)
    {
        CRA_LOG(debug, Client, "Client is connected, no need to reconnect.");
        return;
    }
    if (cli->state == CRA_CLIENT_STATE_CONNECTING)
    {
        CRA_LOG(debug, Client, "Client is connecting, no need to reconnect.");
        return;
    }
    if (cli->state == CRA_CLIENT_STATE_TIME_WAIT)
    {
        cra_loop_del_timer(&cli->timer->base);
        cli->timer = NULL;
    }
    __cra_client_connect(cli);
}

void
cra_client_disconnect(CraClient *cli)
{
    assert(cli);
    cra_loop_assert_in_thread(cli->io.loop);

    cli->retry = false;
    if (cli->state == CRA_CLIENT_STATE_DISCONNECTED)
    {
        CRA_LOG(debug, Client, "Client is disconnected, no need to disconnect.");
        return;
    }
    if (cli->state == CRA_CLIENT_STATE_CONNECTED)
    {
        assert(cli->conn);
        cra_conn_close(cli->conn);
        cli->conn = NULL;
    }
    if (cli->state == CRA_CLIENT_STATE_TIME_WAIT)
    {
        assert(cli->timer);
        cra_loop_del_timer(&cli->timer->base);
        cli->timer = NULL;
    }
    if (cli->state == CRA_CLIENT_STATE_CONNECTING)
    {
        cra_loop_del_io(&cli->io);
        cra_trans_shutdown(cli->trans, true);
        cra_trans_release(cli->trans);
        cli->trans = NULL;
    }
    cli->state = CRA_CLIENT_STATE_DISCONNECTED;
}
