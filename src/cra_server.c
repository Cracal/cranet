#define __CRA_CONN_NO_ASSERT_IN_LOOP
#define __CRA_CONN_INNER
#include "cra_server.h"
#include "cra_log.h"
#include "threads/cra_cdl.h"
#include "threads/cra_thrdpool.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-Server"

#define Server srv

static CraLoop *
cra_server_get_loop(CraServer *srv)
{
    CraLoop *loop;
    if (srv->nsubloops > 0)
    {
        loop = srv->subloops + srv->nextloop;
        srv->nextloop = (srv->nextloop + 1) % srv->nsubloops;
    }
    else
    {
        loop = srv->mainloop;
    }
    return loop;
}

static void
cra_server_release_conn(CraRefcnt *ref)
{
    CraConn *conn = container_of(ref, CraConn, ref);
    cra_conn_uninit(conn);
    cra_dealloc(conn);
}

static void
cra_server_handle_conn_in_loop(CraConn *conn)
{
    CraServer *srv = conn->srv;
#ifndef NDEBUG
    cra_loop_assert_in_thread(srv->mainloop);
#endif

    cra_conn_ref(conn);

    if (!cra_conn_is_connected(conn))
    {
        cra_dict_remove(&srv->conns, &conn->io.fd);
        cra_conn_unref(conn);
    }

    if (srv->on_conn)
        srv->on_conn(conn);

    cra_conn_unref(conn);
}

static void
cra_server_handle_conn(CraConn *conn)
{
    assert(conn->srv);
    cra_loop_run_in_loop(conn->srv->mainloop, (cra_functor_fn)cra_server_handle_conn_in_loop, conn, &conn->ref);
}

static inline void
cra_server_init_conn(CraConn *conn, cra_socket_t fd, CraServer *srv)
{
    CraLoop *loop;

    assert(srv->on_read);

    loop = cra_server_get_loop(srv);
    cra_conn_init(conn, fd, loop, CRA_IO_READ, srv->bufsize, cra_server_release_conn);
    conn->srv = srv;
    cra_conn_set_conn_cb(conn, cra_server_handle_conn);
    cra_conn_set_read_cb(conn, srv->on_read);
    cra_conn_set_write_completed_cb(conn, srv->on_write_completed);
    cra_conn_set_write_high_water_mark_cb(conn, srv->write_high_water_mark, srv->on_write_high_water_mark);
}

static void
cra_server_handle_accept(CraIO *io)
{
    CraServer       *srv;
    CraConn         *conn;
    CraTrans_i     **trans;
    CraConnBuffConn *buffconn;

    srv = container_of(io, CraServer, listenio);

    conn = srv->tempconn;
    if (!conn)
    {
        conn = cra_alloc(CraConn);
        if (!conn)
        {
            int err = cra_get_last_error();
            CRA_LOG(error, Server, "Failed to create conn. err: %d.", err);
            return;
        }
        cra_server_init_conn(conn, CRA_SOCKET_INVALID, srv);
        srv->tempconn = conn;
    }
    buffconn = srv->tempbuff;
    if (!buffconn)
    {
        buffconn = cra_conn_buff_conn_create(srv->bufsize);
        if (!buffconn)
        {
            int err = cra_get_last_error();
            CRA_LOG(error, Server, "Failed to create buffconn. err: %d.", err);
            return;
        }
        srv->tempbuff = buffconn;
    }

    // accept
    conn->peeraddr.hash = -1; // important
    trans = cra_trans_accept(srv->listentrans, &conn->peeraddr, &buffconn->buff, &conn->io.fd);
    if (!trans)
    {
        // TODO: handle EMFILE
        int err = cra_get_last_error();
        if (err != CRA_EINTR && err != CRA_EWOULDBLOCK)
            CRA_LOG(error, Server, "Accept error: %d.", err);
        cra_buffer_retrieve_all_size(&buffconn->buff);
        return;
    }

    if (!cra_dict_get(&srv->conns, &conn->io.fd, (void **)&conn))
    {
        if (!cra_dict_add(&srv->conns, &conn->io.fd, &conn))
        {
            CRA_LOG(error, Server, "Accept error: Failed to add conn to dict.");
            cra_buffer_retrieve_all_size(&buffconn->buff);
            cra_trans_shutdown(trans, true);
            cra_trans_release(trans);
            return;
        }

        conn->trans = trans;
        cra_socket_get_local_address(conn->io.fd, &conn->localaddr);
        if (srv->ct_on_timeout)
            cra_conn_enable_close_timer(conn, srv->mainloop, srv->ct_timeout, srv->ct_on_timeout);
        if (srv->hb_on_heartbeat)
            cra_conn_enable_heartbeat_timer(conn, srv->mainloop, srv->hb_interval, srv->hb_on_heartbeat);

        cra_loop_run_in_loop(conn->io.loop, (cra_functor_fn)cra_conn_establish, conn, &conn->ref);
        srv->tempconn = NULL;
    }

    if (cra_buffer_readable(&buffconn->buff) > 0)
    {
        buffconn->conn = conn;
        cra_loop_run_in_loop(conn->io.loop, (cra_functor_fn)cra_conn_call_read_cb, buffconn, &conn->ref);
        srv->tempbuff = NULL;
    }
}

static void
cra_server_sub_loop_thread(const CraThrdPoolArgs2 *args)
{
    CraLoop *loop = (CraLoop *)args->arg1;
    CraCDL  *cdl = (CraCDL *)args->arg2;

    cra_loop_init(loop);

    cra_cdl_count_down(cdl);

    cra_loop_loop(loop);

    cra_loop_uninit(loop);
}

void
cra_server_init(CraServer *srv, const char *host, int port, CraLoop *loop, unsigned int nsubloops, int bufsize)
{
    assert(host);
    assert(port >= 0 && port < 65536);
    assert(loop);
    assert(bufsize > 0);

    bzero(srv, sizeof(*srv));
    srv->mainloop = loop;
    srv->bufsize = bufsize;

    if (!cra_socket_address_init(&srv->listenaddr, host, (unsigned short)port))
    {
        CRA_LOG(fatal, Server, "Invalid host: %s or port: %d.", host, port);
        exit(EXIT_FAILURE);
    }

    cra_io_init(&srv->listenio, loop, CRA_SOCKET_INVALID, CRA_IO_READ, cra_server_handle_accept);

    if (!cra_dict_init0(cra_socket_t,
                        CraConn *,
                        &srv->conns,
                        false,
                        (cra_hash_fn)cra_hash_socket_p,
                        (cra_compare_fn)cra_compare_socket_p))
    {
        CRA_LOG(fatal, Server, "Failed to init conns dict.");
        exit(EXIT_FAILURE);
    }

    if (nsubloops > 0)
    {
        srv->nsubloops = nsubloops;
        srv->subloops = (CraLoop *)cra_calloc(nsubloops, sizeof(CraLoop));
        srv->loop_pool = cra_alloc(CraThrdPool);
        cra_thrdpool_init(srv->loop_pool, (int)nsubloops, nsubloops);
    }

    CRA_LOG(trace, Server, "Initialized.");
}

void
cra_server_uninit(CraServer *srv)
{
    assert_always(!srv->started);

    if (srv->tempconn)
        cra_conn_unref(srv->tempconn);
    if (srv->tempbuff)
        cra_conn_buff_conn_destroy(srv->tempbuff);

    cra_io_uninit(&srv->listenio);

    // free dict
    cra_dict_uninit(&srv->conns);

    if (srv->nsubloops > 0)
    {
        cra_thrdpool_uninit(srv->loop_pool);
        cra_dealloc(srv->loop_pool);
        cra_free(srv->subloops);
    }

    bzero(srv, sizeof(*srv));

    CRA_LOG(trace, Server, "Uninitialized.");
}

void
cra_server_start(CraServer *srv, const CraTrans_i *trans_i, void *trans_ctx, bool ipv6only)
{
    cra_socket_t fd;

    assert(!srv->started);
    assert(trans_i);
    cra_loop_assert_in_thread(srv->mainloop);

    srv->started = true;

    srv->listentrans = cra_trans_listen(trans_i, trans_ctx, &srv->listenaddr, ipv6only, &fd);
    if (!srv->listentrans)
    {
        CRA_LOG(fatal, Server, "Listen error: %d.", cra_get_last_error());
        exit(EXIT_FAILURE);
    }

    // init subloops
    if (srv->nsubloops > 0)
    {
        CraCDL cdl;
        cra_cdl_init(&cdl, (int)srv->nsubloops);

        for (unsigned int i = 0; i < srv->nsubloops; ++i)
            cra_thrdpool_add_task2(srv->loop_pool, cra_server_sub_loop_thread, srv->subloops + i, &cdl);

        cra_cdl_wait(&cdl);
        cra_cdl_uninit(&cdl);
    }

    // add to loop
    srv->listenio.fd = fd;
    cra_loop_add_io(&srv->listenio);

    char ipport[CRA_IPPORTSTR_MAX];
    cra_socket_address_get_ipport(&srv->listenaddr, ipport, sizeof(ipport));
    CRA_LOG(info, Server, "Listening on %s.", ipport);
}

void
cra_server_stop(CraServer *srv)
{
    CraConn   **connptr;
    CraConn    *conn;
    CraDictIter it;

    assert(srv->started);
    cra_loop_assert_in_thread(srv->mainloop);

    CRA_LOG(trace, Server, "Stopping...");

    srv->started = false;

    // destroy IO
    cra_loop_del_io(&srv->listenio);

    // terminating connections
    for (cra_dict_iter_init(&srv->conns, &it); cra_dict_iter_next(&it, NULL, (void **)&connptr);)
    {
        conn = *connptr;
        cra_loop_run_in_loop(conn->io.loop, (cra_functor_fn)cra_conn_terminate, conn, &conn->ref);
        cra_conn_unref(conn);
    }
    cra_dict_clear(&srv->conns);

    // uninit subloops
    if (srv->nsubloops > 0)
    {
        for (unsigned int i = 0; i < srv->nsubloops; ++i)
            cra_loop_stop_safe(srv->subloops + i);
        cra_thrdpool_wait(srv->loop_pool);
    }

    // destroy transport
    cra_trans_shutdown(srv->listentrans, true);
    cra_trans_release(srv->listentrans);

    CRA_LOG(trace, Server, "Stopped.");
}
