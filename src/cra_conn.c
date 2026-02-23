#define __CRA_CONN_INNER
#include "cra_conn.h"
#include "cra_log.h"
#include "cra_server.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-Conn"

#define Conn conn

typedef struct _CraConnBufConn CraConnBufConn;
struct _CraConnBufConn
{
    CraConnBuf *buff;
    CraConn    *conn;
};

static inline CraConnBufConn *
cra_conn_bufconn_create(CraConn *conn, CraConnBuf *buff)
{
    CraConnBufConn *buffconn = cra_alloc(CraConnBufConn);
    if (buffconn)
    {
        buffconn->conn = conn;
        buffconn->buff = buff;
    }
    return buffconn;
}

static inline void
cra_conn_bufconn_destroy(CraConnBufConn *buffconn)
{
    cra_dealloc(buffconn);
}

// =============================

void
cra_conn_call_read_cb(CraConnBuffConn *buffconn)
{
    CraConn   *conn = buffconn->conn;
    CraBuffer *buff = &buffconn->buff;

    assert(conn);
    assert(conn->on_read);
    assert(cra_buffer_readable(buff) > 0);

    conn->on_read(conn, buff);
    cra_conn_buff_conn_destroy(buffconn);
}

// =============================

static void
cra_conn_handle_read(CraConn *conn)
{
    int        n;
    int        err;
    CraBuffer *inputbuf;
    char       ipport[CRA_IPPORTSTR_MAX];

    assert(conn->on_read);

    if (!cra_conn_is_connected(conn))
        return;

    inputbuf = conn->inputbuf;
    if (!inputbuf)
    {
        inputbuf = cra_alloc(CraBuffer);
        if (!inputbuf)
        {
            CRA_LOG(error, Conn, "Failed to create input buffer.");
            cra_conn_close(conn);
            return;
        }
        if (!cra_buffer_init(inputbuf, conn->bufsize))
        {
            CRA_LOG(error, Conn, "Failed to init input buffer.");
            cra_dealloc(inputbuf);
            cra_conn_close(conn);
            return;
        }
        conn->inputbuf = inputbuf;
    }

    n = cra_trans_recv(conn->trans, inputbuf);
    if (n > 0)
    {
        conn->on_read(conn, inputbuf);
        return;
    }

    if (n < 0)
    {
        err = cra_get_last_error();
        if (err == CRA_EWOULDBLOCK || err == CRA_EINTR)
            return;

#ifdef CRA_OS_WIN
        if (err != 0)
#endif
        {
            cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
            CRA_LOG(error, Conn, "Connection '%s' receive failed with error %d.", ipport, err);
        }
    }
    // close conn
    cra_conn_close(conn);
}

static void
cra_conn_handle_write(CraConn *conn)
{
    int            n;
    int            np;
    size_t         len;
    unsigned char *buf;
    CraBuffer     *outputbuf;

    if (!conn->outputbuf)
        return;

    outputbuf = conn->outputbuf;
    while ((len = cra_buffer_readable(outputbuf)) > 0)
    {
        buf = cra_buffer_read_start(outputbuf);
        np = *(int *)buf;
        assert(np > 0 && (size_t)np < len);
        buf += sizeof(np);
        n = cra_trans_send(conn->trans, buf, np);
        if (n > 0)
        {
            if (conn->on_write_completed)
                conn->on_write_completed(conn, n);

            if (n == np)
            {
                cra_buffer_retrieve_size(outputbuf, sizeof(np) + n);
                continue;
            }
            else
            {
                cra_buffer_retrieve_size(outputbuf, n);
                buf = cra_buffer_read_start(outputbuf);
                *(int *)buf = np - n;
            }
        }
        break;
    }

    if (len == 0)
    {
        // remove write event
        conn->io.events &= ~CRA_IO_WRIT;
        cra_loop_mod_io(&conn->io);
        // check closing
        if (conn->state == CRA_CONN_STATE_DISCONNECTING)
            cra_trans_shutdown(conn->trans, false);
    }
}

static void
cra_conn_handle_io(CraIO *io)
{
    CraConn *conn = container_of(io, CraConn, io);

    cra_conn_ref(conn);

    if (conn->closetimer)
        cra_conntimer_update(conn->closetimer);
    if (conn->heartbeattimer)
        cra_conntimer_update(conn->heartbeattimer);

    if (io->revents & CRA_IO_READ)
        cra_conn_handle_read(conn);
    if (io->revents & CRA_IO_WRIT)
        cra_conn_handle_write(conn);

    cra_conn_unref(conn);
}

void
cra_conn_init(CraConn              *conn,
              cra_socket_t          fd,
              CraLoop              *loop,
              int                   events,
              int                   bufsize,
              cra_refcnt_release_fn handle_destroy)
{
    assert(loop);
    assert(bufsize > 0);
    assert(handle_destroy);

    bzero(conn, sizeof(*conn));
    cra_io_init(&conn->io, loop, fd, events, cra_conn_handle_io);
    cra_refcnt_init(&conn->ref, handle_destroy);
    conn->state = CRA_CONN_STATE_CONNECTING;
    conn->localaddr.hash = -1;
    conn->peeraddr.hash = -1;
    conn->bufsize = bufsize;
}

void
cra_conn_uninit(CraConn *conn)
{
    assert(conn->ref.cnt == 0);
    assert(conn->state == CRA_CONN_STATE_CONNECTING || conn->state == CRA_CONN_STATE_DISCONNECTED);
    assert(!conn->heartbeattimer);
    assert(!conn->closetimer);

    cra_io_uninit(&conn->io);
    if (conn->inputbuf)
    {
        cra_buffer_uninit(conn->inputbuf);
        cra_dealloc(conn->inputbuf);
    }
    if (conn->outputbuf)
    {
        cra_buffer_uninit(conn->outputbuf);
        cra_dealloc(conn->outputbuf);
    }
    if (conn->trans)
        cra_trans_release(conn->trans);
}

void
cra_conn_establish(CraConn *conn)
{
    assert(conn->trans);
    assert(conn->state == CRA_CONN_STATE_CONNECTING);
#ifndef NDEBUG
    cra_loop_assert_in_thread(conn->io.loop);
#endif

    conn->state = CRA_CONN_STATE_CONNECTED;
    cra_loop_add_io(&conn->io);

    cra_conn_ref(conn);
    assert(conn->on_conn);
    conn->on_conn(conn);
    cra_conn_unref(conn);
}

void
cra_conn_terminate(CraConn *conn)
{
    assert(conn->trans);
#ifndef NDEBUG
    cra_loop_assert_in_thread(conn->io.loop);
#endif

    if (conn->state != CRA_CONN_STATE_CONNECTED && conn->state != CRA_CONN_STATE_DISCONNECTING)
        return;

    cra_conn_disable_close_timer(conn);
    cra_conn_disable_heartbeat_timer(conn);

    conn->state = CRA_CONN_STATE_DISCONNECTED;
    cra_loop_del_io(&conn->io);
    cra_trans_shutdown(conn->trans, true);
    conn->io.events = 0;
    conn->io.revents = 0;
}

void
cra_conn_shutdown(CraConn *conn)
{
    cra_loop_assert_in_thread(conn->io.loop);

    if (conn->state != CRA_CONN_STATE_CONNECTED)
        return;
    cra_conn_disable_heartbeat_timer(conn);
    cra_trans_shutdown(conn->trans, false);
}

void
cra_conn_close(CraConn *conn)
{
    cra_loop_assert_in_thread(conn->io.loop);

    if (conn->state == CRA_CONN_STATE_CONNECTED || conn->state == CRA_CONN_STATE_DISCONNECTING)
    {
        cra_conn_terminate(conn);
        cra_conn_ref(conn);
        assert(conn->on_conn);
        conn->on_conn(conn);
        cra_conn_unref(conn);
    }
}

void
cra_conn_send(CraConn *conn, const void *buf, int len)
{
    int  n;
    char ipport[CRA_IPPORTSTR_MAX];

    assert(buf && len > 0);
    cra_loop_assert_in_thread(conn->io.loop);

    if (conn->state != CRA_CONN_STATE_CONNECTED)
    {
        cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
        CRA_LOG(warn, Conn, "Send failed: conn={fd:%d, addr:%s} is closed.", (int)conn->io.fd, ipport);
        return;
    }

    if (conn->closetimer)
        cra_conntimer_update(conn->closetimer);
    if (conn->heartbeattimer)
        cra_conntimer_update(conn->heartbeattimer);

    if (!conn->outputbuf || cra_buffer_readable(conn->outputbuf) == 0)
    {
        n = cra_trans_send(conn->trans, buf, len);
        if (n > 0)
        {
            if (conn->on_write_completed)
            {
                cra_conn_ref(conn);
                conn->on_write_completed(conn, len);
                cra_conn_unref(conn);
            }
            len -= n;
        }
        else if (n < 0)
        {
            int err = cra_get_last_error();
            if (err != 0 && err != CRA_EWOULDBLOCK && err != CRA_EINTR)
            {
                cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
                CRA_LOG(error, Conn, "Send error: conn={fd:%d, addr:%s}, error=%d.", (int)conn->io.fd, ipport, err);
                return;
            }
        }
    }

    if (len > 0)
    {
        if (!conn->outputbuf)
        {
            conn->outputbuf = cra_alloc(CraBuffer);
            if (!conn->outputbuf)
            {
                CRA_LOG(error, Conn, "Failed to create output buffer.");
                return;
            }
            if (!cra_buffer_init(conn->outputbuf, conn->bufsize))
            {
                CRA_LOG(error, Conn, "Failed to init output buffer.");
                return;
            }
        }
        // length
        cra_buffer_append(conn->outputbuf, &len, sizeof(len));
        // data
        cra_buffer_append(conn->outputbuf, buf, len);
        if (!(conn->io.events & CRA_IO_WRIT))
        {
            conn->io.events |= CRA_IO_WRIT;
            cra_loop_mod_io(&conn->io);
        }
        // high water mark?
        size_t length;
        if (conn->on_write_high_water_mark &&
            (length = cra_buffer_readable(conn->outputbuf)) >= (size_t)conn->write_high_water_mark)
        {
            cra_conn_ref(conn);
            conn->on_write_high_water_mark(conn, (int)length);
            cra_conn_unref(conn);
        }
    }
}

static void
cra_conn_send_in_loop(CraConnBufConn *buffconn)
{
    cra_conn_send(buffconn->conn, buffconn->buff->buf, buffconn->buff->len);
    cra_conn_buf_unref(buffconn->buff);
    cra_conn_bufconn_destroy(buffconn);
}

void
cra_conn_send_safe0(CraConn *conn, const void *buf, int len)
{
    assert(buf && len > 0);

    if (cra_loop_is_in_thread(conn->io.loop))
    {
        cra_conn_send(conn, buf, len);
    }
    else
    {
        CraConnBuf *connbuf = cra_conn_buf_create(len, 1);
        if (!connbuf)
        {
            CRA_LOG(error, Conn, "Send failed: Failed to create CraConnBuf.");
            return;
        }
        memcpy(connbuf->buf, buf, len);
        cra_conn_send_safe1(conn, connbuf);
    }
}

void
cra_conn_send_safe1(CraConn *conn, CraConnBuf *buf)
{
    if (cra_loop_is_in_thread(conn->io.loop))
    {
        cra_conn_send(conn, buf->buf, buf->len);
        cra_conn_buf_unref(buf);
    }
    else
    {
        CraConnBufConn *buffconn = cra_conn_bufconn_create(conn, buf);
        if (!buffconn)
        {
            CRA_LOG(error, Conn, "Send failed: Failed to create CraConnBufConn.");
            cra_conn_buf_unref(buf);
            return;
        }
        cra_loop_functor_to_queue(conn->io.loop, (cra_functor_fn)cra_conn_send_in_loop, buffconn, &conn->ref);
    }
}
