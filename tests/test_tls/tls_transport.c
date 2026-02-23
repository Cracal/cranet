#define __OPENSSL_APPLINK_IMPL__
#define __CRA_TRANS_IMPL__
#include "tls_transport.h"
#include "cra_assert.h"
#include "cra_buffer.h"
#include "cra_malloc.h"

typedef enum
{
    TLS_STATE_HANDSHAKE,
    TLS_STATE_DATA,
} TlsState_e;

typedef enum
{
    TLS_SIDE_UNSET,
    TLS_SIDE_SERVER,
    TLS_SIDE_CLIENT,
} TlsSide_e;

typedef struct _TlsTransport
{
    CRA_TRANS_HEAD;
    cra_socket_t fd;
    TlsState_e   state;
    TlsSide_e    side;
    TlsCtx      *ctx;
    SSL         *ssl;
} TlsTransport;

#define TLSTRANS_TAG "TlsTransport"

static TlsTransport *
tls_transport_create(const CraTrans_i *i, TlsCtx *ctx, cra_socket_t fd)
{
    TlsTransport *trans = cra_alloc(TlsTransport);
    if (!trans)
        return NULL;

    CRA_TRANS_I(trans) = i;
    trans->fd = fd;
    trans->state = TLS_STATE_HANDSHAKE;
    trans->side = TLS_SIDE_UNSET;
    trans->ctx = ctx;

    cra_socketopt_set_nonblocking(fd, true);
    cra_socketopt_set_tcp_no_delay(fd, true);
    cra_socketopt_set_close_on_execute(fd, true);

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        cra_dealloc(trans);
        return NULL;
    }
    if (!SSL_set_fd(ssl, (int)fd))
    {
        cra_dealloc(trans);
        SSL_free(ssl);
        return NULL;
    }
    trans->ssl = ssl;
    return trans;
}

static inline void
tls_transport_destroy(TlsTransport *self)
{
    SSL_free(self->ssl);
    cra_dealloc(self);
}

static inline TlsTransport *
tls_transport_make_trans(const CraTrans_i *i, int af, TlsCtx *ctx)
{
    cra_socket_t fd;

    assert(i);
    assert(ctx);
    assert(af == AF_INET || af == AF_INET6);

    fd = cra_socket(af, SOCK_STREAM, 0);
    if (fd == CRA_SOCKET_INVALID)
        return NULL;

    return tls_transport_create(i, ctx, fd);
}

static void
tls_transport_check_handshake(TlsTransport *self)
{
    int ret;

    switch (self->side)
    {
        case TLS_SIDE_SERVER:
            ret = SSL_accept(self->ssl);
            break;
        case TLS_SIDE_CLIENT:
            ret = SSL_connect(self->ssl);
            break;
        default:
            assert_always(false);
    }

    // FIXME: fatal error?
    if (ret > 0)
        self->state = TLS_STATE_DATA;

    cra_set_last_error(CRA_EWOULDBLOCK); // handshaking
}

static CRA_LISTEN_FN(tls_transport_listen)
{
    int           af;
    int           err;
    TlsTransport *trans;

    assert(i);
    assert(ctx);
    assert(retfd);
    assert(listenaddr);
    CRA_TRANS_CHECK(&i, TLSTRANS_TAG);

    af = cra_socket_address_get_af(listenaddr);
    if ((trans = tls_transport_make_trans(i, af, (TlsCtx *)ctx)))
    {
        if (af == AF_INET6)
            cra_socketopt_set_ipv6_only(trans->fd, v6only);
        if (cra_socket_bind(trans->fd, listenaddr) && cra_socket_listen(trans->fd, SOMAXCONN))
        {
            *retfd = trans->fd;
            return (CraTrans_i **)trans;
        }

        err = cra_get_last_error();
        SSL_shutdown(trans->ssl);
        cra_socket_close(trans->fd);
        tls_transport_destroy(trans);
        cra_set_last_error(err);
    }
    return NULL;
}

static CRA_ACCEPT_FN(tls_transport_accept)
{
    cra_socket_t  fd;
    TlsTransport *trans_listen, *trans;

    assert(self);
    assert(retfd);
    CRA_UNUSED_VALUE(inputbuf);
    CRA_TRANS_CHECK(self, TLSTRANS_TAG);

    trans_listen = (TlsTransport *)self;
    fd = cra_socket_accept(trans_listen->fd, fromaddr);
    if (fd == CRA_SOCKET_INVALID)
        return NULL;

    trans = tls_transport_create(CRA_TRANS_I(trans_listen), trans_listen->ctx, fd);
    if (!trans)
    {
        cra_socket_close(fd);
        return NULL;
    }

    trans->side = TLS_SIDE_SERVER;
    if (SSL_accept(trans->ssl) > 0)
        trans->state = TLS_STATE_DATA;
    *retfd = fd;
    return (CraTrans_i **)trans;
}

static CRA_CONNECT_FN(tls_transport_connect)
{
    int           af;
    int           ret;
    TlsTransport *trans;

    assert(i);
    assert(ctx);
    assert(retfd);
    assert(reterr);
    assert(toaddr);
    CRA_TRANS_CHECK(&i, TLSTRANS_TAG);

    af = cra_socket_address_get_af(toaddr);
    if ((trans = tls_transport_make_trans(i, af, (TlsCtx *)ctx)))
    {
        cra_socket_connect(trans->fd, toaddr);
        if ((ret = SSL_connect(trans->ssl)) > 0)
        {
            trans->state = TLS_STATE_DATA;
            goto ok;
        }

        *reterr = SSL_get_error(trans->ssl, ret);
        switch (*reterr)
        {
            case 0:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            ok:
                *retfd = trans->fd;
                trans->side = TLS_SIDE_CLIENT;
                *reterr = CRA_EWOULDBLOCK;
                return (CraTrans_i **)trans;

            default:
                ERR_print_errors_fp(stderr);
                SSL_shutdown(trans->ssl);
                cra_socket_close(trans->fd);
                tls_transport_destroy(trans);
                break;
        }
    }
    return NULL;
}

static CRA_SHUTDOWN_FN(tls_transport_shutdown)
{
    CRA_UNUSED_VALUE(immediately);
    CRA_TRANS_CHECK(self, TLSTRANS_TAG);
    TlsTransport *trans = (TlsTransport *)self;
    SSL_shutdown(trans->ssl);
}

static CRA_RELEASE_FN(tls_transport_release)
{
    CRA_TRANS_CHECK(self, TLSTRANS_TAG);
    TlsTransport *trans = (TlsTransport *)self;
    cra_socket_close(trans->fd);
    tls_transport_destroy(trans);
}

static CRA_RECV_FN(tls_transport_recv)
{
    int           n;
    size_t        len;
    char         *buff;
    TlsTransport *trans;

    assert(self);
    assert(inputbuf);

    trans = (TlsTransport *)self;
    if (trans->state == TLS_STATE_DATA)
    {
        len = cra_buffer_writable(inputbuf);
        if (len == 0)
        {
            // FIXME: Out of memory?
            cra_buffer_resize(inputbuf, cra_buffer_readable(inputbuf) + 1024);
            len = cra_buffer_writable(inputbuf);
        }
        buff = (char *)cra_buffer_write_start(inputbuf);
        n = SSL_read(trans->ssl, buff, (int)len);
        if (n > 0)
        {
            cra_buffer_append_size(inputbuf, (size_t)n);
        }
        return n;
    }
    else
    {
        tls_transport_check_handshake(trans);
        return -1;
    }
}

static CRA_SEND_FN(tls_transport_send)
{
    int           n;
    TlsTransport *trans;

    assert(self);
    assert(buf);
    assert(len > 0);

    trans = (TlsTransport *)self;
    if (trans->state == TLS_STATE_DATA)
    {
        n = SSL_write(trans->ssl, buf, len);
        return n;
    }
    else
    {
        tls_transport_check_handshake(trans);
        return -1;
    }
}

const CraTrans_i g_tls_transport_i = {
    CRA_IF_HEAD_SET(TLSTRANS_TAG),    .listen = tls_transport_listen,     .accept = tls_transport_accept,
    .connect = tls_transport_connect, .shutdown = tls_transport_shutdown, .release = tls_transport_release,
    .recv = tls_transport_recv,       .send = tls_transport_send,
};
