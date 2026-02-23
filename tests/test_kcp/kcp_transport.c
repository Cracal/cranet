#define __CRA_TRANS_IMPL__
#include "kcp_transport.h"
#include "cra_buffer.h"
#include "cra_endian.h"
#include "cra_loop.h"
#include "cra_malloc.h"
#include "cra_time.h"

#define KCPTRANSPORT_TAG "KcpTransport"
#define TransportKcp     trans

typedef struct _KcpTransport KcpTransport;

typedef struct
{
    CraTimer      base;
    KcpTransport *trans;
} KcpTimer;

typedef struct _KcpCommon
{
    KcpCtx            *ctx;
    CraDict            dict; // Dict<CraSocketAddress, KcpTransport *>
    cra_spinlock_t     lock;
    bool               ipv6only;
    cra_atomic_int32_t refcnt;
} KcpCommon;

struct _KcpTransport
{
    CRA_TRANS_HEAD;
    cra_socket_t     fd;
    KcpTimer         timer;
    ikcpcb          *kcpcb;
    KcpCommon       *common;
    CraSocketAddress address;
};

static KcpCommon *
kcp_common_create(KcpCtx *ctx, bool ipv6only)
{
    KcpCommon *common = cra_alloc(KcpCommon);
    if (!common)
        return NULL;

    if (!cra_dict_init0(CraSocketAddress,
                        KcpTransport *,
                        &common->dict,
                        false,
                        (cra_hash_fn)cra_hash_socket_address_p,
                        (cra_compare_fn)cra_compare_socket_address_p))
    {
        cra_dealloc(common);
        return NULL;
    }

    cra_spinlock_init(&common->lock);
    common->ipv6only = ipv6only;
    common->refcnt = 1;
    common->ctx = ctx;
    return common;
}

static inline void
kcp_common_ref(KcpCommon *common)
{
    cra_atomic_inc32(&common->refcnt);
}

static inline void
kcp_common_unref(KcpCommon *common)
{
    if (cra_atomic_dec32(&common->refcnt) == 1)
    {
        assert(common->dict.count == 0);
        cra_dict_uninit(&common->dict);
        cra_spinlock_uninit(&common->lock);
        cra_dealloc(common);
    }
}

static inline KcpTransport *
kcp_common_get_transport(KcpCommon *common, const CraSocketAddress *address)
{
    KcpTransport *trans = NULL;
    cra_spinlock_lock(&common->lock);
    cra_dict_get(&common->dict, (void *)address, &trans);
    cra_spinlock_unlock(&common->lock);
    return trans;
}

static inline void
kcp_common_put_transport(KcpCommon *common, const CraSocketAddress *address, KcpTransport *trans)
{
    cra_spinlock_lock(&common->lock);
    cra_dict_add(&common->dict, (void *)address, &trans);
    cra_spinlock_unlock(&common->lock);
}

static inline void
kcp_common_remove_transport(KcpCommon *common, const CraSocketAddress *address)
{
    cra_spinlock_lock(&common->lock);
    cra_dict_remove(&common->dict, (void *)address);
    cra_spinlock_unlock(&common->lock);
}

static int
kcp_tansport_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
    assert(len > 0);
    KcpTransport *trans = (KcpTransport *)user;
    assert(trans->kcpcb == kcp);
    CRA_UNUSED_VALUE(kcp);
    return cra_socket_send(trans->fd, buf, len);
}

static void
on_update_in_loop(KcpTransport *trans)
{
    assert(trans->kcpcb);
    ikcp_update(trans->kcpcb, (IUINT32)trans->timer.base.loop->current_ms);
}

static void
on_update(CraTimer *timer)
{
    KcpTimer *t = container_of(timer, KcpTimer, base);
    cra_loop_run_in_loop(timer->loop, (cra_functor_fn)on_update_in_loop, t->trans, NULL);
}

static IUINT32
make_conv(void)
{
    // unsafe
    IUINT32 conv;
    srand((unsigned int)(time(NULL) ^ 131));
    do
    {
        conv = (IUINT32)((rand() ^ 13131) | (rand() << 17));
    } while (conv == 0);
    return conv;
}

static KcpTransport *
kcp_transport_create(const CraTrans_i       *i,
                     KcpCtx                 *ctx,
                     const CraSocketAddress *address,
                     const CraSocketAddress *bindaddr,
                     const CraSocketAddress *connecttoaddr,
                     bool                    set_ipv6only,
                     bool                    ipv6only)
{
    int           af;
    cra_socket_t  fd;
    KcpTransport *trans;
    uint32_t      timeout;

    assert(i);
    assert(ctx);
    assert(address);
    assert(bindaddr || connecttoaddr);

    af = cra_socket_address_get_af(address);
    assert(af == AF_INET || af == AF_INET6);

    fd = cra_socket(af, SOCK_DGRAM, 0);
    if (fd == CRA_SOCKET_INVALID)
        return NULL;

    cra_socketopt_set_reuse_address(fd, true);
    cra_socketopt_set_reuse_port(fd, true);
    cra_socketopt_set_nonblocking(fd, true);
    cra_socketopt_set_close_on_execute(fd, true);
    if (set_ipv6only && af == AF_INET6)
        cra_socketopt_set_ipv6_only(fd, ipv6only);

    if (bindaddr && !cra_socket_bind(fd, bindaddr))
    {
        int err = cra_get_last_error();
        cra_socket_close(fd);
        cra_set_last_error(err);
        return NULL;
    }
    if (connecttoaddr && !cra_socket_connect(fd, connecttoaddr))
    {
        int err = cra_get_last_error();
        cra_socket_close(fd);
        cra_set_last_error(err);
        return NULL;
    }

    trans = cra_alloc(KcpTransport);
    if (!trans)
    {
        int err = cra_get_last_error();
        cra_socket_close(fd);
        cra_set_last_error(err);
        return NULL;
    }
    CRA_TRANS_I(trans) = i;
    trans->fd = fd;
    trans->common = NULL;
    memcpy(&trans->address, address, sizeof(*address));

    trans->kcpcb = ikcp_create(0, trans);
    if (!trans->kcpcb)
    {
        int err = cra_get_last_error();
        cra_socket_close(fd);
        cra_dealloc(trans);
        cra_set_last_error(err);
        return NULL;
    }
    ikcp_setoutput(trans->kcpcb, kcp_tansport_output);

    trans->timer.trans = trans;
    timeout = ctx->fastmode ? 10 : 40;
    cra_timer_init(&trans->timer.base, ctx->timer_loop, CRA_TIMER_INFINITE, timeout, on_update, NULL);
    return trans;
}

static inline void
kcp_transport_run_timer(KcpTransport *trans, KcpCtx *ctx)
{
    assert(trans->kcpcb);
    cra_loop_run_in_loop(ctx->timer_loop, (cra_functor_fn)cra_loop_add_timer, &trans->timer.base, NULL);
}

static CRA_LISTEN_FN(kcp_transport_listen)
{
    KcpCtx       *kctx;
    KcpTransport *trans;

    assert(ctx);
    assert(listenaddr);
    assert(retfd);
    CRA_TRANS_CHECK(&i, KCPTRANSPORT_TAG);

    kctx = (KcpCtx *)ctx;
    assert(kctx->timer_loop);

    trans = kcp_transport_create(i, kctx, listenaddr, listenaddr, NULL, true, v6only);
    if (trans)
    {
        *retfd = trans->fd;
        trans->common = kcp_common_create(kctx, v6only);
        if (trans->common)
        {
            kcp_common_put_transport(trans->common, listenaddr, trans);
            kcp_transport_run_timer(trans, kctx);
            return (CraTrans_i **)trans;
        }

        int err = cra_get_last_error();
        cra_timer_uninit(&trans->timer.base);
        cra_socket_close(trans->fd);
        ikcp_release(trans->kcpcb);
        cra_dealloc(trans);
        cra_set_last_error(err);
    }
    return NULL;
}

static int
kcp_transport_input(KcpTransport *trans, const char *buf, int len, CraBuffer *inputbuf)
{
    int n;
    int retn;

    assert(trans->kcpcb);

    if (ikcp_input(trans->kcpcb, buf, len) < 0)
        return -1;

    retn = -1;
    while (true)
    {
        n = ikcp_recv(trans->kcpcb, (char *)cra_buffer_write_start(inputbuf), (int)cra_buffer_writable(inputbuf));
        if (n > 0)
        {
            cra_buffer_append_size(inputbuf, n);
            retn = (retn == -1) ? n : (retn + n);
        }
        else if (n == -3)
        {
            // FIXME: Out of memory?
            cra_buffer_resize(inputbuf, cra_buffer_size(inputbuf) + (size_t)ikcp_peeksize(trans->kcpcb));
        }
        else
        {
            break;
        }
    }

    if (retn == -1)
        cra_set_last_error(CRA_EWOULDBLOCK);
    return retn;
}

static CRA_ACCEPT_FN(kcp_transport_accept)
{
    int           n;
    size_t        len;
    char         *buf;
    KcpTransport *trans;
    KcpTransport *trans_listen;

    assert(fromaddr);
    assert(inputbuf);
    assert(retfd);
    CRA_TRANS_CHECK(self, KCPTRANSPORT_TAG);

    trans_listen = (KcpTransport *)self;
    if (!trans_listen->kcpcb)
        return NULL;

    len = cra_buffer_writable(inputbuf);
    buf = (char *)cra_buffer_write_start(inputbuf);
    n = cra_socket_recvfrom(trans_listen->fd, buf, (int)len, fromaddr);
    if (n <= 0)
        return NULL;

    if (!(trans = kcp_common_get_transport(trans_listen->common, fromaddr)))
    {
        trans = kcp_transport_create(CRA_TRANS_I(trans_listen),
                                     trans_listen->common->ctx,
                                     fromaddr,
                                     &trans_listen->address,
                                     fromaddr,
                                     true,
                                     trans_listen->common->ipv6only);
        if (!trans)
            return NULL;

        trans->kcpcb->conv = ikcp_getconv(buf); // set conv
        trans->common = trans_listen->common;
        kcp_common_put_transport(trans->common, fromaddr, trans);
        kcp_common_ref(trans->common);
        kcp_transport_run_timer(trans, trans->common->ctx);
    }

    *retfd = trans->fd;
    kcp_transport_input(trans, buf, n, inputbuf);
    return (CraTrans_i **)trans;
}

static CRA_CONNECT_FN(kcp_transport_connect)
{
    KcpCtx       *kctx;
    KcpTransport *trans;

    assert(ctx);
    assert(retfd);
    assert(reterr);
    assert(toaddr);
    CRA_TRANS_CHECK(&i, KCPTRANSPORT_TAG);

    kctx = (KcpCtx *)ctx;
    assert(kctx->timer_loop);

    trans = kcp_transport_create(i, kctx, toaddr, NULL, toaddr, false, false);
    if (trans)
        *retfd = trans->fd;
    *reterr = cra_get_last_error();
    kcp_transport_run_timer(trans, kctx);
    return (CraTrans_i **)trans;
}

static CRA_SHUTDOWN_FN(kcp_transport_shutdown)
{
    KcpTransport *trans = (KcpTransport *)self;
    CRA_TRANS_CHECK(self, KCPTRANSPORT_TAG);
    if (immediately)
    {
        assert(trans->kcpcb);

        cra_socket_close(trans->fd);
        trans->fd = CRA_SOCKET_INVALID;
        cra_loop_run_in_loop(trans->timer.base.loop, (cra_functor_fn)cra_loop_del_timer, &trans->timer.base, NULL);
        ikcp_release(trans->kcpcb);
        trans->kcpcb = NULL;
        if (trans->common)
            kcp_common_remove_transport(trans->common, &trans->address);
    }
    else
    {
        cra_socket_shutdown(trans->fd, CRA_SHUT_WR);
    }
}

static CRA_RELEASE_FN(kcp_transport_release)
{
    KcpTransport *trans = (KcpTransport *)self;
    CRA_TRANS_CHECK(self, KCPTRANSPORT_TAG);
    assert(trans->fd == CRA_SOCKET_INVALID);
    assert(trans->kcpcb == NULL);
    if (trans->common)
        kcp_common_unref(trans->common);
    cra_dealloc(trans);
}

static CRA_RECV_FN(kcp_transport_recv)
{
    int           n;
    size_t        len;
    char         *buf;
    KcpTransport *trans;

    assert(inputbuf);
    CRA_TRANS_CHECK(self, KCPTRANSPORT_TAG);

    trans = (KcpTransport *)self;

    len = cra_buffer_writable(inputbuf);
    buf = (char *)cra_buffer_write_start(inputbuf);
    n = cra_socket_recv(trans->fd, buf, (int)len);
    if (n <= 0)
        return n;
    return kcp_transport_input(trans, buf, n, inputbuf);
}

static CRA_SEND_FN(kcp_transport_send)
{
    KcpTransport *trans;

    assert(self);
    assert(buf);
    assert(len > 0);

    trans = (KcpTransport *)self;
    assert(trans->kcpcb);

    // handshake?
    if (trans->kcpcb->conv == 0)
        trans->kcpcb->conv = make_conv();

    // send data
    return ikcp_send(trans->kcpcb, (char *)buf, len);
}

const CraTrans_i g_kcp_trans_i = {
    CRA_IF_HEAD_SET(KCPTRANSPORT_TAG), .listen = kcp_transport_listen,     .accept = kcp_transport_accept,
    .connect = kcp_transport_connect,  .shutdown = kcp_transport_shutdown, .release = kcp_transport_release,
    .recv = kcp_transport_recv,        .send = kcp_transport_send,
};
