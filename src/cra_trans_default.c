#define __CRA_TRANS_IMPL__
#include "collections/cra_dict.h"
#include "cra_assert.h"
#include "cra_malloc.h"
#include "cra_trans_i.h"

#if 1 // TCP

typedef struct _CraTcpTrans
{
    CRA_TRANS_HEAD;
    cra_socket_t fd;
} CraTcpTrans;

#define CRA_TCP_TRANS_TAG "CraTcpTrans"

static inline CraTcpTrans *
cra_tcp_trans_create(const CraTrans_i *i, cra_socket_t fd)
{
    CraTcpTrans *trans = cra_alloc(CraTcpTrans);
    if (trans)
    {
        CRA_TRANS_I(trans) = i;
        trans->fd = fd;
        cra_socketopt_set_nonblocking(fd, true);
        cra_socketopt_set_tcp_no_delay(fd, true);
        cra_socketopt_set_close_on_execute(fd, true);
    }
    return trans;
}

static inline CraTcpTrans *
cra_tcp_trans_make_trans(const CraTrans_i *i, int af)
{
    cra_socket_t fd;
    CraTcpTrans *trans;

    assert(i);
    assert(af == AF_INET || af == AF_INET6);

    fd = cra_socket(af, SOCK_STREAM, 0);
    if (fd == CRA_SOCKET_INVALID)
        return NULL;
    trans = cra_tcp_trans_create(i, fd);
    if (!trans)
        cra_socket_close(fd);
    return trans;
}

static CRA_LISTEN_FN(cra_tcp_trans_listen)
{
    int          af;
    int          err;
    CraTcpTrans *trans;

    assert(i);
    assert(retfd);
    assert(listenaddr);
    CRA_UNUSED_VALUE(ctx);
    CRA_TRANS_CHECK(&i, CRA_TCP_TRANS_TAG);

    af = cra_socket_address_get_af(listenaddr);
    if ((trans = cra_tcp_trans_make_trans(i, af)))
    {
        if (af == AF_INET6)
            cra_socketopt_set_ipv6_only(trans->fd, v6only);
        if (cra_socket_bind(trans->fd, listenaddr) && cra_socket_listen(trans->fd, SOMAXCONN))
        {
            *retfd = trans->fd;
            return (CraTrans_i **)trans;
        }

        err = cra_get_last_error();
        cra_socket_close(trans->fd);
        cra_dealloc(trans);
        cra_set_last_error(err);
    }
    return NULL;
}

static CRA_ACCEPT_FN(cra_tcp_trans_accept)
{
    cra_socket_t fd;
    CraTcpTrans *trans;

    assert(retfd);
    CRA_UNUSED_VALUE(inputbuf);
    CRA_TRANS_CHECK(self, CRA_TCP_TRANS_TAG);

    fd = cra_socket_accept(((CraTcpTrans *)self)->fd, fromaddr);
    if (fd == CRA_SOCKET_INVALID)
        return NULL;

    trans = cra_tcp_trans_create(CRA_TRANS_I(self), fd);
    if (trans)
        *retfd = fd;
    else
        cra_socket_close(fd);
    return (CraTrans_i **)trans;
}

static CRA_CONNECT_FN(cra_tcp_trans_connect)
{
    int          af;
    CraTcpTrans *trans;

    assert(i);
    assert(retfd);
    assert(reterr);
    assert(toaddr);
    CRA_UNUSED_VALUE(ctx);
    CRA_TRANS_CHECK(&i, CRA_TCP_TRANS_TAG);

    af = cra_socket_address_get_af(toaddr);
    if ((trans = cra_tcp_trans_make_trans(i, af)))
    {
        cra_socket_connect(trans->fd, toaddr);
        *reterr = cra_get_last_error();
        switch (*reterr)
        {
            case 0:
            case CRA_EWOULDBLOCK:
            case CRA_EINPROGRESS:
                *retfd = trans->fd;
                return (CraTrans_i **)trans;

            default:
                cra_socket_close(trans->fd);
                cra_dealloc(trans);
                break;
        }
    }
    return NULL;
}

static CRA_SHUTDOWN_FN(cra_tcp_trans_shutdown)
{
    CRA_TRANS_CHECK(self, CRA_TCP_TRANS_TAG);
    CraTcpTrans *trans = (CraTcpTrans *)self;
    if (immediately)
    {
        cra_socket_close(trans->fd);
        trans->fd = CRA_SOCKET_INVALID;
    }
    else
    {
        cra_socket_shutdown(trans->fd, CRA_SHUT_WR);
    }
}

static CRA_RELEASE_FN(cra_tcp_trans_release)
{
    CRA_TRANS_CHECK(self, CRA_TCP_TRANS_TAG);
    assert(((CraTcpTrans *)self)->fd == CRA_SOCKET_INVALID);
    cra_dealloc(self);
}

static CRA_RECV_FN(cra_tcp_trans_recv)
{
    int         n;
    size_t      len1;
    char       *buf1;
    char        buf2[65536];
    CraIOVector vec[2];

    assert(inputbuf);
    CRA_TRANS_CHECK(self, CRA_TCP_TRANS_TAG);

    len1 = cra_buffer_writable(inputbuf);
    buf1 = (char *)cra_buffer_write_start(inputbuf);
    CRA_IOVECTOR_SET(vec[0], buf1, len1);
    CRA_IOVECTOR_SET(vec[1], buf2, sizeof(buf2));

    n = cra_socket_readv(((CraTcpTrans *)self)->fd, vec, 2);
    if (n > 0)
    {
        cra_buffer_append_size(inputbuf, n);
        if ((size_t)n > len1)
            cra_buffer_append(inputbuf, buf2, (size_t)n - len1); // FIXME: Out of memory?
    }
    return n;
}

static CRA_SEND_FN(cra_tcp_trans_send)
{
    assert(buf && len > 0);
    CRA_TRANS_CHECK(self, CRA_TCP_TRANS_TAG);
    return cra_socket_send(((CraTcpTrans *)self)->fd, buf, len);
}

const CraTrans_i cra_g_tcp_transport_i = {
    CRA_IF_HEAD_SET(CRA_TCP_TRANS_TAG), .listen = cra_tcp_trans_listen,     .accept = cra_tcp_trans_accept,
    .connect = cra_tcp_trans_connect,   .shutdown = cra_tcp_trans_shutdown, .release = cra_tcp_trans_release,
    .recv = cra_tcp_trans_recv,         .send = cra_tcp_trans_send,
};

#endif // end TCP

#if 1 // connected-UDP

typedef struct
{
    CraDict            dict; // Dict<CraSocketAddress, CraCUdpTrans *>
    cra_spinlock_t     lock;
    bool               ipv6only;
    cra_atomic_int32_t refcnt;
} CraCUdpCommon;

typedef struct _CraCUdpTrans
{
    CRA_TRANS_HEAD;
    cra_socket_t     fd;
    cra_spinlock_t   lock;
    CraCUdpCommon   *common;
    CraSocketAddress address;
} CraCUdpTrans;

#define CRA_CUDP_TRANS_TAG "CraCUdpTrans"

static CraCUdpCommon *
cra_cudp_common_create(bool ipv6only)
{
    CraCUdpCommon *common = cra_alloc(CraCUdpCommon);
    if (!common)
        return NULL;
    if (!cra_dict_init0(CraSocketAddress,
                        CraCUdpTrans *,
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
    return common;
}

static inline void
cra_cudp_common_ref(CraCUdpCommon *common)
{
    cra_atomic_inc32(&common->refcnt);
}

static inline void
cra_cudp_common_unref(CraCUdpCommon *common)
{
    if (cra_atomic_dec32(&common->refcnt) == 1)
    {
        assert(common->dict.count == 0);
        cra_dict_uninit(&common->dict);
        cra_spinlock_uninit(&common->lock);
        cra_dealloc(common);
    }
}

static inline CraCUdpTrans *
cra_cudp_common_get_trans(CraCUdpCommon *common, const CraSocketAddress *address)
{
    CraCUdpTrans *trans = NULL;
    cra_spinlock_lock(&common->lock);
    cra_dict_get(&common->dict, (void *)address, &trans);
    cra_spinlock_uninit(&common->lock);
    return trans;
}

static inline void
cra_cudp_common_put_trans(CraCUdpCommon *common, const CraSocketAddress *address, CraCUdpTrans *trans)
{
    cra_spinlock_lock(&common->lock);
    cra_dict_add(&common->dict, (void *)address, &trans);
    cra_spinlock_unlock(&common->lock);
}

static inline void
cra_cudp_common_remove_trans(CraCUdpCommon *common, const CraSocketAddress *address)
{
    cra_spinlock_lock(&common->lock);
    cra_dict_remove(&common->dict, (void *)address);
    cra_spinlock_unlock(&common->lock);
}

static CraCUdpTrans *
cra_cudp_trans_create(const CraTrans_i       *i,
                      const CraSocketAddress *address,
                      const CraSocketAddress *bindaddr,
                      const CraSocketAddress *connecttoaddr,
                      bool                    set_ipv6only,
                      bool                    ipv6only)
{
    int           af;
    cra_socket_t  fd;
    CraCUdpTrans *trans;

    assert(i);
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

    trans = cra_alloc(CraCUdpTrans);
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
    cra_spinlock_init(&trans->lock);
    memcpy(&trans->address, address, sizeof(*address));
    return trans;
}

static CRA_LISTEN_FN(cra_cudp_trans_listen)
{
    CraCUdpTrans *trans;

    assert(i);
    assert(retfd);
    assert(listenaddr);
    CRA_UNUSED_VALUE(ctx);
    CRA_TRANS_CHECK(&i, CRA_CUDP_TRANS_TAG);

    trans = cra_cudp_trans_create(i, listenaddr, listenaddr, NULL, true, v6only);
    if (!trans)
        return NULL;
    trans->common = cra_cudp_common_create(v6only);
    if (!trans->common)
    {
        int err = cra_get_last_error();
        cra_socket_close(trans->fd);
        cra_dealloc(trans);
        cra_set_last_error(err);
        return NULL;
    }
    *retfd = trans->fd;
    cra_cudp_common_put_trans(trans->common, listenaddr, trans);
    return (CraTrans_i **)trans;
}

static CRA_ACCEPT_FN(cra_cudp_trans_accept)
{
    int           n;
    size_t        len;
    char         *buf;
    CraCUdpTrans *trans;
    CraCUdpTrans *trans_listen;

    assert(retfd);
    assert(fromaddr);
    assert(inputbuf);
    CRA_TRANS_CHECK(self, CRA_CUDP_TRANS_TAG);

    trans_listen = (CraCUdpTrans *)self;
    assert(trans_listen->common);

    len = cra_buffer_writable(inputbuf);
    buf = (char *)cra_buffer_write_start(inputbuf);

    n = cra_socket_recvfrom(trans_listen->fd, buf, (int)len, fromaddr);
    if (n <= 0)
        return NULL;

    if ((trans = cra_cudp_common_get_trans(trans_listen->common, fromaddr)) == NULL)
    {
        trans = cra_cudp_trans_create(
          CRA_TRANS_I(trans_listen), fromaddr, &trans_listen->address, fromaddr, true, trans_listen->common->ipv6only);
        if (!trans)
            return NULL;

        trans->common = trans_listen->common;
        cra_cudp_common_put_trans(trans->common, fromaddr, trans);
        cra_cudp_common_ref(trans->common);
    }
#ifndef CRA_OS_WIN
    else
    {
        // Discard the packet
        cra_set_last_error(CRA_EWOULDBLOCK);
        return NULL;
    }
#else
    *retfd = trans->fd;
    cra_buffer_append_size(inputbuf, n);
    return (CraTrans_i **)trans;
#endif
}

static CRA_CONNECT_FN(cra_cudp_trans_connect)
{
    CraCUdpTrans *trans;

    assert(i);
    assert(retfd);
    assert(reterr);
    assert(toaddr);
    CRA_UNUSED_VALUE(ctx);
    CRA_TRANS_CHECK(&i, CRA_CUDP_TRANS_TAG);

    trans = cra_cudp_trans_create(i, toaddr, NULL, toaddr, false, false);
    if (trans)
        *retfd = trans->fd;
    *reterr = cra_get_last_error();
    return (CraTrans_i **)trans;
}

static CRA_SHUTDOWN_FN(cra_cudp_trans_shutdown)
{
    CRA_TRANS_CHECK(self, CRA_CUDP_TRANS_TAG);
    CraCUdpTrans *trans = (CraCUdpTrans *)self;
    if (immediately)
    {
        cra_socket_close(trans->fd);
        trans->fd = CRA_SOCKET_INVALID;
        if (trans->common)
            cra_cudp_common_remove_trans(trans->common, &trans->address);
    }
    else
    {
        cra_socket_shutdown(trans->fd, CRA_SHUT_WR);
    }
}

static CRA_RELEASE_FN(cra_cudp_trans_release)
{
    CraCUdpTrans *trans = (CraCUdpTrans *)self;
    CRA_TRANS_CHECK(self, CRA_CUDP_TRANS_TAG);
    assert(trans->fd == CRA_SOCKET_INVALID);
    if (trans->common)
        cra_cudp_common_unref(trans->common);
    cra_spinlock_uninit(&trans->lock);
    cra_dealloc(trans);
}

static CRA_RECV_FN(cra_cudp_trans_recv)
{
    int              n;
    size_t           len;
    char            *buf;
    CraCUdpTrans    *trans;
    CraSocketAddress fromaddr;

    assert(inputbuf);
    CRA_TRANS_CHECK(self, CRA_CUDP_TRANS_TAG);

    trans = (CraCUdpTrans *)self;

    len = cra_buffer_writable(inputbuf);
    buf = (char *)cra_buffer_write_start(inputbuf);
    assert(len > 0 && len <= INT_MAX);

    // n = cra_socket_recv(trans->fd, buf, len);
    // if (n > 0)
    //     cra_buffer_append_size(inputbuf, n);
    // return n;
    n = cra_socket_recvfrom(trans->fd, buf, (int)len, &fromaddr);
    if (n > 0)
    {
        if (cra_compare_socket_address_p(&fromaddr, &trans->address) != 0)
        {
            // Received data from an address different from the connected address, discard it.
            cra_set_last_error(CRA_EWOULDBLOCK);
            return -1;
        }
        cra_buffer_append_size(inputbuf, n);
    }
    return n;
}

static CRA_SEND_FN(cra_cudp_trans_send)
{
    assert(buf && len > 0);
    CRA_TRANS_CHECK(self, CRA_CUDP_TRANS_TAG);
    return cra_socket_send(((CraCUdpTrans *)self)->fd, buf, len);
}

const CraTrans_i cra_g_cudp_transport_i = {
    CRA_IF_HEAD_SET(CRA_CUDP_TRANS_TAG), .listen = cra_cudp_trans_listen,     .accept = cra_cudp_trans_accept,
    .connect = cra_cudp_trans_connect,   .shutdown = cra_cudp_trans_shutdown, .release = cra_cudp_trans_release,
    .recv = cra_cudp_trans_recv,         .send = cra_cudp_trans_send,
};

#endif // end connected-UDP
