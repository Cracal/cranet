/**
 * @file cra_trans_i.h
 * @author Cracal
 * @brief transport interface
 * @version 0.1
 * @date 2025-08-12
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __CRA_TRANS_I_H__
#define __CRA_TRANS_I_H__
#include "cra_buffer.h"
#include "cra_socket.h"

typedef struct _CraTrans_i CraTrans_i;

#define CRA_LISTEN_FN(_name)                                                                                \
    CraTrans_i **_name(                                                                                     \
      const CraTrans_i *i, void *ctx, const CraSocketAddress *listenaddr, bool v6only, cra_socket_t *retfd)
#define CRA_ACCEPT_FN(_name)                                                                                    \
    CraTrans_i **_name(CraTrans_i **self, CraSocketAddress *fromaddr, CraBuffer *inputbuf, cra_socket_t *retfd)
#define CRA_CONNECT_FN(_name) \
    CraTrans_i **_name(const CraTrans_i *i, void *ctx, const CraSocketAddress *toaddr, cra_socket_t *retfd, int *reterr)
#define CRA_SHUTDOWN_FN(_name) void _name(CraTrans_i **self, bool immediately)
#define CRA_RELEASE_FN(_name)  void _name(CraTrans_i **self)
#define CRA_RECV_FN(_name)     int _name(CraTrans_i **self, CraBuffer *inputbuf)
#define CRA_SEND_FN(_name)     int _name(CraTrans_i **self, const void *buf, int len)

struct _CraTrans_i
{
    CRA_IF_HEAD;
    CRA_LISTEN_FN((*listen));
    CRA_ACCEPT_FN((*accept));
    CRA_CONNECT_FN((*connect));
    CRA_SHUTDOWN_FN((*shutdown));
    CRA_RELEASE_FN((*release));
    CRA_RECV_FN((*recv));
    CRA_SEND_FN((*send));
};

#define CRA_TRANS_CHECK(_obj, _tag) CRA_OBJ_CHECK(CraTrans_i, _obj, _tag)
#define CRA_TRANS_I(_obj)           CRA_OBJ_I(CraTrans_i, _obj)
#define CRA_TRANS_HEAD              CRA_OBJ_HEAD(CraTrans_i)

static inline CRA_LISTEN_FN(cra_trans_listen)
{
    return i->listen(i, ctx, listenaddr, v6only, retfd);
}

static inline CRA_ACCEPT_FN(cra_trans_accept)
{
    return CRA_TRANS_I(self)->accept(self, fromaddr, inputbuf, retfd);
}

static inline CRA_CONNECT_FN(cra_trans_connect)
{
    return i->connect(i, ctx, toaddr, retfd, reterr);
}

static inline CRA_SHUTDOWN_FN(cra_trans_shutdown)
{
    CRA_TRANS_I(self)->shutdown(self, immediately);
}

static inline CRA_RELEASE_FN(cra_trans_release)
{
    CRA_TRANS_I(self)->release(self);
}

static inline CRA_RECV_FN(cra_trans_recv)
{
    return CRA_TRANS_I(self)->recv(self, inputbuf);
}

static inline CRA_SEND_FN(cra_trans_send)
{
    return CRA_TRANS_I(self)->send(self, buf, len);
}

#ifndef __CRA_TRANS_IMPL__
#undef CRA_ON_READ_ARGS

#undef CRA_LISTEN_FN
#undef CRA_ACCEPT_FN
#undef CRA_CONNECT_FN
#undef CRA_RELEASE_FN
#undef CRA_SHUTDOWN_FN
#undef CRA_RECV_FN
#undef CRA_SEND_FN

#undef CRA_TRANS_CHECK
#undef CRA_TRANS_I
#undef CRA_TRANS_HEAD
#endif

// =========================

// TCP transport interface
CRA_NET_API const CraTrans_i cra_g_tcp_transport_i;
#define CRA_TCP_TRANSPORT_I (&cra_g_tcp_transport_i)

// UDP(connected) transport interface
CRA_NET_API const CraTrans_i cra_g_cudp_transport_i;
#define CRA_CUDP_TRANSPORT_I (&cra_g_cudp_transport_i)

#endif