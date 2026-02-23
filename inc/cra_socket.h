/**
 * @file cra_socket.h
 * @author Cracal
 * @brief socket
 * @version 0.1
 * @date 2024-12-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __CRA_SOCKET_H__
#define __CRA_SOCKET_H__
#include "collections/cra_collects.h"
#include "cra_common.h"

#ifdef CRA_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#if 1 // socket address

typedef struct _CraSocketAddress
{
    union
    {
        struct sockaddr     sa;
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    };
    socklen_t  length;
    cra_hash_t hash;
} CraSocketAddress;

#define CRA_IPPORTSTR_MAX (INET6_ADDRSTRLEN + 7)

#define CRA_SOCKET_ADDRESS_INIT { { { 0 } }, 0, -1 }

static inline void
cra_socket_address_init_default(CraSocketAddress *address)
{
    bzero(address, sizeof(*address));
    address->hash = -1;
}

CRA_NET_API bool
cra_socket_address_init(CraSocketAddress *address, const char *addr, unsigned short port);

CRA_NET_API cra_hash_t
cra_hash_socket_address_p(CraSocketAddress *addr);

CRA_NET_API int
cra_compare_socket_address_p(const CraSocketAddress *a, const CraSocketAddress *b);

static inline bool
cra_socket_address_is_ipv4(const CraSocketAddress *address)
{
    // return address->sa.sa_family == AF_INET || IN6_IS_ADDR_V4MAPPED(&address->v6.sin6_addr);
    return address->sa.sa_family == AF_INET;
}

static inline bool
cra_socket_address_is_ipv6(const CraSocketAddress *address)
{
    // return address->sa.sa_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&address->v6.sin6_addr);
    return address->sa.sa_family == AF_INET6;
}

static inline int
cra_socket_address_get_af(const CraSocketAddress *address)
{
    // if (cra_socket_address_is_ipv4(address))
    //     return AF_INET;
    // else if (cra_socket_address_is_ipv6(address))
    //     return AF_INET6;
    // else
    //     return -1;
    return address->sa.sa_family;
}

static inline unsigned short
cra_socket_address_get_port(const CraSocketAddress *address)
{
    if (cra_socket_address_is_ipv4(address))
        return ntohs(address->v4.sin_port);
    else
        return ntohs(address->v6.sin6_port);
}

CRA_NET_API bool
cra_socket_address_get_ip(const CraSocketAddress *address, char *buffer, size_t buffer_size);

CRA_NET_API bool
cra_socket_address_get_ipport(const CraSocketAddress *address, char *buffer, size_t buffer_size);

#endif // end socket address

#if 1 // socket

#ifdef CRA_OS_WIN

typedef SOCKET cra_socket_t;

#define CRA_SOCKET_INVALID INVALID_SOCKET
#define CRA_SOCKET_ERROR   SOCKET_ERROR

#define CRA_EINPROGRESS WSAEINPROGRESS
#define CRA_EWOULDBLOCK WSAEWOULDBLOCK
#define CRA_ECONNRESET  WSAECONNRESET
#define CRA_EISCONN     WSAEISCONN
#define CRA_EINTR       WSAEINTR
#define CRA_EMFILE      WSAEMFILE

#else

typedef int cra_socket_t;

#define CRA_SOCKET_INVALID (-1)
#define CRA_SOCKET_ERROR   (-1)

#define CRA_EINPROGRESS EINPROGRESS
#define CRA_EWOULDBLOCK EWOULDBLOCK
#define CRA_ECONNRESET  ECONNRESET
#define CRA_EISCONN     EISCONN
#define CRA_EINTR       EINTR
#define CRA_EMFILE      EMFILE

#endif

static inline cra_hash_t
cra_hash_socket(cra_socket_t sock)
{
    return (cra_hash_t)sock;
}

static inline int
cra_compare_socket(const cra_socket_t a, const cra_socket_t b)
{
    return a == b ? 0 : (a > b ? 1 : -1);
}

CRA_NET_API cra_hash_t
cra_hash_socket_p(cra_socket_t *sock);

CRA_NET_API int
cra_compare_socket_p(const cra_socket_t *a, const cra_socket_t *b);

#ifdef CRA_OS_WIN
CRA_NET_API bool
cra_socket_pair(cra_socket_t fds[2]);
#else
static inline bool
cra_socket_pair(cra_socket_t fds[2])
{
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
}
#endif

#define cra_socket socket

static inline bool
cra_socket_close(cra_socket_t fd)
{
#ifdef CRA_OS_WIN
    return closesocket(fd) == 0;
#else
    return close(fd) == 0;
#endif
}

#ifdef CRA_OS_WIN
#define CRA_SHUT_RD   SD_RECEIVE
#define CRA_SHUT_WR   SD_SEND
#define CRA_SHUT_RDWR SD_BOTH
#else
#define CRA_SHUT_RD   SHUT_RD
#define CRA_SHUT_WR   SHUT_WR
#define CRA_SHUT_RDWR SHUT_RDWR
#endif
static inline bool
cra_socket_shutdown(cra_socket_t fd, int how)
{
    return shutdown(fd, how) == 0;
}

static inline bool
cra_socket_bind(cra_socket_t fd, const CraSocketAddress *address)
{
    return 0 == bind(fd, (struct sockaddr *)address, address->length);
}

static inline bool
cra_socket_listen(cra_socket_t fd, int backlog)
{
    return 0 == listen(fd, backlog);
}

static inline cra_socket_t
cra_socket_accept(cra_socket_t listenfd, CraSocketAddress *peeraddress)
{
    socklen_t    addrlen = sizeof(((CraSocketAddress *)0)->v6);
    cra_socket_t connfd = accept(listenfd, (struct sockaddr *)peeraddress, &addrlen);
    if (peeraddress != NULL)
        peeraddress->length = connfd != CRA_SOCKET_INVALID ? addrlen : 0;
    return connfd;
}

static inline bool
cra_socket_connect(cra_socket_t fd, const CraSocketAddress *peeraddress)
{
    return 0 == connect(fd, (struct sockaddr *)peeraddress, peeraddress->length);
}

static inline int
cra_socket_recv(cra_socket_t fd, void *buffer, int length)
{
    return (int)recv(fd, (char *)buffer, length, 0);
}

static inline int
cra_socket_send(cra_socket_t fd, const void *buffer, int length)
{
    return (int)send(fd, (char *)buffer, length, 0);
}

#ifdef CRA_OS_WIN
typedef WSABUF CraIOVector;
#define CRA_IOVECTOR_SET(_vec_item, _buf, _len) ((_vec_item).buf = (CHAR *)(_buf), (_vec_item).len = (ULONG)(_len))
#define CRA_IOVECTOR_GET_LEN(_vec_item)         (_vec_item).len
#define CRA_IOVECTOR_GET_BUF(_vec_item)         (_vec_item).buf
#else
typedef struct iovec CraIOVector;
#define CRA_IOVECTOR_SET(_vec_item, _buf, _len) ((_vec_item).iov_base = (_buf), (_vec_item).iov_len = (_len))
#define CRA_IOVECTOR_GET_LEN(_vec_item)         (_vec_item).iov_len
#define CRA_IOVECTOR_GET_BUF(_vec_item)         (_vec_item).iov_base
#endif

static inline int
cra_socket_readv(cra_socket_t fd, CraIOVector vec[], int vec_count)
{
#ifdef CRA_OS_WIN
    DWORD n = 0;
    DWORD flags = 0;
    if (SOCKET_ERROR == WSARecv(fd, vec, vec_count, &n, &flags, NULL, NULL))
        return -1;
#else
    ssize_t n = readv(fd, vec, vec_count);
#endif
    return (int)n;
}

static inline int
cra_socket_writev(cra_socket_t fd, CraIOVector *vec, int vec_count)
{
#ifdef CRA_OS_WIN
    DWORD n = 0;
    if (SOCKET_ERROR == WSASend(fd, vec, vec_count, &n, 0, NULL, NULL))
        return -1;
#else
    ssize_t n = writev(fd, vec, vec_count);
#endif
    return (int)n;
}

static inline int
cra_socket_recvfrom(cra_socket_t fd, void *buffer, int length, CraSocketAddress *fromaddress)
{
    fromaddress->length = sizeof(fromaddress->v6);
    return (int)recvfrom(fd, (char *)buffer, length, 0, (struct sockaddr *)fromaddress, &fromaddress->length);
}

static inline int
cra_socket_sendto(cra_socket_t fd, const void *buffer, int length, const CraSocketAddress *toaddress)
{
    return (int)sendto(fd, (char *)buffer, length, 0, (struct sockaddr *)toaddress, (int)toaddress->length);
}

CRA_NET_API bool
cra_socket_is_self_connect(cra_socket_t fd);

CRA_NET_API bool
cra_socket_get_local_address(cra_socket_t fd, CraSocketAddress *addrbuf);

CRA_NET_API bool
cra_socket_get_peer_address(cra_socket_t fd, CraSocketAddress *addrbuf);

#endif // end socket

#if 1 // socket options

static inline bool
cra_socketopt_set_nonblocking(cra_socket_t fd, bool on)
{
#ifdef CRA_OS_WIN
    unsigned long ul = on;
    if (0 != ioctlsocket(fd, FIONBIO, &ul))
        return false;
#else
    int flags = fcntl(fd, F_GETFL);
    if (on)
        flags |= O_NONBLOCK;
    else
        flags &= (~O_NONBLOCK);
    if (0 != fcntl(fd, F_SETFL, flags))
        return false;
#endif
    return true;
}

static inline bool
cra_socketopt_set_close_on_execute(cra_socket_t fd, bool on)
{
#ifdef CRA_OS_LINUX
    int flags = fcntl(fd, F_GETFD);
    if (on)
        flags |= FD_CLOEXEC;
    else
        flags &= (~FD_CLOEXEC);
    if (0 != fcntl(fd, F_SETFD, flags))
        return false;
#else
    CRA_UNUSED_VALUE(fd);
    CRA_UNUSED_VALUE(on);
#endif
    return true;
}

static inline bool
cra_socketopt_set_reuse_address(cra_socket_t fd, bool on)
{
    int optval = on;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) == 0;
}

static inline bool
cra_socketopt_set_reuse_port(cra_socket_t fd, bool on)
{
#ifdef CRA_OS_LINUX
    int optval = on;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&optval, sizeof(optval)) == 0;
#else
    CRA_UNUSED_VALUE(fd);
    CRA_UNUSED_VALUE(on);
    return true;
#endif
}

static inline bool
cra_socketopt_set_sndbuf(cra_socket_t fd, int size)
{
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&size, sizeof(size)) == 0;
}

static inline bool
cra_socketopt_set_rcvbuf(cra_socket_t fd, int size)
{
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&size, sizeof(size)) == 0;
}

static inline bool
cra_socketopt_set_ipv6_only(cra_socket_t fd, bool on)
{
    int optval = on;
    return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&optval, sizeof(optval)) == 0;
}

static inline bool
cra_socketopt_set_keep_alive(cra_socket_t fd, bool on)
{
    int optval = on;
    return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&optval, sizeof(optval)) == 0;
}

static inline bool
cra_socketopt_set_tcp_no_delay(cra_socket_t fd, bool on)
{
    int optval = on;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&optval, sizeof(optval)) == 0;
}

static inline int
cra_socketopt_get_socket_error(cra_socket_t fd)
{
    int       err;
    socklen_t err_len = sizeof err;

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &err_len) < 0)
        return cra_get_last_error();
    return err;
}

#endif // end socket options

#endif