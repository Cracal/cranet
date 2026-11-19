#ifndef __CRANET_CRA_SOCKET_H__
#define __CRANET_CRA_SOCKET_H__
#include "cranet/cra_defs.h"
#include "crabase/cra_macro.h"
#include "crabase/collections/cra_collects.h"

#ifdef CRA_OS_WINDOWS

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#endif

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-Socket"

typedef struct CraSockAddr CraSockAddr;
typedef struct CraSocket   CraSocket;

#if 1 // socket address

#define CRA_ENDPOINT_LEN (INET6_ADDRSTRLEN + 8)

struct CraSockAddr
{
    union
    {
        struct sockaddr     sa;
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } addr;
    socklen_t size;
};

#ifdef CRA_OS_WINDOWS
typedef ADDRESS_FAMILY cra_family_t;
#else
typedef sa_family_t cra_family_t;
#endif

CRA_NAPI void
cra_sockaddr_init(CraSockAddr *addr, const char *host, uint16_t port, cra_family_t family);
// void init(CraSockAddr *addr, const char *host, uint16_t port, cra_family_t family = AF_UNSPEC)
#define cra_sockaddr_init(addr, host, ...)                                                      \
    cra_sockaddr_init(addr, host, CRA_CAT(CRA_SOCKADDR_ARG, CRA_CNT(__VA_ARGS__))(__VA_ARGS__))
#define CRA_SOCKADDR_ARG1(port)         port, AF_UNSPEC
#define CRA_SOCKADDR_ARG2(port, family) port, family

static inline cra_family_t
cra_sockaddr_get_family(const CraSockAddr *addr)
{
    return addr->addr.sa.sa_family;
}

static inline bool
cra_sockaddr_is_ipv4(const CraSockAddr *addr)
{
    return cra_sockaddr_get_family(addr) == AF_INET;
}

static inline bool
cra_sockaddr_is_ipv6(const CraSockAddr *addr)
{
    return cra_sockaddr_get_family(addr) == AF_INET6;
}

static inline uint16_t
cra_sockaddr_get_port(const CraSockAddr *addr)
{
    if (cra_sockaddr_is_ipv4(addr))
        return ntohs(addr->addr.v4.sin_port);
    else
        return ntohs(addr->addr.v6.sin6_port);
}

static inline const void *
cra_sockaddr_get_ip(const CraSockAddr *addr)
{
    if (cra_sockaddr_is_ipv4(addr))
        return (const void *)&addr->addr.v4.sin_addr;
    else
        return (const void *)&addr->addr.v6.sin6_addr;
}

static inline const char *
cra_sockaddr_to_ip(const CraSockAddr *addr, char *buf, size_t buf_size)
{
    const void  *addr_ptr = cra_sockaddr_get_ip(addr);
    cra_family_t family = cra_sockaddr_get_family(addr);
    return inet_ntop(family, addr_ptr, buf, buf_size);
}

CRA_NAPI const char *
cra_sockaddr_to_endpoint(const CraSockAddr *addr, char *buf, size_t buf_size);

CRA_NAPI int
cra_sockaddr_cmp(const CraSockAddr *addr1, const CraSockAddr *addr2);

CRA_NAPI int
cra_sockaddr_cmp_p(const CraSockAddr **paddr1, const CraSockAddr **paddr2);

CRA_NAPI cra_hash_t
cra_sockaddr_hash(const CraSockAddr *addr);

CRA_NAPI cra_hash_t
cra_sockaddr_hash_p(const CraSockAddr **paddr);

#endif // end socket address

#if 1 // socket

struct CraSocket
{
#ifdef CRA_OS_WINDOWS
    SOCKET fd;
#else
    int fd;
#endif
};

#ifdef CRA_OS_WINDOWS
#define CRA_SOCKET_INITIALIZER { INVALID_SOCKET }
#else
#define CRA_SOCKET_INITIALIZER { -1 }
#endif

static inline bool
cra_socket_is_valid(const CraSocket sock)
{
#ifdef CRA_OS_WINDOWS
    return sock.fd != INVALID_SOCKET;
#else
    return sock.fd != -1;
#endif
}

static inline CraSocket
cra_socket_open(cra_family_t family, int type)
{
    return (CraSocket){ .fd = socket(family, type, 0) };
}

static inline void
cra_socket_close(CraSocket sock)
{
#ifdef CRA_OS_WINDOWS
    closesocket(sock.fd);
#else
    close(sock.fd);
#endif
}

static inline bool
cra_socket_bind(CraSocket sock, const CraSockAddr *addr)
{
    return bind(sock.fd, (struct sockaddr *)addr, addr->size) == 0;
}

static inline bool
cra_socket_listen(CraSocket sock, int backlog)
{
    return listen(sock.fd, backlog) == 0;
}

static inline CraSocket
cra_socket_accept(CraSocket listen_sock, CraSockAddr *from_addr)
{
    socklen_t *plen = NULL;

    if (from_addr)
    {
        from_addr->size = sizeof(from_addr->addr);
        plen = &from_addr->size;
    }

    return (CraSocket){ .fd = accept(listen_sock.fd, (struct sockaddr *)from_addr, plen) };
}

static inline bool
cra_socket_connect(CraSocket sock, const CraSockAddr *remote_addr)
{
    return connect(sock.fd, (struct sockaddr *)remote_addr, remote_addr->size) == 0;
}

static inline int
cra_socket_send(CraSocket sock, const void *buf, int len)
{
    return send(sock.fd, buf, len, 0);
}

static inline int
cra_socket_recv(CraSocket sock, void *buf, int len)
{
    return recv(sock.fd, buf, len, 0);
}

static inline int
cra_socket_sendto(CraSocket sock, const void *buf, int len, const CraSockAddr *remote_addr)
{
    return sendto(sock.fd, buf, len, 0, (struct sockaddr *)remote_addr, remote_addr->size);
}

static inline int
cra_socket_recvfrom(CraSocket sock, void *buf, int len, CraSockAddr *remote_addr)
{
    socklen_t *plen = NULL;

    if (remote_addr)
    {
        remote_addr->size = sizeof(remote_addr->addr);
        plen = &remote_addr->size;
    }

    return recvfrom(sock.fd, buf, len, 0, (struct sockaddr *)remote_addr, plen);
}

static inline bool
cra_socket_get_local_addr(CraSocket sock, CraSockAddr *addr_buf)
{
    addr_buf->size = sizeof(addr_buf->addr);
    return getsockname(sock.fd, (struct sockaddr *)addr_buf, &addr_buf->size) == 0;
}

static inline bool
cra_socket_get_remote_addr(CraSocket sock, CraSockAddr *addr_buf)
{
    addr_buf->size = sizeof(addr_buf->addr);
    return getpeername(sock.fd, (struct sockaddr *)addr_buf, &addr_buf->size) == 0;
}

static inline bool
cra_socket_set_nonblocking(CraSocket sock)
{
#ifdef CRA_OS_WINDOWS
    DWORD nonblocking = 1;
    return ioctlsocket(sock.fd, FIONBIO, &nonblocking) != SOCKET_ERROR;
#else
    int nonblocking = 1;
    return fcntl(sock.fd, F_SETFL, O_NONBLOCK, nonblocking) != -1;
#endif
}

#endif // end socket

#endif
