#include "cranet/cra_socket.h"
#ifndef CRA_OS_WINDOWS
#include <netdb.h>
#endif

void
cra_initialize_sockets(void)
{
#ifdef CRA_OS_WINDOWS
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
    {
        cra_log_fatal(g_cranet_logger, "WSAStartup failed, error: %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
#else
#endif
}

void
cra_shutdown_sockets(void)
{
#ifdef CRA_OS_WINDOWS
    WSACleanup();
#endif
}

#if 1 // sock address

void(cra_sockaddr_init)(CraSockAddr *addr, const char *host, uint16_t port, cra_family_t family)
{
    struct addrinfo *res = NULL;
    struct addrinfo  hints = { .ai_family = family };

    int err = getaddrinfo(host, NULL, &hints, &res);
    if (err != 0)
    {
        cra_log_fatal(g_cranet_logger, "Get address info failed, error: %d", err);
        exit(EXIT_FAILURE);
    }

    assert(res->ai_addrlen <= sizeof(addr->addr));
    memcpy(addr, res->ai_addr, res->ai_addrlen);
    addr->size = (socklen_t)res->ai_addrlen;

    if (res->ai_family == AF_INET)
        addr->addr.v4.sin_port = htons(port);
    else
        addr->addr.v6.sin6_port = htons(port);

    freeaddrinfo(res);
}

const char *
cra_sockaddr_to_endpoint(const CraSockAddr *addr, char *buf, size_t buf_size)
{
    int   len;
    char *fmt;
    char  ipstr[INET6_ADDRSTRLEN];

    assert(buf_size > 0);

    buf[0] = '\0';

    if (!cra_sockaddr_to_ip(addr, ipstr, sizeof(ipstr)))
        return NULL;

    fmt = cra_sockaddr_is_ipv4(addr) ? "%s:%hu" : "[%s]:%hu";
    len = snprintf(buf, buf_size, fmt, ipstr, cra_sockaddr_get_port(addr));
    if (len > 0 && (size_t)len < buf_size)
        return buf;
    return NULL;
}

static inline int
cra_sockaddr_cmp_inner(const CraSockAddr *addr1, const CraSockAddr *addr2)
{
    cra_family_t af1, af2;
    const void  *pa1, *pa2;
    uint16_t     port1, port2;

    assert(addr1);
    assert(addr2);

    if (addr1->size != addr2->size)
        return -1;

    af1 = cra_sockaddr_get_family(addr1);
    af2 = cra_sockaddr_get_family(addr2);
    if (af1 != af2)
        return -1;

    port1 = cra_sockaddr_get_port(addr1);
    port2 = cra_sockaddr_get_port(addr2);
    if (port1 != port2)
        return -1;

    if (af1 == AF_INET6)
    {
        if (addr1->addr.v6.sin6_scope_id != addr2->addr.v6.sin6_scope_id)
            return -1;
    }

    pa1 = cra_sockaddr_get_ip(addr1);
    pa2 = cra_sockaddr_get_ip(addr2);
    return memcmp(pa1, pa2, af1 == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr));
}

int
cra_sockaddr_cmp(const CraSockAddr *addr1, const CraSockAddr *addr2)
{
    return cra_sockaddr_cmp_inner(addr1, addr2);
}

int
cra_sockaddr_cmp_p(const CraSockAddr **paddr1, const CraSockAddr **paddr2)
{
    assert(paddr1);
    assert(paddr2);
    return cra_sockaddr_cmp_inner(*paddr1, *paddr2);
}

static inline cra_hash_t
cra_sockaddr_hash_inner(const CraSockAddr *addr)
{
    cra_family_t af;
    uint32_t    *ip;
    uint16_t     port;
    cra_hash_t   hash, n;

    assert(addr);

    af = cra_sockaddr_get_family(addr);
    port = cra_sockaddr_get_port(addr);
    ip = (uint32_t *)cra_sockaddr_get_ip(addr);

    n = 17179869143;
    hash = 2305843009213693951 ^ af;
    hash *= n;
    hash ^= port;
    hash *= n;
    hash ^= ip[0];
    hash *= n;
    if (af == AF_INET6)
    {
        hash ^= ip[1];
        hash *= n;
        hash ^= ip[2];
        hash *= n;
        hash ^= ip[3];
        hash *= n;
        hash ^= addr->addr.v6.sin6_scope_id;
        hash *= n;
    }

    return hash;
}

cra_hash_t
cra_sockaddr_hash(const CraSockAddr *addr)
{
    return cra_sockaddr_hash_inner(addr);
}

cra_hash_t
cra_sockaddr_hash_p(const CraSockAddr **paddr)
{
    assert(paddr);
    return cra_sockaddr_hash_inner(*paddr);
}

#endif // end sock address
