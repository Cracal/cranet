#include "cra_socket.h"
#include "cra_assert.h"

#if 1 // socket address

cra_hash_t
cra_hash_socket_address_p(CraSocketAddress *addr)
{
    if (addr->hash == -1)
    {
        // FNV
        uint8_t *data = (uint8_t *)addr;
        addr->hash = 0x811c9dc5;
        for (socklen_t i = 0; i < addr->length; ++i)
        {
            addr->hash ^= data[i];
            addr->hash *= 0x01000193;
        }
        if (addr->hash == -1)
            addr->hash = -2;
    }
    return addr->hash;
}

int
cra_compare_socket_address_p(const CraSocketAddress *a, const CraSocketAddress *b)
{
    int            afa = cra_socket_address_get_af(a);
    int            afb = cra_socket_address_get_af(b);
    unsigned short porta = cra_socket_address_get_port(a);
    unsigned short portb = cra_socket_address_get_port(b);

    if (afa != afb)
        return afa > afb ? 1 : -1;
    if (porta != portb)
        return porta > portb ? 1 : -1;
    return memcmp(a, b, a->length);
}

bool
cra_socket_address_init(CraSocketAddress *address, const char *addr, unsigned short port)
{
    struct addrinfo *res, hints = { 0 };

    assert(address);
    assert(addr);

    cra_socket_address_init_default(address);
    if (0 == getaddrinfo(addr, NULL, &hints, &res))
    {
        memcpy(address, res->ai_addr, res->ai_addrlen);
        address->length = (socklen_t)res->ai_addrlen;
        freeaddrinfo(res);

        address->v4.sin_port = htons(port);
        return true;
    }
    return false; // error address
}

#define CRA_SET_INVALID_STR(_buff, _size)            \
    do                                               \
    {                                                \
        assert(_size >= sizeof("INVALID"));          \
        memcpy(_buff, "INVALID", sizeof("INVALID")); \
    } while (0)

bool
cra_socket_address_get_ip(const CraSocketAddress *address, char *buffer, size_t buffer_size)
{
    int   af;
    void *addr;

    assert(address);
    assert(buffer);

    af = cra_socket_address_get_af(address);
    addr = af == AF_INET6 ? (void *)&address->v6.sin6_addr : (void *)&address->v4.sin_addr;

    if (inet_ntop(af, addr, buffer, buffer_size) != NULL)
        return true;

    CRA_SET_INVALID_STR(buffer, buffer_size);
    return false;
}

bool
cra_socket_address_get_ipport(const CraSocketAddress *address, char *buffer, size_t buffer_size)
{
    char           ip[INET6_ADDRSTRLEN];
    int            written;
    unsigned short port;
    const char    *fmt;

    assert(address);
    assert(buffer);

    // get ip
    if (cra_socket_address_get_ip(address, ip, sizeof(ip)))
    {
        // get port
        port = cra_socket_address_get_port(address);
        // make string
        fmt = cra_socket_address_is_ipv6(address) ? "[%s]:%u" : "%s:%u";
        written = snprintf(buffer, buffer_size, fmt, ip, port);
        assert((size_t)written < buffer_size);
        CRA_UNUSED_VALUE(written);
        return true;
    }

    CRA_SET_INVALID_STR(buffer, buffer_size);
    return false;
}

#endif // end socket address

#if 1 // socket

cra_hash_t
cra_hash_socket_p(cra_socket_t *sock)
{
    return cra_hash_socket(*sock);
}

int
cra_compare_socket_p(const cra_socket_t *a, const cra_socket_t *b)
{
    return cra_compare_socket(*a, *b);
}

#ifdef CRA_OS_WIN
bool
cra_socket_pair(cra_socket_t fds[2])
{
    struct sockaddr_in addr;
    SOCKET             listener = CRA_SOCKET_INVALID;
    int                addrlen = sizeof(addr);
    int                optval = 1;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == CRA_SOCKET_INVALID)
    {
        return false;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) == SOCKET_ERROR)
    {
        closesocket(listener);
        return false;
    }

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        closesocket(listener);
        return false;
    }

    if (listen(listener, 1) == SOCKET_ERROR)
    {
        closesocket(listener);
        return false;
    }

    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR)
    {
        closesocket(listener);
        return false;
    }

    fds[0] = socket(AF_INET, SOCK_STREAM, 0);
    if (fds[0] == CRA_SOCKET_INVALID)
    {
        closesocket(listener);
        return false;
    }

    if (connect(fds[0], (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        closesocket(fds[0]);
        closesocket(listener);
        return false;
    }

    fds[1] = accept(listener, NULL, NULL);
    if (fds[1] == CRA_SOCKET_INVALID)
    {
        closesocket(fds[0]);
        closesocket(listener);
        return false;
    }

    closesocket(listener);
    return true;
}
#endif

bool
cra_socket_is_self_connect(cra_socket_t fd)
{
    CraSocketAddress localaddr = CRA_SOCKET_ADDRESS_INIT;
    CraSocketAddress peeraddr = CRA_SOCKET_ADDRESS_INIT;

    cra_socket_get_local_address(fd, &localaddr);
    cra_socket_get_peer_address(fd, &peeraddr);
    return cra_compare_socket_address_p(&localaddr, &peeraddr) == 0;
}

bool
cra_socket_get_local_address(cra_socket_t fd, CraSocketAddress *addrbuf)
{
    socklen_t len = sizeof(addrbuf->v6);

    assert(fd != CRA_SOCKET_INVALID);
    assert(addrbuf != NULL);

    cra_socket_address_init_default(addrbuf);
    if (getsockname(fd, (struct sockaddr *)addrbuf, &len) == 0)
    {
        addrbuf->length = len;
        return true;
    }
    return false;
}

bool
cra_socket_get_peer_address(cra_socket_t fd, CraSocketAddress *addrbuf)
{
    socklen_t len = sizeof(addrbuf->v6);

    assert(fd != CRA_SOCKET_INVALID);
    assert(addrbuf != NULL);

    cra_socket_address_init_default(addrbuf);
    if (getpeername(fd, (struct sockaddr *)addrbuf, &len) == 0)
    {
        addrbuf->length = len;
        return true;
    }
    return false;
}

#endif // end socket
