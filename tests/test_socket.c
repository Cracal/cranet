#include "crabase/cra_log.h"
#include "crabase/cra_malloc.h"
#include "cranet/cra_socket.h"

void
test_socket_address(void)
{
    CraSockAddr address1, address2, address3;
    char        buf[CRA_ENDPOINT_LEN];

    cra_sockaddr_init(&address1, "0.0.0.0", 8888, AF_INET);
    assert_always(cra_sockaddr_get_ip(&address1) != NULL);
    assert_always(cra_sockaddr_get_port(&address1) == 8888);
    assert_always(cra_sockaddr_get_family(&address1) == AF_INET);
    assert_always(cra_sockaddr_is_ipv4(&address1));
    assert_always(!cra_sockaddr_is_ipv6(&address1));
    assert_always(address1.size == sizeof(struct sockaddr_in));
    assert_always(cra_sockaddr_to_ip(&address1, buf, sizeof(buf)));
    assert_always(strcmp(buf, "0.0.0.0") == 0);
    assert_always(cra_sockaddr_to_endpoint(&address1, buf, sizeof(buf)));
    assert_always(strcmp(buf, "0.0.0.0:8888") == 0);

    cra_sockaddr_init(&address2, "::", 9999, AF_INET6);
    assert_always(cra_sockaddr_get_ip(&address2) != NULL);
    assert_always(cra_sockaddr_get_port(&address2) == 9999);
    assert_always(cra_sockaddr_get_family(&address2) == AF_INET6);
    assert_always(!cra_sockaddr_is_ipv4(&address2));
    assert_always(cra_sockaddr_is_ipv6(&address2));
    assert_always(address2.size == sizeof(struct sockaddr_in6));
    assert_always(cra_sockaddr_to_ip(&address2, buf, sizeof(buf)));
    assert_always(strcmp(buf, "::") == 0);
    assert_always(cra_sockaddr_to_endpoint(&address2, buf, sizeof(buf)));
    assert_always(strcmp(buf, "[::]:9999") == 0);

    assert_always(cra_sockaddr_cmp(&address1, &address2) != 0);
    cra_hash_t hash1 = cra_sockaddr_hash(&address1);
    cra_hash_t hash2 = cra_sockaddr_hash(&address2);
    assert_always(hash1 != hash2);

    cra_sockaddr_init(&address3, "0.0.0.0", 8888);
    assert_always(cra_sockaddr_get_family(&address3) == AF_INET);
    assert_always(cra_sockaddr_cmp(&address1, &address3) == 0);
    cra_hash_t hash3 = cra_sockaddr_hash(&address3);
    assert_always(hash1 == hash3);

    cra_sockaddr_init(&address3, "::", 9999);
    assert_always(cra_sockaddr_get_family(&address3) == AF_INET6);
    assert_always(cra_sockaddr_cmp(&address2, &address3) == 0);
    hash3 = cra_sockaddr_hash(&address3);
    assert_always(hash2 == hash3);

    cra_sockaddr_init(&address1, "localhost", 8888, AF_INET);
    assert_always(cra_sockaddr_get_family(&address1) == AF_INET);
    assert_always(cra_sockaddr_is_ipv4(&address1));
    assert_always(!cra_sockaddr_is_ipv6(&address1));
    assert_always(address1.size == sizeof(struct sockaddr_in));
    assert_always(cra_sockaddr_to_ip(&address1, buf, sizeof(buf)));
    assert_always(strcmp(buf, "127.0.0.1") == 0);

    cra_sockaddr_init(&address2, "localhost", 8888, AF_INET6);
    assert_always(cra_sockaddr_get_family(&address2) == AF_INET6);
    assert_always(!cra_sockaddr_is_ipv4(&address2));
    assert_always(cra_sockaddr_is_ipv6(&address2));
    assert_always(address2.size == sizeof(struct sockaddr_in6));
    assert_always(cra_sockaddr_to_ip(&address2, buf, sizeof(buf)));
    assert_always(strcmp(buf, "::1") == 0);
}

void
test_socket(void)
{
    CraSocket   listen_fd, accept_fd, client_fd;
    char        endpoint[CRA_ENDPOINT_LEN];
    CraSockAddr address, address2;

    cra_sockaddr_init(&address, "localhost", 8888);

    listen_fd = cra_socket_open(cra_sockaddr_get_family(&address), SOCK_STREAM);
    assert_always(cra_socket_is_valid(listen_fd));
    assert_always(cra_socket_bind(listen_fd, &address));
    assert_always(cra_socket_listen(listen_fd, 1));

    client_fd = cra_socket_open(cra_sockaddr_get_family(&address), SOCK_STREAM);
    assert_always(cra_socket_is_valid(client_fd));
    assert_always(cra_socket_connect(client_fd, &address));
    cranet_log_info("client: connect to %s", cra_sockaddr_to_endpoint(&address, endpoint, sizeof(endpoint)));

    accept_fd = cra_socket_accept(listen_fd, &address);
    assert_always(cra_socket_is_valid(accept_fd));
    cranet_log_info("server: accept from %s", cra_sockaddr_to_endpoint(&address, endpoint, sizeof(endpoint)));
    assert_always(cra_socket_get_remote_addr(accept_fd, &address2));
    cranet_log_info("server: remote addr: %s", cra_sockaddr_to_endpoint(&address2, endpoint, sizeof(endpoint)));
    assert_always(cra_sockaddr_cmp(&address, &address2) == 0);
    assert_always(cra_socket_get_local_addr(accept_fd, &address2));
    cranet_log_info("server: local addr: %s", cra_sockaddr_to_endpoint(&address2, endpoint, sizeof(endpoint)));

    int n = cra_socket_send(accept_fd, "hello world", 11);
    cranet_log_info("server: send bytes: %d", n);
    char buffer[128];
    n = cra_socket_recv(client_fd, buffer, sizeof(buffer));
    cranet_log_info("client: recv bytes: %d", n);

    n = cra_socket_send(client_fd, "hello", 5);
    cranet_log_info("client: send bytes: %d", n);
    n = cra_socket_recv(accept_fd, buffer, sizeof(buffer));
    cranet_log_info("server: recv bytes: %d", n);

    cra_socket_close(listen_fd);
    cra_socket_close(accept_fd);
    cra_socket_close(client_fd);

    // =====================

    cra_sockaddr_init(&address, "localhost", 9999, AF_INET);

    accept_fd = cra_socket_open(cra_sockaddr_get_family(&address), SOCK_DGRAM);
    assert_always(cra_socket_is_valid(accept_fd));
    assert_always(cra_socket_bind(accept_fd, &address));

    client_fd = cra_socket_open(cra_sockaddr_get_family(&address), SOCK_DGRAM);
    assert_always(cra_socket_is_valid(client_fd));

    n = cra_socket_sendto(client_fd, "hello world", sizeof("hello world"), &address);
    cranet_log_info("client: sendto bytes: %d", n);
    n = cra_socket_recvfrom(accept_fd, buffer, sizeof(buffer), &address2);
    cranet_log_info("server: recvfrom bytes: %d", n);
    assert_always(strcmp(buffer, "hello world") == 0);

    cra_socket_close(accept_fd);
    cra_socket_close(client_fd);
}

int
main(void)
{
    cranet_log_init(CRA_LOG_LV_TRACE, true, false, 0, NULL);
    cranet_startup();

    test_socket_address();
    test_socket();

    cranet_cleanup();
    cranet_log_uninit();

    cra_memory_leak_report();

    return 0;
}
