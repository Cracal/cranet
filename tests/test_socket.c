#include "crabase/cra_log.h"
#include "crabase/cra_malloc.h"
#include "cranet/cra_socket.h"

void
test1(void)
{
    CraSockAddr address;
    char        endpoint[CRA_ENDPOINT_LEN];
    CraSocket   server_fd, client_fd, accept_fd;
    CRA_UNUSED(accept_fd);

    cra_sockaddr_init(&address, "localhost", 8888, AF_INET);

    cra_sockaddr_to_endpoint(&address, endpoint, sizeof(endpoint));
    cra_log_info(g_cranet_logger, "endpoint: %s", endpoint);

    server_fd = cra_socket_open(cra_sockaddr_get_family(&address), SOCK_STREAM);
    assert_always(cra_socket_is_valid(server_fd));
    assert_always(cra_socket_bind(server_fd, &address));
    assert_always(cra_socket_listen(server_fd, 1));

    client_fd = cra_socket_open(cra_sockaddr_get_family(&address), SOCK_STREAM);
    assert_always(cra_socket_is_valid(client_fd));
    assert_always(cra_socket_set_nonblocking(client_fd));

    cra_socket_connect(client_fd, &address);

    accept_fd = cra_socket_accept(server_fd, NULL);
    assert_always(cra_socket_is_valid(accept_fd));

    int n = cra_socket_send(accept_fd, "hello world", 11);
    cra_log_info(g_cranet_logger, "A send bytes: %d", n);
    char buffer[128];
    n = cra_socket_recv(client_fd, buffer, sizeof(buffer));
    cra_log_info(g_cranet_logger, "B recv bytes: %d", n);

    n = cra_socket_send(client_fd, "hello", 5);
    cra_log_info(g_cranet_logger, "B send bytes: %d", n);
    n = cra_socket_recv(accept_fd, buffer, sizeof(buffer));
    cra_log_info(g_cranet_logger, "A recv bytes: %d", n);

    cra_socket_close(accept_fd);
    cra_socket_close(client_fd);

    cra_socket_close(server_fd);
}

int
main(void)
{
    g_cranet_logger = cra_log_open("CRANET", CRA_LOG_LV_TRACE, false, false);
    cra_initialize_sockets();

    test1();

    cra_log_close(g_cranet_logger);
    cra_shutdown_sockets();

    cra_memory_leak_report();

    return 0;
}
