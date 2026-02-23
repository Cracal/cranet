#include "cra_client.h"
#include "cra_log.h"
#include "threads/cra_thread.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRATEST-Client"

bool     g_stop_write = false;
CraLoop *g_loop = NULL;

void
on_conn(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];
    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));

    if (cra_conn_is_connected(conn))
    {
        cra_log_info("connected to %s.", ipport);
    }
    else
    {
        cra_log_info("disconnected from %s.", ipport);

        CraLoop *loop = g_loop;
        g_loop = NULL;
        cra_loop_stop_safe(loop);
    }
}

void
on_read(CraConn *conn, CraBuffer *inputbuf)
{
    CRA_UNUSED_VALUE(conn);

    size_t len = cra_buffer_readable(inputbuf);
    char  *buf = (char *)cra_buffer_read_start(inputbuf);

    cra_log_info("%.*s", (int)len, buf);

    cra_buffer_retrieve_all_size(inputbuf);
}

void
on_write_completed(CraConn *conn, int wrote)
{
    CRA_UNUSED_VALUE(conn);
    if (g_stop_write)
    {
        cra_log_debug("wrote %d bytes.", wrote);
        g_stop_write = false;
    }
}

void
on_high_water_mark(CraConn *conn, int n)
{
    CRA_UNUSED_VALUE(conn);
    cra_log_warn("HIGH WATER MARK: %d.", n);
    g_stop_write = true;
}

void
send_data(CraConn *conn)
{
    char buf[1024] = "DATA";
    cra_conn_send_safe0(conn, buf, sizeof(buf));
}

void
enable_timer(CraConn *conn)
{
    cra_conn_enable_heartbeat_timer(conn, g_loop, 100, send_data);
}

CRA_THRD_FUNC(input_thread)
{
    CraClient *cli;
    char       buf[1024];

    cli = (CraClient *)arg;
    while (fgets(buf, sizeof(buf), stdin))
    {
        if (!g_loop || !cli->conn)
            break;

        cra_conn_send_safe0(cli->conn, buf, (int)strlen(buf));

        if (strcmp(buf, "start\n") == 0)
        {
            cra_loop_run_in_loop(cli->conn->io.loop, (cra_functor_fn)enable_timer, cli->conn, &cli->conn->ref);
        }
        else if (strcmp(buf, "stop\n") == 0)
        {
            cra_loop_run_in_loop(
              cli->conn->io.loop, (cra_functor_fn)cra_conn_disable_heartbeat_timer, cli->conn, &cli->conn->ref);
        }
    }

    if (g_loop)
        cra_loop_stop_safe(g_loop);

    return (cra_thrd_ret_t){ 0 };
}

void
test(void)
{
    cra_thrd_t th;
    CraClient  cli;
    CraLoop    loop;

    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 1000);

    g_loop = &loop;

    cra_client_init(&cli, "127.0.0.1", 8888, &loop, 128);
    cra_client_set_conn_cb(&cli, on_conn);
    cra_client_set_read_cb(&cli, on_read);
    cra_client_set_write_completed_cb(&cli, on_write_completed);
    cra_client_set_write_high_water_mark_cb(&cli, 1 * 1024 * 1024, on_high_water_mark);

    // cra_client_connect(&cli, CRA_TCP_TRANSPORT_I, NULL, true);
    cra_client_connect(&cli, CRA_CUDP_TRANSPORT_I, NULL, true);

    cra_thrd_create(&th, input_thread, &cli);

    cra_loop_loop(&loop);

    cra_thrd_join(th);

    g_loop = NULL;
    cra_client_disconnect(&cli);
    cra_client_uninit(&cli);
    cra_loop_uninit(&loop);
}

int
main(void)
{
    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_TRACE, true, (CraLogTo_i **)cra_logto_stdout_create(false));

    test();

    cra_log_cleanup();
    cra_network_cleanup();
    cra_memory_leak_report();
    return 0;
}
