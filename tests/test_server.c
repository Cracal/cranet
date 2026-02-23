#include "cra_log.h"
#include "cra_server.h"
#include "ctrl_c_handler.h"
#include <time.h>

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRATEST-Server"

CraLoop *g_loop = NULL;

CTRL_C_HANDLER_DEF(g_loop)

void
on_conn(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];
    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));

    if (cra_conn_is_connected(conn))
        cra_log_info("conn[%s] is connected.", ipport);
    else
        cra_log_info("conn[%s] is disconnected.", ipport);
}

void
on_write_completed(CraConn *conn, int wrote)
{
    char ipport[CRA_IPPORTSTR_MAX];
    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
    cra_log_info("conn[%s] has wrote %d bytes.", ipport, wrote);
}

void
on_write_high_water_mark(CraConn *conn, int n)
{
    char ipport[CRA_IPPORTSTR_MAX];
    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
    cra_log_warn("conn[%s] has output %d bytes.", ipport, n);
}

void
on_close(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];
    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
    cra_log_debug("TIMEOUT! close conn[%s].", ipport);
    cra_conn_close_safe(conn);
}

void
on_heartbeat(CraConn *conn)
{
    cra_conn_send_safe0(conn, "<<HEARTBEAT>>\n", sizeof("<<HEARTBEAT>>\n"));
}

void
on_read(CraConn *conn, CraBuffer *inputbuf)
{
    char   ipport[CRA_IPPORTSTR_MAX];
    size_t len = cra_buffer_readable(inputbuf);
    char  *buf = (char *)cra_buffer_read_start(inputbuf);
    bool   is_cmd = true;

#define CMD_OK_RESP()      cra_conn_send_safe0(conn, "OK!\n", sizeof("OK!\n") - 1);
#define CMD_ERR_RESP(_msg) cra_conn_send_safe0(conn, "ERROR!" _msg "\n", sizeof("ERROR!" _msg "\n") - 1);

    // kill conn
    if (strncmp(buf, "kill me\n", sizeof("kill me\n") - 1) == 0)
    {
        CMD_OK_RESP();
        cra_conn_close_safe(conn);
    }
    // shutdown
    if (strncmp(buf, "shutdown\n", sizeof("shutdown\n") - 1) == 0)
    {
        CMD_OK_RESP();
        cra_conn_shutdown_safe(conn);
    }
    // disable read
    else if (strncmp(buf, "disable read\n", sizeof("disable read\n") - 1) == 0)
    {
        cra_conn_disable_read(conn);
        CMD_OK_RESP();
    }
    // enable close timer
    else if (strncmp(buf, "set close timer ", sizeof("set close timer ") - 1) == 0)
    {
        buf[len - 1] = '\0';
        int n = atoi(buf + sizeof("set close timer ") - 1);
        if (n >= 100)
        {
            CMD_OK_RESP();
            cra_conn_enable_close_timer(conn, conn->srv->mainloop, n, on_close);
        }
        else
        {
            CMD_ERR_RESP(" cmd: `set close timer <ms>`. ms >= 100.");
        }
    }
    // disable close timer
    else if (strncmp(buf, "remove close timer\n", sizeof("remove close timer\n") - 1) == 0)
    {
        cra_conn_disable_close_timer(conn);
        CMD_OK_RESP();
    }
    // enable heartbeat timer
    else if (strncmp(buf, "set heartbeat timer ", sizeof("set heartbeat timer ") - 1) == 0)
    {
        buf[len - 1] = '\0';
        int n = atoi(buf + sizeof("set heartbeat timer ") - 1);
        if (n >= 100)
        {
            CMD_OK_RESP();
            cra_conn_enable_heartbeat_timer(conn, conn->srv->mainloop, n, on_heartbeat);
        }
        else
        {
            CMD_ERR_RESP(" cmd: `set heartbeat timer <ms>`. ms >= 100.");
        }
    }
    // disable heartbeat timer
    else if (strncmp(buf, "remove heartbeat timer\n", sizeof("remove heartbeat timer\n") - 1) == 0)
    {
        cra_conn_disable_heartbeat_timer(conn);
        CMD_OK_RESP();
    }
    // set write completed cb
    else if (strncmp(buf, "set write completed cb\n", sizeof("set write completed cb\n") - 1) == 0)
    {
        cra_conn_set_write_completed_cb(conn, on_write_completed);
        CMD_OK_RESP();
    }
    // remove write completed cb
    else if (strncmp(buf, "remove write completed cb\n", sizeof("remove write completed cb\n") - 1) == 0)
    {
        cra_conn_set_write_completed_cb(conn, NULL);
        CMD_OK_RESP();
    }
    // set write high water mark cb
    else if (strncmp(buf, "set write high water mark cb ", sizeof("set write high water mark cb ") - 1) == 0)
    {
        buf[len - 1] = '\0';
        int n = atoi(buf + sizeof("set write high water mark cb ") - 1);
        if (n > 0)
        {
            cra_conn_set_write_high_water_mark_cb(conn, n, on_write_high_water_mark);
            CMD_OK_RESP();
        }
        else
        {
            CMD_ERR_RESP(" cmd: `set write high water mark cb <mark>`. mark > 0.");
        }
    }
    // remove write high water mark cb
    else if (strncmp(buf, "remove write high water mark cb\n", sizeof("remove write high water mark cb\n") - 1) == 0)
    {
        cra_conn_set_write_high_water_mark_cb(conn, 0, NULL);
        CMD_OK_RESP();
    }
    // echo
    else if (strncmp(buf, "echo\n", sizeof("echo\n") - 1) == 0)
    {
        conn->user = (void *)((intptr_t)conn->user | 1);
        CMD_OK_RESP();
    }
    // no echo
    else if (strncmp(buf, "no echo\n", sizeof("no echo\n") - 1) == 0)
    {
        conn->user = (void *)((intptr_t)conn->user & ~1);
        CMD_OK_RESP();
    }
    // output
    else if (strncmp(buf, "output\n", sizeof("output\n") - 1) == 0)
    {
        conn->user = (void *)((intptr_t)conn->user | 2);
        CMD_OK_RESP();
    }
    // no output
    else if (strncmp(buf, "no output\n", sizeof("no output\n") - 1) == 0)
    {
        conn->user = (void *)((intptr_t)conn->user & ~2);
        CMD_OK_RESP();
    }
    // show address
    else if (strncmp(buf, "show address\n", sizeof("show address\n") - 1) == 0)
    {
        char ipport_peer[CRA_IPPORTSTR_MAX];
        char message[CRA_IPPORTSTR_MAX * 2 + 20];
        int  msg_len;

        cra_socket_address_get_ipport(&conn->localaddr, ipport, sizeof(ipport));
        cra_socket_address_get_ipport(&conn->peeraddr, ipport_peer, sizeof(ipport_peer));
        msg_len = snprintf(message, sizeof(message), "remote: %s, client: %s\n", ipport, ipport_peer);
        if (msg_len > 0)
            cra_conn_send_safe0(conn, message, msg_len);
        else
            CMD_ERR_RESP("failed to make message.");
    }
    else
    {
        is_cmd = false;
    }

    // ECHO
    if (!is_cmd && ((intptr_t)conn->user & 1))
    {
        cra_conn_send_safe0(conn, buf, (int)len);
    }
    // OUTPUT
    if ((intptr_t)conn->user & 2)
    {
        cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
        cra_log_info("conn[%s]: %zubytes, %.*s", ipport, len, (int)len, buf);
    }

    cra_buffer_retrieve_all_size(inputbuf);
}

void
test1(void)
{
    CraLoop   loop;
    CraServer server;

    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 16, 1000);

    cra_server_init(&server, "::", 8888, &loop, 3, 128);
    cra_server_set_conn_cb(&server, on_conn);
    cra_server_set_read_cb(&server, on_read);
    // cra_server_set_write_completed_cb(&server, on_write_completed);
    // cra_server_set_write_high_water_mark_cb(&server, 8192, on_write_high_water_mark);

    g_loop = &loop;

    // cra_server_start(&server, CRA_TCP_TRANSPORT_I, NULL, false);
    cra_server_start(&server, CRA_CUDP_TRANSPORT_I, NULL, false);
    cra_loop_loop(&loop);

    g_loop = NULL;

    cra_server_stop(&server);

    cra_server_uninit(&server);
    cra_loop_uninit(&loop);
}

int
main(void)
{
    CTRL_C_HANDLER_SET();
    srand((unsigned int)time(NULL));
    cra_log_startup(CRA_LOG_LEVEL_TRACE, true, (CraLogTo_i **)cra_logto_stdout_create(false));
    cra_network_startup();

    test1();

    cra_network_cleanup();
    cra_log_cleanup();
    cra_memory_leak_report();
    return 0;
}
