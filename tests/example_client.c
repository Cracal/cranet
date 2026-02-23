/**
 * @file example_echo_client.c
 * @author Cracal
 * @brief echo client
 * @version 0.1
 * @date 2025-06-23
 *
 * @copyright Copyright (c) 2025
 *
 */
#include "cra_buffer.h"
#include "cra_client.h"
#include "cra_log.h"
#include "cra_mainarg.h"
#include "ctrl_c_handler.h"
#include "threads/cra_thread.h"
#include <time.h>

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRATEST-Echo"

#define MAX_DATA 128

CraConn *g_cli = NULL;
CraLoop *g_loop = NULL;
CTRL_C_HANDLER_DEF(g_loop)

static void
on_connection(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];

    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
    if (cra_conn_is_connected(conn))
    {
        cra_log_info("`%s`  connected.", ipport);
        g_cli = conn;
    }
    else
    {
        cra_log_info("`%s`  disconnected.", ipport);
        g_cli = NULL;
    }
}

static void
on_message(CraConn *conn, CraBuffer *inputbuf)
{
    CRA_UNUSED_VALUE(conn);

    size_t len = cra_buffer_readable(inputbuf);
    char  *msg = (char *)cra_buffer_read_start(inputbuf);
    printf("%zu bytes, %.*s", len, (int)len, msg);

    cra_buffer_retrieve_all_size(inputbuf);
}

static CRA_THRD_FUNC(input_thread)
{
    CRA_UNUSED_VALUE(arg);

    char buf[1024];

    while (fgets(buf, sizeof(buf), stdin))
    {
        if (!g_cli)
            break;

        cra_conn_send_safe0(g_cli, buf, (int)strlen(buf));
    }

    return (cra_thrd_ret_t){ 0 };
}

int
main(int argc, char *argv[])
{
    int               port;
    const char       *host;
    const CraTrans_i *trans_i;
    CraLoop           loop;
    CraClient         cli;
    CraMainArg        ma;
    cra_thrd_t        th;

    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_DEBUG, true, (CraLogTo_i **)cra_logto_stdout_create(false));

    CTRL_C_HANDLER_SET();

    CRA_MAINARG_ELEMENT_BEGIN(options)
    CRA_MAINARG_ELEMENT_BOL("-u", "--udp", "Use UDP instead of default TCP")
    CRA_MAINARG_ELEMENT_END();
    cra_mainarg_init(&ma, argv[0], "This is an echo client program.", "[options] [host] [port]", options);
    cra_mainarg_parse_args(&ma, argc, argv);

    host = cra_mainarg_get_pos_args_s(&ma, 0, "::1", cra_mainarg_stos, NULL);
    port = (int)cra_mainarg_get_pos_args_i(&ma, 1, 8888, cra_mainarg_stoi_in_range, ((int64_t[]){ 1025, 65536 }));
    trans_i = cra_mainarg_get_b(&ma, "u", false) ? CRA_CUDP_TRANSPORT_I : CRA_TCP_TRANSPORT_I;

    g_loop = &loop;
    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 500);
    cra_client_init(&cli, host, port, &loop, 128);
    cra_client_set_conn_cb(&cli, on_connection);
    cra_client_set_read_cb(&cli, on_message);

    cra_client_connect(&cli, trans_i, NULL, false);

    cra_thrd_create(&th, input_thread, NULL);

    cra_loop_loop(&loop);

    g_loop = NULL;
    cra_client_disconnect(&cli);
    cra_client_uninit(&cli);
    cra_loop_uninit(&loop);

    cra_mainarg_uninit(&ma);
    cra_log_cleanup();
    cra_network_cleanup();

    cra_memory_leak_report();
    return 0;
}
