/**
 * @file example_echo_server.c
 * @author Cracal
 * @brief echo server
 * @version 0.1
 * @date 2025-06-23
 *
 * @copyright Copyright (c) 2025
 *
 */
#include "cra_buffer.h"
#include "cra_log.h"
#include "cra_mainarg.h"
#include "cra_server.h"
#include "ctrl_c_handler.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRATEST-Echo"

#define MAX_DATA 128

#ifdef CRA_COMPILER_MSVC
#define strupr_s _strupr_s
#endif

CraLoop *g_loop = NULL;
CTRL_C_HANDLER_DEF(g_loop)

bool g_verbosity = false;

static void
on_connection(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];

    if (g_verbosity)
    {
        cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
        if (cra_conn_is_connected(conn))
            cra_log_info("`%s`  entered.", ipport);
        else
            cra_log_info("`%s`  left.", ipport);
    }
}

static void
on_message(CraConn *conn, CraBuffer *inputbuf)
{
    size_t size;
    char  *buff;
    char   ipport[CRA_IPPORTSTR_MAX];

    size = cra_buffer_readable(inputbuf);
    buff = (char *)cra_buffer_read_start(inputbuf);

    if (g_verbosity)
    {
        cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
        cra_log_info("`%s`: %zu bytes, %.*s", ipport, size, (int)size, buff);
    }

    cra_conn_send(conn, buff, (int)size);
    cra_buffer_retrieve_all_size(inputbuf);
}

int
main(int argc, char *argv[])
{
    const CraTrans_i *trans_i;
    const char       *host;
    int               port;
    int               nsubloops;
    CraLoop           loop;
    CraServer         srv;
    CraMainArg        ma;

    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_DEBUG, true, (CraLogTo_i **)cra_logto_stdout_create(true));

    CTRL_C_HANDLER_SET();

    CRA_MAINARG_ELEMENT_BEGIN(options)
    CRA_MAINARG_ELEMENT_VAL(
      "-n", NULL, "loops", "Number of sub loops", cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 20 }))
    CRA_MAINARG_ELEMENT_BOL("-u", "--udp", "Use UDP instead of default TCP")
    CRA_MAINARG_ELEMENT_BOL("-v", "--verbose", "Set verbosity level")
    CRA_MAINARG_ELEMENT_END();
    cra_mainarg_init(&ma, argv[0], "This is an echo server program.", "[options] [host] [port]", options);
    cra_mainarg_parse_args(&ma, argc, argv);

    host = cra_mainarg_get_pos_args_s(&ma, 0, "::", cra_mainarg_stos, NULL);
    port = (int)cra_mainarg_get_pos_args_i(&ma, 1, 8888, cra_mainarg_stoi_in_range, ((int64_t[]){ 1025, 65536 }));
    nsubloops = (int)cra_mainarg_get_i(&ma, "n", 0);
    g_verbosity = cra_mainarg_get_b(&ma, "v", false);
    trans_i = cra_mainarg_get_b(&ma, "u", false) ? CRA_CUDP_TRANSPORT_I : CRA_TCP_TRANSPORT_I;

    g_loop = &loop;
    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 500);

    cra_server_init(&srv, host, port, &loop, nsubloops, 128);
    cra_server_set_conn_cb(&srv, on_connection);
    cra_server_set_read_cb(&srv, on_message);
    cra_server_enable_close_timer(&srv, 5 * 60 * 1000, cra_conn_close_safe);

    cra_server_start(&srv, trans_i, NULL, false);
    cra_loop_loop(&loop);

    g_loop = NULL;
    cra_server_stop(&srv);

    cra_loop_uninit(&loop);
    cra_server_uninit(&srv);

    cra_mainarg_uninit(&ma);
    cra_log_cleanup();
    cra_network_cleanup();

    cra_memory_leak_report();
    return 0;
}
