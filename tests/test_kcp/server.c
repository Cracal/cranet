
#include "../ctrl_c_handler.h"
#include "cra_log.h"
#include "cra_mainarg.h"
#include "cra_server.h"
#include "cra_time.h"
#include "kcp_transport.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "Test-KCP"

CraLoop *g_loop = NULL;
CTRL_C_HANDLER_DEF(g_loop)

static void
on_connection(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];

    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
    if (cra_conn_is_connected(conn))
        cra_log_info("`%s`  entered.", ipport);
    else
        cra_log_info("`%s`  left.", ipport);
}

static void
on_message(CraConn *conn, CraBuffer *inputbuf)
{
    char   ipport[CRA_IPPORTSTR_MAX];
    size_t len = cra_buffer_readable(inputbuf);
    char  *msg = (char *)cra_buffer_read_start(inputbuf);

    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));

    cra_log_info("`%s`: %zu bytes, %.*s", ipport, len, (int)len, msg);
    cra_conn_send(conn, msg, (int)len);

    cra_buffer_retrieve_all_size(inputbuf);
}

int
main(int argc, char *argv[])
{
    int         nsubloops;
    int         port;
    const char *host;
    KcpCtx      kctx;
    CraLoop     loop;
    CraServer   srv;
    CraMainArg  ma;

    CTRL_C_HANDLER_SET();

    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_DEBUG, true, (CraLogTo_i **)cra_logto_stdout_create(false));

    CRA_MAINARG_ELEMENT_BEGIN(options)
    CRA_MAINARG_ELEMENT_BOL("-f", "--fast", "Set fast mode")
    CRA_MAINARG_ELEMENT_VAL(
      "-n", NULL, "<nsubloops>", "Number of subloops", cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 20 }))
    CRA_MAINARG_ELEMENT_END();
    cra_mainarg_init(&ma, argv[0], "Kcp Server.", "[host] [port]", options);
    cra_mainarg_parse_args(&ma, argc, argv);
    host = cra_mainarg_get_pos_args_s(&ma, 0, "::", cra_mainarg_stos, NULL);
    port = (int)cra_mainarg_get_pos_args_i(&ma, 1, 8888, cra_mainarg_stoi_in_range, ((int64_t[]){ 1025, 65536 }));
    nsubloops = (int)cra_mainarg_get_i(&ma, "n", 0);

    kctx.fastmode = cra_mainarg_get_b(&ma, "f", false);
    kctx.timer_loop = &loop;

    g_loop = &loop;
    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 1000);

    cra_server_init(&srv, host, port, &loop, nsubloops, 128);
    cra_server_set_conn_cb(&srv, on_connection);
    cra_server_set_read_cb(&srv, on_message);
    cra_server_enable_close_timer(&srv, 30 * 1000, cra_conn_close_safe);

    cra_server_start(&srv, KCP_TRANS_I, &kctx, false);
    cra_loop_loop(&loop);

    g_loop = NULL;

    cra_server_stop(&srv);

    cra_server_uninit(&srv);
    cra_loop_uninit(&loop);

    cra_log_cleanup();
    cra_network_cleanup();
    cra_mainarg_uninit(&ma);

    cra_memory_leak_report();
    return 0;
}
