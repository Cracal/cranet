
#include "../ctrl_c_handler.h"
#include "cra_client.h"
#include "cra_log.h"
#include "cra_mainarg.h"
#include "cra_time.h"
#include "kcp_transport.h"
#include "threads/cra_thread.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "Test-KCP"

CraLoop *g_loop = NULL;
CTRL_C_HANDLER_DEF(g_loop)

CraConn *g_client = NULL;

static void
on_connection(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];

    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
    if (cra_conn_is_connected(conn))
    {
        cra_log_info("Connected to %s", ipport);
        g_client = conn;
    }
    else
    {
        cra_log_info("Disconnected from %s", ipport);
        g_client = NULL;
    }
}

static void
on_message(CraConn *conn, CraBuffer *inputbuf)
{
    char   ipport[CRA_IPPORTSTR_MAX];
    size_t len = cra_buffer_readable(inputbuf);
    char  *msg = (char *)cra_buffer_read_start(inputbuf);
    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));
    cra_log_info("`%s`: %zubytes, %.*s", ipport, len, (int)len, msg);
    cra_buffer_retrieve_all_size(inputbuf);
}

static CRA_THRD_FUNC(input_thread)
{
    char buffer[1500];
    CRA_UNUSED_VALUE(arg);

    while (fgets(buffer, sizeof(buffer), stdin))
    {
        if (g_client)
        {
            cra_conn_send_safe0(g_client, buffer, (unsigned int)strnlen(buffer, sizeof(buffer)));
        }
    }
    return (cra_thrd_ret_t)0;
}

int
main(int argc, char *argv[])
{
    int         port;
    const char *host;
    KcpCtx      kctx;
    CraLoop     loop;
    CraClient   cli;
    CraMainArg  ma;

    CTRL_C_HANDLER_SET();

    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_DEBUG, true, (CraLogTo_i **)cra_logto_stdout_create(false));

    CRA_MAINARG_ELEMENT_BEGIN(options)
    CRA_MAINARG_ELEMENT_BOL("-f", "--fast", "Set fast mode")
    CRA_MAINARG_ELEMENT_END();
    cra_mainarg_init(&ma, argv[0], "Kcp Client.", "[host] [port]", options);
    cra_mainarg_parse_args(&ma, argc, argv);
    host = cra_mainarg_get_pos_args_s(&ma, 0, "::1", cra_mainarg_stos, NULL);
    port = (int)cra_mainarg_get_pos_args_i(&ma, 1, 8888, cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 65535 }));

    kctx.fastmode = cra_mainarg_get_b(&ma, "fast", false);
    kctx.timer_loop = &loop;

    g_loop = &loop;
    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 1000);

    cra_client_init(&cli, host, port, &loop, 128);
    cra_client_set_conn_cb(&cli, on_connection);
    cra_client_set_read_cb(&cli, on_message);

    // run input thread
    cra_thrd_t th;
    cra_thrd_create(&th, input_thread, NULL);

    cra_client_connect(&cli, KCP_TRANS_I, &kctx, true);
    cra_loop_loop(&loop);

    g_loop = NULL;
    cra_thrd_join(th);

    cra_client_disconnect(&cli);
    cra_client_uninit(&cli);
    cra_loop_uninit(&loop);

    cra_log_cleanup();
    cra_network_cleanup();
    cra_mainarg_uninit(&ma);

    cra_memory_leak_report();
    return 0;
}
