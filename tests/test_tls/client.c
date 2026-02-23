#include "../ctrl_c_handler.h"
#include "cra_client.h"
#include "cra_log.h"
#include "cra_mainarg.h"
#include "threads/cra_thread.h"
#include "tls_transport.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "TLS-CLIENT"

#define CAFILE "D:\\test_tls\\cert\\ca.crt"

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
        cra_log_info("connection `%s` connected.", ipport);
        g_client = conn;
    }
    else
    {
        cra_log_info("connection `%s` disconnected.", ipport);
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

static TlsCtx *
create_ctx(void)
{
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_load_verify_locations(ctx, CAFILE, NULL))
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static void
destroy_ctx(TlsCtx *ctx)
{
    SSL_CTX_free(ctx);
}

static CRA_THRD_FUNC(input_thread)
{
    char buffer[1024];
    CRA_UNUSED_VALUE(arg);

    while (true)
    {
        if (fgets(buffer, sizeof(buffer), stdin) == NULL)
            break;
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
    bool        retry;
    int         port;
    const char *host;
    TlsCtx     *tctx;
    CraLoop     loop;
    CraClient   client;
    CraMainArg  ma;

    CTRL_C_HANDLER_SET();

    CRA_MAINARG_ELEMENT_BEGIN(options)
    CRA_MAINARG_ELEMENT_BOL("-r", "--retry", "Retry connect if failed.")
    CRA_MAINARG_ELEMENT_END();
    cra_mainarg_init(&ma, argv[0], "TLS Client.", "[host] [port]", options);
    cra_mainarg_parse_args(&ma, argc, argv);
    host = cra_mainarg_get_pos_args_s(&ma, 0, "::1", cra_mainarg_stos, NULL);
    port = (int)cra_mainarg_get_pos_args_i(&ma, 1, 8888, cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 65535 }));
    retry = cra_mainarg_get_b(&ma, "retry", false);

    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_DEBUG, true, (CraLogTo_i **)cra_logto_stdout_create(false));

    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 1000);

    cra_client_init(&client, host, port, &loop, 128);
    cra_client_set_conn_cb(&client, on_connection);
    cra_client_set_read_cb(&client, on_message);
    tctx = create_ctx();

    g_loop = &loop;

    // run input thread
    cra_thrd_t th;
    cra_thrd_create(&th, input_thread, NULL);

    cra_client_connect(&client, TLS_TRANSPORT_I, tctx, retry);
    cra_loop_loop(&loop);

    g_loop = NULL;
    cra_thrd_join(th);

    cra_client_disconnect(&client);
    cra_client_uninit(&client);
    cra_loop_uninit(&loop);

    destroy_ctx(tctx);
    cra_log_cleanup();
    cra_network_cleanup();
    cra_mainarg_uninit(&ma);
    cra_memory_leak_report();
    return 0;
}
