#include "../ctrl_c_handler.h"
#include "cra_log.h"
#include "cra_mainarg.h"
#include "cra_server.h"
#include "tls_transport.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "TLS-CLIENT"

#define CERTFILE "D:\\test_tls\\server.crt"
#define PRIVFILE "D:\\test_tls\\server.key"

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
    cra_log_info("`%s`: %zubytes, %.*s", ipport, len, (int)len, msg);
    cra_conn_send(conn, msg, (unsigned int)len);
    cra_buffer_retrieve_all_size(inputbuf);
}

static TlsCtx *
create_ctx(void)
{
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERTFILE, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, PRIVFILE, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx))
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

int
main(int argc, char *argv[])
{
    int         nth;
    int         port;
    const char *host;
    TlsCtx     *tctx;
    CraLoop     loop;
    CraServer   server;
    CraMainArg  ma;

    CTRL_C_HANDLER_SET();

    CRA_MAINARG_ELEMENT_BEGIN(options)
    CRA_MAINARG_ELEMENT_VAL(
      "-n", NULL, "num", "Set number of subloops", cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 30 }))
    CRA_MAINARG_ELEMENT_END();
    cra_mainarg_init(&ma, argv[0], "TLS Server.", "[host] [port] [-n <num>]", options);
    cra_mainarg_parse_args(&ma, argc, argv);
    host = cra_mainarg_get_pos_args_s(&ma, 0, "::", cra_mainarg_stos, NULL);
    port = (int)cra_mainarg_get_pos_args_i(&ma, 1, 8888, cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 65535 }));
    nth = (int)cra_mainarg_get_i(&ma, "n", 0);

    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_DEBUG, true, (CraLogTo_i **)cra_logto_stdout_create(false));

    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 1000);

    cra_server_init(&server, host, port, &loop, nth, 128);
    cra_server_set_conn_cb(&server, on_connection);
    cra_server_set_read_cb(&server, on_message);
    tctx = create_ctx();

    g_loop = &loop;

    cra_server_start(&server, TLS_TRANSPORT_I, tctx, false);
    cra_loop_loop(&loop);

    g_loop = NULL;

    cra_server_stop(&server);
    cra_server_uninit(&server);
    cra_loop_uninit(&loop);

    destroy_ctx(tctx);
    cra_log_cleanup();
    cra_network_cleanup();
    cra_mainarg_uninit(&ma);
    cra_memory_leak_report();
    return 0;
}
