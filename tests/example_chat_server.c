#include "cra_log.h"
#include "cra_mainarg.h"
#include "cra_server.h"
#include "ctrl_c_handler.h"
#include "threads/cra_lock.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRATEST-Chat"

CraLoop *g_loop = NULL;
CTRL_C_HANDLER_DEF(g_loop)

bool        g_verbose = false;
CraDict     g_clients; // Dict<cra_socket_t, CraConn *>
cra_mutex_t g_clients_lock;

static void
clients_init(void)
{
    cra_mutex_init(&g_clients_lock);
    cra_dict_init0(
      cra_socket_t, CraConn *, &g_clients, false, (cra_hash_fn)cra_hash_socket_p, (cra_compare_fn)cra_compare_socket_p);
}

static void
clients_uninit(void)
{
    CraDictIter it;
    CraConn   **pclient;

    for (cra_dict_iter_init(&g_clients, &it); cra_dict_iter_next(&it, NULL, (void **)&pclient);)
    {
        cra_conn_unref(*pclient);
    }
    cra_dict_uninit(&g_clients);
    cra_mutex_destroy(&g_clients_lock);
}

static void
clients_add(CraConn *conn)
{
    cra_mutex_lock(&g_clients_lock);
    cra_dict_add(&g_clients, &conn->io.fd, &conn);
    cra_conn_ref(conn);
    cra_mutex_unlock(&g_clients_lock);
}

static void
clients_remove(CraConn *conn)
{
    cra_mutex_lock(&g_clients_lock);
    cra_dict_remove(&g_clients, &conn->io.fd);
    cra_conn_unref(conn);
    cra_mutex_unlock(&g_clients_lock);
}

// AList<CraConn *>
static CraAList *
clients_get_all(void)
{
    CraAList   *clients;
    CraConn   **pclient;
    size_t      count;
    CraDictIter it;

    clients = cra_alloc(CraAList);
    if (!clients)
        return NULL;
    count = cra_dict_get_count(&g_clients);
    if (count == 0)
        count = 1;
    if (!cra_alist_init_size0(CraConn *, clients, count, false))
    {
        cra_dealloc(clients);
        return NULL;
    }

    cra_mutex_lock(&g_clients_lock);
    for (cra_dict_iter_init(&g_clients, &it); cra_dict_iter_next(&it, NULL, (void **)&pclient);)
    {
        cra_alist_append(clients, pclient);
        cra_conn_ref(*pclient);
    }
    cra_mutex_unlock(&g_clients_lock);
    return clients;
}

static void
on_connection(CraConn *conn)
{
    char ipport[CRA_IPPORTSTR_MAX];
    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));

    if (cra_conn_is_connected(conn))
    {
        clients_add(conn);
        cra_log_info("%s entered.", ipport);
    }
    else
    {
        clients_remove(conn);
        cra_log_info("%s left.", ipport);
    }
}

static void
on_message(CraConn *conn, CraBuffer *inputbuf)
{
    CraAListIter it;
    size_t       size;
    char        *buff;
    CraConn    **pclient;
    CraAList    *clients;
    CraConnBuf  *connbuf;
    char         ipport[CRA_IPPORTSTR_MAX];

    size = cra_buffer_readable(inputbuf);
    buff = (char *)cra_buffer_read_start(inputbuf);

    cra_socket_address_get_ipport(&conn->peeraddr, ipport, sizeof(ipport));

    if (g_verbose)
    {
        cra_log_info("%s says %.*s", ipport, (int)size, buff);
    }

    clients = clients_get_all();
    if (!clients)
        goto end;

    connbuf = cra_conn_buf_create((int)(size + strlen(ipport) + sizeof(" says ")), (int)cra_alist_get_count(clients));
    if (!connbuf)
    {
        for (cra_alist_iter_init(clients, &it); cra_alist_iter_next(&it, (void **)&pclient);)
        {
            cra_conn_unref(*pclient);
        }
        goto end2;
    }

    snprintf(connbuf->buf, connbuf->len, "%s says %.*s", ipport, (int)size, buff);
    for (cra_alist_iter_init(clients, &it); cra_alist_iter_next(&it, (void **)&pclient);)
    {
        if (*pclient != conn)
            cra_conn_send_safe1(*pclient, connbuf);
        cra_conn_unref(*pclient);
    }

    cra_conn_buf_unref(connbuf);
end2:
    cra_alist_uninit(clients);
    cra_dealloc(clients);
end:
    cra_buffer_retrieve_all_size(inputbuf);
}

int
main(int argc, char *argv[])
{
    const CraTrans_i *trans_i;
    CraServer         server;
    CraLoop           loop;
    CraMainArg        ma;
    char             *host;
    int               port;
    int               nthrd;

    CTRL_C_HANDLER_SET();

    cra_network_startup();
    cra_log_startup(CRA_LOG_LEVEL_INFO, true, (CraLogTo_i **)cra_logto_stdout_create(true));
    CRA_MAINARG_ELEMENT_BEGIN(options)
    CRA_MAINARG_ELEMENT_BOL("-u", "--udp", "Use UDP instead of default TCP")
    CRA_MAINARG_ELEMENT_BOL("-v", "--verbose", "Enable verbose mode")
    CRA_MAINARG_ELEMENT_VAL(
      "-n", NULL, "<loops>", "Number of loops to run", cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 20 }))
    CRA_MAINARG_ELEMENT_END();
    cra_mainarg_init(&ma, argv[0], "ChatServer", "[options] [host] [port]", options);
    cra_mainarg_parse_args(&ma, argc, argv);

    g_verbose = cra_mainarg_get_b(&ma, "v", false);
    trans_i = cra_mainarg_get_b(&ma, "u", false) ? CRA_CUDP_TRANSPORT_I : CRA_TCP_TRANSPORT_I;
    nthrd = (int)cra_mainarg_get_i(&ma, "n", 0);
    host = cra_mainarg_get_pos_args_s(&ma, 0, "0.0.0.0", cra_mainarg_stos, NULL);
    port = (int)cra_mainarg_get_pos_args_i(&ma, 1, 8888, cra_mainarg_stoi_in_range, ((int64_t[]){ 0, 65536 }));

    cra_loop_init(&loop);
    cra_loop_enable_timewheel(&loop, 20, 1000);
    cra_server_init(&server, host, port, &loop, nthrd, 128);
    cra_server_set_conn_cb(&server, on_connection);
    cra_server_set_read_cb(&server, on_message);
    cra_server_enable_close_timer(&server, 5 * 60 * 1000, cra_conn_close_safe);

    clients_init();

    g_loop = &loop;

    cra_server_start(&server, trans_i, NULL, false);
    cra_loop_loop(&loop);

    g_loop = NULL;

    cra_server_stop(&server);

    clients_uninit();

    cra_server_uninit(&server);
    cra_loop_uninit(&loop);

    cra_mainarg_uninit(&ma);
    cra_log_cleanup();
    cra_network_cleanup();

    cra_memory_leak_report();
    return 0;
}