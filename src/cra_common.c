#include "cra_conn.h"
#include "cra_log.h"
#include <timeapi.h>

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-Common"

void
cra_network_startup(void)
{
#ifdef CRA_OS_WIN

    WSADATA data;

    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
    {
        cra_log_fatal("WSAStartup() failed: %d", cra_get_last_error());
        exit(1);
    }

#else

#endif
}

void
cra_network_cleanup(void)
{
#ifdef CRA_OS_WIN

    WSACleanup();

#else

#endif
}
