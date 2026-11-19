#include "cranet/cra_defs.h"
#include "cranet/cra_socket.h"

#ifndef CRANET_LOG_NAME
#define CRANET_LOG_NAME "cranet"
#endif

CraLogger *cranet_g_logger = NULL;

void
cranet_startup(void)
{
#ifdef CRA_OS_WINDOWS
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
    {
        fprintf(stderr, "WSAStartup failed, error: %d\n", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
#endif
}

void
cranet_cleanup(void)
{
#ifdef CRA_OS_WINDOWS
    WSACleanup();
#endif
}
