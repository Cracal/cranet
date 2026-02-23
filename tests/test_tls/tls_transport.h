/**
 * @file tls_transport.h
 * @author Cracal
 * @brief tls transport impl
 * @version 0.1
 * @date 2025-11-25
 *
 * @copyright Copyright (c) 2025
 *
 */
#ifndef __TLS_TRANSPORT_H__
#define __TLS_TRANSPORT_H__
// #ifdef __OPENSSL_APPLINK_IMPL__
// #ifdef CRA_OS_WIN
// #include <openssl/applink.c>
// #endif
// #endif
#include "cra_trans_i.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef struct _TlsTransport TlsTransport;
#define TlsCtx SSL_CTX

CRA_EXTERN const CraTrans_i g_tls_transport_i;
#define TLS_TRANSPORT_I (&g_tls_transport_i)

#endif