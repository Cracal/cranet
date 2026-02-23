/**
 * @file cra_poller.h
 * @author Cracal
 * @brief poller interface
 * @version 0.1
 * @date 2024-12-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __CRA_POLLER_H__
#define __CRA_POLLER_H__
#include "collections/cra_alist.h"
#include "cra_event.h"

#ifdef CRA_OS_LINUX
#define CRA_WITH_EPOLL
#elif defined(CRA_OS_WIN)
#define CRA_WITH_POLL
#else
#error "暂不支持"
#endif

typedef struct _CraPollerCtx CraPollerCtx;

CRA_NET_API CraPollerCtx *
cra_poller_create_ctx(void);

CRA_NET_API void
cra_poller_destroy_ctx(CraPollerCtx *ctx);

CRA_NET_API bool
cra_poller_add(CraPollerCtx *ctx, CraIO *io);

CRA_NET_API bool
cra_poller_del(CraPollerCtx *ctx, CraIO *io);

CRA_NET_API bool
cra_poller_mod(CraPollerCtx *ctx, CraIO *io);

// `active_list`: List<CraIO *>
CRA_NET_API int
cra_poller_poll(CraPollerCtx *ctx, CraAList *active_list, int timeout_ms);

#endif