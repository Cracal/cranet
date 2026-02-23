/**
 * @file cra_conn_timer.h
 * @author Cracal
 * @brief timer for conn
 * @version 0.1
 * @date 2025-11-18
 *
 * @copyright Copyright (c) 2025
 *
 */
#ifndef __CRA_CONNTIMER_H__
#define __CRA_CONNTIMER_H__
#include "cra_event.h"

typedef struct _CraConnTimer CraConnTimer;
typedef struct _CraConn      CraConn;

typedef void (*cra_conntimer_fn)(CraConn *conn);

CRA_NET_API CraConnTimer *
cra_conntimer_open_safe(CraLoop *loop, CraConn *conn, bool call_once, uint32_t timeout_ms, cra_conntimer_fn on_timeout);

CRA_NET_API void
cra_conntimer_close_safe(CraConnTimer **ptimer);

CRA_NET_API void
cra_conntimer_update(CraConnTimer *timer);

#endif