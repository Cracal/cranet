/**
 * @file kcp_transport.h
 * @author Cracal
 * @brief kcp transport impl
 * @version 0.1
 * @date 2025-11-20
 *
 * @copyright Copyright (c) 2025
 *
 */
#ifndef __CRA_KCP_TRANSPORT_H__
#define __CRA_KCP_TRANSPORT_H__
#include "cra_trans_i.h"
#include "kcp/ikcp.h"

typedef struct _CraLoop CraLoop;
typedef struct _KcpCtx  KcpCtx;

struct _KcpCtx
{
    CraLoop *timer_loop;
    bool     fastmode;
};

CRA_EXTERN const CraTrans_i g_kcp_trans_i;
#define KCP_TRANS_I (&g_kcp_trans_i)

#endif