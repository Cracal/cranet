#ifndef __CRANET_CRA_COMMON_H__
#define __CRANET_CRA_COMMON_H__
#include "crabase/cra_defs.h"
#include "crabase/cra_log.h"

#ifdef CRANET_STATIC
#define CRA_NAPI CRA_EXTERN
#else
#ifdef CRANET_EXPORT
#define CRA_NAPI CRA_EXPORT_API
#else
#define CRA_NAPI CRA_IMPORT_API
#endif
#endif

CRA_NAPI CraLogger *g_cranet_logger;

#endif
