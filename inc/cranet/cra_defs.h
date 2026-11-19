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

CRA_NAPI CraLogger *cranet_g_logger;
#define cranet_log_trace(...) cra_log_trace(cranet_g_logger, __VA_ARGS__)
#define cranet_log_debug(...) cra_log_debug(cranet_g_logger, __VA_ARGS__)
#define cranet_log_info(...)  cra_log_info(cranet_g_logger, __VA_ARGS__)
#define cranet_log_warn(...)  cra_log_warn(cranet_g_logger, __VA_ARGS__)
#define cranet_log_error(...) cra_log_error(cranet_g_logger, __VA_ARGS__)
#define cranet_log_fatal(...) cra_log_fatal(cranet_g_logger, __VA_ARGS__)
#define cranet_log_init(level, utc, to_file, max_file_size, directory) \
    do                                                                 \
    {                                                                  \
        cranet_g_logger = cra_log_open("cranet", level, utc, to_file); \
        if (max_file_size > 0 && directory)                            \
            cra_log_config(cranet_g_logger, max_file_size, directory); \
    } while (0)
#define cranet_log_uninit() cra_log_close(cranet_g_logger)

CRA_NAPI void
cranet_startup(void);

CRA_NAPI void
cranet_cleanup(void);

#endif
