/**
 * @file cra_confs.h
 * @author Cracal
 * @brief common
 * @version 0.1
 * @date 2024-12-12
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __CRA_CONFS_H__
#define __CRA_CONFS_H__
#include "cra_atomic.h"
#include "cra_defs.h"
#include <inttypes.h> // for PRIxPTR

#ifdef CRA_NET_BUILD_DLL
#define CRA_NET_API CRA_EXPORT_API
#else
#define CRA_NET_API CRA_IMPORT_API
#endif

// cra_log_`level`("obj[0xhex]: fmt", (uintptr_t)(obj), ...). include "cra_log.h"
#define __CRA_LOG_WITH_OBJ(_level, _obj, _fmt, ...)                                     \
    cra_log_##_level(#_obj "[0x%" PRIxPTR "]: " _fmt, (uintptr_t)(_obj), ##__VA_ARGS__)
// cra_log_message(LEVEL, "obj[0xhex]: fmt", (uintptr_t)(obj), ...). include "cra_log.h"
#define __CRA_LOG_WITH_OBJ2(_LEVEL, _obj, _fmt, ...)                                           \
    cra_log_message(_LEVEL, #_obj "[0x%" PRIxPTR "]: " _fmt, (uintptr_t)(_obj), ##__VA_ARGS__)

// cra_log_`level`("fmt", ...). include "cra_log.h"
#define __CRA_LOG_WITHOUT_OBJ(_level, _obj, _fmt, ...)  cra_log_##_level(_fmt, ##__VA_ARGS__)
// cra_log_message(LEVEL, "fmt", ...). include "cra_log.h"
#define __CRA_LOG_WITHOUT_OBJ2(_LEVEL, _obj, _fmt, ...) cra_log_message(_LEVEL, _fmt, ##__VA_ARGS__)

#ifndef NDEBUG
#define CRA_LOG  __CRA_LOG_WITH_OBJ
#define CRA_LOG2 __CRA_LOG_WITH_OBJ2
#else
#define CRA_LOG  __CRA_LOG_WITHOUT_OBJ
#define CRA_LOG2 __CRA_LOG_WITHOUT_OBJ2
#endif

#define CRA_OBJ_HEAD(_Type_i)    const _Type_i *const i
#define CRA_OBJ_I(_Type_i, _obj) (*(const _Type_i **)(_obj))
#define CRA_IF_HEAD              const char *const tag
#define CRA_IF_HEAD_SET(_tag)    .tag = _tag
#ifndef NDEBUG
#define CRA_OBJ_CHECK(_Type_i, _obj, _tag) assert(strcmp(CRA_OBJ_I(_Type_i, _obj)->tag, _tag) == 0)
#else
#define CRA_OBJ_CHECK(_Type_i, _obj, _tag) CRA_UNUSED_VALUE(_obj)
#endif

typedef cra_atomic_flag_t cra_spinlock_t;
#define cra_spinlock_init   cra_atomic_flag_clear
#define cra_spinlock_uninit cra_atomic_flag_clear
#ifdef CRA_OS_WIN
#define __cra_spinlock_pause YieldProcessor()
#elif defined(__i386) || defined(__x86_64__)
#define __cra_spinlock_pause __asm__ volatile("pause" ::"memory")
#else
#define __cra_spinlock_pause
#endif
#define cra_spinlock_lock(_lock)                \
    while (cra_atomic_flag_test_and_set(_lock)) \
    __cra_spinlock_pause
#define cra_spinlock_unlock cra_atomic_flag_clear

CRA_NET_API void
cra_network_startup(void);

CRA_NET_API void
cra_network_cleanup(void);

#endif