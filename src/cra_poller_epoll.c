#include "cra_poller.h"

#ifdef CRA_WITH_EPOLL
#include "cra_assert.h"
#include "cra_log.h"
#include "cra_malloc.h"

#undef CRA_LOG_NAME
#define CRA_LOG_NAME "CRANET-EPoll"

#define EPoll ctx

#endif
