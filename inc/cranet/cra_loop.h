#ifndef __CRANET_CRA_LOOP_H__
#define __CRANET_CRA_LOOP_H__
#include "cranet/cra_socket.h"
#include "crabase/threads/cra_thread.h"

typedef struct CraLoop CraLoop;

struct CraLoop
{
    bool running;
};

#endif
