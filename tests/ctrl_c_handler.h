#include "cra_common.h"

#ifdef CRA_OS_WIN
#define CTRL_C_HANDLER_DEF(_g_main_loop_name)                  \
    static BOOL WINAPI __ctrl_c_handler(DWORD type)            \
    {                                                          \
        if (type == CTRL_C_EVENT && _g_main_loop_name != NULL) \
            cra_loop_stop_safe(_g_main_loop_name);             \
        return TRUE;                                           \
    }
#define CTRL_C_HANDLER_SET() SetConsoleCtrlHandler(__ctrl_c_handler, TRUE)
#else
#define CTRL_C_HANDLER_DEF(_g_main_loop_name)      \
    static void __ctrl_c_handler(int sig)          \
    {                                              \
        if (_g_main_loop_name != NULL)             \
            cra_loop_stop_safe(_g_main_loop_name); \
    }
#define CTRL_C_HANDLER_SET() signal(SIGINT, __ctrl_c_handler)
#endif
