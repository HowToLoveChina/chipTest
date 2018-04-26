#ifndef _DEBUG_TOOL_H_
#define _DEBUG_TOOL_H_
#include <pthread.h>

#define FIFO_SERVER2CLIENT             "/tmp/fifo_s2c"
#define FIFO_CLIENT2SERVER             "/tmp/fifo_c2s"
#define FIFO_SIZE               1024

#define MAX_PARAM_NUM               20
#define DEBUG_CMD_MAX_LEN           20
#define DEBUG_HELP_INFO_MAX_LEN     128
#define MAX_ENTRY_NUM               20

typedef int(*pDbgProcfunc)(int argc, char *argv[], char *ret_msg);
typedef struct
{
    char cmd[DEBUG_CMD_MAX_LEN];
    char help_info[DEBUG_HELP_INFO_MAX_LEN];
    pDbgProcfunc pfnDbgProc;
}debug_tool_entry;

struct debug_tool_info{
    int fd_read;
    int fd_write;
    debug_tool_entry entry[MAX_ENTRY_NUM];
    int debug_entry_num;
    pthread_t p_debug_handle;
};

int debugtool_init();
void debugtool_exit();

#endif
