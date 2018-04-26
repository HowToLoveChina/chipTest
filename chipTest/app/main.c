#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "logging.h"
#include "uart.h"
#include "debug-server.h"
#include "platform-app.h"
#include "platform-driver.h"
#include "chip-api.h"
#include "comm-api.h"
#include "midd-api.h"
#include "bitmain-chips.h"
#include "app.h"
#include "ioctl-type.h"
#include "factory-test.h"
#include "util.h"

int quit_app = 0;

int main()
{
    chip_api_init(ZCASH_BM1794);
    comm_api_init(COMM_TYPE_UART);
    //comm_api_init(COMM_TYPE_SIMU);
    midd_api_init();
    app_init(ZCASH_BM1794);

#if defined(WIN32)
    factory_test_init();
#else
    debugtool_init();
#endif

    while(!quit_app)
    {
        z_sleep(3);
    }

    app_exit(ZCASH_BM1794);
    midd_api_exit();
#if defined(WIN32)
    factory_test_exit();
#else
    debugtool_exit();
#endif		
    return 0;
}

