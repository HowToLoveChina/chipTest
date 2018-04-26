#include "bitmain-chips.h"
#include "platform-app.h"
#include "logging.h"

int app_init(int type)
{
    (void)type;
    return platform_app_init();
}

void app_exit(int type)
{
    (void)type;
    return platform_app_exit();
}