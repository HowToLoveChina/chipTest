#ifndef __PLATFORM_APP_H__
#define __PLATFORM_APP_H__

#include "bm1794-app.h"

typedef struct bm1794_app platform_app_t;
typedef struct bm1794_reg_info platform_reg_info_t;

extern platform_app_t g_bm1794_app;
extern platform_reg_info_t bm1794_info;

static inline int platform_app_init(void) {
    return bm1794_app_init();
}

static inline void platform_app_exit(void) {
    bm1794_app_exit();
}

static inline platform_app_t * platform_get_app(void) {
    return &g_bm1794_app;
}

static inline platform_reg_info_t * platform_get_appInfo(void) {
    return &bm1794_info;
}



#endif
