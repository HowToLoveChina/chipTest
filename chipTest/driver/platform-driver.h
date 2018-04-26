#ifndef __PLATFORM_DRIVER_H__
#define __PLATFORM_DRIVER_H__

#include "bm1794-driver.h"

typedef union bm1794_reg   platform_reg_t;

#define PLATFORM_CRC16_LEN              BM1794_CRC16_LEN
#define PLATFORM_RESP_NONCE_LEN         BM1794_RESP_NONCE_LEN
#define PLATFORM_RESP_REG_LEN           BM1794_RESP_REG_LEN

static inline int platform_soc_init(void *arg) {
    return bm1794_soc_init(arg);
}

static inline int platform_soc_exit(void) {
    return bm1794_soc_exit();
}

static inline int platform_ioctl_regtable(uint32_t oper_type, void *param) {
    return bm1794_ioctl_regtable(oper_type, param);
}

static inline int platform_pack_ioctl_pkg(uint8_t *str,
        uint32_t str_len, uint32_t oper_type, void *param) {
    return bm1794_pack_ioctl_pkg(str, str_len, oper_type, param);
}

static inline int platform_parse_respond_pkg(uint8_t *str,
        int len, int *type, uint8_t *out_str, uint32_t out_len) {
    return bm1794_parse_respond_pkg(str, len, type, out_str, out_len);
}

static inline int platform_parse_respond_len(uint8_t *str, int len, int *read_len) {
    return bm1794_parse_respond_len(str, len, read_len);
}

static inline int platform_pack_work_pkg(uint8_t *str) {
    return bm1794_pack_work_pkg(str);
}

#endif
