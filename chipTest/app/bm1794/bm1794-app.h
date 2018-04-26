#ifndef _BM1794_APP_H_
#define _BM1794_APP_H_
#include "stdint.h"
#include <pthread.h>
#include "param.h"
#include "sha256.h"

#define MAX_CHAIN_NUM 1

struct err_info
{
    int dup_error;
    int xor_error;
    int ticket_mask_error;
};

struct bm1794_reg_info
{
	int txok_en;
};

struct zcash_work_info
{
    uint8_t target[SHA256_DIGEST_SIZE];
    char    job_id[256];
    uint8_t header[ZCASH_BLOCK_HEADER_LEN];
    size_t  fixed_nonce_bytes;
};

struct bm1794_app
{
    int is_alive;

    pthread_mutex_t work_info_mutex;
    struct zcash_work_info work_info;

    struct err_info err_counts;

    pthread_t p_get_nonce_back;
    pthread_t p_get_reg_back;
    pthread_t p_get_pm_monitor;
    pthread_t p_mining_mode;
};

int open_tty_dev(void *param);

int bm1794_app_init();
void bm1794_app_exit();

#endif
