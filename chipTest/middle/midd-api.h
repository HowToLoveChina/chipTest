#ifndef _STDAPI_H_
#define _STDAPI_H_

#include "ringbuffer.h"
#include <stdint.h>

#define MAX_RECV_LEN_EACH_TIME        	200
#define MAX_NONCE_LEN                   2048

/* API for upper layer */
struct midd_api
{
    struct rt_ringbuffer bm_nonce_rb;
    struct rt_ringbuffer bm_reg_rb;
    struct rt_ringbuffer bm_pmonitor_rb;
	struct rt_ringbuffer bm_bist_rb;
	struct rt_ringbuffer bm_work_rb;

	uint8_t *rb_nonce;
	uint8_t *rb_pm;
	uint8_t *rb_reg;
	uint8_t *rb_bist;
	uint8_t *rb_work;

    int (*send_work)(uint8_t *str, uint32_t len);
    int (*recv_work)(uint8_t *str, uint32_t len);
    int (*recv_regdata)(uint8_t *str, uint32_t len);
    int (*recv_pmonitor)(uint8_t *str, uint32_t len);
	int (*recv_bist)(uint8_t *str, uint32_t len);
    int (*ioctl)(int fd, uint32_t oper_type, void *param);
	int (*ioctl_regtable)(uint32_t oper_type, void *param);
};

struct std_chain_info
{
	int fd;
	uint8_t chain_id;

	char devname[12];
	int bandrate;
	
	pthread_t p_dispatch;
	pthread_t p_send_work;
};


int start_send_work(void *param);
void stop_send_work(void *param);

int start_dispatch_packet(void *param);
void stop_dispatch_packet(void *param);

int midd_api_init();
void midd_api_exit();

#endif
