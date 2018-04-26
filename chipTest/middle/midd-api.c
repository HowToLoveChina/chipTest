#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "midd-api.h"
#include "logging.h"
#include "util.h"
#include "ringbuffer.h"
#include "chip-api.h"
#include "comm-api.h"

struct midd_api  g_midd_api;
extern struct chip_api g_chip_api;
extern struct comm_api g_comm_api;

static int midd_send_work_to_rb(uint8_t *str, uint32_t len)
{
	return rt_ringbuffer_put(&g_midd_api.bm_work_rb, str, len);
}

static int midd_recv_work(uint8_t *str, uint32_t len)
{
    if (g_midd_api.bm_nonce_rb.block_flag == BLOCK_TYPE) {
        return rt_ringbuffer_get(&g_midd_api.bm_nonce_rb, str, len);
    } else {
        uint32_t rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_nonce_rb);
        if (rb_len < len) {
            return rb_len;
        }

        return rt_ringbuffer_get(&g_midd_api.bm_nonce_rb, str, len);
    }
}

static int midd_recv_regdata(uint8_t *str, uint32_t len)
{
    if (g_midd_api.bm_reg_rb.block_flag == BLOCK_TYPE) {
        return  rt_ringbuffer_get(&g_midd_api.bm_reg_rb, str, len);
    } else {
        uint32_t rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_reg_rb);
        if (rb_len < len) {
            return rb_len;
        }

        return  rt_ringbuffer_get(&g_midd_api.bm_reg_rb, str, len);
    }
}

static int midd_recv_pmonitor(uint8_t *str, uint32_t len)
{
    if (g_midd_api.bm_reg_rb.block_flag == BLOCK_TYPE) {
        return  rt_ringbuffer_get(&g_midd_api.bm_pmonitor_rb, str, len);
    } else {
        uint32_t rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_pmonitor_rb);
        if (rb_len < len) {
            return rb_len;
        }

        return  rt_ringbuffer_get(&g_midd_api.bm_pmonitor_rb, str, len);
    }
}

/* 
    mode is used for get mode. if mode=0, get from chip, else get from reg-table
*/
static int midd_ioctl(int fd, uint32_t oper_type, void *param)
{
    uint8_t str[256] = {0};
    int len = g_chip_api.pack_ioctl_pkg(str, 256, oper_type, param);
	if (len < 0)
		return len;
    return g_comm_api.bm_send(fd, str, len);
}

static int midd_ioctl_regtable(uint32_t oper_type, void *param)
{
    return g_chip_api.ioctl_regtable(oper_type, param);
}

static void *midd_dispatch_packet(void *param)
{
    uint8_t rev_buf[MAX_RECV_LEN_EACH_TIME] = {0};
    uint8_t complete_pkg[MAX_RECV_LEN_EACH_TIME] = {0};
    uint8_t *p_complete_pkg = complete_pkg;
    uint8_t out_str[MAX_NONCE_LEN] = {0};
	struct std_chain_info *chain = (struct std_chain_info *)param;
    int out_len = 0;
    int rsp_type = 0;
    int read_bytes = 1;
    int next_bytes = 1;
    int parse_stage = 0;
	
	pthread_detach(pthread_self());

    while(1)
    {
		z_msleep(20);
        int len = g_comm_api.bm_recv(chain->fd, rev_buf, read_bytes);
		if (len != read_bytes)
			continue;

        parse_stage = g_chip_api.parse_respond_len(rev_buf, read_bytes, &next_bytes);

        if (parse_stage == PKG_PARSE_IDLE_STATE) {
            read_bytes = 1;
            p_complete_pkg = complete_pkg;
            continue;
        } else if (parse_stage == PKG_PARSE_MIDDLE_STATE) {
            memcpy(p_complete_pkg, rev_buf, read_bytes);
            p_complete_pkg += read_bytes;
            read_bytes = next_bytes;
        } else {
            memcpy(p_complete_pkg, rev_buf, read_bytes);
            p_complete_pkg += read_bytes;

            out_len = g_chip_api.parse_respond_pkg(complete_pkg, p_complete_pkg-complete_pkg, &rsp_type, out_str, MAX_NONCE_LEN);
            if (out_len > 0) {
				//Add chain-id
				out_str[out_len] = chain->chain_id;
				out_len += 1;

                switch (rsp_type)
                {
                    case NONCE_RESPOND:
                        rt_ringbuffer_put(&g_midd_api.bm_nonce_rb, out_str, out_len);
                        break;
                    case REGISTER_RESPOND:
                        rt_ringbuffer_put(&g_midd_api.bm_reg_rb, out_str, out_len);
                        break;
                    case PMONITOR_RESPOND:
                        rt_ringbuffer_put(&g_midd_api.bm_pmonitor_rb, out_str, out_len);
						break;
					case BIST_RESPOND:
						rt_ringbuffer_put(&g_midd_api.bm_bist_rb, out_str, out_len);
						break;
                    default:
                        applog(LOG_WARNING, "unknow receive type %d\n", rsp_type);
                        break;
                }
            }

            p_complete_pkg = complete_pkg;
            read_bytes = 1;
        }
    }

    return NULL;
}


int start_dispatch_packet(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	if (0 != pthread_create(&chain->p_dispatch, NULL, midd_dispatch_packet, param))
	{
		printf("create p_dispatch failed\n");
		return -1;
	}

	return 0;
}

void stop_dispatch_packet(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	pthread_cancel(chain->p_dispatch);
}

static void *midd_send_work(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	uint8_t *str = (uint8_t *)malloc(g_chip_api.chip.work_len);
	if (str == NULL) {
		printf("%s malloc failed\n", __func__);
		exit(1);
	}

	pthread_detach(pthread_self());

	while(1)
	{
		rt_ringbuffer_get(&g_midd_api.bm_work_rb, str, g_chip_api.chip.work_len);
		g_chip_api.pack_work_pkg(str);
		g_comm_api.bm_send(chain->fd, str, g_chip_api.chip.work_len);
	}

	free(str);
	return NULL;
}

int start_send_work(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	if (0 != pthread_create(&chain->p_send_work, NULL, midd_send_work, param))
	{
		printf("create p_dispatch failed\n");
		return -1;
	}

	return 0;
}

void stop_send_work(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	pthread_cancel(chain->p_send_work);
}

int midd_api_init()
{
    g_midd_api.send_work        = midd_send_work_to_rb;
    g_midd_api.recv_work        = midd_recv_work;
    g_midd_api.recv_regdata     = midd_recv_regdata;
    g_midd_api.recv_pmonitor    = midd_recv_pmonitor;
    g_midd_api.ioctl            = midd_ioctl;
	g_midd_api.ioctl_regtable	= midd_ioctl_regtable;

	g_midd_api.rb_nonce	= (uint8_t *)malloc(100 * 16 * g_chip_api.chip.nonce_len);
	g_midd_api.rb_pm 	= (uint8_t *)malloc(100 * g_chip_api.chip.pm_len);
	g_midd_api.rb_reg 	= (uint8_t *)malloc(100 * g_chip_api.chip.reg_len);
	g_midd_api.rb_bist 	= (uint8_t *)malloc(100 * g_chip_api.chip.bist_len);	
	g_midd_api.rb_work 	= (uint8_t *)malloc(100 * g_chip_api.chip.work_len);
	if (g_midd_api.rb_nonce == NULL || 
		g_midd_api.rb_pm == NULL || 
		g_midd_api.rb_reg == NULL || 
		g_midd_api.rb_bist == NULL || 
		g_midd_api.rb_work == NULL) {
		printf("%s malloc failed\n", __func__);
		exit(1);
	}	
	memset(g_midd_api.rb_nonce, 0, 100 * 16 * g_chip_api.chip.nonce_len);
	memset(g_midd_api.rb_pm, 0, 100 * g_chip_api.chip.pm_len);
	memset(g_midd_api.rb_reg, 0, 100 * g_chip_api.chip.reg_len);
	memset(g_midd_api.rb_bist, 0, 100 * g_chip_api.chip.bist_len);	
	memset(g_midd_api.rb_work, 0, 100 * g_chip_api.chip.work_len);

	
    rt_ringbuffer_init(&g_midd_api.bm_nonce_rb, g_midd_api.rb_nonce, 100 * 16 * g_chip_api.chip.nonce_len, BLOCK_TYPE);
    rt_ringbuffer_init(&g_midd_api.bm_reg_rb, g_midd_api.rb_reg, 100 * g_chip_api.chip.reg_len, BLOCK_TYPE);
    rt_ringbuffer_init(&g_midd_api.bm_pmonitor_rb, g_midd_api.rb_pm, 100 * g_chip_api.chip.pm_len, BLOCK_TYPE);
	rt_ringbuffer_init(&g_midd_api.bm_bist_rb, g_midd_api.rb_bist, 100 * g_chip_api.chip.bist_len, BLOCK_TYPE);
	rt_ringbuffer_init(&g_midd_api.bm_work_rb, g_midd_api.rb_work, 100 * g_chip_api.chip.work_len, BLOCK_TYPE);
	return 0;
}

void midd_api_exit()
{
    rt_ringbuffer_lock_destory(&g_midd_api.bm_nonce_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_reg_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_pmonitor_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_bist_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_work_rb);

	free(g_midd_api.rb_nonce);
	free(g_midd_api.rb_pm);
	free(g_midd_api.rb_reg);
	free(g_midd_api.rb_bist);
	free(g_midd_api.rb_work);
}
