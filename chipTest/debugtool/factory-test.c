#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include "midd-api.h"
#include "bitmain-chips.h"
#include "ioctl-type.h"
#include "reg-scan.h"
#include "platform-driver.h"
#include "platform-app.h"
#include "util.h"

pthread_t p_factory_test;
extern uint8_t g_test_header[140];
extern struct midd_api g_midd_api;
extern int quit_app;
struct std_chain_info g_chain[MAX_CHAIN_NUM];

static void usage()
{
	fprintf(stdout, "\n************Usage**************\n");
	fprintf(stdout, "a	-	send a assigned work\n");
	fprintf(stdout, "s	-	set a regisger\n");
	fprintf(stdout, "g	-	get a register\n");
	fprintf(stdout, "h	-	help info\n");
	fprintf(stdout, "*********************************\n");
}

void *factory_test_handle()
{
	int alive = 1;

	while (alive) 
	{
		char type[2] = {0};
		z_sleep(1);
		setbuf(stdin,NULL);
		printf("\nInput test paramter:");
		fscanf(stdin, "%s", type);

		switch (type[0]) {
		case 'a':
		{
			char header[280] = {0};
	
			printf("input [work]\n");
			scanf("%s", header);
			if (strlen(header) < 280)
			{
				printf("wrong header\n");
				break;
			}

			struct work_input work;
			work.sno_valid = 1;
			work.workid = 0;
			uint8_t work_bin[ZCASH_HEAD_LEN] = {0};
			hex2bin(work_bin, header, ZCASH_HEAD_LEN);
			memcpy(work.head, work_bin, ZCASH_HEAD_LEN);
			memcpy(g_test_header, work_bin, ZCASH_HEAD_LEN);
			g_midd_api.send_work((uint8_t *)&work, sizeof(work));
			break;
		}
		case 's':
		{
			uint32_t addr;
			uint32_t data;
			struct base_type_t item;
			
			printf("read reg: input reg [address data]\n");
			scanf("%x %x", &addr, &data);

			item.all = 1;
			item.chip_addr = 0;
			item.addr = addr;
			item.data = data;
			g_midd_api.ioctl(g_chain[0].fd, IOCTL_SET_REG, &item);
			break;
		}
		case 'g':
		{
			uint32_t addr;
			struct reg_scan_item_t reg;
			
			printf("write reg: input reg [address]\n");

			scanf("%x", &addr);
			struct base_type_t item;
			item.all = 1;
			item.chip_addr = 0x00;
			item.addr = addr;
			g_midd_api.ioctl(g_chain[0].fd, IOCTL_GET_REG, &item);

			reg.chain_id = 0;
			reg.chip_addr = 0;
			reg.reg_addr = addr;
			read_reg_item(&reg);
			printf("Reg Value=%08x\n", reg.reg_data);
			break;
		}
		case 'q':
			alive = 0;
			quit_app = 1;
			break;
		case 'h':
			usage();
			break;
		default:
			printf("unknow command\n");
			break;
		}
	}

	return NULL;
}

int factory_test_init()
{
    if(0 != pthread_create(&p_factory_test, NULL, factory_test_handle, NULL))
    {
       printf("%s create thread failed\n", __func__);
       return -1;
    }

	return 0;
}

void factory_test_exit()
{
	pthread_cancel(p_factory_test);
}
