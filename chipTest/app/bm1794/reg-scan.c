#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "reg-scan.h"
#include "util.h"

static struct reg_scan_item_t reg_scan_items[REG_SCAN_NUM];
static pthread_mutex_t reg_scan_mutex;
static pthread_t p_reg_scan;

int add_reg_item(struct reg_scan_item_t item)
{
	int ret = -1;

	pthread_mutex_lock(&reg_scan_mutex);

	for(int i=0; i<REG_SCAN_NUM; i++)
	{
		if (reg_scan_items[i].age <= 0)
		{
			reg_scan_items[i] = item;
			fprintf(stdout, "ADD: chainid=0x%02x chipid=0x%02x regaddr=0x%06x regdata=0x%08x age=%d\n", \
				item.chain_id, item.chip_addr, item.reg_addr, item.reg_data, item.age);
			ret = 1;
			break;
		}
	}

	pthread_mutex_unlock(&reg_scan_mutex);

	return ret;
}

//int read_reg_item(struct reg_scan_item_t *read_item)
int read_reg_item(struct reg_scan_item_t *item)
{
	int ret = -1;

	pthread_mutex_lock(&reg_scan_mutex);
	for(int i=0; i<REG_SCAN_NUM; i++)
	{
		if (reg_scan_items[i].chain_id == item->chain_id &&
			reg_scan_items[i].chip_addr == item->chip_addr &&
			reg_scan_items[i].reg_addr == item->reg_addr)
		{
			reg_scan_items[i].age = 0;
			item->reg_data = reg_scan_items[i].reg_data;
			ret = 1;
			break;
		}
	}
	pthread_mutex_unlock(&reg_scan_mutex);

	return ret;
}

static void *reg_scan_aging()
{
	while(1)
	{
		z_sleep(1);

		pthread_mutex_lock(&reg_scan_mutex);

		for (int i=0; i<REG_SCAN_NUM; i++)
		{
			if (reg_scan_items[i].age > 0)
			{
				reg_scan_items[i].age --;
				fprintf(stdout, "chainid=%02x chipid=%02x regaddr=%02x regdata=%02x age=%d\n", \
					reg_scan_items[i].chain_id, reg_scan_items[i].chip_addr, reg_scan_items[i].reg_addr, reg_scan_items[i].reg_data, reg_scan_items[i].age);
			}
		}

		pthread_mutex_unlock(&reg_scan_mutex);
	}

	return NULL;
}

void reg_scan_init()
{
	memset(reg_scan_items, 0, sizeof(struct reg_scan_item_t) * REG_SCAN_NUM);
	pthread_mutex_init(&reg_scan_mutex, NULL);

	int err = pthread_create(&p_reg_scan, NULL, reg_scan_aging, NULL);
	if (err != 0)
	{
		fprintf(stderr, "create pthread failed\n");
	}
	pthread_detach(p_reg_scan);
}

void reg_scan_exit()
{
	pthread_cancel(p_reg_scan);
	pthread_join(p_reg_scan, NULL);
	pthread_mutex_destroy(&reg_scan_mutex);
}

void input_parse(int mode, struct reg_scan_item_t *new_item)
{
	uint32_t tmp;

	fprintf(stdout, "input chainid\n");
	scanf("%x", &tmp);
	new_item->chain_id = (uint8_t)tmp;

	fprintf(stdout, "input chipid\n");
	scanf("%x", &tmp);
	new_item->chip_addr = (uint8_t)tmp;

	fprintf(stdout, "input regaddr\n");
	scanf("%x", &tmp);
	new_item->reg_addr = (uint8_t)tmp;

	if (mode == 1)
	{
		fprintf(stdout, "input reg_data\n");
		scanf("%x", &tmp);
		new_item->reg_data = (uint8_t)tmp;

		fprintf(stdout, "input age\n");
		scanf("%d", &tmp);
		new_item->age = (uint8_t)tmp;
	}

}

int reg_scan_test()
{
	reg_scan_init();

	while(1)
	{
		char ch = getchar();
		fflush(stdin);

		switch(ch)
		{
			case '1':
			{
				struct reg_scan_item_t new_item;
				input_parse(1, &new_item);
				add_reg_item(new_item);
				break;
			}
			case '2':
			{
				struct reg_scan_item_t new_item;
				input_parse(2, &new_item);
				if (read_reg_item(&new_item) < 0) {
					printf("timeout error\n");
				} else {
					fprintf(stdout, "Reg Data = %02x\n", new_item.reg_data);
				}
				break;
			}
			default:
				break;
		}
	}
}
