#ifndef __REG_SCAN_H__
#define __REG_SCAN_H__

#define REG_SCAN_NUM				100
#define REG_SCAN_READ_TOTAL_MS		3000
#define REG_SCAN_READ_INTEVAL_MS	100

struct reg_scan_item_t
{
	uint8_t chain_id;
	uint8_t chip_addr;
	uint8_t reg_addr;
	uint32_t reg_data;
	uint8_t age;
};

int add_reg_item(struct reg_scan_item_t item);
int read_reg_item(struct reg_scan_item_t *item);
void reg_scan_init();
void reg_scan_exit();
#endif
