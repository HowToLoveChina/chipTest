#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "platform-driver.h"
#include "util.h"
#include "crc.h"
#include "logging.h"
#include "chip-api.h"
#include "ioctl-type.h"

pthread_mutex_t g_reg_table_mutex = PTHREAD_MUTEX_INITIALIZER;
struct bm1794_realtime_reg_table g_reg_table;

/*************only for test begin**************/
int g_crc16_err_enable;
int g_crc5_err_enable;
/*************only for test end**************/



/*************Depends function**************/
struct baud_BT8D_value {
	uint32_t baud;
	uint8_t bt8d;
	int divider_value;
};

static struct baud_BT8D_value baud_BT8D_values[] = {
	{ 115200, 26,216 },
	{ 460800, 6, 56 },
	{ 921600, 2, 24 },
	{ 1500000,1, 16 },
	{ 3000000,0,  8 },
};

static uint8_t get_bt8d_from_baud(const uint32_t baud)
{
	size_t index;
	size_t max = sizeof(baud_BT8D_values)/sizeof(struct baud_BT8D_value);
	for (index = 0; index < max; ++index) {
		if (baud == baud_BT8D_values[index].baud) {
			printf("get bt8d %d\n",baud_BT8D_values[index].bt8d);
			return baud_BT8D_values[index].bt8d;
		}
	}
	if (index == max) {
		printf("get bt8d value failed!!!,use default to continue\n");
		return get_bt8d_from_baud(BMSC_DEFAULT_BAUD);
	}

	return -1;
}

/************* Base Function to Makeup Packets**************/
int bm1794_pack_work_pkg(uint8_t *str)
{
    struct work_input *work = (struct work_input *)str;

    work->type = 0x01;
    work->header_55 = BM1794_HEADER_55;
    work->header_aa = BM1794_HEADER_AA;

    uint16_t crc16 = CRC16(&str[2], BM1794_WORK_LEN - BM1794_HEADER_LEN - BM1794_CRC16_LEN);
    work->crc16 = bswap_16(crc16);
    if (g_crc16_err_enable){
        printf("true crc16 = %x\n", work->crc16);
        work->crc16 += 1;
    }

    return sizeof(struct work_input);
}

/*
    Set Address Format :
    Byte0	                Byte1	    Byte2	Byte3	    Byte4
    7:5	    4	    3:0	    7:0	        7:0	    7:0	        7:5	        4:0
    TYPE=2	ALL=0	CMD	    Length=5	ADDR	Reserved	Reserved	CRC5
*/
static int bm1794_makeup_set_address_cmd(uint8_t *str, uint32_t str_len, uint8_t chip_addr)
{
    struct set_address_cmd_t set_address_cmd;

    if (str_len < (sizeof(set_address_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(set_address_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&set_address_cmd, 0, sizeof(set_address_cmd));
    set_address_cmd.type = COMMAND_INPUT;
    set_address_cmd.all = CMD_SINGLE_CHIP;
    set_address_cmd.cmd = CMD_SET_ADDRESS;
    set_address_cmd.length = INPUT_CMD_LEN_5;
    set_address_cmd.chip_addr = chip_addr;
    set_address_cmd.crc5 = CRC5((uint8_t *)&set_address_cmd, (INPUT_CMD_LEN_5 - 1)*8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&set_address_cmd, sizeof(set_address_cmd));

    return (sizeof(set_address_cmd) + BM1794_HEADER_LEN);
}

/*
    Set Config Format :
    Byte0	            Byte1	    Byte2	Byte3	    Byte4~7	        Byte8
    7:5	    4	3:0	    7:0	        7:0	    7:0		                    7:5	        4:0
    TYPE=2	ALL	CMD	    Length=9	ADDR	REGADDR	    REGDATA6a	    Reserved	CRC5
*/
static int bm1794_makeup_set_config_cmd(uint8_t *str, uint32_t str_len, 
                        uint8_t all, uint8_t all_core, uint8_t chip_addr, 
                        uint32_t regaddr, uint32_t regdata)
{
    struct set_config_cmd_t set_config_cmd;

    if (str_len < (sizeof(struct set_config_cmd_t) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(set_config_cmd) + BM1794_HEADER_LEN));
        return -1;  
    }

    memset(&set_config_cmd, 0, sizeof(set_config_cmd));
    set_config_cmd.type = COMMAND_INPUT;
    set_config_cmd.all = all;
    set_config_cmd.all_core = all_core;
    set_config_cmd.cmd = CMD_SET_CONFIG;
    set_config_cmd.length = INPUT_CMD_LEN_11;
    set_config_cmd.chip_addr = chip_addr;
    set_config_cmd.regaddr[0] = regaddr;
    set_config_cmd.regaddr[1] = regaddr >> 8;
    set_config_cmd.regaddr[2] = regaddr >> 16;
    set_config_cmd.regdata = regdata;
    //uint32_t swap_reg = bswap_32(regdata);
    //memcpy(set_config_cmd.regdata, (uint8_t *)&swap_reg, 4);
    set_config_cmd.crc5 = CRC5((uint8_t *)&set_config_cmd, (INPUT_CMD_LEN_11 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], &set_config_cmd, sizeof(struct set_config_cmd_t));

    return (sizeof(set_config_cmd) + BM1794_HEADER_LEN);
}

/*
    Get Status Format :
    Byte0	            Byte1	    Byte2	Byte3	    Byte4
    7:5	    4	3:0	    7:0	        7:0	    7:0	        7:5	        4:0
    TYPE=2	ALL	CMD	    Length=0x5	ADDR	REGADDR	    Reserved	CRC5
*/
static int bm1794_makeup_get_status_cmd(uint8_t *str, uint32_t str_len, uint8_t all, uint8_t chip_addr, uint32_t regaddr)
{
    struct get_status_cmd_t get_status_cmd;

    if (str_len < (sizeof(get_status_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(get_status_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&get_status_cmd, 0, sizeof(get_status_cmd));
    get_status_cmd.type = COMMAND_INPUT;
    get_status_cmd.all = all;
    get_status_cmd.cmd = CMD_GET_STATUS;
    get_status_cmd.length = INPUT_CMD_LEN_7;
    get_status_cmd.chip_addr = chip_addr;
    get_status_cmd.regaddr[0] = regaddr;
    get_status_cmd.regaddr[1] = regaddr >> 8;
    get_status_cmd.regaddr[2] = regaddr >> 16;
    get_status_cmd.crc5 = CRC5((uint8_t *)&get_status_cmd, (INPUT_CMD_LEN_7 - 1) * 8);

	if (g_crc5_err_enable){
		printf("true crc5 = %x\n", get_status_cmd.crc5);
		get_status_cmd.crc5 += 1;
	}

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&get_status_cmd, sizeof(get_status_cmd));

    return (sizeof(get_status_cmd) + BM1794_HEADER_LEN);
}

/*
    Chain Inactive Format    
    Byte0	                Byte1	    Byte2	    Byte3	    Byte4
    7:5	    4	    3:0	    7:0	        7:0	        7:0	        7:5	        4:0
    TYPE=2	ALL=1	CMD	    Length=5	Reserved	Reserved	Reserved	CRC5
*/
static int bm1794_makeup_chain_inactive_cmd(uint8_t *str, uint32_t str_len)
{
    struct chain_inactive_cmd_t chain_inactive_cmd;

    if (str_len < (sizeof(chain_inactive_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(chain_inactive_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&chain_inactive_cmd, 0, sizeof(chain_inactive_cmd));
    chain_inactive_cmd.type = COMMAND_INPUT;
    chain_inactive_cmd.all = CMD_ALL_CHIP;
    chain_inactive_cmd.cmd = CMD_CHAIN_INACTIVE;
    chain_inactive_cmd.length = INPUT_CMD_LEN_5;
    chain_inactive_cmd.crc5 = CRC5((uint8_t *)&chain_inactive_cmd, (INPUT_CMD_LEN_5 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&chain_inactive_cmd, sizeof(chain_inactive_cmd));

    return (sizeof(chain_inactive_cmd) + BM1794_HEADER_LEN);
}

/*
    Bist Setup
    Byte0	                    Byte1	    Byte2	    Byte3	    Byte4
    7:5	    4       3:0	        7:0	        7:0	        7:0	        7:5	        4:0
    TYPE=3	ALL	    4’h0	    Length=5	ChipAddr	Reserved	Reserved	CRC5
*/
static int bm1794_makeup_bist_setup_cmd(uint8_t all, uint8_t chip_addr, uint8_t *str, uint32_t str_len)
{
    struct bist_setup_cmd_t bist_setup_cmd;

    if (str_len < (sizeof(bist_setup_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(bist_setup_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&bist_setup_cmd, 0, sizeof(bist_setup_cmd));
    bist_setup_cmd.type = COMMAND_INPUT;
    bist_setup_cmd.all = all;
    bist_setup_cmd.cmd = BIST_SETUP;
    bist_setup_cmd.length = 5;
    bist_setup_cmd.chip_addr = chip_addr;
    bist_setup_cmd.crc5 = CRC5((uint8_t *)&bist_setup_cmd, (INPUT_CMD_LEN_5 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&bist_setup_cmd, sizeof(bist_setup_cmd));

    return (sizeof(bist_setup_cmd) + BM1794_HEADER_LEN);
}

/*
    Bist_write_wait
    Byte0	            Byte1	    Byte2	    Byte3- Byte8	Byte9	        Byte10
    7:5	    4	3:0	    7:0	        7:0	        7:0	            7:0	            7:5	        4:0
    TYPE=3	ALL	4’h1	Length=11	ChipAddr	WrData[47:0]	WriteRepeatNum	Reserved	CRC5
*/
static int bm1794_makeup_bist_write_wait_cmd(uint8_t all, uint8_t chip_addr, uint8_t *wr_data, uint8_t wr_repeat_num, uint8_t *str, uint32_t str_len)
{
    struct bist_write_wait_cmd_t bist_write_wait_cmd;

    if (str_len < (sizeof(bist_write_wait_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(bist_write_wait_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&bist_write_wait_cmd, 0, sizeof(bist_write_wait_cmd));
    bist_write_wait_cmd.type = BIST_INPUT;
    bist_write_wait_cmd.all = all;
    bist_write_wait_cmd.cmd = BIST_WRITE_WAIT;
    bist_write_wait_cmd.length = INPUT_BIST_LEN_11;
    bist_write_wait_cmd.chip_addr = chip_addr;
    memcpy(bist_write_wait_cmd.wr_data, wr_data, sizeof(bist_write_wait_cmd.wr_data));
    bist_write_wait_cmd.write_repeat_num = wr_repeat_num;
    bist_write_wait_cmd.crc5 = CRC5((uint8_t *)&bist_write_wait_cmd, (INPUT_BIST_LEN_11 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&bist_write_wait_cmd, sizeof(bist_write_wait_cmd));

    return (sizeof(bist_write_wait_cmd) + BM1794_HEADER_LEN);
}

/*
    Byte0	            Byte1	    Byte2	    Byte3- Byte8	Byte9	    Byte10
    7:5	    4	3:0	    7:0	        7:0	        7:0	            7:0	        7:5	        4:0
    TYPE=3	ALL	4’h2	Length=11	ChipAddr	WrData[47:0]	Reserved	Reserved	CRC5
*/
static int bm1794_makeup_bist_write_wait_read_cmd(uint8_t all, uint8_t chip_addr, uint8_t *wr_data, uint8_t *str, uint32_t str_len)
{
    struct bist_write_wait_read_cmd_t bist_write_wait_read_cmd;

    if (str_len < (sizeof(bist_write_wait_read_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(bist_write_wait_read_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&bist_write_wait_read_cmd, 0, sizeof(bist_write_wait_read_cmd));
    bist_write_wait_read_cmd.type = BIST_INPUT;
    bist_write_wait_read_cmd.all = all;
    bist_write_wait_read_cmd.cmd = BIST_WRITE_WAIT_READ;
    bist_write_wait_read_cmd.length = INPUT_BIST_LEN_11;
    bist_write_wait_read_cmd.chip_addr = chip_addr;
    memcpy(bist_write_wait_read_cmd.wr_data, wr_data, sizeof(bist_write_wait_read_cmd.wr_data));
    bist_write_wait_read_cmd.crc5 = CRC5((uint8_t *)&bist_write_wait_read_cmd, (INPUT_BIST_LEN_11 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&bist_write_wait_read_cmd, sizeof(bist_write_wait_read_cmd));

    return (sizeof(bist_write_wait_read_cmd) + BM1794_HEADER_LEN);
}

/*
    Byte0	            Byte1	    Byte2	    Byte3- Byte7	    Byte8
    7:5	    4	3:0	    7:0	        7:0	        7:0	                7:5	        4:0
    TYPE=3	ALL	4’h3	Length=9	ChipAddr	WaitCycle [39:0]	Reserved	CRC5
*/
static int bm1794_makeup_bist_wait_cmd(uint8_t all, uint8_t chip_addr, uint8_t *wait_cycle, uint8_t *str, uint32_t str_len)
{
    struct bist_wait_cmd_t bist_wait_cmd;

    if (str_len < (sizeof(bist_wait_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(bist_wait_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&bist_wait_cmd, 0, sizeof(bist_wait_cmd));
    bist_wait_cmd.type = BIST_INPUT;
    bist_wait_cmd.all = all;
    bist_wait_cmd.cmd = BIST_WAIT;
    bist_wait_cmd.length = INPUT_BIST_LEN_9;
    bist_wait_cmd.chip_addr = chip_addr;
    memcpy(bist_wait_cmd.wait_cycle, wait_cycle, sizeof(bist_wait_cmd.wait_cycle));
    bist_wait_cmd.crc5 = CRC5((uint8_t *)&bist_wait_cmd, (INPUT_BIST_LEN_9 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&bist_wait_cmd, sizeof(bist_wait_cmd));

    return (sizeof(bist_wait_cmd) + BM1794_HEADER_LEN);
}

/*
    Byte0	            Byte1	    Byte2	    Byte3	    Byte4
    7:5	    4	3:0	    7:0	        7:0	        7:0	        7:5	        4:0
    TYPE=3	ALL	4’h4	Length=5	ChipAddr	Reserved	Reserved	CRC5
*/
static int bm1794_makeup_bist_read_cmd(uint8_t all, uint8_t chip_addr, uint8_t *str, uint32_t str_len)
{
    struct bist_read_cmd_t bist_read_cmd;

    if (str_len < (sizeof(bist_read_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(bist_read_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&bist_read_cmd, 0, sizeof(bist_read_cmd));
    bist_read_cmd.type = BIST_INPUT;
    bist_read_cmd.all = all;
    bist_read_cmd.cmd = BIST_READ;
    bist_read_cmd.length = INPUT_BIST_LEN_5;
    bist_read_cmd.chip_addr = chip_addr;
    bist_read_cmd.crc5 = CRC5((uint8_t *)&bist_read_cmd, (INPUT_BIST_LEN_5 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&bist_read_cmd, sizeof(bist_read_cmd));

    return (sizeof(bist_read_cmd) + BM1794_HEADER_LEN);
}

/*
    Byte0	                Byte1	    Byte2	    Byte3	    Byte4
    7:5	    4	    3:0	    7:0	        7:0	        7:0	        7:5	        4:0
    TYPE=3	ALL	    4’h5	Length=5	ChipAddr	Reserved	Reserved	CRC5
*/
static int bm1794_makeup_bist_disable_cmd(uint8_t all, uint8_t chip_addr, uint8_t *str, uint32_t str_len)
{
    struct bist_disable_cmd_t bist_disable_cmd;

    if (str_len < (sizeof(bist_disable_cmd) + BM1794_HEADER_LEN)) {
        applog(LOG_ERR, "%s input param error: str length = %u\n", __func__, (uint32_t)(sizeof(bist_disable_cmd) + BM1794_HEADER_LEN));
        return -1;
    }

    memset(&bist_disable_cmd, 0, sizeof(bist_disable_cmd));
    bist_disable_cmd.type = BIST_INPUT;
    bist_disable_cmd.all = all;
    bist_disable_cmd.cmd = BIST_DISABLE;
    bist_disable_cmd.length = INPUT_BIST_LEN_5;
    bist_disable_cmd.chip_addr = chip_addr;
    bist_disable_cmd.crc5 = CRC5((uint8_t *)&bist_disable_cmd, (INPUT_BIST_LEN_5 - 1) * 8);

    str[0] = BM1794_HEADER_55;
    str[1] = BM1794_HEADER_AA;
    memcpy(&str[2], (uint8_t *)&bist_disable_cmd, sizeof(bist_disable_cmd));

    return (sizeof(bist_disable_cmd) + BM1794_HEADER_LEN);
}

/**************Local Variable to Store Registers****************/
static void bm1794_set_reg_table(uint8_t reg_addr, uint32_t reg_data)
{
    pthread_mutex_lock(&g_reg_table_mutex);
    switch (reg_addr)
    {
        case REG_CHIP_ADDRESS:
            memcpy(&g_reg_table.chip_addr, &reg_data, 4);
            break;
        case REG_HASH_RATE:
            memcpy(&g_reg_table.hash_rate, &reg_data, 4);
            break;
        case REG_PLL_PARAMETER:
            memcpy(&g_reg_table.pll_parameter, &reg_data, 4);
            break;
        case REG_TICKET_MASK:
            memcpy(&g_reg_table.ticket_mask, &reg_data, 4);
            break;
        case REG_MISC_CONTROL:
            memcpy(&g_reg_table.misc_control, &reg_data, 4);
            break;
        case REG_GENERAL_I2C_COMMAND:
            memcpy(&g_reg_table.general_i2c_command, &reg_data, 4);
            break;
        case REG_NONCE_TX_OK:
            memcpy(&g_reg_table.nonce_tx_ok, &reg_data, 4);
            break;
        case REG_CORE_TIMEOUT:
            memcpy(&g_reg_table.core_timeout, &reg_data, 4);
            break;
        case REG_IO_DRIVE_STRENGTH:
            memcpy(&g_reg_table.io_drive_strength, &reg_data, 4);
            break;
        case REG_CHIP_STATUS:
            memcpy(&g_reg_table.chip_status, &reg_data, 4);
            break;
        case REG_TIME_OUT:
            memcpy(&g_reg_table.time_out, &reg_data, 4);
            break;
        case REG_PMONITOR_CTRL:
            memcpy(&g_reg_table.pmonitor_ctrl, &reg_data, 4);
            break;
        case REG_ANALOG_MUX_CONTROL:
            memcpy(&g_reg_table.analog_mux_control, &reg_data, 4);
            break;
        case REG_START_NONCE_OFFSET:
            memcpy(&g_reg_table.start_nonce_offset, &reg_data, 4);
            break;
        case REG_TXN_DATA:
            memcpy(&g_reg_table.txn_data, &reg_data, 4);
            break;
        default:
            fprintf(stderr, "error: %s unknow reg type\n", __func__);
            break;
    }

    pthread_mutex_unlock(&g_reg_table_mutex);
}

static void bm1794_get_reg_table(uint8_t reg_addr, uint32_t *reg_bin)
{
    pthread_mutex_lock(&g_reg_table_mutex);
    switch (reg_addr)
    {
        case REG_CHIP_ADDRESS:
            memcpy(reg_bin, &g_reg_table.chip_addr, 4);
            break;
        case REG_HASH_RATE:
            memcpy(reg_bin, &g_reg_table.hash_rate, 4);
            break;
        case REG_PLL_PARAMETER:
            memcpy(reg_bin, &g_reg_table.pll_parameter, 4);
            break;
        case REG_TICKET_MASK:
            memcpy(reg_bin, &g_reg_table.ticket_mask, 4);
            break;
        case REG_MISC_CONTROL:
            memcpy(reg_bin, &g_reg_table.misc_control, 4);
            break;
        case REG_GENERAL_I2C_COMMAND:
            memcpy(reg_bin, &g_reg_table.general_i2c_command, 4);
            break;
        case REG_NONCE_TX_OK:
            memcpy(reg_bin, &g_reg_table.nonce_tx_ok, 4);
            break;
        case REG_CORE_TIMEOUT:
            memcpy(reg_bin, &g_reg_table.core_timeout, 4);
            break;
        case REG_IO_DRIVE_STRENGTH:
            memcpy(reg_bin, &g_reg_table.io_drive_strength, 4);
            break;
        case REG_CHIP_STATUS:
            memcpy(reg_bin, &g_reg_table.chip_status, 4);
            break;
        case REG_TIME_OUT:
            memcpy(reg_bin, &g_reg_table.time_out, 4);
            break;
        case REG_PMONITOR_CTRL:
            memcpy(reg_bin, &g_reg_table.pmonitor_ctrl, 4);
            break;
        case REG_ANALOG_MUX_CONTROL:
            memcpy(reg_bin, &g_reg_table.analog_mux_control, 4);
            break;
        case REG_START_NONCE_OFFSET:
            memcpy(reg_bin, &g_reg_table.start_nonce_offset, 4);
            break;
        case REG_TXN_DATA:
            memcpy(reg_bin, &g_reg_table.txn_data, 4);
            break;
        default:
            fprintf(stderr, "error: %s unknow reg type\n", __func__);
            break;
    }

    pthread_mutex_unlock(&g_reg_table_mutex);
}

static int bm1794_parse_nonce_respond(uint8_t *str, uint32_t str_len, uint8_t *out_str, uint32_t out_len)
{
    if (str_len != BM1794_RESP_NONCE_LEN || out_len < str_len) {
        applog(LOG_ERR, "%s input str len error, input len=%d\n", __func__, str_len);
        return -1;
    }

	memcpy(out_str, str, str_len);
    return BM1794_RESP_NONCE_LEN;
}

static int bm1794_parse_reg_respond(uint8_t *str, uint32_t str_len, uint8_t *out_str, uint32_t out_len)
{
    uint8_t crc5 = 0;
    struct reg_respond *reg_resp = (struct reg_respond *)str;

    if (str_len != BM1794_RESP_REG_LEN || out_len < BM1794_RESP_REG_LEN) {
        applog(LOG_ERR, "%s length error\n", __func__);
        return -1;
    }

    crc5 = CRC5(&str[2], 6 * 8 + 3);
    if (crc5 != reg_resp->crc5) {
        applog(LOG_ERR, "%s CRC error crc = %02x\n", __func__, crc5);
        return -1;
    }

    memcpy(out_str, str, str_len);
    return str_len;
}

static int bm1794_parse_pmonitor_respond(uint8_t *str, uint32_t str_len, uint8_t *out_str, uint32_t out_len)
{
    struct pmonitor_respond *pmonitor_resp = (struct pmonitor_respond *)str;

    if (str_len != BM1794_RESP_PM_LEN || out_len < BM1794_RESP_PM_LEN) {
        applog(LOG_ERR, "%s length error\n", __func__);
        return -1;
    }

	uint8_t crc5 = CRC5(&str[2], 6*8 + 3);
    if (crc5 != pmonitor_resp->crc5) {
        applog(LOG_ERR, "%s CRC error. cal-crc=%x, chip-crc=%x\n", __func__, crc5, pmonitor_resp->crc5);
        return -1;
    }

    memcpy(out_str, &str, str_len);

    return str_len;
}
static int bm1794_parse_bist_respond(uint8_t *str, uint32_t str_len, uint8_t *out_str, uint32_t out_len)
{
    struct bist_respond *bist_resp = (struct bist_respond *)str;

    if (str_len != BM1794_RESP_BIST_LEN || out_len < BM1794_RESP_BIST_LEN) {
        applog(LOG_ERR, "%s length error\n", __func__);
        return -1;
    }

	uint8_t crc5 = CRC5(&str[2], 8 * 8 + 3);
    if (crc5 != bist_resp->crc5) {
        applog(LOG_ERR, "%s CRC error. cal-crc=%x, chip-crc=%x\n", __func__, crc5, bist_resp->crc5);
        return -1;
    }

    memcpy(out_str, &str, str_len);
    return str_len;
}

/*
    Parse response string from UART
*/
int bm1794_parse_respond_len(uint8_t *str, int len, int *read_len)
{
    static int state = SEARCH_0XAA;
    int ret = PKG_PARSE_IDLE_STATE;
    
    switch(state)
    {
        case SEARCH_0XAA:
            if (len > 0 && str[0] == BM1794_HEADER_AA) {
                state = SEARCH_0X55;
                ret = PKG_PARSE_MIDDLE_STATE;
            } else {
                ret = PKG_PARSE_IDLE_STATE;
            }
            *read_len = 1;
            break;
        case SEARCH_0X55:
            if (len > 0 && str[0] == BM1794_HEADER_55) {
                state = SEARCH_PKG_TYPE;
                ret = PKG_PARSE_MIDDLE_STATE;
            } else {
                state = SEARCH_0XAA;
                ret = PKG_PARSE_IDLE_STATE;
            }
            *read_len = 1;
            break;
        case SEARCH_PKG_TYPE:
            if (len > 0) {
                if ((str[0] & 0xf0) == 0xe0) {
                    *read_len = BM1794_RESP_NONCE_LEN - BM1794_HEADER_LEN - 1;
                } else if (str[0] == 0xcc) {
                    *read_len = BM1794_RESP_PM_LEN - BM1794_HEADER_LEN - 1;
                } else {
                    *read_len = BM1794_RESP_REG_LEN -BM1794_HEADER_LEN - 1;
                }
                ret = PKG_PARSE_MIDDLE_STATE;
                state = SEARCH_PKG_BODY;
            } else {
                *read_len = 1;  
                ret = PKG_PARSE_IDLE_STATE;
                state = SEARCH_0XAA;
            }
            break;
        case SEARCH_PKG_BODY:
            ret = PKG_PARSE_FINISHED_STATE;
            *read_len = 1;
            state = SEARCH_0XAA;
            break;
        default:
            ret = PKG_PARSE_IDLE_STATE;
            *read_len = 1;
            state = SEARCH_0XAA;
            break;
    }

    return ret;
}

/*
    <param>
    str: input string, 0xaa55 ...
    len:  str length
    out_str: return the checked packet
    out_len: length of the checked packet

    <return>
    type of respond
*/
int bm1794_parse_respond_pkg(uint8_t *str, int len, int *type, uint8_t *out_str, uint32_t out_len)
{
    int ret_len = 0;

    if ((str[2] & 0xf0) == 0xe0) {
        *type = NONCE_RESPOND;
		ret_len = bm1794_parse_nonce_respond(str, len, out_str,out_len);
    } else if (str[2] == 0xcc) {
        *type = PMONITOR_RESPOND;
		ret_len = bm1794_parse_pmonitor_respond(str, len, out_str, out_len);
    } else if (str[2] == 0xbb){
		*type = BIST_RESPOND;
		ret_len = bm1794_parse_bist_respond(str, len, out_str, out_len);
	}else if (str[2] < 0x80){
        *type = REGISTER_RESPOND;
		ret_len = bm1794_parse_reg_respond(str, len, out_str, out_len);
    } else {
        *type = UNKNOW_RESPOND;
        applog(LOG_ERR, "%s unknow respond type %02x\n", __func__, str[2]);
        return -1;
    }

    return ret_len;
}

static struct freq_pll_str freq_pll[] =
{
        {100, 0x020040, 0x0420, 0x200241},
        {125, 0x028040, 0x0420, 0x280241},
        {150, 0x030040, 0x0420, 0x300241},
        {175, 0x038040, 0x0420, 0x380241},
        {200, 0x040040, 0x0420, 0x400241},
        {225, 0x048040, 0x0420, 0x480241},
        {250, 0x050040, 0x0420, 0x500241},
        {275, 0x058040, 0x0420, 0x580241},
        {300, 0x060040, 0x0420, 0x600241},
        {325, 0x068040, 0x0420, 0x680241},
        {350, 0x070040, 0x0420, 0x700241},
        {375, 0x078040, 0x0420, 0x780241},
        {400, 0x080040, 0x0420, 0x800241},
        {404, 0x061040, 0x0320, 0x610231},
        {406, 0x041040, 0x0220, 0x410221},
        {408, 0x062040, 0x0320, 0x620231},
        {412, 0x042040, 0x0220, 0x420221},
        {416, 0x064040, 0x0320, 0x640231},
        {418, 0x043040, 0x0220, 0x430221},
        {420, 0x065040, 0x0320, 0x650231},
        {425, 0x044040, 0x0220, 0x440221},
        {429, 0x067040, 0x0320, 0x670231},
        {431, 0x045040, 0x0220, 0x450221},
        {433, 0x068040, 0x0320, 0x680231},
        {437, 0x046040, 0x0220, 0x460221},
        {441, 0x06a040, 0x0320, 0x6a0231},
        {443, 0x047040, 0x0220, 0x470221},
        {445, 0x06b040, 0x0320, 0x6b0231},
        {450, 0x048040, 0x0220, 0x480221},
        {454, 0x06d040, 0x0320, 0x6d0231},
        {456, 0x049040, 0x0220, 0x490221},
        {458, 0x06e040, 0x0320, 0x6e0231},
        {462, 0x04a040, 0x0220, 0x4a0221},
        {466, 0x070040, 0x0320, 0x700231},
        {468, 0x04b040, 0x0220, 0x4b0221},
        {470, 0x071040, 0x0320, 0x710231},
        {475, 0x04c040, 0x0220, 0x4c0221},
        {479, 0x073040, 0x0320, 0x730231},
        {481, 0x04d040, 0x0220, 0x4d0221},
        {483, 0x074040, 0x0320, 0x740231},
        {487, 0x04e040, 0x0220, 0x4e0221},
        {491, 0x076040, 0x0320, 0x760231},
        {493, 0x04f040, 0x0220, 0x4f0221},
        {495, 0x077040, 0x0320, 0x770231},
        {500, 0x050040, 0x0220, 0x500221},
        {504, 0x079040, 0x0320, 0x790231},
        {506, 0x051040, 0x0220, 0x510221},
        {508, 0x07a040, 0x0320, 0x7a0231},
        {512, 0x052040, 0x0220, 0x520221},
        {516, 0x07c040, 0x0320, 0x7c0231},
        {518, 0x053040, 0x0220, 0x530221},
        {520, 0x07d040, 0x0320, 0x7d0231},
        {525, 0x054040, 0x0220, 0x540221},
        {529, 0x07f040, 0x0320, 0x7f0231},
        {531, 0x055040, 0x0220, 0x550221},
        {533, 0x080040, 0x0320, 0x800231},
        {537, 0x056040, 0x0220, 0x560221},
        {543, 0x057040, 0x0220, 0x570221},
        {550, 0x058040, 0x0220, 0x580221},
        {556, 0x059040, 0x0220, 0x590221},
        {562, 0x05a040, 0x0220, 0x5a0221},
        {568, 0x05b040, 0x0220, 0x5b0221},
        {575, 0x05c040, 0x0220, 0x5c0221},
        {581, 0x05d040, 0x0220, 0x5d0221},
        {587, 0x05e040, 0x0220, 0x5e0221},
        {593, 0x05f040, 0x0220, 0x5f0221},
        {600, 0x060040, 0x0220, 0x600221},
        {606, 0x061040, 0x0220, 0x610221},
        {612, 0x062040, 0x0220, 0x620221},
        {618, 0x063040, 0x0220, 0x630221},
        {625, 0x064040, 0x0220, 0x640221},
        {631, 0x065040, 0x0220, 0x650221},
        {637, 0x066040, 0x0220, 0x660221},
        {643, 0x067040, 0x0220, 0x670221},
        {650, 0x068040, 0x0220, 0x680221},
        {656, 0x069040, 0x0220, 0x690221},
        {662, 0x06a040, 0x0220, 0x6a0221},
        {668, 0x06b040, 0x0220, 0x6b0221},
        {675, 0x06c040, 0x0220, 0x6c0221},
        {681, 0x06d040, 0x0220, 0x6d0221},
        {687, 0x06e040, 0x0220, 0x6e0221},
        {693, 0x06f040, 0x0220, 0x6f0221},
        {700, 0x070040, 0x0220, 0x700221},
        {706, 0x071040, 0x0220, 0x710221},
        {712, 0x072040, 0x0220, 0x720221},
        {718, 0x073040, 0x0220, 0x730221},
        {725, 0x074040, 0x0220, 0x740221},
        {731, 0x075040, 0x0220, 0x750221},
        {737, 0x076040, 0x0220, 0x760221},
        {743, 0x077040, 0x0220, 0x770221},
        {750, 0x078040, 0x0220, 0x780221},
        {756, 0x079040, 0x0220, 0x790221},
        {762, 0x07a040, 0x0220, 0x7a0221},
        {768, 0x07b040, 0x0220, 0x7b0221},
        {775, 0x07c040, 0x0220, 0x7c0221},
        {781, 0x07d040, 0x0220, 0x7d0221},
        {787, 0x07e040, 0x0220, 0x7e0221},
        {793, 0x07f040, 0x0220, 0x7f0221},
        {800, 0x080040, 0x0220, 0x800221},
        {825, 0x042040, 0x0120, 0x420211},
};

static void bm1794_get_plldata(uint32_t freq, uint32_t *vil_data)
{
    uint32_t i;
    for(i=0; i < sizeof(freq_pll)/sizeof(freq_pll[0]); i++)
    {
        if( freq == freq_pll[i].freq)
            break;
    }

    if(i == sizeof(freq_pll)/sizeof(freq_pll[0]))
    {
        i = 4;
    }
    *vil_data = freq_pll[i].vilpll;
}

int bm1794_ioctl_regtable(uint32_t oper_type, void *param)
{
	switch(oper_type)
	{
		case IOCTL_GET_REG:
		{
			struct base_type_t *item = (struct base_type_t *)param;
			bm1794_get_reg_table(item->addr, &item->data);
			break;
		}
		case IOCTL_SET_REG:
		{            
			struct base_type_t *item = (struct base_type_t *)param;
            bm1794_set_reg_table(item->addr, item->data);
			break;
		}
		default:
			printf("%s failed\n", __func__);
			return 1;
	}

	return 0;
}

int bm1794_pack_ioctl_pkg(uint8_t *str, uint32_t str_len, uint32_t oper_type, void *param)
{
    switch (oper_type)
    {
        case IOCTL_SET_BAND:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            
            bm1794_get_reg_table(REG_MISC_CONTROL, &reg_data.reg_bin);
            reg_data.misc_control.bt8d = get_bt8d_from_baud(item->param) ;
            
            bm1794_set_reg_table(REG_MISC_CONTROL, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_MISC_CONTROL, reg_data.reg_bin);
        }
        case IOCTL_GET_BAND:
        { 
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_MISC_CONTROL);
        }
        case IOCTL_GET_LATCH_CI:
        case IOCTL_GET_ADDRPIN:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_MISC_CONTROL);
        }
        case IOCTL_SET_INV_CLKO:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            
            bm1794_get_reg_table(REG_MISC_CONTROL, &reg_data.reg_bin);
            reg_data.misc_control.invclko = item->param;
            bm1794_set_reg_table(REG_MISC_CONTROL, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_MISC_CONTROL, reg_data.reg_bin);

        }
        case IOCTL_SET_HASHRATE_TWS:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            
            bm1794_get_reg_table(REG_MISC_CONTROL, &reg_data.reg_bin);
            reg_data.misc_control.hashrate_tws = item->param;
            bm1794_set_reg_table(REG_MISC_CONTROL, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_MISC_CONTROL, reg_data.reg_bin);
        }
        case IOCTL_GET_REG:
        {
            struct base_type_t *item = (struct base_type_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, item->addr);
        }
        case IOCTL_SET_REG:
        {
            struct base_type_t *item = (struct base_type_t *)param;
            //bm1794_set_reg_table(item->addr, item->data);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, item->all_core, item->chip_addr, item->addr, item->data);
        }
        case IOCTL_SET_ADDRESS:
        {
            union bm1794_reg reg_data;
            uint8_t *address = (uint8_t *)param;
            bm1794_get_reg_table(REG_CHIP_ADDRESS, &reg_data.reg_bin);
            reg_data.chip_addr.chip_addr = *address;
            bm1794_set_reg_table(REG_CHIP_ADDRESS, reg_data.reg_bin);
            return bm1794_makeup_set_address_cmd(str, str_len, *address);
        }
        case IOCTL_CHAIN_INACTIVE:
        {
            return bm1794_makeup_chain_inactive_cmd(str, str_len);
        }
        case IOCTL_GET_CHIP_ADDR:
        case IOCTL_GET_CHIP_TYPE:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_CHIP_ADDRESS);
        }
        case IOCTL_SET_HASHRATE:
        {
            union bm1794_reg reg_data;
            struct base_param_t *item = (struct base_param_t *)param;
            reg_data.reg_bin = 0;
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_HASH_RATE, reg_data.reg_bin);
        }
        case IOCTL_GET_HASHRATE:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_HASH_RATE);
        }
        case IOCTL_SET_PLL:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;

            bm1794_get_reg_table(REG_PLL_PARAMETER, &reg_data.reg_bin);
            bm1794_get_plldata(item->param, &reg_data.reg_bin);
            
            bm1794_set_reg_table(REG_PLL_PARAMETER, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_PLL_PARAMETER, reg_data.reg_bin);
        }
        case IOCTL_SET_TICKET_MASK:	//valid
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;

            bm1794_get_reg_table(REG_TICKET_MASK, &reg_data.reg_bin);
            reg_data.ticket_mask.ticket_mask = item->param;
            
            bm1794_set_reg_table(REG_TICKET_MASK, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_TICKET_MASK, reg_data.reg_bin);
        }
        case IOCTL_GET_TICKET_MASK:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_TICKET_MASK);
        }
		case IOCTL_I2C_ENABLE:	//valid
		{
			union bm1794_reg reg_data;
			struct base_param_t *item = (struct base_param_t *)param;
			bm1794_get_reg_table(REG_GENERAL_I2C_COMMAND, &reg_data.reg_bin);
			reg_data.misc_control.rfs = 0x1;
			reg_data.misc_control.tfs = 0x3;
			bm1794_set_reg_table(REG_GENERAL_I2C_COMMAND, reg_data.reg_bin);
			return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_GENERAL_I2C_COMMAND, reg_data.reg_bin);
		}
		case IOCTL_I2C_STATUS:
		{
			struct base_param_t *item = (struct base_param_t *)param;
			return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_GENERAL_I2C_COMMAND);
		}
        case IOCTL_I2C_READ:
        {
            union bm1794_reg reg_data;
            struct i2c_read_t *item = (struct i2c_read_t *)param;
            bm1794_get_reg_table(REG_GENERAL_I2C_COMMAND, &reg_data.reg_bin);
            reg_data.general_i2c_command.rwctrl = 0;
            reg_data.general_i2c_command.devaddr = item->dev_addr;
            reg_data.general_i2c_command.regaddr = item->reg_addr;
            
            bm1794_set_reg_table(REG_GENERAL_I2C_COMMAND, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_GENERAL_I2C_COMMAND, reg_data.reg_bin);
        }
        case IOCTL_I2C_WRITE:
        {
            union bm1794_reg reg_data;
            struct i2c_write_t *item = (struct i2c_write_t *)param;
            
            bm1794_get_reg_table(REG_GENERAL_I2C_COMMAND, &reg_data.reg_bin);
            reg_data.general_i2c_command.rwctrl = 1;
            reg_data.general_i2c_command.devaddr = item->dev_addr;
            reg_data.general_i2c_command.regaddr = item->reg_addr;
            reg_data.general_i2c_command.data = item->reg_data;
            
            bm1794_set_reg_table(REG_GENERAL_I2C_COMMAND, reg_data.reg_bin);   
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_GENERAL_I2C_COMMAND, reg_data.reg_bin);
        }
		case IOCTL_SET_TXOK_EN:
		{
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            
            bm1794_get_reg_table(REG_NONCE_TX_OK, &reg_data.reg_bin);
            reg_data.nonce_tx_ok.txok_en = item->param;
            
            bm1794_set_reg_table(REG_NONCE_TX_OK, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_NONCE_TX_OK, reg_data.reg_bin);
		}
        case IOCTL_SET_NONCE_TXOK:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            
            bm1794_get_reg_table(REG_NONCE_TX_OK, &reg_data.reg_bin);
            reg_data.nonce_tx_ok.nonce_txok = item->param;
            
            bm1794_set_reg_table(REG_NONCE_TX_OK, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_NONCE_TX_OK, reg_data.reg_bin);
        }
        case IOCTL_GET_NONCEID:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_NONCE_TX_OK);
        }
        case IOCTL_SET_CORE_TIMEOUT:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            bm1794_get_reg_table(REG_CORE_TIMEOUT, &reg_data.reg_bin);
            reg_data.core_timeout.core_timeout = item->param;
            bm1794_set_reg_table(REG_CORE_TIMEOUT, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_CORE_TIMEOUT, reg_data.reg_bin);    
        }
        case IOCTL_SET_IO_DRIVE_STRENGTH:
        {
            union bm1794_reg reg_data;
            struct set_io_drive_strength_t *item = (struct set_io_drive_strength_t *)param;

            bm1794_get_reg_table(REG_IO_DRIVE_STRENGTH, &reg_data.reg_bin);
            reg_data.io_drive_strength.rf_ds = item->rf_ds;
            reg_data.io_drive_strength.tf_df = item->tf_ds;
            reg_data.io_drive_strength.ro_ds = item->ro_ds;
            reg_data.io_drive_strength.clko_ds = item->clko_ds;
            reg_data.io_drive_strength.nrsto_ds = item->nrsto_ds;
            reg_data.io_drive_strength.bo_ds = item->bo_ds;
            reg_data.io_drive_strength.co_ds = item->co_ds;
            
            bm1794_set_reg_table(REG_IO_DRIVE_STRENGTH, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->basep.all, 0, item->basep.chip_addr, REG_IO_DRIVE_STRENGTH, reg_data.reg_bin);
        }
        case IOCTL_CLR_CRC_ERR_COUNT:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            bm1794_get_reg_table(REG_CHIP_STATUS, &reg_data.reg_bin);
            if (item->param == 0)
                reg_data.chip_status.clrerr = 0;
            else
                reg_data.chip_status.clrerr = 1;
        
            bm1794_set_reg_table(REG_CHIP_STATUS, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_CHIP_STATUS, reg_data.reg_bin);
        }
        case IOCTL_GET_CRC_ERR_COUNT:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_get_status_cmd(str, str_len, item->all, item->chip_addr, REG_CHIP_STATUS);
        }
        case IOCTL_SET_NONCE_TX_TIMEOUT:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            bm1794_get_reg_table(REG_TIME_OUT, &reg_data.reg_bin);
            reg_data.time_out.nonce_tx_timeout = item->param;
            
            bm1794_set_reg_table(REG_TIME_OUT, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_TIME_OUT, reg_data.reg_bin);
        }
        case IOCTL_SET_TMOUT:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            bm1794_get_reg_table(REG_TIME_OUT, &reg_data.reg_bin);
            reg_data.time_out.timeout = item->param;
            
            bm1794_set_reg_table(REG_TIME_OUT, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_TIME_OUT, reg_data.reg_bin);
        }
        case IOCTL_SET_VTSEL:
        {
            union bm1794_reg reg_data;
            struct base_param8_t *item = (struct base_param8_t *)param;
            bm1794_get_reg_table(REG_PMONITOR_CTRL, &reg_data.reg_bin);
            reg_data.pmonitor_ctrl.vtsel = item->param;
            
            bm1794_set_reg_table(REG_PMONITOR_CTRL, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_PMONITOR_CTRL, reg_data.reg_bin);
        }
        case IOCTL_SET_COREID:
        {
            union bm1794_reg reg_data;
            struct base_param8_t *item = (struct base_param8_t *)param;
            bm1794_get_reg_table(REG_PMONITOR_CTRL, &reg_data.reg_bin);
            reg_data.pmonitor_ctrl.coreid = item->param;
            
            bm1794_set_reg_table(REG_PMONITOR_CTRL, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_PMONITOR_CTRL, reg_data.reg_bin);
        }
        case IOCTL_SET_ANALOG_MUX:
        {    
            union bm1794_reg reg_data;
            struct base_param8_t *item = (struct base_param8_t *)param;
            bm1794_get_reg_table(REG_ANALOG_MUX_CONTROL, &reg_data.reg_bin);
            reg_data.analog_mux_control.diode_vdd_mux_sel = item->param;
            
            bm1794_set_reg_table(REG_ANALOG_MUX_CONTROL, reg_data.reg_bin);
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_ANALOG_MUX_CONTROL, reg_data.reg_bin);
        }
        case IOCTL_SET_START_NONCE_OFFSET:
        {
            union bm1794_reg reg_data;
            struct base_param32_t *item = (struct base_param32_t *)param;
            bm1794_get_reg_table(REG_START_NONCE_OFFSET, &reg_data.reg_bin);
            reg_data.start_nonce_offset.sno = item->param;
        
            bm1794_set_reg_table(REG_START_NONCE_OFFSET, reg_data.reg_bin);  
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_START_NONCE_OFFSET, reg_data.reg_bin);
        }
        case IOCTL_SET_TXN_DATA:
        {
            union bm1794_reg reg_data;
            struct base_2param32_t *item = (struct base_2param32_t *)param;
            bm1794_get_reg_table(REG_TXN_DATA, &reg_data.reg_bin);
            reg_data.txn_data.txn_shalow = item->param1;
            reg_data.txn_data.txn_zero = item->param2;
        
            bm1794_set_reg_table(REG_TXN_DATA, reg_data.reg_bin);  
            return bm1794_makeup_set_config_cmd(str, str_len, item->all, 0, item->chip_addr, REG_TXN_DATA, reg_data.reg_bin);
        }
        case IOCTL_SET_BIST_SETUP:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_bist_setup_cmd(item->all, item->chip_addr, str, str_len);
        }
        case IOCTL_SET_BIST_WRITE_WAIT:
        {
            struct set_bist_write_wait_t *item = (struct set_bist_write_wait_t *)param;
            return bm1794_makeup_bist_write_wait_cmd(item->basep.all, item->basep.chip_addr, item->wr_data, item->wr_repeat_num, str, str_len);
        }
        case IOCTL_SET_BIST_WRITE_WAIT_READ:
        {
            struct set_bist_write_wait_read_t *item = (struct set_bist_write_wait_read_t *)param;
            return bm1794_makeup_bist_write_wait_read_cmd(item->basep.all, item->basep.chip_addr, item->wr_data, str, str_len);
        }
        case IOCTL_SET_BIST_WAIT:
        {
            struct set_bist_wait_t *item = (struct set_bist_wait_t *)param;
            return bm1794_makeup_bist_wait_cmd(item->basep.all, item->basep.chip_addr, item->wait_cycle, str, str_len); 
        }
        case IOCTL_SET_BIST_READ:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_bist_read_cmd(item->all, item->chip_addr, str, str_len); 
        }
        case IOCTL_SET_BIST_DISABLE:
        {
            struct base_param_t *item = (struct base_param_t *)param;
            return bm1794_makeup_bist_disable_cmd(item->all, item->chip_addr, str, str_len); 
        }
        default:
        {
            applog(LOG_ERR, "unknow ioctl type %d\n", oper_type);
            break;
        }
    }
    
    return 0;
}

int bm1794_soc_init(void *arg)
{
    uint32_t reg;
	struct chip_info *chip = (struct chip_info *)arg;

    reg = 0x17400000; memcpy(&g_reg_table.chip_addr,           &reg, 4);
    reg = 0x80000000; memcpy(&g_reg_table.hash_rate,           &reg, 4);
    reg = 0x80300211; memcpy(&g_reg_table.pll_parameter,       &reg, 4);
    reg = 0x00000005; memcpy(&g_reg_table.ticket_mask,         &reg, 4);
    reg = 0x07003a01; memcpy(&g_reg_table.misc_control,        &reg, 4);
    reg = 0x00000000; memcpy(&g_reg_table.general_i2c_command,&reg, 4);
    reg = 0x00000000; memcpy(&g_reg_table.nonce_tx_ok,         &reg, 4);
    reg = 0xffffffff; memcpy(&g_reg_table.core_timeout,        &reg, 4);
    reg = 0x02112111; memcpy(&g_reg_table.io_drive_strength,   &reg, 4);
    reg = 0x000f0000; memcpy(&g_reg_table.chip_status,         &reg, 4);
    reg = 0xffffffff; memcpy(&g_reg_table.time_out,            &reg, 4);
    reg = 0x00000000; memcpy(&g_reg_table.pmonitor_ctrl,       &reg, 4);
    reg = 0x00000000; memcpy(&g_reg_table.analog_mux_control,  &reg, 4);
    reg = 0x00000000; memcpy(&g_reg_table.start_nonce_offset,  &reg, 4);
    reg = 0x00000003; memcpy(&g_reg_table.txn_data,            &reg, 4);

	chip->work_len = BM1794_WORK_LEN;
	chip->nonce_len = BM1794_RESP_NONCE_LEN;
	chip->pm_len = BM1794_RESP_PM_LEN;
	chip->reg_len = BM1794_RESP_REG_LEN;
	chip->bist_len = BM1794_RESP_BIST_LEN;

    return 0;
}

int bm1794_soc_exit()
{
    return 0;
}

