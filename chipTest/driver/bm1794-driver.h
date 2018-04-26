#ifndef _BM1794_REG_OPERATION_H_
#define _BM1794_REG_OPERATION_H_

#include <stdint.h>

/*********************Default Value**********************/
#define BMSC_DEFAULT_BAUD	115200


/***************SPEC. Basic Definition**********************/
//#define ZCASH_WORK_LEN          140
#define ZCASH_HEAD_LEN          32


#define BM1794_HEADER_55    	0x55
#define BM1794_HEADER_AA    	0xaa

#define BM1794_HEADER_LEN     	2
#define BM1794_CRC16_LEN        2
#define BM1794_CRC5_LEN         1
#define BM1794_WORK_LEN        	46

#define BM1794_RESP_NONCE_LEN       	(93)
#define BM1794_RESP_REG_LEN             (9)
#define BM1794_RESP_PM_LEN              (9)
#define BM1794_RESP_BIST_LEN            (11)

/******************Common Definition******************/
enum ret_type
{
    RET_OK,
    RET_FAIL,
};

/***************SPEC. Top Register Defination****************/ 
enum bm1794_reg_address
{
    REG_CHIP_ADDRESS                = 0x00,
    REG_HASH_RATE                   = 0x08,
    REG_PLL_PARAMETER              	= 0x0c,
    REG_TICKET_MASK                 = 0x14,
    REG_MISC_CONTROL                = 0x1c,
    REG_GENERAL_I2C_COMMAND     	= 0x20,
    REG_NONCE_TX_OK                 = 0x24,
    REG_CORE_TIMEOUT                = 0x28,
    REG_IO_DRIVE_STRENGTH       	= 0x30,
    REG_CHIP_STATUS                 = 0x34,
    REG_TIME_OUT                    = 0x38,
    REG_PMONITOR_CTRL               = 0x3c,
    REG_ANALOG_MUX_CONTROL      	= 0x40,
    REG_BIST_STATUS                 = 0x48,
    REG_START_NONCE_OFFSET          = 0x54,
    REG_TXN_DATA                    = 0x58,
};

// Chip Address.    default: 0x1740_0000
struct bm1794_chip_addr
{
    uint32_t chip_addr      :8;
    uint32_t reserve2       :5;
    uint32_t reserve1       :3;
    uint32_t chip_name      :16;
};

// Hash Rate.   default: 0x8000_0000.
enum {

    REALTIME_RATE = 0,
    AVERAGE_RATE = 1,
};
struct bm1794_hash_rate
{
    uint32_t hash_rate              :31;
    uint32_t hash_rate_flag         :1;
};

// PLL Parameter.  defalut: 0x8030_0211
struct bm1794_pll_parameter
{
    uint32_t postdiv2       :3;
    uint32_t reserve4       :1;
    uint32_t postdiv1       :3;
    uint32_t reserve3       :1;
    uint32_t refdiv         :6;
    uint32_t reserve2       :2;
    uint32_t fbdiv          :12;
    uint32_t reserve1       :3;
    uint32_t locked         :1;
};

/* Ticket Mask.     default: 0x0a */
struct bm1794_ticket_mask
{
    uint32_t ticket_mask        :8;
    uint32_t reserve            :24;
};

// Misc Control.   default: 0x07003a01
struct bm1794_misc_control
{
    uint32_t hashrate_tws       :2;
    uint32_t reserve4           :3;
    uint32_t tfs                :2;
    uint32_t reserve3           :1;
    uint32_t bt8d               :5;
    uint32_t invclko            :1;
    uint32_t rfs                :1;
    uint32_t reservex           :1;
    uint32_t reserve2           :8;
    uint32_t addrpin            :2;
    uint32_t latch_ci           :1;
    uint32_t reserve1           :5;
};

// General I2C Command.  default: 0x01000000 
struct bm1794_general_i2c_command
{
    uint32_t data               :8;
    uint32_t regaddr            :8;
    uint32_t rwctrl             :1;
    uint32_t devaddr            :7;
    uint32_t ravalid            :1;
    uint32_t reserve            :5;
    uint32_t rwfail             :1;
    uint32_t busy               :1;
};

// Nonce TX ok.     default: 0
struct bm1794_nonce_tx_ok
{
    uint32_t nonce_txok         :16;
    uint32_t nid                :8;
    uint32_t reserve            :7;
    uint32_t txok_en            :1;
};

// Core Time Out.       default: 0xffffffff
struct bm1794_core_timeout
{
    uint32_t core_timeout;  
};

// IO Drive Strength Configuration.     default: 0x02110211
struct bm1794_io_drive_strength
{
    uint32_t co_ds              :4;
    uint32_t bo_ds              :4;
    uint32_t nrsto_ds           :4;
    uint32_t clko_ds            :4;
    uint32_t ro_ds              :4;
    uint32_t tf_df              :4;
    uint32_t rf_ds              :4;
    uint32_t reserve            :4;
};

// Chip Status.     default: 0x000f0000
struct bm1794_chip_status
{
    uint32_t crc5err            :8;
    uint32_t crc16err           :8;
    uint32_t ram_empty          :4;
    uint32_t reserve            :11;
    uint32_t clrerr             :1;
};

// Time Out.        default: 0xffff_ffff
struct bm1794_time_out
{
    uint32_t timeout                :16;
    uint32_t nonce_tx_timeout       :16;
};

// Pmonitor Ctrl.   default: 0
struct bm1794_pmonitor_ctrl
{
    uint32_t coreid                 :6;
    uint32_t vtsel                  :2;
    uint32_t reserve                :24;
};

// Analog Mux Control.      default:0
struct bm1794_analog_mux_control
{
    uint32_t diode_vdd_mux_sel      :3;
    uint32_t reserve                :29;
};

// Bist Status.     default: 0
struct bm1794_bist_status
{
    uint32_t bist_ok    :1;
    uint32_t bist_crc_error     :1;
    uint32_t reserve        :30;
};

// Start Nonce Offset.      default: 0
struct bm1794_start_nonce_offset
{
    uint32_t sno;
};

// Txn Data.        default: 0x00000003
struct bm1794_txn_data
{
    uint32_t txn_zero   :1;
    uint32_t txn_shalow :1;
    uint32_t reaseve    :30;
};

union bm1794_reg 
{
    struct bm1794_chip_addr                 chip_addr;
    struct bm1794_hash_rate                 hash_rate;
    struct bm1794_pll_parameter             pll_parameter;
    struct bm1794_ticket_mask               ticket_mask;
    struct bm1794_misc_control              misc_control;
    struct bm1794_general_i2c_command       general_i2c_command;
    struct bm1794_nonce_tx_ok               nonce_tx_ok;
    struct bm1794_core_timeout              core_timeout;
    struct bm1794_io_drive_strength         io_drive_strength;
    struct bm1794_chip_status               chip_status;
    struct bm1794_time_out                  time_out;
    struct bm1794_pmonitor_ctrl             pmonitor_ctrl;
    struct bm1794_analog_mux_control        analog_mux_control;
    struct bm1794_start_nonce_offset        start_nonce_offset;
    struct bm1794_txn_data                  txn_data;
    uint32_t reg_bin;
};

struct bm1794_realtime_reg_table
{
    struct bm1794_chip_addr             chip_addr;
    struct bm1794_hash_rate             hash_rate;
    struct bm1794_pll_parameter         pll_parameter;
    struct bm1794_ticket_mask           ticket_mask;
    struct bm1794_misc_control          misc_control;
    struct bm1794_general_i2c_command       general_i2c_command;
    struct bm1794_nonce_tx_ok               nonce_tx_ok;
    struct bm1794_core_timeout              core_timeout;
    struct bm1794_io_drive_strength         io_drive_strength;
    struct bm1794_chip_status               chip_status;
    struct bm1794_time_out                  time_out;
    struct bm1794_pmonitor_ctrl             pmonitor_ctrl;
    struct bm1794_analog_mux_control        analog_mux_control;
    struct bm1794_start_nonce_offset        start_nonce_offset;
    struct bm1794_txn_data                  txn_data;
};

/***************SPEC. bm1794 Command Definition***************/
enum input_data_type
{
    WORK_INPUT      = 0x01,
    COMMAND_INPUT   = 0x02,
    BIST_INPUT      = 0x03,
};

enum input_cmd_type
{
    CMD_SET_ADDRESS 	= 0,
    CMD_SET_CONFIG  	= 1,
    CMD_GET_STATUS  	= 2,
    CMD_CHAIN_INACTIVE  = 3,
};

enum input_bist_type
{
    BIST_SETUP,
    BIST_WRITE_WAIT,
    BIST_WRITE_WAIT_READ,
    BIST_WAIT,
    BIST_READ,
    BIST_DISABLE
};

enum input_cmd_length_type
{
    INPUT_CMD_LEN_5 = 5,
    INPUT_CMD_LEN_7 = 7,
    INPUT_CMD_LEN_9 = 9,
    INPUT_CMD_LEN_11 = 11,
};

enum input_bist_length_type
{
    INPUT_BIST_LEN_5 = 5,
    INPUT_BIST_LEN_9 = 9,
    INPUT_BIST_LEN_11 = 11,
};

enum input_cmd_allchip_type
{
    CMD_SINGLE_CHIP = 0,
    CMD_ALL_CHIP = 1
};

struct work_input
{
    uint8_t header_55;
    uint8_t header_aa;
    uint8_t reserve			:4;
    uint8_t sno_valid		:1;
    uint8_t type			:3;
    uint8_t workid;
    uint64_t start_nonce;
    uint8_t head[ZCASH_HEAD_LEN];
    uint16_t crc16;
} __attribute__((packed, aligned(1)));

struct get_status_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t regaddr[3];
    uint8_t crc5        :5;
    uint8_t reserve     :3;

} __attribute__((packed, aligned(1)));

struct set_config_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length      :7;
    uint8_t all_core    :1;
    uint8_t chip_addr;
    uint8_t regaddr[3];
    uint32_t regdata;
    uint8_t crc5        :5;
    uint8_t reserve     :3;
} __attribute__((packed, aligned(1)));

struct set_address_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t reserve1;
    uint8_t crc5        :5;
    uint8_t reserve2    :3;
} __attribute__((packed, aligned(1)));

struct chain_inactive_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t reserve1;
    uint8_t reserve2;
    uint8_t crc5        :5;
    uint8_t reserve3    :3;
} __attribute__((packed, aligned(1)));

struct bist_setup_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t reserve1;
    uint8_t crc5        :5;
    uint8_t reserve2    :3;
} __attribute__((packed, aligned(1)));

struct bist_write_wait_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t wr_data[6];
    uint8_t write_repeat_num;
    uint8_t crc5        :5;
    uint8_t reserve2    :3;    
} __attribute__((packed, aligned(1)));

struct bist_write_wait_read_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t wr_data[6];
    uint8_t reserve1;
    uint8_t crc5        :5;
    uint8_t reserve2    :3;    
} __attribute__((packed, aligned(1)));

struct bist_wait_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t wait_cycle[5];
    uint8_t crc5        :5;
    uint8_t reserve2    :3;    
} __attribute__((packed, aligned(1)));

struct bist_read_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t reserve1;
    uint8_t crc5        :5;
    uint8_t reserve2    :3;    
} __attribute__((packed, aligned(1)));

struct bist_disable_cmd_t
{
    uint8_t cmd         :4;
    uint8_t all         :1;
    uint8_t type        :3;
    uint8_t length;
    uint8_t chip_addr;
    uint8_t reserve1;
    uint8_t crc5        :5;
    uint8_t reserve2    :3;    
} __attribute__((packed, aligned(1)));

struct reg_respond
{
	uint8_t header_aa;
	uint8_t header_55;
    uint8_t reg_addr;
    uint8_t reg_data[4];
    uint8_t chip_addr;
    uint8_t crc5        :5;
    uint8_t reserve     :3;
} __attribute__((packed, aligned(1)));

struct reg_rb_format
{
	uint8_t reg_addr;
	uint8_t reg_data[4];
	uint8_t chip_addr;
} __attribute__((packed, aligned(1)));

// part of a complete nonce
struct nonce_respond_t
{
	uint8_t header_aa;
	uint8_t header_55;
    uint8_t nonce_num   :4;
    uint8_t format      :4;
    uint8_t chip_address;
    uint8_t work_id;
    uint8_t nonce_id;
    uint8_t nonce[85];
    uint8_t crc16[2];
} __attribute__((packed, aligned(1)));

// a complete nonce
struct nonce_rb_format
{
    uint8_t Nonce[1344];
    uint8_t chip_addr;
    uint8_t work_id;
    uint8_t nonce_id;
    uint8_t diff0;
    uint8_t sha256[4];
    uint8_t chip_nonce[4];
} __attribute__((packed, aligned(1)));

struct pmonitor_respond
{
	uint8_t header_aa;
	uint8_t header_55;
    uint8_t format;
    uint8_t pm_data[4];
    uint8_t chip_addr;
    uint8_t crc5        :5;
    uint8_t reserve     :3;
} __attribute__((packed, aligned(1)));

struct bist_respond
{
	uint8_t header_aa;
	uint8_t header_55;
    uint8_t format;
    uint8_t bist_read_data[6];
    uint8_t chip_addr;
    uint8_t crc5        :5;
    uint8_t reserve     :3;
} __attribute__((packed, aligned(1)));

/**********************Custom Definition*****************************/
struct freq_pll_str
{
    unsigned int freq;
    unsigned int fildiv1;
    unsigned int fildiv2;
    unsigned int vilpll;
};

/******************function declaration******************/
int bm1794_soc_init(void *arg);
int bm1794_soc_exit();
int bm1794_ioctl_regtable(uint32_t oper_type, void *param);
int bm1794_pack_ioctl_pkg(uint8_t *str, uint32_t str_len, uint32_t oper_type, void *param);
int bm1794_parse_respond_pkg(uint8_t *str, int len, int *type, uint8_t *out_str, uint32_t out_len);
int bm1794_parse_respond_len(uint8_t *str, int len, int *read_len);
int bm1794_pack_work_pkg(uint8_t *str);

#endif
