#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "debug-server.h"
#include "logging.h"
#include "midd-api.h"
#include "ioctl-type.h"
#include "util.h"
#include "platform-driver.h"
#include "platform-app.h"
#include "crc.h"

extern struct midd_api g_midd_api;
extern int miner_enable;
struct debug_tool_info g_dt_info;

#define MAX_CHAIN_NUM	1
extern struct std_chain_info g_chain[MAX_CHAIN_NUM];
extern unsigned char g_test_header[140];

/****************single chip test BEGIN*****************/
extern int g_crc5_err_enable;
extern int g_crc16_err_enable;
/****************single chip test END*****************/

#if defined(__linux__) || defined(__FreeBSD__)

static int debug_exec(int argc, char *argv[], char *ret_str)
{
    int i;

    for (i=0; i<g_dt_info.debug_entry_num; i++)
    {
        if (strcmp(argv[0], g_dt_info.entry[i].cmd) == 0) {
            return g_dt_info.entry[i].pfnDbgProc(argc, argv, ret_str);
        }
    }

    sprintf(ret_str, "unsupport command type\n");
    return -1;
}

static void *debug_tool_handle()
{
    int len = 0;
    char buffer[FIFO_SIZE] = {0};
    int argc;
    char *pbuf;
    char *argv[MAX_PARAM_NUM];
    char send_buf[FIFO_SIZE] = {0};
    char *ret_str = send_buf + sizeof(int);
    int send_num;
    int ret_code;

    while (1)
    {
        pthread_testcancel();
        memset(buffer, 0, FIFO_SIZE);
        len = read(g_dt_info.fd_read, buffer, FIFO_SIZE);
        
        if (len > 0) {
			
            memcpy(&argc, buffer, sizeof(int));
            if (argc <= 0)
                continue;
            pbuf = buffer + sizeof(int);
            memset(argv,0,sizeof(argv));
            for (int i = 0; i < argc; i++)
            {
                argv[i] = malloc(strlen(pbuf) + 1);
                if (argv[i] == NULL)
                {
                    applog(LOG_ERR, "debug tool memery alloc failed i=%d\n", i);
                    for (int k = 0; k < i; k++)
                    {
                        free(argv[k]);
                    }
                    break;
                }
                strcpy(argv[i], pbuf);
                pbuf += strlen(pbuf) + 1;
            }

            memset(ret_str, 0, FIFO_SIZE-sizeof(int));
            ret_code = debug_exec(argc, argv, ret_str);

            for (int i=0;i<argc;i++)
            {
                free(argv[i]);
            }

            memcpy(send_buf, &ret_code, sizeof(int));
            send_num = sizeof(int) + strlen(ret_str);
            len = write(g_dt_info.fd_write, send_buf, send_num);
            if (len != send_num) {
                applog(LOG_ERR, "send ret str to client failed. len=%d, send_num=%d\n", len, send_num);
            }
        }
    }
	return NULL;
}

// format: bmdbg event w 1 0 xxxxxx
// format: bmdbg event g 0x00
// format: bmdbg event s 0x00 0x00000000
static void usage(char *ret_str)
{
	strcat(ret_str, "w	send work               [bmdbg event w 1 start_nonce header]\n");
	strcat(ret_str, "s 	set register            [bmdbg event s 0x00 0x00000000]\n");
	strcat(ret_str, "g	get register            [bmdbg event g 0x00]\n");
	strcat(ret_str, "t	open/close pool         [bmdbg event t 0/1]\n");
	strcat(ret_str, "c	set chip address test   [bmdbg event c address]\n");
	strcat(ret_str, "1	bandrate setting test   [bmdbg event 1 bandrate]\n");
	strcat(ret_str, "2	crc register test.      [bmdbg event 2 5/16]\n");
	strcat(ret_str, "3 	read voltage test       \n");
	strcat(ret_str, "h 	help info\n");
}

static int create_event(int argc, char *argv[], char *ret_str)
{
    if (argc < 2) {
        sprintf(ret_str, "params error\n");
        return -1;
    }

    char cmd = argv[1][0];
    switch (cmd)
    {
        case 'w':	//send work. [dbg event w sno_valid test_patten work]
        {
            if (argc < 5) {
               sprintf(ret_str, "params error\n");
               return -1;
            }
            struct work_input work;
            work.sno_valid = atoi(argv[2]);
            work.start_nonce = atoi(argv[3]);
            work.workid = 0x0;
            uint8_t work_bin[ZCASH_HEAD_LEN] = {0};
            hex2bin(work_bin, argv[4], ZCASH_HEAD_LEN);
            memcpy(work.head, work_bin, ZCASH_HEAD_LEN);
            memcpy(g_test_header, work_bin, ZCASH_HEAD_LEN);
            g_midd_api.send_work((uint8_t *)&work, sizeof(work));
            break;
        }
        case 's':
        {
            if (argc < 4) {
               sprintf(ret_str, "params error\n");
               return -1;
            }

            struct base_type_t item;
            item.all = 1;
            item.all_core = 1;
            item.chip_addr = 0;
            item.addr = strtol(argv[2], NULL, 16);
            item.data = strtol(argv[3], NULL, 16);
            g_midd_api.ioctl(g_chain[0].fd, IOCTL_SET_REG, &item);
            ret_str[0] = '\0';
            break;
        }
        case 'g':
        {
            if (argc < 3) {
               sprintf(ret_str, "params error\n");
               return -1;
            }
            struct base_type_t item;
            item.all = 1;
            item.chip_addr = 0x00;
            item.addr = strtol(argv[2], NULL, 16);
            g_midd_api.ioctl(g_chain[0].fd, IOCTL_GET_REG, &item);
            ret_str[0] = '\0';
            break;
        }
        case 'm':
        {
            if (argc < 3) {
               sprintf(ret_str, "params error\n");
               return -1;
            }
            miner_enable = atoi(argv[2])?1:0;
			if (miner_enable == 1)
            	sprintf(ret_str, "enable miner %d\n", miner_enable);
			else
				sprintf(ret_str, "disable miner %d\n", miner_enable);
            break;
        }
        case 'c':   //set chip address test. [dbg event c address]. for testcase 3
        {
            if (argc < 3) {
               sprintf(ret_str, "params error\n");
               return -1;
            }
            uint8_t address = strtol(argv[2], NULL, 16);
            g_midd_api.ioctl(g_chain[0].fd, IOCTL_CHAIN_INACTIVE, NULL);
            g_midd_api.ioctl(g_chain[0].fd, IOCTL_SET_ADDRESS, &address);
            ret_str[0] = '\0';
            break;
        }
        case '1':	//bandrate setting test. [dbg event 1 bandrate]. for test case 3
        {
        	if (argc < 3) {
				sprintf(ret_str, "param error\n");
				return -1;
			}

			struct base_param32_t item;
			item.all = 1;
			item.chip_addr = 0;
			item.param = atoi(argv[2]);
			g_midd_api.ioctl(g_chain[0].fd, IOCTL_SET_BAND, &item);
            break;
        }
		case '2':	//crc register test. [dbg event 2 5/16]
		{
		/*
			if param is 5, it will open/close crc5-error test. if enable, the get-status command will carry a fake crc5;
			if param is 16, it will open/close crc16-error test. if enable,  the sending-work will carry a fake crc16;
		*/
			if (argc < 3){
				sprintf(ret_str, "param error\n");
				return -1;
			}
			
			if (atoi(argv[2]) == 5){
				g_crc5_err_enable = !g_crc5_err_enable;
				printf("g_crc5_err_enable=%d\n", g_crc5_err_enable);
			} else if(atoi(argv[2]) == 16) {
				g_crc16_err_enable = !g_crc16_err_enable;
				printf("g_crc16_err_enable=%d\n", g_crc16_err_enable);
			} else {
				sprintf(ret_str, "param error\n");
			}
			break;
		}
		case '3': //read voltage test
		{
			//enable i2c, the chip address should be specially assigned.
			struct base_param_t item;
			item.all = 1;
			item.chip_addr = 0;
			g_midd_api.ioctl(g_chain[0].fd, IOCTL_I2C_ENABLE, &item);

			//select the analog mux control value
			struct base_param8_t item2;
			item2.all = 1;
			item2.chip_addr = 0;
			item2.param = 0;	//diode[0,1,2,3], vdd[4,5,6,7]
			g_midd_api.ioctl(g_chain[0].fd, IOCTL_SET_ANALOG_MUX, &item2);
			break;
		}
		case '4':	//send 50 nonce which meet the ticket mask requrment 11;
		{
			struct base_param32_t item;
			item.all = 1;
			item.chip_addr = 0x00;
			item.param = 0x0000000b;
			for (int chain_id=0;chain_id<MAX_CHAIN_NUM;chain_id++)
				g_midd_api.ioctl(g_chain[chain_id].fd, IOCTL_SET_TICKET_MASK, &item);

			FILE *fp = fopen("ticketmasklt10.txt", "r+");
			if (fp == NULL)
			{
				printf("open error\n");
				break;
			}

			char tm[8] = {0};
			char header[280+2] = {0};
			char nonce[2688+2] = {0};
			struct work_input work;
			while (!feof(fp))
			{
				fgets(tm, 10, fp);
				fgets(header, 300, fp);
				fgets(nonce, 2700, fp);
/*
				fprintf(stdout, "%s", tm);
				fprintf(stdout, "%s", header);
				fprintf(stdout, "%s", nonce);
*/
				work.sno_valid = 1;
				work.start_nonce = 0;
				work.workid = 0x0;
				uint8_t work_bin[ZCASH_HEAD_LEN] = {0};
				hex2bin(work_bin, header, ZCASH_HEAD_LEN);
				memcpy(work.head, work_bin, ZCASH_HEAD_LEN);
				memcpy(g_test_header, work_bin, ZCASH_HEAD_LEN);
				g_midd_api.send_work((uint8_t *)&work, sizeof(work));

				z_sleep(10);
			}
			fclose(fp);
			break;
		}
		case '5':
		{
			struct base_param8_t item;
			item.all=1;
			item.chip_addr=0;
			item.param=atoi(argv[2])?1:0;
			g_midd_api.ioctl(g_chain[0].fd, IOCTL_SET_TXOK_EN, &item);
			platform_get_appInfo()->txok_en = item.param;
			if (item.param)
				sprintf(ret_str, "enable txok-en\n");
			else
				sprintf(ret_str, "disable txok-en\n");
			break;
		}
		case 'h':
		{
			usage(ret_str);
			break;
		}
        default:
        {
            sprintf(ret_str, "unknow command\n");
            return -1;
        }
    }

    return 0;
}

int debugtool_init()
{
    // if fifo file is not exist, create it
    if (access(FIFO_CLIENT2SERVER, F_OK) < 0) {
        if (mkfifo(FIFO_CLIENT2SERVER, 0666) != 0) {
            applog(LOG_ERR, "mkfifo %s\n", strerror(errno));
            return -1;
        }
    }

    if (access(FIFO_SERVER2CLIENT, F_OK) < 0) {
        if (mkfifo(FIFO_SERVER2CLIENT, 0777) != 0) {
            applog(LOG_ERR, "create fifo failed %s\n", strerror(errno));
            return -1;
        }
    }

    // if server open readonly first, the client must open writeonly first
    g_dt_info.fd_read = open(FIFO_CLIENT2SERVER, O_RDONLY);
    if (g_dt_info.fd_read < 0){
        applog(LOG_ERR, "open failed %s\n", strerror(errno));
        return -1;
    }

    g_dt_info.fd_write = open(FIFO_SERVER2CLIENT, O_WRONLY);
    if (g_dt_info.fd_write < 0) {
        applog(LOG_ERR, "open failed %s\n", strerror(errno));
        return -1;
    }

    //register handler
    debug_tool_entry entry[] = \
    { \
        {"event", "work register", create_event}, \
        {"status", "get statistic data", NULL}, \
    };

    g_dt_info.debug_entry_num = sizeof(entry)/sizeof(debug_tool_entry);

    for (int i=0; i<g_dt_info.debug_entry_num; i++)
    {
        strcpy(g_dt_info.entry[i].cmd, entry[i].cmd);
        strcpy(g_dt_info.entry[i].help_info, entry[i].help_info);
        g_dt_info.entry[i].pfnDbgProc = entry[i].pfnDbgProc;
    }

    if(0 != pthread_create(&g_dt_info.p_debug_handle, NULL, debug_tool_handle, NULL))
    {
       applog(LOG_ERR, "%s create debug_tool_handle thread failed\n", __func__);
       return -1;
    }

    return 0;
}

void debugtool_exit()
{
    close(g_dt_info.fd_read);
    close(g_dt_info.fd_write);

    pthread_cancel(g_dt_info.p_debug_handle);
    pthread_join(g_dt_info.p_debug_handle, NULL);
}

#else

int debugtool_init()
{
	printf("win32 pipe: unsupport\n");
	return 0;
}

void debugtool_exit()
{
	printf("win32 pipe: unsupport\n");
}

#endif
