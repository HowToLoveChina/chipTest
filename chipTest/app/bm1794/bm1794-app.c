#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include "platform-driver.h"
#include "util.h"
#include "uart.h"
#include "midd-api.h"
#include "comm-api.h"
#include "logging.h"
#include "blake2b.h"
#include "sort-verify.h"
#include "platform-app.h"
#include "sha256.h"
#include "ioctl-type.h"
#include "reg-scan.h"
#include "crc.h"
#if defined(__linux__)
#include "endian.h"
#endif
#define MINER_ENABLE 0

extern struct midd_api g_midd_api;
extern struct comm_api g_comm_api;

struct bm1794_app g_bm1794_app;
struct bm1794_reg_info bm1794_info;
uint8_t g_test_header[140];
uint8_t g_nonce_list[16][91];
struct std_chain_info g_chain[MAX_CHAIN_NUM];

/**************test config***************/
int miner_enable = 0;
/**************const config***************/
int tty[MAX_CHAIN_NUM] = {0};

FILE *fl = NULL;

uint64_t now(void)
{
    struct timeval	tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

void randomize(void *p, ssize_t l)
{
    const char	*fname = "/dev/urandom";
    int		fd;
    ssize_t	ret;

    if (-1 == (fd = open(fname, O_RDONLY))) {
	    applog(LOG_ERR, "open %s: %s\n", fname, strerror(errno));
        exit(1);
    }
    if (-1 == (ret = read(fd, p, l))){
	    applog(LOG_ERR, "read %s: %s\n", fname, strerror(errno));
        exit(1);
    }
    if (ret != l) {
	    applog(LOG_ERR, "%s: short read %ld bytes out of %ld\n", fname, ret, l);
        exit(1);
    }
    if (-1 == close(fd)) {
	    applog(LOG_ERR, "close %s: %s\n", fname, strerror(errno));
        exit(1);
    }
}

void set_blocking_mode(int fd, int block)
{
    int	f;

    if (-1 == (f = fcntl(fd, F_GETFL))) {
	    applog(LOG_ERR, "fcntl F_GETFL: %s\n", strerror(errno));
        exit(1);
    }
    if (-1 == fcntl(fd, F_SETFL, block ? (f & ~O_NONBLOCK) : (f | O_NONBLOCK))) {
	    applog(LOG_ERR, "fcntl F_SETFL: %s\n", strerror(errno));
        exit(1);
    }
}

uint8_t hex2val(const char *base, size_t off)
{
    const char c = base[off];
    if (c >= '0' && c <= '9')           return c - '0';
    else if (c >= 'a' && c <= 'f')      return 10 + c - 'a';
    else if (c >= 'A' && c <= 'F')      return 10 + c - 'A';
    applog(LOG_ERR, "Invalid hex char at offset %zd: ...%c...\n", off, c);
    return 0;
}

char *s_hexdump(const void *_a, uint32_t a_len)
{
    const uint8_t	*a = _a;
    static char		buf[4096];
    uint32_t		i;
    for (i = 0; i < a_len && i + 2 < sizeof (buf); i++)
        sprintf(buf + i * 2, "%02x", a[i]);
    buf[i * 2] = 0;
    return buf;
}

#define hex_print(p) fprintf(stderr, "%s\n", p)
#define BYTES_PER_LINE 0x10
static char nibble[] =
        {
                '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };

void hexdump(const unsigned char *p, unsigned int len)
{
    unsigned int i, addr;
    unsigned int wordlen = sizeof(void*);
    unsigned char v, line[BYTES_PER_LINE * (wordlen + 1)];

    for (addr = 0; addr < len; addr += BYTES_PER_LINE)
    {
        /* clear line */
        for (i = 0; i < sizeof(line); i++)
        {
            if (i == wordlen * 2 + 52 || i == wordlen * 2 + 69)
            {
                line[i] = '|';
                continue;
            }

            if (i == wordlen * 2 + 70)
            {
                line[i] = '\0';
                continue;
            }

            line[i] = ' ';
        }
        /* print address */
        for (i = 0; i < wordlen * 2; i++)
        {
            v = addr >> ((wordlen * 2 - i - 1) * 4);
            line[i] = nibble[v & 0xf];
        }
        /* dump content */
        for (i = 0; i < BYTES_PER_LINE; i++)
        {
            int pos = (wordlen * 2) + 3 + (i / 8);

            if (addr + i >= len)
                break;

            v = p[addr + i];
            line[pos + (i * 3) + 0] = nibble[v >> 4];
            line[pos + (i * 3) + 1] = nibble[v & 0xf];

            /* character printable? */
            line[(wordlen * 2) + 53 + i] =
                    (v >= ' ' && v <= '~') ? v : '.';
        }
        hex_print(line);
    }
}


/*
** Write ZCASH_SOL_LEN bytes representing the encoded solution as per the
** Zcash protocol specs (512 x 21-bit inputs).
**
** out		ZCASH_SOL_LEN-byte buffer where the solution will be stored
** inputs	array of 32-bit inputs
** n		number of elements in array
*/
void store_encoded_sol(uint8_t *out, uint32_t *inputs, uint32_t n)
{
    uint32_t byte_pos = 0;
    int32_t bits_left = PREFIX + 1;
    uint8_t x = 0;
    uint8_t x_bits_used = 0;
    while (byte_pos < n)
      {
        if (bits_left >= 8 - x_bits_used)
          {
            x |= inputs[byte_pos] >> (bits_left - 8 + x_bits_used);
            bits_left -= 8 - x_bits_used;
            x_bits_used = 8;
          }
        else if (bits_left > 0)
          {
            uint32_t mask = ~(-1 << (8 - x_bits_used));
            mask = ((~mask) >> bits_left) & mask;
            x |= (inputs[byte_pos] << (8 - x_bits_used - bits_left)) & mask;
            x_bits_used += bits_left;
            bits_left = 0;
          }
        else if (bits_left <= 0)
          {
            assert(!bits_left);
            byte_pos++;
            bits_left = PREFIX + 1;
          }
        if (x_bits_used == 8)
          {
	    *out++ = x;
            x = x_bits_used = 0;
          }
      }
}

/*
** Verify if the solution's block hash is under the target, and if yes print
** it formatted as:
** "sol: <job_id> <ntime> <nonce_rightpart> <solSize+sol>"
**
** Return 1 iff the block hash is under the target.
*/
uint32_t print_solver_line(uint8_t *soln, uint8_t *header, size_t fixed_nonce_bytes, char *job_id)
{
    uint8_t	buffer[ZCASH_BLOCK_HEADER_LEN + ZCASH_SOLSIZE_LEN +
	ZCASH_SOL_LEN];

    uint8_t	*p;
    p = buffer;
    memcpy(p, header, ZCASH_BLOCK_HEADER_LEN);
    p += ZCASH_BLOCK_HEADER_LEN;
    memcpy(p, "\xfd\x40\x05", ZCASH_SOLSIZE_LEN);
    p += ZCASH_SOLSIZE_LEN;
    memcpy(p, soln, ZCASH_SOL_LEN);

    printf("sol: %s ", job_id);
    p = header + ZCASH_BLOCK_OFFSET_NTIME;
    printf("%02x%02x%02x%02x ", p[0], p[1], p[2], p[3]);
    printf("%s ", s_hexdump(header + ZCASH_BLOCK_HEADER_LEN - ZCASH_NONCE_LEN +
		fixed_nonce_bytes, ZCASH_NONCE_LEN - fixed_nonce_bytes));
    printf("%s%s\n", ZCASH_SOLSIZE_HEX,
	    s_hexdump(buffer + ZCASH_BLOCK_HEADER_LEN + ZCASH_SOLSIZE_LEN,
		ZCASH_SOL_LEN));
    fflush(stdout);
    return 1;
}

static int target_zero_cal(uint8_t *target)
{
    int zero_num = 0;
    uint8_t tmphash[32] = { 0 };

    for (int i=0;i<32;i++)
    {
        tmphash[i] = target[31-i];
    }
    for (int i=0;i < 32;i++)
    {
        for (int j=7; j>=0; j--)
        {
            if (bit_read(&tmphash[i], j)) {
                return zero_num;
            } else {
                zero_num++;
            }
        }
    }
    return zero_num;
}

static int targetValidator(uint8_t *target, const uint8_t *work, const uint8_t *nonce)
{
    uint8_t str[3] = {0xfd, 0x40, 0x05};
    uint8_t input[140 + 3 + 1344] = { 0 };
    uint8_t tmphash[32] = { 0 };
    uint8_t output[32] = { 0 };

    memcpy(input, work, 140);
    memcpy(&input[140], str, 3);
    memcpy(&input[140+3], nonce, 1344);

    Sha256_Onestep(input, sizeof(input), tmphash);
    Sha256_Onestep(tmphash, sizeof(tmphash), output);

	return target_zero_cal(output) - target_zero_cal(target);
}

static int bm1794_handle_nonce(FILE *fnonce, struct nonce_rb_format *nonce)
{
    uint8_t verify[140] = {0};
    uint8_t soln[1344] = {0};
    int valid, ticket_mask_valid;
	static int golden_nonce = 0;
    pthread_mutex_lock(&g_bm1794_app.work_info_mutex);

    // form matched work and nonce
	if (miner_enable == 1)
        memcpy(verify, g_bm1794_app.work_info.header, 140);
	else
        memcpy(verify, g_test_header, 140);

    memcpy(&verify[116], nonce->chip_nonce, 4);
    memcpy(soln, nonce->Nonce, 1344);

    // verify nonce
    blake2b_state digest[1];
    struct validData valData = {.n = 200, .k = 9, .digest = digest};
    digestInit(digest, 200, 9);
    blake2b_update(digest, verify, 140);
    valid = sortValidator((void *) &valData, soln);
    ticket_mask_valid = targetValidator(g_bm1794_app.work_info.target, verify, soln);

#if defined(WIN32)
	if (valid == 0 && ticket_mask_valid >= 0)
	{
		printf("pass!\n");
		return 0;
	}
#endif

	if (miner_enable == 1)
	{
	    uint64_t        total = 0;
	    uint64_t        total_shares = 0;
	    uint64_t        t0 = 0, t1;
	    uint64_t        status_period = 500e3; // time (usec) between statuses

	    // notify the python scrum protocol
	    total++;
	    if (valid == 0 && ticket_mask_valid >= 0) {
			fprintf(fl, "Golden Nonce Found! %d\n", golden_nonce++);
	        print_solver_line(soln, verify, g_bm1794_app.work_info.fixed_nonce_bytes, g_bm1794_app.work_info.job_id);
	        total_shares++;
	    }
	    if ((t1 = now()) > t0 + status_period)
	    {
	        t0 = t1;
	        printf("status: %" PRId64 " %" PRId64 "\n", total, total_shares);
	        fflush(stdout);
	    }
	}

	// print out the work and nonce information
    time_t now;
    time(&now);
    fprintf(fnonce, "%s", ctime(&now));
    dump_str(fnonce, NULL, verify, 140);
    dump_str(fnonce, NULL, soln, 1344);

    fprintf(fnonce, "valid=%s, errtype=%d, ticket mask=%d, diff0=%02x, sha256=%02x%02x%02x%02x\n\n", \
        !valid?"yes":"no", \
        valid, \
        ticket_mask_valid, \
        nonce->diff0, \
        nonce->sha256[0], nonce->sha256[1], nonce->sha256[2], nonce->sha256[3]);
    fflush(fnonce);
    pthread_mutex_unlock(&g_bm1794_app.work_info_mutex);

    return 0;
}

/*
<Nonce Handle>

return:
	=0  	- success
	<0 		- failed
	>0		- crc error happened and return crc mask
*/
static int bm1794_verify_nonce_integrality(struct nonce_rb_format *nonce_rb)
{
	int crc_error = 0;

	for (int i=0;i<16;i++)
	{
		uint16_t crc16 = CRC16(g_nonce_list[i], (91-PLATFORM_CRC16_LEN));
		crc16 = bswap_16(crc16);
		if (memcmp(&crc16, &g_nonce_list[i][91-PLATFORM_CRC16_LEN], 2) != 0) {
			applog(LOG_ERR, "%s CRC error. cal-crc=%x, chip-crc=%x\n", __func__, crc16, g_nonce_list[i][91-PLATFORM_CRC16_LEN]);
			crc_error  = crc_error | (1<<i);
		}
	}

    for (int i=0; i<16; i++)
    {
        if ((g_nonce_list[i][0] & 0x0f) != i) {
            applog(LOG_ERR, "nonce is not continous i=%d\n", i);
            return -1;
        }
    }

    for (int i=0; i<15; i++) {
        if(g_nonce_list[i][1] != g_nonce_list[i+1][1]) {
            applog(LOG_ERR, "chip_addr is different %02x != %02x\n", g_nonce_list[i][1], g_nonce_list[i+1][1]);
            return -1;
        }
    }

    for (int i=0; i<15; i++) {
        if(g_nonce_list[i][2] != g_nonce_list[i+1][2]) {
            applog(LOG_ERR, "workID is different %02x != %02x\n", g_nonce_list[i][2], g_nonce_list[i+1][2]);
            return -1;
        }
    }

    for (int i=0; i<15; i++) {
        if(g_nonce_list[i][3] != g_nonce_list[i+1][3]) {
            applog(LOG_ERR, "nonceID is different %02x != %02x\n", g_nonce_list[i][3], g_nonce_list[i+1][3]);
            return -1;
        }
    }

    // maintain a nonce, length = 1344
    uint8_t *nonce_p = nonce_rb->Nonce;
    for (int i=0; i<15; i++)
    {
        memcpy(nonce_p, &g_nonce_list[i][4], 85);
        nonce_p += 85;
    }
    memcpy(nonce_p, &g_nonce_list[15][4], 85-16);
    memcpy(nonce_rb->chip_nonce, &g_nonce_list[15][85], 4);
    nonce_rb->chip_addr = g_nonce_list[15][1];
    nonce_rb->work_id = g_nonce_list[15][2];
    nonce_rb->nonce_id = g_nonce_list[15][3];
    nonce_rb->diff0 = g_nonce_list[15][76];
    memcpy(nonce_rb->sha256, &g_nonce_list[15][77], 4);
    return crc_error;
}

/*
	return 1 : continue
	return 0 : complete nonce
	return <0: error
*/
static int bm1794_combine_one_nonce(struct nonce_rb_format *nonce_rb, uint8_t *str, uint8_t chain_id)
{
	uint8_t index = (str[0] & 0x0f);
	uint8_t nonceid = str[3];
	static int retransmit = 0;
	int ret = 1;

	//a special handle for txoken enable
	if (nonceid != nonce_rb->nonce_id && retransmit == 1) {
		printf("retransmit == 1\n");
		retransmit = 0;
		ret = bm1794_verify_nonce_integrality(nonce_rb);	//process the last nonce
		memcpy(g_nonce_list[index], str, 91);	//save the new comming packet
		return ret;
	}

	memcpy(g_nonce_list[index], str, 91);

	if (index == 15 && retransmit == 0) {
		ret = bm1794_verify_nonce_integrality(nonce_rb);	//process the last nonce
		if (ret > 0 && bm1794_info.txok_en == 1) {
			struct base_param32_t item;
			item.all = 0;
			item.chip_addr = nonce_rb->chip_addr;
			item.param = ret;
			g_midd_api.ioctl(g_chain[chain_id].fd, IOCTL_SET_NONCE_TXOK, &item);
			retransmit = 1;
			printf("enable retransmit\n");
		}
	}
	return ret;
}

static void *bm1794_get_nonce()
{
    struct nonce_rb_format nonce;

	uint8_t str[200] = {0};
	uint8_t chain_id;
	int ret = 0;

    FILE *fnonce = fopen("fnonce.txt", "a+");
    if (fnonce == NULL) {
        applog(LOG_ERR, "open fnonce failed %s\n", strerror(errno));
        exit(1);
    }

	pthread_detach(pthread_self());

    while(g_bm1794_app.is_alive)
    {
        g_midd_api.recv_work((uint8_t *)&str, PLATFORM_RESP_NONCE_LEN);
		g_midd_api.recv_work(&chain_id, 1);

		/* combine 16 packets to a complete nonce */
		ret = bm1794_combine_one_nonce(&nonce, &str[2], chain_id);
		if (ret == 0){
			bm1794_handle_nonce(fnonce, &nonce);
	    } else if (ret < 0) {
			printf("receive a error nonce\n");
		} else {
			//continue receive next packets
		}
    }

    fclose(fnonce);
    return NULL;
}

static void *bm1794_get_reg()
{
    struct reg_respond reg;
	struct reg_scan_item_t new_item;
	uint8_t chain_id;
    FILE *freg = fopen("freg.txt", "a+");
    if (freg == NULL) {
        applog(LOG_ERR, "open freg failed %s\n", strerror(errno));
        exit(1);
    }
	pthread_detach(pthread_self());

    while(g_bm1794_app.is_alive)
    {
        g_midd_api.recv_regdata((uint8_t *)&reg, PLATFORM_RESP_REG_LEN);
		g_midd_api.recv_regdata(&chain_id, 1);

		new_item.age = 3;
		new_item.chain_id = chain_id;
		new_item.chip_addr = reg.chip_addr;
		new_item.reg_addr = reg.reg_addr[0] << 16 | reg.reg_addr[1] << 8 | reg.reg_addr[2];
        new_item.reg_data = reg.reg_data[0] << 24 | reg.reg_data[1] << 16 | reg.reg_data[2] << 8 | reg.reg_data[3];
		add_reg_item(new_item);


		read_reg_item(&new_item);
        fprintf(freg, "addr:%02x data=%02x%02x%02x%02x chip=%02x\n", reg.reg_addr, reg.reg_data[0], reg.reg_data[1], reg.reg_data[2], reg.reg_data[3], reg.chip_addr);
        fflush(freg);
    }

    fclose(freg);
    return NULL;
}

static void *bm1794_get_pmonitor()
{
    struct pmonitor_respond pm;
	uint8_t chain_id;

    // for test
    FILE *fpm = fopen("fpm.txt", "a+");
    if (fpm == NULL) {
        applog(LOG_ERR, "open fpm failed %s\n", strerror(errno));
        exit(1);
    }
	pthread_detach(pthread_self());

    while(g_bm1794_app.is_alive)
    {
        g_midd_api.recv_pmonitor((uint8_t *)&pm, sizeof(struct pmonitor_respond));
		g_midd_api.recv_pmonitor(&chain_id, 1);
        fprintf(fpm, "data=%08x chip=%02x\n", *(uint32_t*)pm.pm_data, pm.chip_addr);
        fflush(fpm);
    }

    fclose(fpm);
    return NULL;
}

/*
** Read a complete line from stdin. If 2 or more lines are available, store
** only the last one in the buffer.
**
** buf		buffer to store the line
** len		length of the buffer
** block	blocking mode: do not return until a line was read
**
** Return 1 iff a line was read.
*/
int read_last_line(char *buf, size_t len, int block)
{
    char	*start;
    size_t	pos = 0;
    ssize_t	n;

    set_blocking_mode(0, block);
    while (42)
    {
	    n = read(0, buf + pos, len - pos);
    	if (n == -1 && errno == EINTR)
    	    continue ;
    	else if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    	{
    	    if (!pos)
    		    return 0;
    	    applog(LOG_WARNING, "strange: a partial line was read %s\n", strerror(errno));
    	    // a partial line was read, continue reading it in blocking mode
    	    // to be sure to read it completely
    	    set_blocking_mode(0, 1);
    	    continue ;
    	}
    	else if (n == -1)
    	    applog(LOG_ERR, "read stdin: %s\n", strerror(errno));
    	else if (!n)
    	    applog(LOG_ERR, "%s EOF on stdin\n", __func__);

        pos += n;
	    if (buf[pos - 1] == '\n')
	        // 1 (or more) complete lines were read
	        break ;
    }

    start = memrchr(buf, '\n', pos - 1);
    if (start)
    {
        applog(LOG_WARNING, "%s strange: more than 1 line was read\n", __func__);
        // more than 1 line; copy the last line to the beginning of the buffer
        pos -= (start + 1 - buf);
        memmove(buf, start + 1, pos);
    }
    // overwrite '\n' with NUL
    buf[pos - 1] = 0;
    return 1;
}

/*
** Parse a string:
**   "<target> <job_id> <header> <nonce_leftpart>"
** (all the parts are in hex, except job_id which is a non-whitespace string),
** decode the hex values and store them in the relevant buffers.
**
** The remaining part of <header> that is not set by
** <header><nonce_leftpart> will be randomized so that the miner
** solves a unique Equihash PoW.
**
** str		string to parse
** target	buffer where the <target> will be stored
** target_len	size of target buffer
** job_id	buffer where the <job_id> will be stored
** job_id_len	size of job_id buffer
** header	buffer where the <header><nonce_leftpart> will be
** 		concatenated and stored
** header_len	size of the header_buffer
** fixed_nonce_bytes
** 		nr of bytes represented by <nonce_leftpart> will be stored here;
** 		this is the number of nonce bytes fixed by the stratum server
*/
void mining_parse_job(char *str, uint8_t *target, size_t target_len,
	char *job_id, size_t job_id_len, uint8_t *header, size_t header_len,
	size_t *fixed_nonce_bytes)
{
    uint32_t		str_i, i;

    // parse target
    str_i = 0;
    for (i = 0; i < target_len; i++, str_i += 2)
	    target[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
    assert(str[str_i] == ' ');
    str_i++;

    // parse job_id
    for (i = 0; i < job_id_len && str[str_i] != ' '; i++, str_i++)
	    job_id[i] = str[str_i];
    assert(str[str_i] == ' ');
    assert(i < job_id_len);
    job_id[i] = 0;
    str_i++;

    // parse header and nonce_leftpart
    for (i = 0; i < header_len && str[str_i] != ' '; i++, str_i += 2)
	    header[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
    assert(str[str_i] == ' ');
    str_i++;
    *fixed_nonce_bytes = 0;

    while (i < header_len && str[str_i])
    {
    	header[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
    	i++;
    	str_i += 2;
        (*fixed_nonce_bytes)++;
    }
    assert(!str[str_i]);

    // Randomize rest of the bytes except N_ZERO_BYTES bytes which must be zero
    applog(LOG_DEBUG, "Randomizing %lu bytes in nonce\n", header_len - N_ZERO_BYTES - i);
    randomize(header + i, header_len - N_ZERO_BYTES - i);
    memset(header + header_len - N_ZERO_BYTES, 0, N_ZERO_BYTES);
}

static void *mining_mode()
{
    char        line[4096];
    uint64_t    i = 0;
	struct work_input work;

    //puts("SILENTARMY mining mode ready"), fflush(stdout);
	pthread_detach(pthread_self());

    while (g_bm1794_app.is_alive)
    {
		z_msleep(100);
        if (miner_enable == 0)
            continue;

        if (read_last_line(line, sizeof (line), !i)) {
            pthread_mutex_lock(&g_bm1794_app.work_info_mutex);
            mining_parse_job(line,
                    g_bm1794_app.work_info.target, SHA256_DIGEST_SIZE,
                    g_bm1794_app.work_info.job_id, 256,
                    g_bm1794_app.work_info.header, ZCASH_HEAD_LEN, //ZCASH_BLOCK_HEADER_LEN,
                    &g_bm1794_app.work_info.fixed_nonce_bytes);
			work.type = 0x01;
			work.sno_valid = 1;
			work.workid = 0;
            work.start_nonce = 0;
			memcpy(work.head, g_bm1794_app.work_info.header, ZCASH_HEAD_LEN);
            g_midd_api.send_work((uint8_t *)&work, sizeof(work));
			dump_str(fl, NULL, work.head, ZCASH_HEAD_LEN);
            pthread_mutex_unlock(&g_bm1794_app.work_info_mutex);
        }
    }

    return NULL;
}

int i2c_status(int fd, uint8_t chain_id, uint8_t chip_addr, uint32_t *i2c_reg_data)
{
	struct base_param_t item;
	const int timeout_ms = 3000;
	const int query_interval_ms = 200;
	struct reg_scan_item_t reg_scan_item = {chain_id, chip_addr, REG_GENERAL_I2C_COMMAND, 0, 0};

	item.all = 0;
	item.chip_addr = chip_addr;
	g_midd_api.ioctl(fd, IOCTL_I2C_STATUS, &item);

	for (int count=0;count<(timeout_ms/query_interval_ms);count++)
	{
		z_msleep(query_interval_ms);
		if (read_reg_item(&reg_scan_item) > 0){
			*i2c_reg_data = reg_scan_item.reg_data;
			return 1;
		}
	}

	printf("not received the i2c response\n");
	return -1;
}

int i2c_read(int fd, uint8_t chain_id, uint8_t chip_addr, uint8_t i2c_dev_addr, uint8_t i2c_reg_addr, uint8_t *reg_data)
{
	platform_reg_t union_reg;

	if (i2c_status(fd, chain_id, chip_addr, &union_reg.reg_bin) < 0) {
		return -1;
	}

	if (union_reg.general_i2c_command.busy == 1) {
		printf("i2c is busy\n");
		return -1;
	}

	// set dev_addr and reg_addr and enable read
	struct i2c_read_t r_item;
	r_item.all = 0;
	r_item.chip_addr = chip_addr;
	r_item.dev_addr = i2c_dev_addr;
	r_item.reg_addr = i2c_reg_addr;
	g_midd_api.ioctl(fd, IOCTL_I2C_READ, &r_item);

	for (int count=0; count<5; count++)
	{
		if (i2c_status(fd, chain_id, chip_addr, &union_reg.reg_bin) < 0)
			continue;
		else {
			*reg_data = union_reg.general_i2c_command.data;
			return 1;
		}
	}

	return -1;
}

int i2c_write(int fd, uint8_t chain_id, uint8_t chip_addr, uint8_t i2c_dev_addr, uint8_t i2c_reg_addr, uint8_t reg_data)
{
	platform_reg_t union_reg;

	if (i2c_status(fd, chain_id, chip_addr, &union_reg.reg_bin) < 0) {
		return -1;
	}

	if (union_reg.general_i2c_command.busy == 1) {
		printf("i2c is busy\n");
		return -1;
	}

	// set dev_addr and reg_addr and enable read
	struct i2c_write_t w_item;
	w_item.all = 0;
	w_item.chip_addr = chip_addr;
	w_item.dev_addr = i2c_dev_addr;
	w_item.reg_addr = i2c_reg_addr;
	w_item.reg_data = reg_data;
	g_midd_api.ioctl(fd, IOCTL_I2C_WRITE, &w_item);

	return 1;
}

int open_tty_dev(void *arg)
{
	struct std_chain_info *chain = (struct std_chain_info *)arg;
    struct uart_info param;

    param.speed = chain->bandrate;
    param.flow_ctrl = 0;
    param.databits = 8;
    param.stopbits = 1;
    param.parity = 'N';
    param.cc_vtime = 0;
    param.cc_vmin = 1024;

    int fd = g_comm_api.bm_open(chain->devname, &param);
    if (fd < 0) {
        applog(LOG_ERR, "%s open %s failed\n", __func__, chain->devname);
        return -1;
    }

	chain->fd = fd;

	return 0;
}

void close_tty_dev(void *arg)
{
    struct std_chain_info *chain = (struct std_chain_info *)arg;
    g_comm_api.bm_close(chain->fd);
}

#define UART_DEV    "ttyUSB2"

int chain_init(int chain_id)
{
    struct std_chain_info *chain = &g_chain[chain_id];

    //#ifdef WIN32
    //sprintf(chain->devname, "COM%d", tty[chain_id]);
    //#else
    //sprintf(chain->devname, "ttyUSB%d", tty[chain_id]);
    //#endif
    memcpy(chain->devname, UART_DEV, sizeof(UART_DEV));

    applog(LOG_INFO, "name of the dev: %s", chain->devname);
    chain->bandrate = 19200;
    chain->chain_id = chain_id;

    open_tty_dev(chain);
    start_dispatch_packet(chain);
    start_send_work(chain);

    return 0;
}

void chain_exit(int chain_id)
{
	struct std_chain_info *chain = &g_chain[chain_id];

	close_tty_dev(chain);
	stop_dispatch_packet(chain);
	stop_send_work(chain);
}

int bm1794_app_init()
{
    int ret;

    g_bm1794_app.is_alive = 1;
    pthread_mutex_init(&g_bm1794_app.work_info_mutex, NULL);

	memset(g_bm1794_app.work_info.target, 0xff, SHA256_DIGEST_SIZE);

	reg_scan_init();

	for (int chain_id=0; chain_id<MAX_CHAIN_NUM; chain_id++)
	{
		chain_init(chain_id);
	}

    if(0 != (ret = pthread_create(&g_bm1794_app.p_get_nonce_back, NULL, bm1794_get_nonce, NULL)))
    {
       applog(LOG_ERR, "create get_nonce_back thread failed ret = %d\n", ret);
       return -1;
    }

    if(0 != (ret = pthread_create(&g_bm1794_app.p_get_reg_back, NULL, bm1794_get_reg, NULL))) {
       applog(LOG_ERR, "create get_reg_back thread failed ret = %d\n", ret);
       return -1;
    }

    if(0 != (ret = pthread_create(&g_bm1794_app.p_get_pm_monitor, NULL, bm1794_get_pmonitor, NULL))) {
       applog(LOG_ERR, "create get_pm_monitor thread failed ret = %d\n", ret);
       return -1;
    }

	fl= fopen("fl.txt", "a+");
	if (fl == NULL) {
		applog(LOG_ERR, "open fl failed %s\n", strerror(errno));
		exit(1);
	}

    if (0 != (ret = pthread_create(&g_bm1794_app.p_mining_mode, NULL, mining_mode, NULL))) {
        applog(LOG_ERR, "create mining mode thread failed ret = %d\n", ret);
        return -1;
    }

#if 0
    struct base_param32_t item;
    item.all = 1;
    item.chip_addr = 0x00;
    item.param = 0x00100000;
	for (int chain_id=0;chain_id<MAX_CHAIN_NUM;chain_id++)
    	g_midd_api.ioctl(g_chain[chain_id].fd, IOCTL_SET_CORE_TIMEOUT, &item);

    item.all = 1;
    item.chip_addr = 0x00;
    item.param = 0x00000002;
	for (int chain_id=0;chain_id<MAX_CHAIN_NUM;chain_id++)
    	g_midd_api.ioctl(g_chain[chain_id].fd, IOCTL_SET_TICKET_MASK, &item);
#endif

    return 0;
}

void bm1794_app_exit()
{
    g_bm1794_app.is_alive = 0;

	reg_scan_exit();

	for (int chain_id=0; chain_id<MAX_CHAIN_NUM; chain_id++)
	{
		chain_exit(chain_id);
	}

    pthread_cancel(g_bm1794_app.p_get_nonce_back);
    pthread_cancel(g_bm1794_app.p_get_reg_back);
    pthread_cancel(g_bm1794_app.p_get_pm_monitor);

	pthread_cancel(g_bm1794_app.p_mining_mode);
	fclose(fl);

    pthread_mutex_destroy(&(g_bm1794_app.work_info_mutex));
}
