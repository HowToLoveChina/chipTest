#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define FIFO_SERVER2CLIENT             "/tmp/fifo_s2c"
#define FIFO_CLIENT2SERVER             "/tmp/fifo_c2s"
#define FIFO_SIZE               1024

void print_u8s( const char *info, uint8_t buf[ ], int n)
{
  printf( "%s:", info);
  for ( int i = 0; i < n; i++) {
    if ((i%8) == 0) printf("\n  ");
    printf( "0x%02x, ", (uint8_t)buf[ i]);
  }
  printf( "\n\n");
}


int main(int argc, char *argv[])
{
    int fd_read;
    int fd_write;

    char send_buf[FIFO_SIZE] = {0};
    char recv_buf[FIFO_SIZE] = {0};
    int ret_code = 0;

    fd_write = open(FIFO_CLIENT2SERVER, O_WRONLY);
    if (fd_write < 0) {
        printf("open failed %s\n", strerror(errno));
        return -1;
    }

    fd_read = open(FIFO_SERVER2CLIENT, O_RDONLY);
    if (fd_read < 0){
        printf("open failed %s\n", strerror(errno));
        return -1;
    }

    int argcs = argc-1;
    char *pbuf = send_buf;
    memcpy(pbuf, &argcs, sizeof(int));
    pbuf += sizeof(int);
    for (int i=1; i<argc; i++)
    {
        memcpy(pbuf, argv[i], strlen(argv[i])+1);
        pbuf += (strlen(argv[i])+1);
    }

    write(fd_write, send_buf, pbuf-send_buf);
    int len = read(fd_read, recv_buf, FIFO_SIZE);
    print_u8s("receive data", recv_buf, len);

    ret_code = recv_buf[3] << 24 | recv_buf[2] << 16 | recv_buf[1] << 8 | recv_buf[3];

    printf("%s\n", &recv_buf[4]);

    close(fd_read);
    close(fd_write);
    return 0;
}

