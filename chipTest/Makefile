#CROSS_COMPILER_PATH=/Users/felix/Desktop/share/make-package/gcc-linaro-arm-linux-gnueabihf-4.7-2012.11-20121123_linux
#CROSS_COMPILER=arm-linux-gnueabihf-
#CC=$CROSS_COMPILER_PATH/bin/$CROSS_COMPILER-gcc

LDFLAGS += -pthread
CFLAGS += -O0 -g -Wextra -Wall -std=gnu99

#LIB_DIR += -lpthread

INCLUDE_DIR += \
		-I $(CURDIR)/app/bm1794  \
		-I $(CURDIR)/app  \
		-I $(CURDIR)/start  \
		-I $(CURDIR)/common  \
		-I $(CURDIR)/uart  \
		-I $(CURDIR)/driver \
		-I $(CURDIR)/middle \
        	-I $(CURDIR)/crypt \
        	-I $(CURDIR)/pool \
		-I $(CURDIR)/debugtool

BIN=bm1794_chipTest
SUBDIR=$(shell ls -d */)
ROOTSRC=$(wildcard *.c)
ROOTOBJ=$(ROOTSRC: %.c=%.o)
SUBSRC=$(shell find $(SUBDIR) -name '*.c')
SUBOBJ=$(SUBSRC:%.c=%.o)

$(BIN): $(ROOTOBJ) $(SUBOBJ)
	$(CC) $(CFLAGS) $(LIB_DIR) $(INCLUDE_DIR) $(LDFLAGS) -o $(BIN) $(ROOTOBJ) $(SUBOBJ)
.c.o:
	$(CC) $(CFLAGS) $(LIB_DIR) $(INCLUDE_DIR) -c $< -o $@

clean:
	rm -f $(BIN) $(ROOTOBJ) $(SUBOBJ)


