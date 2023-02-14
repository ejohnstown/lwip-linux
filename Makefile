CROSS_COMPILE:=
CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)gcc
AS:=$(CROSS_COMPILE)gcc
OBJCOPY:=$(CROSS_COMPILE)objcopy
SIZE:=$(CROSS_COMPILE)size
WOLFSSL_ROOT:=$(PWD)/wolfssl
WOLFSSH_ROOT:=$(PWD)/wolfssh
LWIP_ROOT:=$(PWD)/lwip/src
LWIP_BUILD:=$(PWD)/build
WOLFSSL_BUILD:=./build/lib
DEBUG?=1

CFLAGS+=-Wall -Wextra -Wno-main -Wstack-usage=1024 -Wno-unused \
		-I. \
	    -I build/include  \
	    -I lwip/src/include  \
		-I lwip/contrib/ports/unix/port/include \
		-pthread \
	-DWOLFSSL_USER_SETTINGS -I$(WOLFSSL_ROOT) -I$(WOLFSSH_ROOT) 

ifneq ($(DEBUG),0)
  CFLAGS+=-O0 -ggdb3
else
  CFLAGS+=-Os
endif


LDFLAGS=$(CFLAGS) -Wl,-gc-sections -Wl,-Map=image.map -Wl,-lc -Wl,-lm -Wl,-lpthread




OBJS:= \
  $(WOLFSSH_ROOT)/src/internal.o \
  $(WOLFSSH_ROOT)/src/ssh.o \
  $(WOLFSSH_ROOT)/src/log.o \
  $(WOLFSSH_ROOT)/src/io.o \
  $(WOLFSSH_ROOT)/src/port.o \
  $(WOLFSSH_ROOT)/src/wolfsftp.o \
  $(PWD)/wolfsshd.o \
  $(PWD)/default_netif.o \
  $(LWIP_BUILD)/api/api_lib.o \
  $(LWIP_BUILD)/api/api_msg.o \
  $(LWIP_BUILD)/api/err.o \
  $(LWIP_BUILD)/api/netbuf.o \
  $(LWIP_BUILD)/api/netdb.o \
  $(LWIP_BUILD)/api/netifapi.o \
  $(LWIP_BUILD)/api/sockets.o \
  $(LWIP_BUILD)/api/tcpip.o \
  $(LWIP_BUILD)/core/def.o \
  $(LWIP_BUILD)/core/inet_chksum.o \
  $(LWIP_BUILD)/core/init.o \
  $(LWIP_BUILD)/core/mem.o \
  $(LWIP_BUILD)/core/memp.o \
  $(LWIP_BUILD)/core/netif.o \
  $(LWIP_BUILD)/core/pbuf.o \
  $(LWIP_BUILD)/core/stats.o \
  $(LWIP_BUILD)/core/sys.o \
  $(LWIP_BUILD)/core/tcp.o \
  $(LWIP_BUILD)/core/tcp_in.o \
  $(LWIP_BUILD)/core/tcp_out.o \
  $(LWIP_BUILD)/core/timeouts.o \
  $(LWIP_BUILD)/core/udp.o \
  $(LWIP_BUILD)/core/ip.o \
  $(LWIP_BUILD)/core/ipv4/autoip.o \
  $(LWIP_BUILD)/core/ipv4/dhcp.o \
  $(LWIP_BUILD)/core/ipv4/etharp.o \
  $(LWIP_BUILD)/core/ipv4/acd.o \
  $(LWIP_BUILD)/core/ipv4/icmp.o \
  $(LWIP_BUILD)/core/ipv4/igmp.o \
  $(LWIP_BUILD)/core/ipv4/ip4.o \
  $(LWIP_BUILD)/core/ipv4/ip4_addr.o \
  $(LWIP_BUILD)/core/ipv4/ip4_frag.o \
  $(LWIP_BUILD)/unix/netif/tapif.o \
  $(LWIP_BUILD)/netif/ethernet.o \
  $(LWIP_BUILD)/unix/sys_arch.o



WOLFSSL_OBJS += 	\
	$(WOLFSSL_BUILD)/wolfcrypt/aes.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/asn.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/chacha.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/chacha20_poly1305.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/coding.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/curve25519.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/error.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/ecc.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/ed25519.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/dh.o \
	$(WOLFSSL_BUILD)/wolfcrypt/rsa.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/fe_low_mem.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/fe_operations.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/ge_low_mem.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/ge_operations.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/hash.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/hmac.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/integer.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/logging.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/md5.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/memory.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/poly1305.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/pwdbased.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/random.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/sha.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/sha3.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/sha256.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/sha512.o  \
    $(WOLFSSL_BUILD)/wolfcrypt/signature.o \
	$(WOLFSSL_BUILD)/wolfcrypt/wc_encrypt.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/wc_port.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/wolfmath.o
	
OBJS_SPMATH:= $(WOLFSSL_BUILD)/wolfcrypt/sp_c64.o  \
	$(WOLFSSL_BUILD)/wolfcrypt/sp_int.o \
	$(WOLFSSL_BUILD)/wolfcrypt/sp_x86_64.o 

	

OBJS+=$(WOLFSSL_OBJS) $(OBJS_SPMATH)

vpath %.c $(dir $(WOLFSSL_ROOT)/src)
vpath %.c $(dir $(WOLFSSL_ROOT)/wolfcrypt/src)

vpath %.c $(dir $(LWIP_ROOT)/core)
vpath %.c $(dir $(LWIP_ROOT)/lwip/contrib/ports/unix/port/netif)
vpath %.c $(dir $(LWIP_ROOT)/api)
vpath %.c $(dir $(LWIP_ROOT)/netif)

all: image.elf

$(WOLFSSL_BUILD)/wolfcrypt:
	mkdir -p $(@)

$(LWIP_BUILD)/core:
	mkdir -p $(@)/ipv4

$(LWIP_BUILD)/api:
	mkdir -p $(@)

$(LWIP_BUILD)/netif:
	mkdir -p $(@)

$(LWIP_BUILD)/unix:
	mkdir -p $(@)/netif

%.o:%.S
	$(CC) -c -o $(@) $(CFLAGS) $^

%.o:%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(WOLFSSL_BUILD)/%.o: $(WOLFSSL_ROOT)/src/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(WOLFSSL_BUILD)/wolfcrypt/%.o: $(WOLFSSL_ROOT)/wolfcrypt/src/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(LWIP_BUILD)/core/%.o: $(LWIP_ROOT)/core/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(LWIP_BUILD)/core/ipv4/%.o: $(LWIP_ROOT)/core/ipv4/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(LWIP_BUILD)/api/%.o: $(LWIP_ROOT)/api/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(LWIP_BUILD)/netif/%.o: $(LWIP_ROOT)/netif/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(LWIP_BUILD)/unix/netif/%.o: $(LWIP_ROOT)/../contrib/ports/unix/port/netif/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^

$(LWIP_BUILD)/unix/%.o: $(LWIP_ROOT)/../contrib/ports/unix/port/%.c
	$(CC) -c -o $(@) $(CFLAGS) $^



image.elf: $(WOLFSSL_BUILD)/wolfcrypt $(LWIP_BUILD)/unix $(LWIP_BUILD)/core $(LWIP_BUILD)/api $(LWIP_BUILD)/netif $(LIBS) $(OBJS) $(LSCRIPT)
	$(LD) $(LDFLAGS) -Wl,--start-group $(OBJS) $(LIBS) -Wl,--end-group -o $@

clean:
	rm -f *.bin *.elf $(OBJS) wolfboot.map *.bin  *.hex src/*.o freeRTOS/*.o wolfssh/src/*.o  *.map tags

FORCE:
