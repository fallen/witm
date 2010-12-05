include Makefile.include

CFLAGS += -g -I${LIBDUMBNET_INCLUDE_PATH}
LDLIBS += -lpcap

witm: witm.o got_packet.o forward.o
