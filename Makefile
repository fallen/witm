include Makefile.include

CFLAGS += -g -I${LIBDUMBNET_INCLUDE_PATH}
LDLIBS += -lpcap

witm: witm.o got_packet.o forward.o
	gcc -g ${LDLIBS} forward.o got_packet.o witm.o -o witm

witm.o: witm.c
	gcc ${CFLAGS} -c witm.c

got_packet.o: got_packet.c
	gcc ${CFLAGS} -c got_packet.c

forward.o: forward.c
	gcc ${CFLAGS} -c forward.c
