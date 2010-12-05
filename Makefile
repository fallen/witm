include Makefile.include

CFLAGS += -Wall -Wextra -O3 -g -I${LIBDUMBNET_INCLUDE_PATH}
LDLIBS += -lpcap

witm: witm.o got_packet.o forward.o

clean:
	rm -rf *.o

distclean: clean
	rm -rf witm
