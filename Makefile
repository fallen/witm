include Makefile.include

witm: witm.o got_packet.o forward.o
	gcc -g -lpcap forward.o got_packet.o witm.o -o witm

witm.o: witm.c
	gcc -g -I${LIBDUMBNET_INCLUDE_PATH} -c witm.c

got_packet.o: got_packet.c
	gcc -g -I${LIBDUMBNET_INCLUDE_PATH} -c got_packet.c

forward.o: forward.c
	gcc -g -I${LIBDUMBNET_INCLUDE_PATH} -c forward.c
