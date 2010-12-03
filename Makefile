witm: witm.o got_packet.o
	gcc -g -lpcap got_packet.o witm.o -o witm

witm.o: witm.c
	gcc -g -I/opt/libdumbnet/include -c witm.c

got_packet.o: got_packet.c
	gcc -g -I/opt/libdumbnet/include -c got_packet.c
