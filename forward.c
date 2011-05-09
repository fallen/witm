#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#ifdef DNET_NAME
#include DNET_NAME
#else
#include <dnet.h>
#endif

#include "witm.h"

extern pcap_t *handle;
extern eth_addr_t my_mac_addr;

void forward(const u_char *packet, size_t size, eth_addr_t to) {

	struct eth_hdr *header_ethernet;
	u_char *new_packet;
	int ret;
	size_t i;

	printf("We forward\n");
	printf("\t size of the packet = %ld\n", size);


	printf("A dump of what we received from the network : \n");
	for (i = 0 ; i < size ; i++) {
		printf("%02X ", packet[i]);
	}

	new_packet = malloc(sizeof(u_char) * size);

	if (new_packet == NULL) {
		perror("Error : cannot allocate memory for a new packet");
		exit(1);
	}

	memcpy(new_packet, packet, size);
	header_ethernet = (struct eth_hdr *)new_packet;

	memcpy(header_ethernet->eth_src.data, my_mac_addr.data, ETH_ADDR_LEN);
	memcpy(header_ethernet->eth_dst.data, to.data, ETH_ADDR_LEN);

	ret = pcap_sendpacket(handle, new_packet, size);

	if (ret < 0) {
		printf("\t ERROR : failed to forward packet\n");
		exit(1);
	}

	printf("A dump of what we sent to the network : \n");
	for (i = 0 ; i < size ; i++) {
		printf("%02X ", new_packet[i]);
	}

	printf("\n");
	free(new_packet);
}
