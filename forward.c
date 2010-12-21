#include <stdio.h>
#include <dnet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#include "witm.h"

extern pcap_t *handle;
extern eth_addr_t my_mac_addr;

void forward(const u_char *packet, size_t taille, eth_addr_t to) {

	struct eth_hdr *header_ethernet;
	u_char *new_packet;
	int ret;

	printf("On forward\n");
	printf("\t taille = %ld\n", taille);
	new_packet = malloc(sizeof(u_char) * taille);
	memcpy(new_packet, packet, taille);
	header_ethernet = (struct eth_hdr *)new_packet;

	memcpy(header_ethernet->eth_src.data, my_mac_addr.data, ETH_ADDR_LEN);
	memcpy(header_ethernet->eth_dst.data, to.data, ETH_ADDR_LEN);

	ret = pcap_sendpacket(handle, new_packet, taille);

	if (ret < 0) {
		printf("ERROR : failed to forward packet\n");
		exit(1);
	}
}
