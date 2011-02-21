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

struct arp_packet {
	struct eth_hdr ethernet_header;
	struct arp_hdr arp_header;
	struct arp_ethip arp_payload;
} __attribute__((__packed__));

void arp_request(eth_addr_t to, eth_addr_t from, eth_addr_t sha, ip_addr_t spa, eth_addr_t tha, ip_addr_t tpa) {

	int ret, i;
	struct arp_packet packet;
	//uint32_t spa2, tpa2;

	//spa2 = *(uint32_t *)spa;
	//tpa2 = *(uint32_t *)tpa;

	eth_pack_hdr(&packet, to, from, ETH_TYPE_ARP);
	arp_pack_hdr_ethip((uint8_t *)&packet + sizeof(struct eth_hdr), ARP_OP_REQUEST, sha, spa, tha, tpa);

	ret = pcap_sendpacket(handle, (u_char *)&packet, sizeof(struct arp_packet));

	if (ret < 0) {
		printf("ERROR : failed to forward packet\n");
		exit(1);
	}

	printf("On envoie un paquet arp request : \n");
	for (i = 0 ; i < sizeof(struct arp_packet) ; i++)
		printf("0x%02hhX ", *((uint8_t *)&packet + i));
	printf("\n");

}
