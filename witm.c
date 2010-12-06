#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dnet.h>

#include "witm.h"

pcap_t *handle;
eth_addr_t my_mac_addr;
eth_addr_t router_mac_addr;

int main(int argc, char **argv) {
	int ret;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char arguments[67];

	if (argc < 5) {
		printf("usage : witm networkInterface routerIpAddress routerMacAddress yourMacAddress\n");
		exit(1);
	}

	ret = pcap_lookupnet(argv[1], &netp, &maskp, errbuf);

	if (ret == -1) {
		printf("ERROR : %s\n", errbuf);
		exit(1);
	}	


	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		printf("ERROR : Couldn't open device %s: %s\n", argv[1], errbuf);
		exit(1);
	}
	
	printf("Checking internal stuff...\n");

	eth_addr_t router_addr;
	string_to_mac_addr(argv[3], &router_addr);
	string_to_mac_addr(argv[3], &router_mac_addr);
	printf("Router MAC addr : ");
	print_mac_address(router_addr);
	printf("\n\n");
	sprintf((char *)arguments, "%s;%s;%s;%s", argv[2], argv[3], argv[4], argv[5]);

	// Some debug
	printf("argv 2 = %s\nargv 3 = %s\nargv 4 = %s\nargv 5 = %s\n", argv[2], argv[3], argv[4], argv[5]);
	printf("arguments = %s\n", arguments);

	printf("\n\n sizeof(struct arp_hdr) = %lu\n", sizeof(struct arp_hdr));
	printf("sizeof(struct eth_hdr) = %lu\n", sizeof(struct eth_hdr));
	printf("sizeof(struct arp_ethip) = %lu\n", sizeof(struct arp_ethip));

	printf("Check DONE.\n");

	pcap_loop(handle, -1, got_packet, arguments);
	printf("WITM> v0.1\n\n");

	return 0;
}
