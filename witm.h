#ifndef __WITM_H__
#define __WITM_H__

void print_mac_address(eth_addr_t addr);
void string_to_mac_addr(char *string, eth_addr_t *addr);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


#endif
