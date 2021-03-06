#ifndef __WITM_H__
#define __WITM_H__

void print_mac_address(eth_addr_t addr);
void string_to_mac_addr(char *string, eth_addr_t *addr);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void forward(const u_char *packet, size_t taille, eth_addr_t to);
void arp_request(eth_addr_t to, eth_addr_t from, eth_addr_t sha, ip_addr_t spa, eth_addr_t tha, ip_addr_t tpa);
void arp_answer(eth_addr_t victim_mac, uint8_t *victim_ip, uint8_t *router_ip);

void *poisoning_thread(void *);

#endif
