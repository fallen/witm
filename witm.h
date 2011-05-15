#ifndef __WITM_H__
#define __WITM_H__

#include <pcap.h>

#ifdef DNET_NAME
#include DNET_NAME
#else
#include <dnet.h>
#endif

struct plugin {
	char *name; // name of the plugin
	char *author; // name of the plugin's author
	void *lib; // pointer returned by dlopen()
  int (*do_match)(const u_char *packet);
  void (*process_packet)(u_char *packet, size_t size);
	struct plugin *next; // next plugin of the linked list
};

void print_mac_address(eth_addr_t addr);
void string_to_mac_addr(char *string, eth_addr_t *addr);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void forward(const u_char *packet, size_t taille, eth_addr_t to);
void arp_request(eth_addr_t to, eth_addr_t from, eth_addr_t sha, ip_addr_t spa, eth_addr_t tha, ip_addr_t tpa);
int load_plugins(void);
int add_plugin(char *name, char *author, void *lib, int (*do_match)(const u_char *), void (*process_packet)(u_char *, size_t));
void arp_answer(eth_addr_t victim_mac, uint8_t *victim_ip, uint8_t *router_ip);


void show_plugins_info(void);

void *poisoning_thread(void *);

#endif
