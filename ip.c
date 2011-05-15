#include <stdio.h>

#include "ip.h"

int is_ip_packet(u_char *packet, size_t size)
{
  struct eth_hdr *ethernet_header;

  if (size < ETH_HDR_LEN) // Too short to have a valid Ethernet Header
    return 0;

  ethernet_header = (struct eth_hdr *)packet;

  printf("\nEther Type == %04X\n", ntohs(ethernet_header->eth_type));

  return (ntohs(ethernet_header->eth_type) == ETH_TYPE_IP);
}

static inline void update_ip_checksum(u_char *packet, size_t size)
{
  ip_checksum(packet + ETH_HDR_LEN, size - ETH_HDR_LEN);
}

void ip_postprocess(u_char *packet, size_t size)
{
  update_ip_checksum(packet, size);
}
