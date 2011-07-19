#include "icmp.h"

int is_icmp_packet(u_char *packet, size_t size)
{
  struct ip_hdr *ip_header;

  if (size < (ETH_HDR_LEN + IP_HDR_LEN))
    return 0;

  ip_header = (struct ip_hdr *)(packet + ETH_HDR_LEN + IP_HDR_LEN);

  return (ip_header->ip_p == IP_PROTO_ICMP);

}
