#ifndef __TCP_H__
#define __TCP_H__

#include "witm.h"
#include "ip.h"

struct tcp_pseudo_header
{
  uint32_t ip_addr_s;
  uint32_t ip_addr_d;
  char reserved; // == 0
  char proto; // TCP == 6
  uint16_t tcp_length;
  u_char tcp_segment[ETH_LEN_MAX];
} __attribute__((packed));

int is_tcp_packet(const u_char *packet, size_t size);
void tcp_postprocess(u_char *packet, size_t size);

#endif
