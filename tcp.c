#include <stdio.h>

#include "tcp.h"
#include <string.h>
#include <stdlib.h>

int is_tcp_packet(const u_char *packet, size_t size)
{
  struct ip_hdr *ip_header;

  if (size < ETH_HDR_LEN + IP_HDR_LEN)
    return 0;

  ip_header = (struct ip_hdr *)(packet + ETH_HDR_LEN);

  return (ip_header->ip_p == IP_PROTO_TCP);
}

static inline void update_tcp_checksum(u_char *packet, size_t size)
{
  struct tcp_pseudo_header *tph;
  struct ip_hdr *ip_header;
  struct tcp_hdr *tcp_header;
  uint32_t checksum = 0;
  uint8_t padd = 0;
  uint16_t pseudo_header_length;
  uint16_t word16;
  uint16_t i;

  ip_header = (struct ip_hdr *)(packet + ETH_HDR_LEN);
  tcp_header = (struct tcp_hdr *)(packet + ETH_HDR_LEN + IP_HDR_LEN);
  printf("\n\n TCP checksum was : %04X\n\n", tcp_header->th_sum); 
  tcp_header->th_sum = 0; // set the checksum to 0 before computation
 
  tph = malloc(sizeof(struct tcp_pseudo_header));

  if (tph == NULL)
  {
    printf("Cannot allocate memory for pseudo tcp header\n");
    exit(1);
  }

  printf("LOL");
  memcpy(tph, &(ip_header->ip_src), 8);
  printf("LOL");
  tph->reserved = 0;
  printf("LOL");
  tph->proto = 6;
  printf("LOL");
  tph->tcp_length = size - ETH_HDR_LEN - IP_HDR_LEN;
  printf("LOL");
  memcpy(tph + 12, tcp_header, tph->tcp_length); 
  printf("LOL");
  pseudo_header_length = 12 + tph->tcp_length;

  if (pseudo_header_length & 1)
  {
    padd = 1;
    *((char *)tph + pseudo_header_length) = 0;
  }

  for ( i = 0 ; i < pseudo_header_length + padd ; i += 2)
  {
    word16 = ( ( ((uint16_t *)tph)[i] << 8) & 0xFF00 ) + ( ((uint16_t *)tph)[i + 1] & 0xFF ); 
    checksum += (uint32_t)word16; 
  }   

  while (checksum >> 16) 
    checksum = (checksum & 0xFFFF) + (checksum >> 16); 
 
  checksum = ~checksum;
  free(tph);
  tcp_header->th_sum = (uint16_t)checksum;

  printf("\n\nTCP checksum is now : %04X\n\n", tcp_header->th_sum);
}

void tcp_postprocess(u_char *packet, size_t size)
{
  update_tcp_checksum(packet, size);
}
