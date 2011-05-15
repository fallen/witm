#include <stdio.h>

#include "icmp.h"
#include "ip.h"
#include "witm.h"

char name[] = "ping_hack";
char author[] = "Yann Sionneau";

int do_match(const u_char *packet, size_t size)
{
  return is_ip_packet(packet, size);
}

void process_packet(u_char *packet, size_t size)
{
  printf("\n[ping_hack] We process the packet\n");

  if ( ! is_icmp_packet(packet, size) )
    return;

  packet[size - 1] = '@'; // modify the last byte by a @

  ip_postprocess(packet, size);
}

int startup(void) {

	printf("[ping_hack] plugin started !\n");

	return 1;
}
