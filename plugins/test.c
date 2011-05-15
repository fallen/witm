#include <stdio.h>

#include "witm.h"

char name[] = "test";
char author[] = "Yann Sionneau";

int do_match(const char *packet)
{
  return is_ip_packet(packet);
}

void process_packet(char *packet, size_t size)
{
  printf("\n[test] We process the packet\n");

  ip_postprocess(packet, size);
}

int startup(void) {

	printf("Ok on est lancé !\n");

	return 1;
}
