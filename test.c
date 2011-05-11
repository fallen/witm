#include <stdio.h>

char name[] = "test";
char author[] = "Yann Sionneau";

int do_match(const char *packet)
{
  return 1;
}

void process_packet(char *packet, size_t size)
{
  printf("\n[test] We process the packet\n");
  packet[size - 1] = '@';
}

int startup(void) {

	printf("Ok on est lancé !\n");

	return 1;
}
