#include <stdio.h>

char name[] = "test2";
char author[] = "Yannou";

int do_match(const char *packet)
{
  return 0;
}

void process_packet(char *packet)
{
  printf("[test2] We process the packet\n");
}

int startup(void) {

	printf("Ok test2 !\n");

	return 1;
}
