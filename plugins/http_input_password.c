#include <stdio.h>

#include "http.h"
#include "witm.h"

char name[] = "http_input_password";
char author[] = "Yann Sionneau";

int do_match(const u_char *packet, size_t size)
{

  printf("\nTEST TEST TEST\n");
  fflush(stdout);

  if ( ! is_tcp_packet(packet, size) )
  {
    printf("\nNOT A TCP PACKET\n");
    return 0;
  }

  return 1; 
}

void process_packet(u_char *packet, size_t size)
{
  printf("\n[http_input_password] We process the packet\n");

  http_postprocess(packet, size);
  tcp_postprocess(packet, size);
  ip_postprocess(packet, size);

}

int startup(void)
{
  
  printf("[http_input_password] plugin started !\n");

  return 1;
}
