#include "http.h"

#define HTTP_PORT 80

int is_http_packet(const u_char *packet, size_t size)
{
  struct tcp_hdr *tcp_header;

  if (size < (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN))
    return 0;

  tcp_header = (struct tcp_hdr *)(packet + ETH_HDR_LEN + IP_HDR_LEN);

  return (tcp_header->th_sport == HTTP_PORT || tcp_header->th_dport == HTTP_PORT);

}

void http_postprocess(u_char *packet, size_t size)
{

}
