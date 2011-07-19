#include "http.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

#define HTTP_PORT 80

int is_http_packet(const u_char *packet, size_t size)
{
  struct tcp_hdr *tcp_header;

  if (size < (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN))
    return 0;

  tcp_header = (struct tcp_hdr *)(packet + ETH_HDR_LEN + IP_HDR_LEN);

  return (tcp_header->th_sport == HTTP_PORT || tcp_header->th_dport == HTTP_PORT);

}

void http_postprocess(u_char **packet, size_t size, int content_length_delta)
{
  u_char *p = *packet;
  int content_length;
  u_char *new_packet;
  u_char *http_packet = p + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
  char *content_length_str;

  if (content_length_delta == 0)
    return;

  content_length_str = strstr((char *)http_packet, "Content-Length: ");

  if (content_length_str == NULL)
    return;

  content_length_str += strlen("Content-Length: ");

  sscanf(content_length_str, "%d", &content_length);

  if (log10(content_length) == log10(content_length_delta))
  {
    sprintf(content_length_str, "%d", content_length + content_length_delta);
    return;
  }

  new_packet = realloc(p, size + content_length_delta);

  memcpy(new_packet, p, (u_char *)content_length_str - p);
  sprintf((char *)new_packet + ((u_char *)content_length_str - p), "%d", content_length + (int)content_length_delta);
  memcpy(new_packet + ((u_char *)content_length_str - p) + (int)log10(content_length + content_length_delta), content_length_str + (int)log10(content_length), size + content_length_delta);

  packet = &new_packet;
}
