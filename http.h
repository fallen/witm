#ifndef __HTTP_H__
#define __HTTP_H__

#include "witm.h"
#include "tcp.h"

int is_http_packet(const u_char *packet, size_t size);
void http_postprocess(u_char *packet, size_t size);

#endif
