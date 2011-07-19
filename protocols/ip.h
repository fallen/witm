#ifndef __IP_H__
#define __IP_H__

#include "witm.h"

int is_ip_packet(const u_char *packet, size_t size);
void ip_postprocess(u_char *packet, size_t size);

#endif
