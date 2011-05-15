#ifndef __IP_H__
#define __IP_H__

#include "witm.h"

int is_ip_packet(u_char *packet, size_t size);
static inline void update_ip_checksum(u_char *packet, size_t size);

#endif
