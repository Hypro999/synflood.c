#ifndef SYNFLOOD_SYNFLOOD_H
#define SYNFLOOD_SYNFLOOD_H

#include "utils.h"
#include "cli.h"
#include "sniffer.h"

#include <stdint.h>
#include <sys/wait.h>

#define PACKET_BUFFER_LEN sizeof(struct iphdr) + sizeof(struct tcphdr)


typedef struct {
  uint32_t saddr;       /* The source IP address (spoofed) */
  uint32_t daddr;       /* The destination IP address. */
  uint8_t  rsvd;        /* These bytes are not used and are just buffer. */
  uint8_t  proto;       /* The protocol as in the IP headers - 0x6 */
  uint16_t seglen;      /* The computed length of the TCP segment. */
  struct tcphdr thdr;   /* The actual tcp headers - not a part of the pseudo header itself but it makes memory handling easier with this here. */
} tcp_pseudo_header_t;

#endif

