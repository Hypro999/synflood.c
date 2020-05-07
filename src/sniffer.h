#ifndef SYNFLOOD_SNIFFER_H
#define SYNFLOOD_SNIFFER_H

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#include "utils.h"

#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define ETHERNET_HEADERS_LEN 14
#define LINKTYPE_ETHERNET DLT_EN10MB
#define FILTER_EXPR_TEMPLATE "tcp and (tcp[tcpflags] & tcp-syn == tcp-syn \
or tcp[tcpflags] & tcp-ack == tcp-ack) and host %s and port %d"

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_ACK  0x10


void sniff(char *hostname, int port);

#endif

