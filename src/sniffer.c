#include "sniffer.h"

char *
getDefaultDevice ()
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL)
    die("%d: Couldn't find default device: %s\n", __LINE__ - 2, errbuf);
  return dev;
}


pcap_t *
getDeviceHandle (char *dev)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL)
	  die("%d: Couldn't open device %s: %s\n", __LINE__ - 2, dev, errbuf);
  return handle;
}


void
setFilterOnDeviceHandle (char *dev, pcap_t *handle, const char *filter_expr)
{
  bpf_u_int32 netmask, dev_ip;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program compiled_filter;

  if (pcap_lookupnet(dev, &dev_ip, &netmask, errbuf) == -1) {
	  fprintf(stderr, "Can't get netmask for device %s\n", dev);
	  dev_ip = 0;
	  netmask = 0;
	}

  if (pcap_compile(handle, &compiled_filter, filter_expr, 1, dev_ip) == -1)
    die("%d: Couldn't parse filter %s: %s\n", __LINE__ - 1, filter_expr, pcap_geterr(handle));

  if (pcap_setfilter(handle, &compiled_filter) == -1)
    die("%d: Couldn't install filter %s: %s\n", __LINE__ - 1, filter_expr, pcap_geterr(handle));

  pcap_freecode(&compiled_filter);
}


/**
 * The callback function that's supposed to be passed to the pcap_loop function call.
 * Simply print basic data about the packet received. It is assumed that we are dealing
 * with a wireless transmission of TCP packets.
*/
void
packetHandlerCallback (unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
  struct iphdr *ip_headers = (struct iphdr *)(packet + ETHERNET_HEADERS_LEN);
  unsigned int ip_headers_len = ip_headers->ihl * 4;
  struct tcphdr *tcp_headers = (struct tcphdr *)(packet + ETHERNET_HEADERS_LEN + ip_headers_len);

  bool is_syn = (tcp_headers->th_flags & TH_SYN) == TH_SYN;
  bool is_ack = (tcp_headers->th_flags & TH_ACK) == TH_ACK;
  char *pkt_type;
  if (is_syn && is_ack)
    pkt_type = "SYN-ACK";
  else if (is_syn)
    pkt_type = "SYN";
  else if (is_ack)
    pkt_type = "ACK";
  else
    pkt_type = "???";

  unsigned short int src_port = ntohs(tcp_headers->th_sport);
  unsigned short int dst_port = ntohs(tcp_headers->th_dport);

  char src_addr_str[HOSTNAME_BUFFER_LENGTH], dst_addr_str[HOSTNAME_BUFFER_LENGTH];

  if (inet_ntop(AF_INET, &(ip_headers->saddr), src_addr_str, HOSTNAME_BUFFER_LENGTH) == NULL)
    die("Failed to convert source address to ASCII: %s\n", strerror(errno));

  if (inet_ntop(AF_INET, &(ip_headers->daddr), dst_addr_str, HOSTNAME_BUFFER_LENGTH) == NULL)
    die("Failed to convert destination address to ASCII: %s\n", strerror(errno));
  
  printf("%s:%hu -> %s:%hu %10s\n", src_addr_str, src_port, dst_addr_str, dst_port, pkt_type);
}


void
sniff (char *hostname, int port)
{
  char filter_expr[1024];
  memset(filter_expr, (int) '\0', 1024);
  sprintf(filter_expr, FILTER_EXPR_TEMPLATE, hostname, port);
  vlog("Sniffing using filter expression:\n\"%s\"\n", filter_expr);

  char *dev = getDefaultDevice();
  pcap_t *handle = getDeviceHandle(dev);
  setFilterOnDeviceHandle(dev, handle, filter_expr);

  int llh_type = pcap_datalink(handle);
  if (llh_type != LINKTYPE_ETHERNET) {
    pcap_close(handle);
    errno = -1;
    die("Unsupported device: %s. Packets captured on the device won't be represented \
with ethernet type link layer headers using libpcap (see pcap-linktype(7)).\n", dev);
  }

  if (pcap_loop(handle, -1, packetHandlerCallback, NULL) == -1) {
    pcap_close(handle);
    errno = -1;
    die("Main packet capture loop failed: %s\n", pcap_geterr(handle));
  }

  pcap_close(handle);
  exit(EXIT_SUCCESS);
}
