#include "cli.h"

bool verbose = false;
bool enable_sniffer = false;
bool enable_spoofing = false;

char usage_message[] = "\
Usage: [sudo] synflood [REQUIRED PARAMETERS] [OPTIONAL PARAMETERS]\n\
\n\
Required parameters:\n\
-h, --hostname\n\
    The hostname of the target to attack. Only use hostnames of TCP servers\n\
    that are available to your default network interface (usually wlo1 or\n\
    eth0) and that you either directly own or have explicit permission to\n\
    attack. We expect the hostname to resolve to an IPv4 address.\n\
    Because we use wlo1/eth0 you can't use any loopback interface hostnames\n\
    to directly synflood yourself.\n\
\n\
-p, --port\n\
    The port number that you want to attack. Can be any valid TCP port that's\n\
    open on the server. For example, aim for webservers (80/443) or SSH (22).\n\
\n\
-t, --attack-time\n\
    The number of seconds to launch the attack for. Must be a positive integer\n\
    less than 120 (seconds) this is done for your own (and the target)\n\
    network's safety. We just want to demonstrate synflooding here and not\n\
    cause any serious damage lasting longer than a short while (plus 2 minutes\n\
    should actually be enough to take down most test servers).\n\
\n\
Optional parameters:\n\
-v\n\
    Enable verbose mode (recommended).\n\
\n\
--enable-sniffer\n\
    Enable the packet sniffer. We use libpcap and a child process to manage\n\
    sniffing only the packets we're interested in. If verbose mode is enabled\n\
    you'll be able to see the exact packet capture filter being employed.\n\
\n\
--enable-spoofing\n\
    Enable random IPv4 address spoofing. Not recommended since more often\n\
    than not these packets would be dropped by the network at some point\n\
    or the other. For example, all major VPS providers will block outgoing\n\
    packets with spoofed ip addresses. Even incoming spoofed packets can\n\
    potentially be detected and dropped. This is done for the general good\n\
    of the internet. Note: the spoofer is currently not perfect and does\n\
    not take into consideration special or reserved addresses. It's\n\
    completely random.\n\
";


/**
 * Validate the given port number string and then return it's unsigned integer value.
*/
unsigned short int
validatePort (const char *inp)
{
  int port_no;
  bool invalid_port_no = false;
  size_t slen = strlen(inp);

  for (int i = 0; i < slen; ++i) {
    if (isdigit(inp[i]))
      continue;
    invalid_port_no = true;
    break;
  }

  if (!invalid_port_no) {
    port_no = atoi(inp);
    if (port_no > 65535 || port_no < 0)
      invalid_port_no = true;
  }

  if (invalid_port_no) {
    fprintf(stderr, "Invalid port.\n");
    exit(EXIT_FAILURE);
  }

  return (unsigned short int) port_no;
}


/**
 * Validate the input and populate the hostname string. Also perform a DNS lookup of the given
 * hostname and populate host_addr.
 * @returns     true if the hostname is valid and exists. false otherwise.
*/
bool
validateHostname (const char *inp, char hostname[HOSTNAME_BUFFER_LENGTH],
                  unsigned short int port, struct sockaddr_in *host_addr)
{
  if (strlen(inp) > HOSTNAME_BUFFER_LENGTH)
    return false;

  memset(hostname, (int)'\0', HOSTNAME_BUFFER_LENGTH);
  strncpy(hostname, inp, HOSTNAME_BUFFER_LENGTH-1);

  vlog("Performing hostname lookup... ");
  resolveHostName(hostname, port, host_addr);

  return true;
}


/**
 * Make sure that the attack time is positive and not longer than 2 minutes.
*/
unsigned int
validateAttackTime (char *inp)
{
  bool invalid = false;
  
  size_t inplen = strlen(inp);
  for (int i = 0; i < inplen; ++i) {
    if (!isdigit(inp[i])) {
      invalid = true;
      break;
    }
  }

  int attack_time = atoi(inp);
  if (attack_time > 120)
    invalid = true;

  if (invalid) { 
    fprintf(stderr, "Invalid attack time: %s.\n", inp);
    exit(EXIT_FAILURE);
  }

  return (unsigned int) attack_time;
}


/**
 * Parse the command line options and represent them in a way we can manipulate and use.
*/
void
getOptions (int argc, char *argv[], char hostname[HOSTNAME_BUFFER_LENGTH],
            unsigned short int *port, struct sockaddr_in *host_addr,
            unsigned int *attack_time)

{
  int opt = 0;
  char *hostname_placeholder;
  bool hostname_initialized = false, port_initialized = false,
       attack_time_intialized = false;

  *attack_time = DEFAULT_ATTACK_TIME;

  struct option option_array[] = {
      {"help", no_argument, NULL, (int) 'H'},
      {"hostname", required_argument, NULL, (int) 'h'},
      {"port", required_argument, NULL,  (int) 'p'},
      {"verbose", no_argument, NULL, (int) 'v'},
      {"attack-time", required_argument, NULL,  (int) 't'},
      {"enable-sniffer", no_argument, NULL, (int) 's'},
      {"enable-spoofing", no_argument, NULL, (int) 'e'},
      {0, 0, 0, 0}
  };

  char *short_opts = "h:p:vt:";

  opt = getopt_long(argc, argv, short_opts, option_array, NULL);
  while (opt != -1) {
    switch (opt) {
      case 'h':
        hostname_placeholder = optarg;
        hostname_initialized = true;
        break;

      case 'p':
        *port = validatePort(optarg);
        port_initialized = true;
        break;

      case 'v':
        verbose = true;
        break;

      case 't':
        *attack_time = validateAttackTime(optarg);
        attack_time_intialized = true;
        break;

      case 's':
        enable_sniffer = true;
        break;

      case 'e':
        enable_spoofing = true;
        break;

      case 'H':
        fprintf(stderr, "%s", usage_message);
        exit(EXIT_SUCCESS);

      default:
        fprintf(stderr, "%s", usage_message);
        exit(EXIT_FAILURE);
    }
    opt = getopt_long(argc, argv, short_opts, option_array, NULL);
  }

  if (!(hostname_initialized && port_initialized && attack_time_intialized)) {
      fprintf(stderr, "%s", usage_message);
      exit(EXIT_FAILURE);
  }

  if (!validateHostname(hostname_placeholder, hostname, *port, host_addr)) {
    fprintf(stderr, "Invalid hostname.\n");
    exit(EXIT_FAILURE);
  }

  return;
}

