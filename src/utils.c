#include "utils.h"

extern bool verbose;  /* Defined in cli.c */


/**
 * A utility function to print the specified formatted message to stdout
 * if only if verbose mode is set to true.
*/
void
vlog (const char format_string[], ...)
{
  if (verbose == false)
    return;

  va_list args;
  va_start(args, format_string);
  vfprintf(stdout, format_string, args);
  va_end(args);
  fflush(stdout);
}


/**
 * A utility function to print the specified formatted message to stderr,
 * flush both stdout and stderr, then terminate all processes in the
 * current process group.
*/
__attribute__((noreturn)) void
die (const char format_string[], ...)
{
  va_list args;
  va_start(args, format_string);
  vfprintf(stderr, format_string, args);
  va_end(args);

  fflush(stdout);
  fflush(stderr);

  if (killpg(0, SIGTERM) == -1)
    fprintf(stderr, "%d: %s.\n", __LINE__ - 1, strerror(errno));

  exit(errno);
}


/**
 * A simple utility function to dump some memory in a readable hex format.
*/
void
hexDump (void *ptr, ssize_t len)
{
  if (len == -1 || len == 0) {
    printf("00\n");
    return;
  }

  unsigned char *_ptr = (unsigned char *) ptr;
  for (int i = 0; i < len; ++i) {
    printf("%02x  ", *_ptr);
    ++_ptr;
  }
  printf("\n");
}


/**
 * Seed the random number generator using /dev/urandom. See random(7) for more details.
 */
void
seedRandomNumberGenerator ()
{
  unsigned int seed;
  ssize_t bytes_read = getrandom(&seed, sizeof(unsigned int), 0);
  if (bytes_read == -1) {
    fprintf(stderr, "%d: Failed to initialize the random number generator. %s.\n", __LINE__ - 2, strerror(errno));
    exit(EXIT_FAILURE);
  }
  srand(seed);
}


/**
 * Use gethostbyname() to perform a DNS lookup and then move through the entries in a linear
 * manner, trying to form a TCP connection with each IP address. When we are able to successfully
 * form a TCP connection, close it, populate the address, and return.
*/
void
resolveHostName (char *hostname, unsigned short int port, struct sockaddr_in *addr)
{
  int sockfd;
  char **hptr;
  char buf[HOSTNAME_BUFFER_LENGTH];

  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);

  struct hostent *host = gethostbyname(hostname);
  if (host == NULL)
    die("%d: Failed to resolve host %s: %s.\n", __LINE__ - 2, hostname, hstrerror(h_errno));

  if (host->h_addrtype != AF_INET)
    die("%d: Failed to find IPv4 records for the host: %s.\n", __LINE__ - 1, strerror(errno));

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd == -1)
    die("%d: Failed to open hostname resolver checker socket: %s.\n", __LINE__ - 2, strerror(errno));

  for (hptr = host->h_addr_list; *hptr != NULL; ++hptr) {
    inet_ntop(host->h_addrtype, *hptr, buf, HOSTNAME_BUFFER_LENGTH);
    memset(&addr->sin_addr, 0, sizeof(struct in_addr));
    addr->sin_addr.s_addr = inet_addr(buf);
    if (connect(sockfd, (struct sockaddr *) addr, sizeof(struct sockaddr_in)) == -1)
      continue;
    close(sockfd);
    vlog("%s\n", buf);
    return;
  }

  die("Failed to perform a successful hostname lookup.\n");
}


/**
 * Get the current IP address being used.
*/
struct in_addr
getCurrentIpAddr ()
{
  struct in_addr ip_addr;
  struct sockaddr_in *addr = NULL;
  struct ifaddrs *addrs, *cur_addr;
  if (getifaddrs(&addrs) == -1)
    die("%d: Failed to get the current IP address: %s\n", __LINE__ - 1, strerror(errno));

  cur_addr = addrs;
  while (cur_addr) {
      if (cur_addr->ifa_addr
            && cur_addr->ifa_addr->sa_family == AF_INET
            && strcmp(cur_addr->ifa_name, "lo") != 0) {
          addr = (struct sockaddr_in *) cur_addr->ifa_addr;
          if (addr != NULL)
            ip_addr = addr->sin_addr;
          break;
      }

      cur_addr = cur_addr->ifa_next;
  }

  freeifaddrs(addrs);

  if (addr == NULL)
    die("Failed to determine current IP address.\n");

  return ip_addr;
}



/**
 * Get a random ephemeral port number.
*/
uint16_t
getSpoofedPortNumber ()
{
  return (random() % (65535 - 32768 + 1)) + 32768;
}

/**
 * This is a REALLY simple and dumb function to generate a fake IPv4 address. The main problem
 * with this generator is that it may also generate addresses like 127.0.0.1 and 255.255.255.255
 * and in general this function does not adhere to special use addresses like the ones mentioned
 * in https://en.wikipedia.org/wiki/IPv4#Special-use_addresses.
 * But since almost all VPS providers (like DigitalOcean, AWS, GCP, Azure, etc.) block
 * spoofed IP packets from being sent from one of their servers, and since household routers can
 * only support oh so much traffic before crashing, I didn't waste much time on this function.
 * With the amount of anti-spoofing measures being taken on the internet, trying to spoof is
 * just a bad idea.
*/
in_addr_t
getSpoofedIpAddr ()
{
  unsigned int spoofed_parts[4];
  for (int i = 0; i < 4; ++i)
    spoofed_parts[i]= random() % 256;
 
  char spoofed_source_address[17];
  memset(spoofed_source_address, (int) '\0', 17);
  sprintf(spoofed_source_address, "%u.%u.%u.%u", spoofed_parts[0], spoofed_parts[1],
          spoofed_parts[2], spoofed_parts[3]);

  return inet_addr(spoofed_source_address);
}

