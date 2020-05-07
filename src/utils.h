#ifndef SYNFLOOD_UTILS_H
#define SYNFLOOD_UTILS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>

#define HOSTNAME_BUFFER_LENGTH 256


void vlog(const char format_string[], ...);
void die(const char format_string[], ...);
void hexDump(void *ptr, ssize_t len);
void seedRandomNumberGenerator();
void resolveHostName(char *hostname, unsigned short int port, struct sockaddr_in *addr);
struct in_addr getCurrentIpAddr();
uint16_t getSpoofedPortNumber();
in_addr_t getSpoofedIpAddr();

#endif

