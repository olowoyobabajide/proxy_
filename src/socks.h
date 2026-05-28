#ifndef SOCKS_H
#define SOCKS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

int socks5_tunnel(int sockfd, const char *host, uint16_t port, const char *user, const char *pass);
int socks4_tunnel(int sockfd, const char *host, uint16_t port);

#endif