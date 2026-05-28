#ifndef PROXY_CHAIN_H
#define PROXY_CHAIN_H

#include <sys/socket.h>
#include <stdint.h>

int proxy_chain_connect(int sockfd, const char *host, uint16_t port, 
                        int (*real_connect)(int, const struct sockaddr *, socklen_t));

#endif
