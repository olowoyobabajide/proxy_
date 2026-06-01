#ifndef PROXY_CHAIN_H
#define PROXY_CHAIN_H

#include <sys/socket.h>
#include <stdint.h>

int proxy_chain_connect(int sockfd, const char *host, uint16_t port,
                        const struct sockaddr *orig_addr, socklen_t orig_addrlen);
#endif
