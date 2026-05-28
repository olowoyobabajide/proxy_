#ifndef HTTP_CONNECT_H
#define HTTP_CONNECT_H

#include <stdint.h>

int http_connect_tunnel(int sockfd, const char *host, uint16_t port, const char *user, const char *pass);

#endif
