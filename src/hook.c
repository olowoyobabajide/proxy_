#include "main.h"
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    static int(*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    real_connect = dlsym(RTLD_NEXT, "connect");
    if(real_connect == NULL){
        fprintf(stderr, "Error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    char ip[INET_ADDRSTRLEN];
    char ip6[INET6_ADDRSTRLEN];
    if(addr->sa_family == AF_INET){
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        int port = ntohs(addr_in->sin_port);
        inet_ntop(AF_INET, &addr_in->sin_addr, ip, INET_ADDRSTRLEN);
        fprintf(stderr, "Connecting to %s:%d\n", ip, port);
    }
    else if(addr->sa_family == AF_INET6){
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        int port6 = ntohs(addr_in6->sin6_port);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip6, INET6_ADDRSTRLEN);
        fprintf(stderr, "Connecting to %s:%d\n", ip6, port6);
    }
    else{
        fprintf(stderr, "Unknown address family\n");
    }
    return real_connect(sockfd, addr, addrlen);
}

