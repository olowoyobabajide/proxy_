#include "main.h"
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "proxy_chain.h"
#include <errno.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    static int(*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if(real_connect == NULL){
        real_connect = dlsym(RTLD_NEXT, "connect");
        if(real_connect == NULL){
            fprintf(stderr, "Error: %s\n", dlerror());
            exit(EXIT_FAILURE);
        }
    }

    char ip[INET6_ADDRSTRLEN];
    uint16_t port = 0;

    if(addr->sa_family == AF_INET){
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
        port = ntohs(addr_in->sin_port);
    }
    else if(addr->sa_family == AF_INET6){
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
        port = ntohs(addr_in6->sin6_port);
    }
    else{
        return real_connect(sockfd, addr, addrlen);
    }

    if(proxy_chain_connect(sockfd, ip, port, addr, addrlen) < 0){
        errno = ECONNREFUSED;
        return -1;
    }
    return 0;
}

