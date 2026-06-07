#include "main.h"
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "proxy_chain.h"
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>

#define DUMIP_BASE 0xC0000200

typedef struct {
    uint32_t dum_ip;
    char dum_hostname[256];
}DNSEntry;

static DNSEntry dnsentry[254] = {0, };
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t dns_map_add(const char *hostname);
static const char *dns_map_lookup(uint32_t ip);
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
    const char *target_host = NULL;

    if(addr->sa_family == AF_INET){
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        if(ntohl(addr_in->sin_addr.s_addr) == 0x7F000001){
            return real_connect(sockfd, addr, addrlen);
        }
        uint32_t raw_ip = addr_in->sin_addr.s_addr;
        uint32_t base = htonl(0xC0000200);  // 192.0.2.0 
        uint32_t top  = htonl(0xC00002FF);  // 192.0.2.255 
        if(raw_ip > htonl(0xC0000200) && raw_ip <= htonl(0xC00002FE)){
            const char *hostname = dns_map_lookup(raw_ip);
            if(hostname != NULL){
                target_host = hostname;
            }
        }
        if (target_host == NULL) {
            inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
            target_host = ip;
        }
        port = ntohs(addr_in->sin_port);
        if(port == 0){
            return real_connect(sockfd, addr, addrlen);
        }
    }
    else if(addr->sa_family == AF_INET6){
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
        target_host = ip;
        port = ntohs(addr_in6->sin6_port);
        if(port == 0){
            return real_connect(sockfd, addr, addrlen);
        }
    }
    else{
        return real_connect(sockfd, addr, addrlen);
    }

    if(proxy_chain_connect(sockfd, target_host, port, addr, addrlen) < 0){
        errno = ECONNREFUSED;
        return -1;
    }
    return 0;
}

int getaddrinfo(const char *restrict hostname, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res){

    static int(*real_getaddrinfo)(const char *restrict hostname, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res) = NULL;
    if(real_getaddrinfo == NULL){
        real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
        if(real_getaddrinfo == NULL){
            fprintf(stderr, "Error: %s\n", dlerror());
            exit(EXIT_FAILURE);
        }
    }
    if(hostname == NULL){
        return real_getaddrinfo(hostname, service, hints, res);
    }
    
    uint32_t fake_ip = 0;
    struct in6_addr dummy_addr;
    if(inet_pton(AF_INET, hostname, &dummy_addr) || inet_pton(AF_INET6, hostname, &dummy_addr)){
        return real_getaddrinfo(hostname, service, hints, res);
    }
    fake_ip = dns_map_add(hostname);
    if(fake_ip == 0){ return EAI_MEMORY; }
    
    struct addrinfo *real_res = calloc(1, sizeof(struct addrinfo));
    struct sockaddr_in *sock = calloc(1, sizeof(struct sockaddr_in));
    sock->sin_family = AF_INET;
    uint16_t out_port = 0;
    if (service != NULL) {
        out_port = htons(atoi(service));
        if (out_port == 0) {
            struct servent *srv = getservbyname(service, "tcp");
            if (srv != NULL) {
                out_port = srv->s_port;
            }
        }
    }
    sock->sin_port = out_port;
    sock->sin_addr.s_addr = fake_ip;
    
    real_res->ai_addr = (struct sockaddr *)sock;
    real_res->ai_addrlen = sizeof(struct sockaddr_in);
    real_res->ai_family = AF_INET;
    real_res->ai_socktype = SOCK_STREAM;
    real_res->ai_next = NULL;

    *res = real_res;

    return 0;
}


static uint32_t dns_map_add(const char *hostname){
    pthread_mutex_lock(&mutex);
    for(int i = 0; i < 254; i++){
        if(strcmp(dnsentry[i].dum_hostname, hostname) == 0){
            pthread_mutex_unlock(&mutex);
            return dnsentry[i].dum_ip;
        }
    }
    for(int i = 0; i < 254; i++){
        if(dnsentry[i].dum_ip == 0){
            dnsentry[i].dum_ip = htonl(0xC0000200 + i + 1);
            strncpy(dnsentry[i].dum_hostname, hostname, 255);
            pthread_mutex_unlock(&mutex);
            return dnsentry[i].dum_ip;
        }
    }
    pthread_mutex_unlock(&mutex);
    return 0;
}

static const char *dns_map_lookup(uint32_t ip){
    pthread_mutex_lock(&mutex);
    for(int i = 0; i < 254; i++){
        if(dnsentry[i].dum_ip == ip){
            pthread_mutex_unlock(&mutex);
            return dnsentry[i].dum_hostname;
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void freeaddrinfo(struct addrinfo *res){
    static void(*real_freeaddrinfo)(struct addrinfo *) = NULL;
    if(real_freeaddrinfo == NULL){
        real_freeaddrinfo = dlsym(RTLD_NEXT, "freeaddrinfo");
        if(real_freeaddrinfo == NULL){
            fprintf(stderr, "Error: %s\n", dlerror());
            exit(EXIT_FAILURE);
        }
    }

    if(res == NULL){
        return;
    }

    if(res->ai_family == AF_INET && res->ai_addr != NULL){
        struct sockaddr_in *addr_in = (struct sockaddr_in *)res->ai_addr;
        uint32_t raw_ip = addr_in->sin_addr.s_addr;
        uint32_t base = htonl(0xC0000200);  
        uint32_t top  = htonl(0xC00002FF);
        if(raw_ip > htonl(0xC0000200) && raw_ip <= htonl(0xC00002FE)){
            if (dns_map_lookup(raw_ip) != NULL) {
                struct addrinfo *next = res->ai_next;
                free(res->ai_addr);
                free(res);
                if (next) freeaddrinfo(next);
                return;
            }
        }
    }

    real_freeaddrinfo(res);
}

static __thread struct hostent dummy_hostent;
static __thread char dummy_aliases[1];
static __thread char *dummy_alias_list[2];
static __thread uint32_t dummy_ip;
static __thread char *dummy_addr_list[2];

struct hostent *gethostbyname(const char *name) {
    static struct hostent *(*real_gethostbyname)(const char *) = NULL;
    if (!real_gethostbyname) {
        real_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");
        if (!real_gethostbyname) return NULL;
    }

    if (!name) return real_gethostbyname(name);

    struct in6_addr dummy_addr;
    if (inet_pton(AF_INET, name, &dummy_addr) || inet_pton(AF_INET6, name, &dummy_addr)) {
        return real_gethostbyname(name);
    }

    uint32_t fake_ip = dns_map_add(name);
    if (!fake_ip) return NULL;

    dummy_ip = fake_ip;
    dummy_addr_list[0] = (char *)&dummy_ip;
    dummy_addr_list[1] = NULL;
    dummy_alias_list[0] = dummy_aliases;
    dummy_alias_list[1] = NULL;
    dummy_aliases[0] = '\0';

    dummy_hostent.h_name = (char *)name;
    dummy_hostent.h_aliases = dummy_alias_list;
    dummy_hostent.h_addrtype = AF_INET;
    dummy_hostent.h_length = sizeof(uint32_t);
    dummy_hostent.h_addr_list = dummy_addr_list;

    return &dummy_hostent;
}

struct hostent *gethostbyname2(const char *name, int af) {
    if (af != AF_INET) {
        static struct hostent *(*real_gethostbyname2)(const char *, int) = NULL;
        if (!real_gethostbyname2) {
            real_gethostbyname2 = dlsym(RTLD_NEXT, "gethostbyname2");
        }
        if (real_gethostbyname2) return real_gethostbyname2(name, af);
        return NULL;
    }
    return gethostbyname(name);
}

struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type) {
    static struct hostent *(*real_gethostbyaddr)(const void *, socklen_t, int) = NULL;
    if (!real_gethostbyaddr) {
        real_gethostbyaddr = dlsym(RTLD_NEXT, "gethostbyaddr");
    }

    if (type == AF_INET && len == sizeof(uint32_t)) {
        uint32_t raw_ip = *(uint32_t *)addr;
        if (ntohl(raw_ip) > 0xC0000200 && ntohl(raw_ip) <= 0xC00002FE) {
            const char *hostname = dns_map_lookup(raw_ip);
            if (hostname) {
                dummy_ip = raw_ip;
                dummy_addr_list[0] = (char *)&dummy_ip;
                dummy_addr_list[1] = NULL;
                dummy_alias_list[0] = dummy_aliases;
                dummy_alias_list[1] = NULL;
                dummy_aliases[0] = '\0';

                dummy_hostent.h_name = (char *)hostname;
                dummy_hostent.h_aliases = dummy_alias_list;
                dummy_hostent.h_addrtype = AF_INET;
                dummy_hostent.h_length = sizeof(uint32_t);
                dummy_hostent.h_addr_list = dummy_addr_list;
                return &dummy_hostent;
            }
        }
    }
    if (real_gethostbyaddr) return real_gethostbyaddr(addr, len, type);
    return NULL;
}

int getnameinfo(const struct sockaddr *sa, socklen_t salen,
                char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags) {
    static int (*real_getnameinfo)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int) = NULL;
    if (!real_getnameinfo) {
        real_getnameinfo = dlsym(RTLD_NEXT, "getnameinfo");
    }

    if (sa && sa->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)sa;
        uint32_t raw_ip = addr_in->sin_addr.s_addr;
        if (ntohl(raw_ip) > 0xC0000200 && ntohl(raw_ip) <= 0xC00002FE) {
            const char *hostname = dns_map_lookup(raw_ip);
            if (hostname) {
                if (host && hostlen > 0) {
                    strncpy(host, hostname, hostlen - 1);
                    host[hostlen - 1] = '\0';
                }
                if (serv && servlen > 0) {
                    snprintf(serv, servlen, "%d", ntohs(addr_in->sin_port));
                }
                return 0;
            }
        }
    }
    if (real_getnameinfo) return real_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
    return EAI_FAIL;
}

int getaddrinfo_a(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp) {
    for (int i = 0; i < nitems; i++) {
        if (list[i]) {
            getaddrinfo(list[i]->ar_name, list[i]->ar_service, list[i]->ar_request, &list[i]->ar_result);
        }
    }
    if (sevp) {
        if (sevp->sigev_notify == SIGEV_SIGNAL) {
            union sigval val = sevp->sigev_value;
            sigqueue(getpid(), sevp->sigev_signo, val);
        } else if (sevp->sigev_notify == SIGEV_THREAD) {
            if (sevp->sigev_notify_function) {
                sevp->sigev_notify_function(sevp->sigev_value);
            }
        }
    }
    return 0;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_sendto) {
        real_sendto = dlsym(RTLD_NEXT, "sendto");
    }

    if (dest_addr && dest_addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)dest_addr;
        if (ntohs(addr_in->sin_port) == 53) {
            int type;
            socklen_t length = sizeof(int);
            if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &length) == 0) {
                if (type == SOCK_DGRAM) {
                    errno = EACCES;
                    return -1;
                }
            }
        }
    } else if (dest_addr && dest_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)dest_addr;
        if (ntohs(addr_in6->sin6_port) == 53) {
            int type;
            socklen_t length = sizeof(int);
            if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &length) == 0) {
                if (type == SOCK_DGRAM) {
                    errno = EACCES;
                    return -1;
                }
            }
        }
    }
    
    if (real_sendto) return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    errno = EACCES;
    return -1;
}