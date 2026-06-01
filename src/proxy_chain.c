#include "main.h"
#include "proxy_chain.h"
#include "config.h"
#include "socks.h"
#include "http_connect.h"
#include <dlfcn.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>

ProxyConfig proxy_chain_deserialize(const char *str);
int proxy_chain_connect(int sockfd, const char *host, uint16_t port,
                        const struct sockaddr *orig_addr, socklen_t orig_addrlen){   
   
    const char *env = getenv("PROXYTOOL_CHAIN");
    char temp[2048];

    if(env == NULL){fprintf(stderr, "Error: PROXYTOOL_CHAIN not set\n"); return -1;}

    static int(*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if(real_connect == NULL){
        real_connect = dlsym(RTLD_NEXT, "connect");
        if(real_connect == NULL){ fprintf(stderr, "Error: %s\n", dlerror()); return -1; }
    }
        
    int sock_family;
    socklen_t slen = sizeof(sock_family);
    getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &sock_family, &slen);
    if(sock_family == AF_INET6){
        return real_connect(sockfd, orig_addr, orig_addrlen);
    }

    strncpy(temp, env, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    ProxyConfig cfg = proxy_chain_deserialize(temp);
    
    if(cfg.count == 0){
        fprintf(stderr, "Error: No proxies configured\n");
        return -1;
    }
    
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(cfg.entries[0].port);

    if(inet_pton(AF_INET, cfg.entries[0].host, &proxy_addr.sin_addr) != 1){
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_NUMERICSERV;
        int err = getaddrinfo(cfg.entries[0].host, NULL, &hints, &res);
        if(err != 0){
            fprintf(stderr, "Error: %s\n", gai_strerror(err));
            return -1;
        }
        memcpy(&proxy_addr, res->ai_addr, sizeof(proxy_addr));
        proxy_addr.sin_port = htons(cfg.entries[0].port);
        freeaddrinfo(res);
    }
    int rc = real_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    int connect_errno = errno;  
    if(rc < 0 && connect_errno != EINPROGRESS){
        perror("connect");
        return -1;
    }
    if(rc < 0 && connect_errno == EINPROGRESS){
        fd_set set;
        struct timeval timeout;
        FD_ZERO(&set);
        FD_SET(sockfd, &set);
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        int sel = select(sockfd + 1, NULL, &set, NULL, &timeout);
        if(sel < 0){ perror("select"); return -1; }
        if(sel == 0){ fprintf(stderr, "Error: Connection timeout\n"); return -1; }
        int sock_err;
        socklen_t errlen = sizeof(sock_err);
        if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_err, &errlen) < 0){
            perror("getsockopt"); return -1;
        }
        if(sock_err != 0){
            fprintf(stderr, "Error: Connection failed: %d\n", sock_err);
            return -1;
        }
    }

    int index = 0;
    while(index < cfg.count){
        const char *target_host;
        uint16_t target_port;
        if(index == (cfg.count -1)){
            target_host = host;
            target_port = port;
        }
        else{
            target_host = cfg.entries[index + 1].host;
            target_port = cfg.entries[index + 1].port;
        }
        if(cfg.entries[index].type == PROXY_SOCKS4){
            if(socks4_tunnel(sockfd, target_host, target_port) < 0){
                fprintf(stderr, "Error: socks4 tunnel failed\n");
                return -1;
            }
        }
        else if(cfg.entries[index].type == PROXY_SOCKS5){
            if(socks5_tunnel(sockfd, target_host, target_port, cfg.entries[index].user, cfg.entries[index].pass) < 0){
                fprintf(stderr, "Error: socks5 tunnel failed\n");
                return -1;
            }
        }
        else if(cfg.entries[index].type == PROXY_HTTP_CONNECT){
            if(http_connect_tunnel(sockfd, target_host, target_port, cfg.entries[index].user, cfg.entries[index].pass) < 0){
                fprintf(stderr, "Error: http connect tunnel failed\n");
                return -1;
            }
        }
        index++;
    }
    return 0;
}

ProxyConfig proxy_chain_deserialize(const char *str){
    ProxyConfig cfg;
    char *temp = strdup(str);
    if(temp == NULL){
        perror("strdup");
        exit(EXIT_FAILURE);
    }

    cfg.mode = CHAIN_STRICT;
    cfg.count = 0;
    char *token;
    char *chainMode = strtok(temp, "\n");
    if(strcmp(chainMode, "strict_chain") == 0){
        cfg.mode = CHAIN_STRICT;
    }
    else if(strcmp(chainMode, "dynamic_chain") == 0){
        cfg.mode = CHAIN_DYNAMIC;
    }
    else if(strcmp(chainMode, "random_chain") == 0){
        cfg.mode = CHAIN_RANDOM;
    }

    token = strtok(NULL, "\n");
    while(token != NULL && cfg.count < 64){
        ProxyEntry entry;
        memset(&entry, 0, sizeof(entry));

        if(strncmp(token, "chain_len", 9) == 0){
            sscanf(token, "chain_len = %d", &cfg.random_chain_len);
            token = strtok(NULL, "\n");
            continue;
        }
        char type[16];
        sscanf(token, "%s %s %hu %s %s", type, entry.host, &entry.port, entry.user, entry.pass);

        if(strcmp(type, "socks4") == 0){
            entry.type = PROXY_SOCKS4;
        }
        else if(strcmp(type, "socks5") == 0){
            entry.type = PROXY_SOCKS5;
        }
        else if(strcmp(type, "http") == 0){
            entry.type = PROXY_HTTP_CONNECT;
        }
        else{
            fprintf(stderr, "Error: Unknown proxy type: %s\n", type);
            token = strtok(NULL, "\n");
            continue;
        }
        cfg.entries[cfg.count] = entry; 
        cfg.count++;
        token = strtok(NULL, "\n");
    }
    free(temp);
    return cfg;
}
