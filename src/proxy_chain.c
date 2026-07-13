#include "main.h"
#include "proxy_chain.h"
#include "config.h"
#include "socks.h"
#include "http_connect.h"
#include <dlfcn.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <fcntl.h>

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
    
    int flags = fcntl(sockfd, F_GETFL, 0);

    if (cfg.mode == CHAIN_RANDOM) {
        int len = cfg.random_chain_len;
        if (len <= 0 || len > cfg.count) len = cfg.count;
        ProxyConfig r_cfg;
        r_cfg.mode = CHAIN_RANDOM;
        r_cfg.count = len;
        
        int indices[64];
        for(int i = 0; i < cfg.count; i++) indices[i] = i;
        
        static int seeded = 0;
        if(!seeded) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            srand((unsigned int)(tv.tv_sec ^ tv.tv_usec ^ getpid()));
            seeded = 1;
        }
        
        for(int i = cfg.count - 1; i > 0; i--) {
            int j = rand() % (i + 1);
            int t = indices[i]; indices[i] = indices[j]; indices[j] = t;
        }
        for(int i = 0; i < len; i++) {
            r_cfg.entries[i] = cfg.entries[indices[i]];
        }
        cfg = r_cfg;
    }

    int dead[64] = {0};
    int max_retries = (cfg.mode == CHAIN_STRICT) ? 1 : 15;
    int retries = 0;

again:
    if (retries++ > max_retries) {
        fprintf(stderr, "Error: Proxy chain failed after retries\n");
        return -1;
    }
    
    ProxyEntry *active[64];
    int active_indices[64];
    int active_count = 0;
    
    for(int i = 0; i < cfg.count; i++) {
        if(!dead[i]) {
            active[active_count] = &cfg.entries[i];
            active_indices[active_count] = i;
            active_count++;
        }
    }
    
    if (active_count == 0) {
        fprintf(stderr, "Error: No alive proxies left\n");
        return -1;
    }

    int ns = socket(AF_INET, SOCK_STREAM, 0);
    if (ns < 0) return -1;
    fcntl(ns, F_SETFL, O_NONBLOCK);
    
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(active[0]->port);

    if (inet_pton(AF_INET, active[0]->host, &proxy_addr.sin_addr) != 1) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_NUMERICSERV;
        int err = getaddrinfo(active[0]->host, NULL, &hints, &res);
        if (err != 0) {
            fprintf(stderr, "Error: %s\n", gai_strerror(err));
            close(ns);
            dead[active_indices[0]] = 1;
            if(cfg.mode != CHAIN_STRICT) goto again;
            return -1;
        }
        memcpy(&proxy_addr, res->ai_addr, sizeof(proxy_addr));
        proxy_addr.sin_port = htons(active[0]->port);
        freeaddrinfo(res);
    }

    int rc = real_connect(ns, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    int connect_errno = errno;
    if (rc < 0 && connect_errno != EINPROGRESS) {
        perror("connect");
        close(ns);
        dead[active_indices[0]] = 1;
        if(cfg.mode != CHAIN_STRICT) goto again;
        return -1;
    }
    
    if (rc < 0 && connect_errno == EINPROGRESS) {
        fd_set set;
        struct timeval timeout;
        FD_ZERO(&set);
        FD_SET(ns, &set);
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        int sel = select(ns + 1, NULL, &set, NULL, &timeout);
        if(sel <= 0){ 
            close(ns);
            dead[active_indices[0]] = 1;
            if(cfg.mode != CHAIN_STRICT) goto again;
            return -1; 
        }
        int sock_err;
        socklen_t errlen = sizeof(sock_err);
        if(getsockopt(ns, SOL_SOCKET, SO_ERROR, &sock_err, &errlen) < 0 || sock_err != 0){
            close(ns);
            dead[active_indices[0]] = 1;
            if(cfg.mode != CHAIN_STRICT) goto again;
            return -1;
        }
    }

    fcntl(ns, F_SETFL, 0);

    int index = 0;
    while(index < active_count) {
        const char *target_host;
        uint16_t target_port;
        if (index == active_count - 1) {
            target_host = host;
            target_port = port;
        } else {
            target_host = active[index + 1]->host;
            target_port = active[index + 1]->port;
        }

        int tunnel_res = -1;
        if(active[index]->type == PROXY_SOCKS4){
            tunnel_res = socks4_tunnel(ns, target_host, target_port);
        }
        else if(active[index]->type == PROXY_SOCKS5){
            tunnel_res = socks5_tunnel(ns, target_host, target_port, active[index]->user, active[index]->pass);
        }
        else if(active[index]->type == PROXY_HTTP_CONNECT){
            tunnel_res = http_connect_tunnel(ns, target_host, target_port, active[index]->user, active[index]->pass);
        }

        if(tunnel_res < 0) {
            fprintf(stderr, "Error: tunnel %d failed\n", index);
            close(ns);
            if (index == active_count - 1) {
                return -1; 
            } else {
                dead[active_indices[index + 1]] = 1;
            }
            if(cfg.mode != CHAIN_STRICT) goto again;
            return -1;
        }
        index++;
    }

    dup2(ns, sockfd);
    close(ns);
    fcntl(sockfd, F_SETFL, flags);
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
