#include "config.h"

ProxyConfig config_parse(FILE* config_file){
    ProxyConfig config;
    char buf[1024];
    config.count = 0;

    while(fgets(buf, sizeof(buf), config_file)){
        // Skip comment lines and blank lines
        if(buf[0] == '#' || buf[0] == '\n' || buf[0] == '\r'){
            continue;
        }

        if(strncmp(buf, "strict_chain", 12) == 0){config.mode = CHAIN_STRICT;}
        else if(strncmp(buf, "dynamic_chain", 13) == 0){config.mode = CHAIN_DYNAMIC;}
        else if(strncmp(buf, "random_chain", 12) == 0){config.mode = CHAIN_RANDOM;}
        else if(strncmp(buf, "chain_len", 9) == 0){
            sscanf(buf, "chain_len = %d", &config.random_chain_len);
        }

        if(strstr(buf, "socks4 ") || strstr(buf, "socks5 ") || strstr(buf, "http")){
            if(config.count >= 64){ break; }// guard

            char *token = strtok(buf, " \n");
            if(token == NULL){ continue; }

            ProxyEntry *e = &config.entries[config.count];

            if(strcmp(token, "socks4") == 0)       { e->type = PROXY_SOCKS4; }
            else if(strcmp(token, "socks5") == 0)  { e->type = PROXY_SOCKS5; }
            else if(strcmp(token, "https") == 0)    { e->type = PROXY_HTTP_CONNECT; }

            char *host = strtok(NULL, " \n");
            char *port = strtok(NULL, " \n");
            char *user = strtok(NULL, " \n");
            char *pass = strtok(NULL, " \n");

            if(host) strncpy(e->host, host, sizeof(e->host) - 1);
            if(port) e->port = (uint16_t)atoi(port);
            if(user) strncpy(e->user, user, sizeof(e->user) - 1);
            if(pass) strncpy(e->pass, pass, sizeof(e->pass) - 1);

            config.count++;
        }
    }

    if(config.count == 0){ printf("No proxies found\n"); }

    return config;
}

// Serialize cfg into buf of size bufsz.
// Returns total bytes written (excl. NUL), or -1 on overflow. 
int config_serialize(const ProxyConfig *cfg, char *buf, int bufsz){
    const char *mode_str;
    switch(cfg->mode){
        case CHAIN_STRICT:  mode_str = "strict_chain";  break;
        case CHAIN_DYNAMIC: mode_str = "dynamic_chain"; break;
        case CHAIN_RANDOM:  mode_str = "random_chain";  break;
        default:            mode_str = "strict_chain";  break;
    }

    int off = 0;
    int rem = bufsz;
    int n;

    /* Chain mode */
    n = snprintf(buf + off, rem, "%s\n", mode_str);
    if(n < 0 || n >= rem){ return -1; }
    off += n; rem -= n;

    /* chain_len only relevant for random mode */
    if(cfg->mode == CHAIN_RANDOM){
        n = snprintf(buf + off, rem, "chain_len = %d\n", cfg->random_chain_len);
        if(n < 0 || n >= rem){ return -1; }
        off += n; rem -= n;
    }

    /* Proxy entries */
    const char *type_str;
    for(int i = 0; i < cfg->count; i++){
        const ProxyEntry *e = &cfg->entries[i];
        switch(e->type){
            case PROXY_SOCKS4:       type_str = "socks4"; break;
            case PROXY_SOCKS5:       type_str = "socks5"; break;
            case PROXY_HTTP_CONNECT: type_str = "http";   break;
            default:                 type_str = "socks5"; break;
        }

        if(e->user[0]){
            n = snprintf(buf + off, rem, "%s %s %d %s %s\n",
                         type_str, e->host, e->port, e->user, e->pass);
        } else {
            n = snprintf(buf + off, rem, "%s %s %d\n",
                         type_str, e->host, e->port);
        }
        if(n < 0 || n >= rem){ return -1; }
        off += n; rem -= n;
    }

    return off;
}
