#include "main.h"


/* Proxy types supported */
typedef enum {
    PROXY_SOCKS4,
    PROXY_SOCKS5,
    PROXY_HTTP_CONNECT
} ProxyType;

/* A single proxy entry parsed from the config file */
typedef struct {
    ProxyType type;
    char      host[256];
    uint16_t  port;
    char      user[64];
    char      pass[64];
} ProxyEntry;

/* Chain modes */
typedef enum {
    CHAIN_STRICT,   /* All proxies used in order; failure aborts */
    CHAIN_DYNAMIC,  /* Skip dead proxies, continue with live ones */
    CHAIN_RANDOM    /* Randomise proxy order for each connection */
} ChainMode;

/* Top-level config */
typedef struct proxyconfig{
    ProxyEntry entries[64];
    int        count;
    ChainMode  mode;
    int        random_chain_len; /* For CHAIN_RANDOM: how many hops */
} ProxyConfig;

ProxyConfig config_parse(FILE* config_file);
int config_serialize(const ProxyConfig *cfg, char *buf, int bufsz);
