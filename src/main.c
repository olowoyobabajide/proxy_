#include "config.h"
#include "main.h"

#define MAX_ENV_LENGTH 1024

int main(int argc, char **argv){
    if(argc = 1){fprintf(stderr, "No arguments. Try proxy_h(working on it)"); return 1;}

    FILE *f = fopen("proxychains4.conf", "r");
    if (!f) { fprintf(stderr, "Cannot open config file\n"); return 1; }

    ProxyConfig cfg = config_parse(f);

    char out[MAX_ENV_LENGTH];
    int written = config_serialize(&cfg, out, MAX_ENV_LENGTH);

    if(written < 0){
        fprintf(stderr, "Serialization failed: buffer too small\n");
        return 1;
    }

    puts(out);
    fclose(cfg);
    return 0;
}