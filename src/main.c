#include "config.h"
#include "main.h"

#define MAX_ENV_LENGTH 1024

int main(int argc, char **argv){
    if(argc == 1){fprintf(stderr, "No arguments. Try proxy_h(working on it)"); return 1;}

    FILE *f = fopen("proxychains4.conf", "r");
    if (!f) { fprintf(stderr, "Cannot open config file\n"); return 1; }

    ProxyConfig cfg = config_parse(f);
    fclose(f);

    char out[MAX_ENV_LENGTH];
    int written = config_serialize(&cfg, out, MAX_ENV_LENGTH);

    if(written < 0){
        fprintf(stderr, "Serialization failed: buffer too small\n");
        return -1;
    }

    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if(len < 0){fprintf(stderr, "readlink Failed\n"); return -1;}
    buf[len] = '\0';

    char *p = strrchr(buf, '/');
    if(p == NULL){ fprintf(stderr, "Unexpected exe path\n"); return -1; }
    *p = '\0';

    strncat(buf, "/proxytool_hook.so", sizeof(buf) - strlen(buf) - 1);
    
    const char *existing = getenv("LD_PRELOAD");
    char new_string[PATH_MAX];
    if(existing == NULL){setenv("LD_PRELOAD", buf, 1);}
    else{
        snprintf(new_string, sizeof(new_string)-1, "%s %s", existing, buf);
        setenv("LD_PRELOAD", new_string, 1);
    }

    if(execvp(argv[1], &argv[1]) < 0){perror("execvp"); return -1;}

    return 0;
}