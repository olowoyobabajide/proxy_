#include "main.h"
#include <unistd.h>
#include <limits.h>

int hook_path(){
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if(len < 0){fprintf(stderr, "readlink Failed\n"); return -1;}
    buf[len] = '\0';

    buf = strrchr(buf, '/');
    *buf = '\0';

    strncat(buf, "/proxytool_hook.so", 18);
    
    if(getenv("LD_PRELOAD") == NULL){setenv("LD_PRELOAD", buf, 1);}
    else{setenv("LD_PRELOAD", new_string, 1)}
}