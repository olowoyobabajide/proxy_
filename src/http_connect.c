#include "main.h"
#include "base64.h"
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <strings.h>

int http_response_tunnel(int sockfd);

static int wait_readable(int fd, int timeout_sec){
    fd_set set;
    struct timeval tv;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    int r = select(fd + 1, &set, NULL, NULL, &tv);
    if(r <= 0) return -1;
    return 0;
}       
int http_connect_tunnel(int sockfd, const char *host, uint16_t port, const char *user, const char *pass){
    bool auth = false;
    char buffer[1024];
    int len;
    char *base64_auth = NULL;

    auth = (user && user[0] != '\0') ? true : false;
    
    if(auth){ 
        base64_auth = base64_encode(user, pass);
        len = snprintf(buffer, sizeof(buffer), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\n\r\n", host, port, host, port, base64_auth);
        if(len >= sizeof(buffer)){fprintf(stderr, "Error: Buffer overflow\n"); return -1;}
    }
    else{
        len = snprintf(buffer, sizeof(buffer), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port);
        if(len >= sizeof(buffer)){fprintf(stderr, "Error: Buffer overflow\n"); return -1;}
    }
    free(base64_auth);
    base64_auth = NULL;
    
    size_t buf_len = strlen(buffer);
    int off = 0;
    int rem = buf_len;
    while(rem > 0){
        int sent = write(sockfd, buffer + off, rem);
        if(sent < 0){
            if(errno == EINTR) continue;
            perror("write");
            return -1;
        }
        off += sent;
        rem -= sent;
    }
    int result = http_response_tunnel(sockfd);
    return result;
}

int http_response_tunnel(int sockfd){
    char a;
    char buffer[257];
    int off = 0;
    int sequence = 0;

    int read_len;
    while(1){
        if(wait_readable(sockfd, 10) < 0){
            fprintf(stderr, "Error: read timeout\n");
            return -1;
        }
        read_len = read(sockfd, &a, 1);
        if(read_len == 0){fprintf(stderr, "Error: Connection closed\n"); return -1;}
        if(read_len < 0){
            if(errno == EINTR) continue;
            perror("read");
            return -1;
        }
        if(off >= sizeof(buffer)){
            fprintf(stderr, "Error: Buffer overflow\n");
            return -1;
        }
        buffer[off] = a;
        off += read_len;
        
        if((a == '\r' && sequence == 0) || (a == '\r' && sequence == 2)){
            sequence++;
        }
        else if(a == '\n' && sequence == 1){
            sequence++;
        }
        else if(a == '\n' && sequence == 3){
            sequence++;
            break;
        }
        else{
            sequence = 0;
        }
       
    }

    buffer[off] = '\0';
    int status_code;
    sscanf(buffer, "%*s %d", &status_code);
    if(status_code != 200){
        fprintf(stderr, "Error: %s\n", buffer);
        return -1;
    }
    
    return 0;
}