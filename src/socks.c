#include "main.h"
#include "base64.h"
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

static int sock5_phase1(int sockfd);
static int sock5_phase2(int sockfd, const char *user, const char *pass);
static int sock5_phase3(int sockfd, const char *host, uint16_t port);

static int sock5_phase1(int sockfd){
    unsigned char buffer[4];

    buffer[0] = 0x05;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = 0x02;
    if(write(sockfd, buffer, 4) != 4){
        perror("write");
        return -1;
    }

    if(read(sockfd, buffer, 2) != 2){
        perror("read");
        return -1;
    }
    if(buffer[0] != 0x05){fprintf(stderr, "Invalid version\n"); return -1;}
    else if(buffer[1] == 0xFF){fprintf(stderr, "server rejected all methods\n"); return -1;} 
    else if(buffer[1] == 0x02){ return 0x02;} 
    else{fprintf(stderr, "Unsupported auth method\n"); return -1;}  

}
       
static int sock5_phase2(int sockfd, const char *user, const char *pass){
    unsigned char buffer[513];
    size_t user_len = strlen(user);
    size_t pass_len = strlen(pass);

    buffer[0] = 0x01;
    buffer[1] = user_len;
    memcpy(buffer + 2, user, user_len);
    buffer[2 + user_len] = pass_len;
    memcpy(buffer + 2 + user_len + 1, pass, pass_len);

    if(write(sockfd, buffer, 2 + user_len + 1 + pass_len) != 2 + user_len + 1 + pass_len){
        perror("write");
        return -1;
    }

    if(read(sockfd, buffer, 2) != 2){
        perror("read");
        return -1;
    }
    if(buffer[0] != 0x01){fprintf(stderr, "Invalid version\n"); return -1;}
    else if(buffer[1] == 0x00){return 0x00;} 
    else{fprintf(stderr, "Unsupported auth method\n"); return -1;}  
}

static int sock5_phase3(int sockfd, const char *host, uint16_t port){
    unsigned char buffer[262];
    size_t host_len = strlen(host);
    uint16_t port_net = htons(port);

    buffer[0] = 0x05;
    buffer[1] = 0x01;
    buffer[2] = 0x00;
    buffer[3] = 0x03;
    buffer[4] = host_len;
    memcpy(buffer + 5, host, host_len);
    buffer[5 + host_len] = (port_net >> 8) & 0xFF;
    buffer[5 + host_len + 1] = port_net & 0xFF;

    if(write(sockfd, buffer, 5 + host_len + 2) != 5 + host_len + 2){
        perror("write");
        return -1;
    }

    if(read(sockfd, buffer, 4) != 4){
        perror("read");
        return -1;
    }
    if(buffer[0] != 0x05){fprintf(stderr, "Invalid version\n"); return -1;}
    else if(buffer[0] == 0x00){return 0x00;} 
   
    unsigned char discard[18];
    if(buffer[3] == 0x01){
        if(read(sockfd, discard, 6) != 6){perror("read"); return -1;}
    }
    else if(buffer[3] == 0x04){
        if(read(sockfd, discard, 18) != 18){perror("read"); return -1;}
    }
    else if(buffer[3] == 0x03){
        int read_len = read(sockfd, discard, 1);
        if(read_len != 1){
            perror("read");
            return -1;
        }
        if(read(sockfd, discard, discard[0] + 2) != discard[0] + 2){perror("read"); return -1;}
    }
    else{fprintf(stderr, "Unknown address type: %d\n", buffer[0]); return -1;}  

     
    
}

int socks5_tunnel(int sockfd, const char *host, uint16_t port, const char *user, const char *pass){

    int method = sock5_phase1(sockfd);
    if(method < 0){
        fprintf(stderr, "Error: socks5 phase 1 failed\n");
        return -1;
    }
    if(method == 0x02){
        if(sock5_phase2(sockfd, user, pass) < 0){
            fprintf(stderr, "Error: socks5 phase 2 failed\n");
            return -1;
        }   
    }
    if(sock5_phase3(sockfd, host, port) < 0){
        fprintf(stderr, "Error: socks5 phase 3 failed\n");
        return -1;
    }
    
    return 0;

}

int socks4_tunnel(int sockfd, const char *host, uint16_t port){
    unsigned char buffer[9];
    
    buffer[0] = 0x04;
    buffer[1] = 0x01;
    uint16_t port_net = htons(port);
    buffer[2] = (port_net >> 8) & 0xFF;
    buffer[3] = port_net & 0xFF;
    // need to work on this line 138 - 146
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    int err = getaddrinfo(host, NULL, &hints, &res);
    if(err != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }
    struct sockaddr_in *addr_in = (struct sockaddr_in *)res->ai_addr;
    memcpy(buffer + 4, &addr_in->sin_addr, 4);
    buffer[8] = 0x00;
    
    freeaddrinfo(res);
    if(write(sockfd, buffer, 9) != 9){
        perror("write");
        return -1;
    }

    if(read(sockfd, buffer, 8) != 8){
        perror("read");
        return -1;
    }
    if(buffer[0] != 0x00){fprintf(stderr, "Invalid version\n"); return -1;}
    else if(buffer[1] == 0x5A){return 0x00;} 
    else{fprintf(stderr, "Connection rejected: %d\n", buffer[1]); return -1;}    
}

        
