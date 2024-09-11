//
// Created by chen on 9/4/24.
//
#include "socketAttribute.h"

int createTCPIPv4Socket() { return socket(AF_INET, SOCK_STREAM, 0); }

struct sockaddr_in *createTCPIPv4Address(char *ip, int port) {
    struct sockaddr_in *address = malloc(sizeof(struct sockaddr_in));
    address->sin_port = htons(port);  // Make sure to convert to network byte order
    address->sin_family = AF_INET;
    if (strlen(ip) == 0) {
        address->sin_addr.s_addr = INADDR_ANY;  // Bind to all available interfaces
    } else {
        inet_pton(AF_INET, ip, &address->sin_addr.s_addr);
    }
    return address;
}

