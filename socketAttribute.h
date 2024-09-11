//
// Created by chen on 9/4/24.
//

#ifndef SERVER_CLIENT_ENCRPTION_SOCKETATTRIBUTE_H
#define SERVER_CLIENT_ENCRPTION_SOCKETATTRIBUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

int createTCPIPv4Socket();

struct sockaddr_in *createTCPIPv4Address(char *ip, int port);

#endif //SERVER_CLIENT_ENCRPTION_SOCKETATTRIBUTE_H
