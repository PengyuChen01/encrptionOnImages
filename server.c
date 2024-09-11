#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "socketAttribute.h"

#define BUFFERSIZE 1024
#define MAX_FILENAME_LEN 256

// Define AcceptedASocket structure
struct AcceptedASocket {
    int acceptedSocketFD;
    struct sockaddr_in address;
    int error;
    bool acceptedSuccessfully;
};

// Function to decrypt the data using EVP
int decryptData(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    // Initialize the decryption operation
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide the ciphertext to be decrypted
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalize decryption
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Function to receive data over multiple chunks
int receiveFullData(int socket, unsigned char *buffer, int totalSize) {
    int received = 0;
    int result;
    while (received < totalSize) {
        result = recv(socket, buffer + received, totalSize - received, 0);
        if (result < 0) {
            return -1;  // Error
        }
        received += result;
    }
    return received;
}

void *receiveAndDecryptIncomingData(void *clientSocketPtr) {
    struct AcceptedASocket *clientSocket = (struct AcceptedASocket *) clientSocketPtr;
    int encryptedSize;
    ssize_t amountReceived;

    // AES Key and IV (must match client values)
    unsigned char aesKey[16] = "mysecretkey12345"; // 16-byte AES key (same as client)
    unsigned char iv[16] = {0};  // Initialization vector (same as client)

    // Step 1: Receive the file name
    char fileName[MAX_FILENAME_LEN];
    amountReceived = recv(clientSocket->acceptedSocketFD, fileName, sizeof(fileName), 0);
    if (amountReceived <= 0) {
        printf("Failed to receive file name.\n");
        close(clientSocket->acceptedSocketFD);
        free(clientSocket);
        return NULL;
    }
    fileName[amountReceived] = '\0';  // Null-terminate the received file name
    printf("Received file name: %s\n", fileName);

    // Create the output file name by prepending "decrypted_"
    char decryptedFileName[MAX_FILENAME_LEN];
    snprintf(decryptedFileName, sizeof(decryptedFileName), "decrypted_%s", fileName);

    // Step 2: Receive the size of the encrypted data
    amountReceived = recv(clientSocket->acceptedSocketFD, &encryptedSize, sizeof(encryptedSize), 0);
    if (amountReceived != sizeof(encryptedSize)) {
        printf("Failed to receive encrypted data size.\n");
        close(clientSocket->acceptedSocketFD);
        free(clientSocket);
        return NULL;
    }

    encryptedSize = ntohl(encryptedSize); // Convert size from network byte order to host byte order
    printf("Expecting encrypted data of size: %d bytes\n", encryptedSize);

    // Step 3: Allocate buffer and receive the actual encrypted data
    unsigned char *buffer = (unsigned char *) malloc(encryptedSize);
    if (!buffer) {
        perror("Failed to allocate memory for receiving encrypted data.");
        close(clientSocket->acceptedSocketFD);
        free(clientSocket);
        return NULL;
    }

    amountReceived = receiveFullData(clientSocket->acceptedSocketFD, buffer, encryptedSize);
    if (amountReceived != encryptedSize) {
        printf("Failed to receive all encrypted data.\n");
        free(buffer);
        close(clientSocket->acceptedSocketFD);
        free(clientSocket);
        return NULL;
    }

    printf("Received encrypted data from client. Length: %d bytes\n", encryptedSize);

    // Step 4: Decrypt the data
    unsigned char *decryptedData = (unsigned char *) malloc(
            encryptedSize);  // Allocating the same size for decrypted data
    if (!decryptedData) {
        perror("Failed to allocate memory for decryption.");
        free(buffer);
        close(clientSocket->acceptedSocketFD);
        free(clientSocket);
        return NULL;
    }

    int decryptedDataLen = decryptData(buffer, encryptedSize, aesKey, iv, decryptedData);
    if (decryptedDataLen > 0) {
        printf("Decryption successful. Data length: %d bytes.\n", decryptedDataLen);

        // Save the decrypted data with the new file name
        FILE *outputFile = fopen(decryptedFileName, "wb");
        if (outputFile) {
            fwrite(decryptedData, 1, decryptedDataLen, outputFile);
            fclose(outputFile);
            printf("Decrypted image saved as '%s'.\n", decryptedFileName);
        } else {
            perror("Error opening file to save decrypted data");
        }
    } else {
        printf("Decryption failed.\n");
    }

    free(buffer);
    free(decryptedData);
    close(clientSocket->acceptedSocketFD); // Close the connection socket
    free(clientSocket); // Free the allocated structure
    return NULL;
}

// Accepts an incoming connection and returns a structure containing socket information
struct AcceptedASocket *acceptIncomingConnection(int serverSocketFD) {
    struct sockaddr_in clientAddress;
    socklen_t clientAddressSize = sizeof(clientAddress);
    int clientSocketFD = accept(serverSocketFD, (struct sockaddr *) &clientAddress, &clientAddressSize);

    struct AcceptedASocket *acceptedASocket = malloc(sizeof(struct AcceptedASocket));
    acceptedASocket->address = clientAddress;
    acceptedASocket->acceptedSocketFD = clientSocketFD;
    acceptedASocket->acceptedSuccessfully = (clientSocketFD > 0);

    if (!acceptedASocket->acceptedSuccessfully) {
        acceptedASocket->error = clientSocketFD;
    }

    return acceptedASocket;
}

void receiveAndDecryptIncomingDataOnSeparateThread(struct AcceptedASocket *clientSocket) {
    pthread_t threadID;
    pthread_create(&threadID, NULL, receiveAndDecryptIncomingData, (void *) clientSocket);
    pthread_detach(threadID); // Automatically cleans up resources after the thread finishes
}

// This function should be implemented in your server.c or in another source file
void startAcceptingIncomingConnections(int serverSocketFD) {
    while (true) {
        struct AcceptedASocket *clientSocket = acceptIncomingConnection(serverSocketFD);
        if (clientSocket->acceptedSuccessfully) {
            receiveAndDecryptIncomingDataOnSeparateThread(clientSocket);
        } else {
            printf("Error accepting connection: %d\n", clientSocket->error);
            free(clientSocket); // Clean up if the connection was unsuccessful
        }
    }
}

int main() {
    int serverSocketFD = createTCPIPv4Socket();
    struct sockaddr_in *serverAddress = createTCPIPv4Address("67.205.188.101", 2003);

    // Correct the bind() call by casting to (struct sockaddr *)
    int result = bind(serverSocketFD, (struct sockaddr *) serverAddress, sizeof(*serverAddress));
    if (result == 0) {
        printf("Socket bound to port %d\n", ntohs(serverAddress->sin_port));
    } else {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    int listenResult = listen(serverSocketFD, 10);
    if (listenResult == 0) {
        printf("Listening for incoming connections...\n");
    } else {
        perror("Error starting to listen");
        exit(EXIT_FAILURE);
    }

    // Start accepting connections
    startAcceptingIncomingConnections(serverSocketFD);

    // Close the server socket
    shutdown(serverSocketFD, SHUT_RDWR);
    close(serverSocketFD);
    return 0;
}
