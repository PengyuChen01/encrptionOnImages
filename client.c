#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // For getcwd
#include <limits.h>  // For PATH_MAX
#include <openssl/evp.h>
#include "socketAttribute.h"

#define BUFFERSIZE 1024
#define MAX_FILENAME_LEN 256

// Function to encrypt the data using EVP
int encryptData(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    // Initialize the encryption operation
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide the plaintext to be encrypted
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main() {
    char inputFilePath[MAX_FILENAME_LEN];
    char outputFilePath[MAX_FILENAME_LEN];
    char fullInputPath[PATH_MAX];
    char currentDir[PATH_MAX];

    // Ask user for the image file to send
    printf("Enter the image file name (or full path if not in the current directory with {name}.jpg): ");
    fgets(inputFilePath, MAX_FILENAME_LEN, stdin);
    inputFilePath[strcspn(inputFilePath, "\n")] = 0;  // Remove newline

    // Get the current working directory
    if (getcwd(currentDir, sizeof(currentDir)) != NULL) {
        // Check if the user entered a relative file name (no leading '/')
        if (inputFilePath[0] != '/') {
            // Assume the file is in the current directory, and construct the full path
            snprintf(fullInputPath, sizeof(fullInputPath), "%s/%s", currentDir, inputFilePath);
        } else {
            // If the user entered a full path, use it directly
            strncpy(fullInputPath, inputFilePath, sizeof(fullInputPath));
        }
    } else {
        perror("getcwd() error");
        exit(1);
    }

// Automatically save in the current directory
    snprintf(outputFilePath, MAX_FILENAME_LEN, "./%s", inputFilePath);  // Save in the current directory


    int clientSocketFD = createTCPIPv4Socket();
    struct sockaddr_in *address = createTCPIPv4Address("67.205.188.101", 2003);
    int result = connect(clientSocketFD, (struct sockaddr *) address, sizeof(*address));
    if (result == 0)
        printf("Connection is made!\n");
    else {
        perror("Connection failed");
        exit(1);
    }

    // Open the image file (with the full path) for reading
    FILE *imageFile = fopen(fullInputPath, "rb");
    if (!imageFile) {
        perror("Cannot open image file");
        exit(1);
    }

    // Get the size of the file
    fseek(imageFile, 0, SEEK_END);
    long imageSize = ftell(imageFile);
    fseek(imageFile, 0, SEEK_SET);

    unsigned char *imageData = (unsigned char *) malloc(imageSize);
    fread(imageData, 1, imageSize, imageFile);
    fclose(imageFile);

    // Prepare for AES encryption
    unsigned char aesKey[16] = "mysecretkey12345"; // 16-byte AES key
    unsigned char iv[16] = {0};  // Initialization vector (IV) for AES
    unsigned char *encryptedData = (unsigned char *) malloc(
            imageSize + AES_BLOCK_SIZE); // Allocate more space for encryption output
    int encryptedDataLen = encryptData(imageData, imageSize, aesKey, iv, encryptedData);

    if (encryptedDataLen < 0) {
        perror("Encryption failed");
        free(imageData);
        free(encryptedData);
        close(clientSocketFD);
        exit(1);
    }

    // Send the file name to the server
    char *fileName = inputFilePath; // Send the original image file name
    size_t fileNameLen = strlen(fileName) + 1;  // +1 to include the null terminator
    ssize_t nameSent = send(clientSocketFD, fileName, fileNameLen, 0);
    if (nameSent != fileNameLen) {
        perror("Failed to send file name");
        free(imageData);
        free(encryptedData);
        close(clientSocketFD);
        exit(1);
    }

    // Send the size of the encrypted data to the server
    int encryptedSizeNetworkOrder = htonl(encryptedDataLen);  // Convert size to network byte order
    ssize_t sizeSent = send(clientSocketFD, &encryptedSizeNetworkOrder, sizeof(encryptedSizeNetworkOrder), 0);
    if (sizeSent != sizeof(encryptedSizeNetworkOrder)) {
        perror("Failed to send encrypted data size");
        free(imageData);
        free(encryptedData);
        close(clientSocketFD);
        exit(1);
    }

    // Send the encrypted data to the server
    ssize_t amountSent = send(clientSocketFD, encryptedData, encryptedDataLen, 0);
    if (amountSent > 0) {
        printf("Encrypted data sent to the server.\n");
    } else {
        perror("Failed to send encrypted data");
        free(imageData);
        free(encryptedData);
        close(clientSocketFD);
        exit(1);
    }

    // Receive the decrypted data back from the server
    unsigned char *receivedData = (unsigned char *) malloc(imageSize);
    ssize_t amountReceived = recv(clientSocketFD, receivedData, imageSize, 0);
    if (amountReceived > 0) {
        printf("Decrypted data received from the server.\n");

        // Save the decrypted image to the path specified by the user
        FILE *outputFile = fopen(outputFilePath, "wb");
        if (!outputFile) {
            perror("Cannot open output file");
        } else {
            fwrite(receivedData, 1, amountReceived, outputFile);
            fclose(outputFile);
            printf("Decrypted image saved as '%s'.\n", outputFilePath);
        }
    } else if (amountReceived == 0) {
        printf("Server closed the connection.\n");
    } else {
        perror("Failed to receive decrypted data");
    }

    free(imageData);
    free(encryptedData);
    free(receivedData);
    close(clientSocketFD);
    return 0;
}

