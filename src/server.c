#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sessionProtocol.h>

#define PORT 4567

void *handle_client(void *socket_desc) 
{
    unsigned char* plaintext = "Sending data with encryption over secure channel to verify text on other side";
    int client_sock = *(int*)socket_desc;
    ecc_protocol server_ctx;

    /* Initialize ECC model */
    ecc_protocol_init(&server_ctx, SERVER);

    /* populate the ecc ctx with relevant socket number for communication*/
    ecc_protocol_sockfd_set(&server_ctx,client_sock);

    /* Initiate the Handshake for ECC protocol to establish secure connection */
    if(ecc_protocol_call_handshake(&server_ctx) < 0)
    {
        perror("Unable to complete secure connection");
        ecc_protocol_cleanup(&server_ctx);
        exit(EXIT_FAILURE);
    }

    /*
     * for demo purpose we are using the server to send data and 
     * client to receive data. other way can also be done to continue
     * communication
     */
    if((encrypt_send_data(&server_ctx, plaintext, strlen(plaintext))) < 0)
    {
        perror("Send Failed");
        ecc_protocol_cleanup(&server_ctx);
        exit(EXIT_FAILURE);
    }

    /* Clean up the ecc protoco connection this closes the communication socket as well */
    ecc_protocol_cleanup(&server_ctx);
    free(socket_desc);
    return 0;

}
int main() 
{
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) 
    {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    if (bind(sock, (struct sockaddr*)&server, sizeof(server)) < 0) 
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    listen(sock, 100);

    while (1) 
    {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        int client_sock = accept(sock, (struct sockaddr *)&client, &client_len);
        if (client_sock < 0) 
        {
            perror("Accept failed");
            continue;
        }

        int *new_sock = malloc(sizeof(int));
        *new_sock = client_sock;
        pthread_t thread_id;

        /* Create a theread to continue client communication*/
        if (pthread_create(&thread_id, NULL, handle_client, (void*)new_sock) < 0) 
        {
            perror("Could not create thread");
            return 1;
        }

        // Optionally detach the thread - lets the thread release resources upon finishing
        pthread_detach(thread_id);
    }

    close(sock);
}
