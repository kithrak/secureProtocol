#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sessionProtocol.h>

#define PORT 4567

int main()
{
    int sock;
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char decryptedtext[1024 + AES_BLOCK_SIZE];
    ecc_protocol client_ctx;

    /* Initialize ECC model */
    ecc_protocol_init(&client_ctx, CLIENT);

    /* create socket for communication */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) 
    {
	    perror("Unable to create socket");
	    exit(EXIT_FAILURE);
    }

    /* For development purpose set the IP and port to internal*/
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Connect to the server and wait for ack */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
    {
	    perror("Unable to connect");
	    exit(EXIT_FAILURE);
    }

    /* populate the ecc ctx with relevant socket number for communication*/
    ecc_protocol_sockfd_set(&client_ctx, sock);

    /* Initiate the Handshake for ECC protocol to establish secure connection */
    if(ecc_protocol_call_handshake(&client_ctx) < 0)
    {
        perror("Unable to complete secure connection");
        ecc_protocol_cleanup(&client_ctx);
        exit(EXIT_FAILURE);
    }

    /*
     * for demo purpose we are using the server to send data and 
     * client to receive data. other way can also be done to continue
     * communication
     */
    if((recv_decrypt_data(&client_ctx, decryptedtext, iv)) < 0)
    {
        perror("Read Failed");
        ecc_protocol_cleanup(&client_ctx);
        exit(EXIT_FAILURE);
    }

    printf("Decrypted text: %s\n", decryptedtext );

    /* Clean up the ecc protoco connection this closes the communication socket as well */
    ecc_protocol_cleanup(&client_ctx);
    return 0;

}
