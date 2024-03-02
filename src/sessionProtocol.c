#include "sessionProtocol.h"
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static EVP_PKEY *generate_key();
static void generate_key_and_packet(ecc_protocol* ctx, protocol_message_data* data);
static void generate_server_greet_message(ecc_protocol* ctx, protocol_message_data* data);

void print_data_dump(ecc_protocol *ecc, protocol_message_data *data)
{
    printf("message_type %d\n", data->message_type);
    printf("session_id %d\n", data->session_id);

    printf("handshake_message_stage %d\n", data->protocol_data.handshake_message_stage);
    printf("protocol_version %d\n", data->protocol_data.protocol_version);

    handshakeStages state = data->protocol_data.handshake_message_stage;


    if(state == CLIENT_GREET ||  state == SERVER_GREET )
    {
        printf("cipher_suite_length %d\n", data->protocol_data.message_data.hello_message.cipher_suite_length);
        printf("compression_methods_length %d\n", data->protocol_data.message_data.hello_message.compression_methods_length);    
        // TODO cipher suite and compression methods prints will be added once more suites are added
    }
    else if(state == SERVER_KEY || state == CLIENT_KEY)
    {
        printf("Public key_length %d\n", data->protocol_data.message_data.key.key_length);
        printf("Public key %s\n", data->protocol_data.message_data.key.public_key);
    }
    else if(state == SERVER_CERTIFICATE || state == CLIENT_CERTIFICATE)
    {
        printf("certificate key_length %d\n", data->protocol_data.message_data.certificate.certificate_length);
        printf("Certificate %s\n", data->protocol_data.message_data.certificate.certificate);
    }
}


static EVP_PKEY *generate_key() 
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    if (!pctx) return NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0) return NULL;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) return NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) return NULL;
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static unsigned char* secret_key(EVP_PKEY *host_key, EVP_PKEY *target_key,size_t* secret_len)
{
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(host_key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, target_key);
    
    EVP_PKEY_derive(ctx, NULL, secret_len);
    unsigned char *secret = malloc(*secret_len);
    EVP_PKEY_derive(ctx, secret, secret_len);
    
    EVP_PKEY_CTX_free(ctx);

    return secret;
}

/* Function to send data over network*/
static ssize_t send_all(int socket, const void *buffer, size_t length) 
{
    const char *ptr = (const char*)buffer;
    while (length > 0) 
    {
        ssize_t i = send(socket, ptr, length, 0);
        if (i < 1)
        {
            return i; // Error or disconnect
        }
        ptr += i;
        length -= i;
    }
    return 1; // Success
}

// Function to read `n` bytes from a socket using recv()
static ssize_t recv_n(int sockfd, void *buf, size_t n) {
    size_t left = n;
    ssize_t recv_count;
    char *ptr = (char*)buf;

    while (left > 0) 
    {
        if ((recv_count = recv(sockfd, ptr, left, 0)) < 0) 
        {
            if (errno == EINTR) 
            {
                continue; // If interrupted by signal, try again
            }
            if (left == n)
            {
                return -1; // No data read, return error
            }
            else
            {
                break; // Some data was read before error
            }
        } 
        else if (recv_count == 0)
        {
            break; // EOF, the peer has performed an orderly shutdown
        }
        left -= recv_count;
        ptr += recv_count;
    }
    return (n - left); // Return number of bytes read
}

// Function to read `n` bytes from a socket
static ssize_t read_n(int sockfd, void *buf, size_t n) 
{
    size_t left = n;
    ssize_t read_count;
    char *ptr = (char*)buf;

    while (left > 0) 
    {
        if ((read_count = read(sockfd, ptr, left)) < 0) 
        {
            if (left == n) return -1; // No data read
            else break; // Some data was read
        } 
        else if (read_count == 0) 
        {
            break; // EOF
        }
        left -= read_count;
        ptr += read_count;
    }
    return (n - left); // Return number of bytes read
}

/*
 * Generates public key from raw data and creates a EVP key 
 * this needs to freed by the user in the end.
 */
static EVP_PKEY* convert_data_to_public_key(protocol_message_data* data)
{
    size_t length = data->protocol_data.message_data.key.key_length;
    char* data_pubKey = malloc(length);

    BIO *mem = BIO_new_mem_buf(data_pubKey, length);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);

    free(data_pubKey);
    BIO_free(mem);

    return pkey;
}

// Function to hash the shared secret to derive an AES key
static int derive_aes_key_from_secret(ecc_protocol* ctx) 
{

    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256))
        return 0;
    if (!SHA256_Update(&sha256, ctx->session_key.secret_key, ctx->session_key.secret_len))
        return 0;
    if (!SHA256_Final(ctx->aes_encryption_key.aes_key, &sha256)) // First 256 bits for the key
        return 0;

    if(ctx->serv_client != CLIENT)
    {
        // Generate a random IV for AES-CBC
        if (!RAND_bytes(&ctx->aes_encryption_key.iv, AES_BLOCK_SIZE))
            return 0;
    }
    return 1;
}

static void generate_key_and_packet(ecc_protocol* ctx, protocol_message_data* data)
{
    size_t message_length = sizeof(protocol_message_data);
    memset(data,0,message_length);

    data->message_type = HANDSHAKE;
    data->session_id   = 0;   

    EVP_PKEY *key = generate_key();
    ctx->session_key.private_key = key;
    
    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mem, key);

    data->protocol_data.message_data.key.key_length = BIO_get_mem_data(mem, data->protocol_data.message_data.key.public_key);
    data->protocol_data.handshake_message_stage = ctx->state;

    BIO_free(mem);
}

static void generate_certificate(ecc_protocol* ctx, protocol_message_data* data)
{
    size_t message_length = sizeof(protocol_message_data);
    memset(data,0,message_length);

    data->message_type = HANDSHAKE;
    data->session_id   = 0;

    // We can add certificate like this to the data to send 
    // encrpyt the certificare data and add the same 
    // memcpy(&data->protocol_data.message_data.certificate.certificate,&ctx->certificate.certificate,ctx->certificate.certificate_length);

    data->protocol_data.handshake_message_stage = SERVER_CERTIFICATE;
    data->protocol_data.protocol_version        = 1;
    data->protocol_data.message_data.certificate.certificate_length = 0;
}


static void generate_handshake_completed(ecc_protocol* ctx, protocol_message_data* data)
{
    size_t message_length = sizeof(protocol_message_data);
    memset(data,0,message_length);

    data->message_type = HANDSHAKE;
    data->session_id   = 0;

    data->protocol_data.handshake_message_stage = FINISHED;
    data->protocol_data.protocol_version        = 1;
}
/*-----------------------------------------------------------------------------------*/
/*                                   SERVER FUNCTIONS                                */
/*-----------------------------------------------------------------------------------*/       

static uint8_t check_and_reply_agreed_protocol_version(ecc_protocol* ctx)
{
    protocol_message_data* recv_packet = ctx->recv_packet;
    uint16_t protocol_version = recv_packet->protocol_data.protocol_version;

    if(protocol_version < ctx->server_version)
    {
        return protocol_version;
    }
    return ctx->server_version;
}

/*
 * Currently the protocol uses ECC for key generation and 
 * will be changed in the future for proper negotiation
 */
static void check_and_reply_agreed_cipher_suite(ecc_protocol* ctx, protocol_message_data* data)
{
    /* No implmentation for now as both client and server provide the mechanism
     * Encryption
     */
}

static void generate_server_greet_message(ecc_protocol* ctx, protocol_message_data* data)
{
    data->message_type = HANDSHAKE;
    data->session_id   = 0; // Todo updated in the future providing way to save the sessions
    data->protocol_data.protocol_version    = check_and_reply_agreed_protocol_version(ctx);
    data->protocol_data.handshake_message_stage = SERVER_GREET;

    handshake_hello_message* hello_msg = &data->protocol_data.message_data.hello_message;

    check_and_reply_agreed_cipher_suite(ctx, data);
    hello_msg->cipher_suite_length        = 0; // will be calculated in the above function
    hello_msg->compression_method         = NULL; // Nothing implemented yet
    hello_msg->compression_methods_length = 0;
    
}

static void create_handshake_message_server(ecc_protocol* ctx,handshakeStages state,protocol_message_data* data)
{
    switch (state)
    {
        case SERVER_GREET:
            generate_server_greet_message(ctx, data);
            break;
        case SERVER_KEY:
            generate_key_and_packet(ctx, data);
            break;
        //case SERVER_INIT_DONE:
        //    break;
        case SERVER_CERTIFICATE:
            generate_certificate(ctx, data);
            break;
        case FINISHED:
            generate_handshake_completed(ctx,data);
            break;
        default:
            break;
    }
}

static int server_greet(ecc_protocol* ctx, protocol_message_data* data)
{
    ssize_t message_length = sizeof(protocol_message_data);
    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("SERVER_GREET Message receving failed, try again");
        return -1;
    }
    ctx->recv_packet = &data;    
    create_handshake_message_server(ctx,ctx->state,data);

    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("SERVER_GREET Message sending failed, try again");
        return -1;
    }
    ctx->state = SERVER_KEY;
    return 0;
}

static int send_server_key(ecc_protocol* ctx, protocol_message_data* data)
{
    ssize_t message_length = sizeof(protocol_message_data);

    create_handshake_message_server(ctx,SERVER_KEY,data);

    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("SERVER_KEY Message sending failed, try again");
        return -1;
    }
    ctx->state = CLIENT_KEY;

    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("SERVER_KEY Message receving failed, try again");
        return -1;
    }

    ctx->session_key.recv_public_key = convert_data_to_public_key(data);
    ctx->session_key.secret_key = secret_key(ctx->session_key.private_key, ctx->session_key.recv_public_key,
                                             &ctx->session_key.secret_len);

    ctx->state = SERVER_CERTIFICATE;
    return 0;
}

static int send_server_certificate(ecc_protocol* ctx, protocol_message_data* data)
{
    ssize_t message_length = sizeof(protocol_message_data);
    /* 
     * Server Will send pre obtained certificate from 3rd party 
     * Before Sending the certificate it will encrypted using  
     * AES key exchanged during handshake already
     */
    
    create_handshake_message_server(ctx,SERVER_CERTIFICATE,data);

    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("SERVER_SEND_CERTIFICATE Message sending failed, try again");
        return -1;
    }

    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("SERVER_HANDSHAKE_COMPLETE Message receving failed, try again");
        return -1;
    }

    ctx->state = FINISHED;
    return 0;
}

static int server_handshake_complete(ecc_protocol* ctx,protocol_message_data* data)
{
    ssize_t message_length = sizeof(protocol_message_data);
    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("SERVER_HANDSHAKE_COMPLETE Message receving failed, try again");
        return -1;
    }

    if(data->protocol_data.handshake_message_stage != FINISHED)
    {
        perror("SERVER_HANDSHAKE_COMPLETE Message is in wrong state");
        return -1;
    }

    create_handshake_message_server(ctx,FINISHED,data);
    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("SERVER_HANDSHAKE_COMPLETE Message sending failed, try again");
        return -1;
    }

    printf("SERVER_HANDSHAKE_COMPLETE\n");
    ctx->current_protocol_state = ACTIVE;
    return 0;
}

static int handshake_server(ecc_protocol* ctx)
{
    protocol_message_data data;

    handshakeStages state = ctx->state;

    switch (state)
    {
        case SERVER_GREET:
            if(server_greet(ctx,&data) < 0)
            {
                return -1;
            }
        case SERVER_KEY:
            if(send_server_key(ctx,&data) < 0)
            {
                return -1;
            }
            derive_aes_key_from_secret(ctx);
        //case SERVER_INIT_DONE: // Current implementation skips 
        case SERVER_CERTIFICATE:
            if((send_server_certificate(ctx, &data)) < 0)
            {
                return -1;
            }
        case FINISHED:
            if((server_handshake_complete(ctx, &data)) < 0)
            {
                return -1;
            }
            break;
        default:
            return -1;
            break;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*                                   CLIENT FUNCTIONS                                */
/*-----------------------------------------------------------------------------------*/

static void generate_client_greet_message(ecc_protocol* ctx, protocol_message_data* data)
{
    data->message_type = HANDSHAKE;
    data->session_id   = 0; // Todo updated in the future providing way to save the sessions
    data->protocol_data.handshake_message_stage = CLIENT_GREET;
    data->protocol_data.protocol_version        = ctx->client_version;

    handshake_hello_message* hello_msg = &data->protocol_data.message_data.hello_message;

    hello_msg->compression_method               = NULL; // Nothing implemented yet
    hello_msg->compression_methods_length       = 0;
}

static void create_handshake_message_client(ecc_protocol* ctx,handshakeStages state, protocol_message_data* data)
{
    switch (state)
    {
        case CLIENT_GREET:
            generate_client_greet_message(ctx, data);
            break;
        case CLIENT_KEY:
            generate_key_and_packet(ctx, data);
            break;
        case CLIENT_CERTIFICATE:
            generate_certificate(ctx, data);
            break;
        case FINISHED:
            generate_handshake_completed(ctx,data);
            break;
        default:
            break;
    }
}

static int client_greet(ecc_protocol* ctx, protocol_message_data* data)
{
    ssize_t message_length = sizeof(protocol_message_data);
    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("CLIENT_GREET1 Message sending failed, try again");
        return -1;
    }
    create_handshake_message_client(ctx,ctx->state,data);
    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("CLIENT_GREET Message receving failed, try again");
        return -1;
    }
    ctx->state = CLIENT_KEY;
    return 0;
}

static int send_client_key(ecc_protocol* ctx, protocol_message_data* data)
{
    ssize_t message_length = sizeof(protocol_message_data);

    
    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("CLIENT_KEY Message receving failed, try again");
        return -1;
    }
    // create public from recieved data.
    ctx->session_key.recv_public_key = convert_data_to_public_key(data);   
    ctx->state = SERVER_KEY;

    create_handshake_message_client(ctx,CLIENT_KEY,data);

    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("CLIENT_KEY Message sending failed, try again");
        return -1;
    }

    // calculate the secret Key
    ctx->session_key.secret_key = secret_key(ctx->session_key.private_key, ctx->session_key.recv_public_key,
                                             &ctx->session_key.secret_len);
    ctx->state = CLIENT_CERTIFICATE;
    return 0;
}

static int process_certificate(ecc_protocol* ctx, protocol_message_data* data)
{
    return 0;
}

static int receive_and_send_client_certificate(ecc_protocol* ctx, protocol_message_data* data)
{
    /* 
     * Server Will send pre obtained certificate from 3rd party 
     * Before Sending the certificate it will encrypted using  
     * AES key exchanged during handshake already
     */
    size_t message_length = sizeof(protocol_message_data);
    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("CLIENT_CERTIFICATE Message receving failed, try again");
        return -1;
    }
    if(process_certificate(ctx,data) < 0)
    {
        perror("CLIENT_CERTIFICATE process certificate failed, try again");
        return -1;
    }
    create_handshake_message_client(ctx,CLIENT_CERTIFICATE,data);

    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("SERVER_SEND_CERTIFICATE Message sending failed, try again");
        return -1;
    }

    ctx->state = FINISHED;
    return 0;
}

static int client_handshake_completed(ecc_protocol* ctx, protocol_message_data* data)
{
    ssize_t message_length = sizeof(protocol_message_data);
    create_handshake_message_client(ctx,FINISHED,data);
    if((send_all(ctx->sockfd, data, message_length)) != 1)
    {
        perror("CLIENT_Recive_FINISHED Message sending failed, try again");
        return -1;
    }

    printf("CLIENT_HANDSHAKE_COMPLETE\n");
    
    if((recv_n(ctx->sockfd, data, message_length)) != message_length)
    {
        perror("CLIENT_Send_FINISHED Message receving failed, try again");
        return -1;
    }

    ctx->current_protocol_state = ACTIVE;
    return 0;
}

static int handshake_client(ecc_protocol* ctx)
{
    int handshakeReturn = 0;
    handshakeStages state = ctx->state;
    protocol_message_data data;

    switch (state)
    {
        case CLIENT_GREET:
            if((client_greet(ctx,&data)) < 0)
            {
               return -1;
            }
        case CLIENT_KEY:
            if((send_client_key(ctx, &data)) < 0)
            {
                return -1;
            }
            derive_aes_key_from_secret(ctx);
        case CLIENT_CERTIFICATE:
            if((receive_and_send_client_certificate(ctx, &data)) < 0)
            {
                return -1;
            }
        case FINISHED:
            if((client_handshake_completed(ctx, &data)) < 0)
            {
                return -1;
            }
            break;
        default:
            return -1;
            break;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*                                   Initialization                                  */
/*-----------------------------------------------------------------------------------*/

int ecc_protocol_init(ecc_protocol* ctx, entity system_entity)
{
    memset(ctx,0,sizeof(ecc_protocol));
    if(system_entity == SERVER)
    {
        ctx->handshake_func          = handshake_server;
        ctx->state                   = SERVER_GREET;
    }
    if(system_entity == CLIENT)
    {    
        ctx->handshake_func          = handshake_client;
        ctx->state                   = CLIENT_GREET;
    }

    ctx->server_version          = 1;
    ctx->current_protocol_state  = NO_CONNECTION;
    ctx->session_id              = 0;
    ctx->cipherList              = NULL;
    ctx->serv_client             = system_entity;

    return 0;

}

void ecc_protocol_sockfd_set(ecc_protocol* ctx, int sockfd)
{
    ctx->sockfd = sockfd;
}

int ecc_protocol_call_handshake(ecc_protocol* ctx)
{
    int handshake_status = ctx->handshake_func(ctx);
    return handshake_status;
}

void ecc_protocol_cleanup(ecc_protocol* ctx)
{
    if(ctx->session_key.private_key)
    {
        free(ctx->session_key.private_key);
    }
    if(ctx->session_key.recv_public_key)
    {
        free(ctx->session_key.recv_public_key);
    }
    if(ctx->session_key.secret_key)
    {
        free(ctx->session_key.secret_key);
    }
    ctx->recv_packet = NULL;

    close(ctx->sockfd);
}
/*-----------------------------------------------------------------------------------*/
/*                                   SEND_RECV                                  */
/*-----------------------------------------------------------------------------------*/

static unsigned char* ecc_protocol_read(ecc_protocol* ctx, int* ciphertext_len, unsigned char* iv)
{
    int sock = ctx->sockfd;
    int net_len = 7;
    int n = 0;

    // Read the IV from the socket
    if ((n = recv_n(sock, iv, AES_BLOCK_SIZE)) != AES_BLOCK_SIZE)
    {
        perror("Failed to read IV");
        return NULL;
    }
    //printf("N AES_BLOCK SIZE is %d and iv is %s\n",n,iv);

    //printf("IV read is %s",iv);

    // Read the ciphertext length (network byte order) and convert to host byte order
    if ((n = recv_n(sock, &net_len, sizeof(net_len))) != sizeof(net_len))
    {
        perror("Failed to read ciphertext length");
        return NULL;
    }
    *ciphertext_len = ntohl(net_len);

    if (*ciphertext_len > 1024) 
    {
        fprintf(stderr, "Ciphertext size too large\n");
        return NULL;
    }

    unsigned char* ciphertext = malloc(*ciphertext_len);

    if(ciphertext == NULL)
    {
        printf("Memory allocation failed for recevinig data\n");
        return NULL;
    }
    // Read the ciphertext from the socket
    if (recv_n(sock, ciphertext, *ciphertext_len) != *ciphertext_len) 
    {
        perror("Failed to read ciphertext");
        return NULL;
    }

    return ciphertext;
}


// Helper function to decrypt data using AES-256-CBC
static int decrypt_ecc_data_aes_256_cbc(ecc_protocol* ecc_ctx, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, unsigned char* iv) 
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) 
    {
        return 0;
    }

    // Initialise the decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &ecc_ctx->aes_encryption_key.aes_key, iv /*&ecc_ctx->aes_encryption_key.iv*/))
    { 
       return 0;
    }

    // Provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        return 0;
    }
    plaintext_len = len;

    // Finalise the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        printf("Decryption failed.\n");
        return 0; // Note: This can happen if the ciphertext or key/iv is incorrect
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

static int ecc_protocol_send(ecc_protocol* ctx, char* ciphertext, int ciphertext_len)
{
    int client_sock = ctx->sockfd;
    // Send the IV to the client
    if (send_all(client_sock, ctx->aes_encryption_key.iv, AES_BLOCK_SIZE) != 1)
    {
        printf("Failed to send IV.\n");
        return -1;
    }

    // Send the ciphertext length (network byte order for consistency)
    uint32_t net_len = htonl(ciphertext_len); // Ensure the length is in network byte order
    if (send_all(client_sock, &net_len, sizeof(net_len)) != 1) 
    {
        printf("Failed to send ciphertext length.\n");
        return -1;
    }

    // Send the ciphertext to the client
    if (send_all(client_sock, ciphertext, ciphertext_len) != 1) 
    {
        printf("Failed to send ciphertext.\n");
        return -1;
    }
    return 0;
}

// Function to encrypt data using AES-256-CBC
static int encrypt_ecc_data_aes_256_cbc(ecc_protocol* ecc_ctx, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) 
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

    // Initialise the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &ecc_ctx->aes_encryption_key.aes_key, ecc_ctx->aes_encryption_key.iv))
    {
        return 0;
    }
    // Provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        return 0;
    }
    ciphertext_len = len;

    // Finalise the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
    {
        return 0; 
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int encrypt_send_data(ecc_protocol* ecc_ctx, const unsigned char *plaintext, int plaintext_len)
{
    unsigned char* ciphertext = malloc(plaintext_len);

    int ciphertext_len = encrypt_ecc_data_aes_256_cbc(ecc_ctx, plaintext, plaintext_len,
                                                      ciphertext);

    if((ecc_protocol_send(ecc_ctx, ciphertext, ciphertext_len)) < 0)
    {
        perror("User Send Failed");
        return -1;
    }

    free(ciphertext);
    return 0;
                                        
}

int recv_decrypt_data(ecc_protocol* ecc_ctx,unsigned char* decryptedtext, unsigned char* iv)
{
    int ciphertext_len = 0;
    unsigned char* ciphertext;
    if((ciphertext = ecc_protocol_read(ecc_ctx,&ciphertext_len,iv)) == NULL)
    {
        perror("Read Failed");
        return -1;
    }

    int decryptedtext_len = decrypt_ecc_data_aes_256_cbc(ecc_ctx, ciphertext, ciphertext_len, decryptedtext, iv);
    decryptedtext[decryptedtext_len] = '\0';

    free(ciphertext);
    return 0;
}
