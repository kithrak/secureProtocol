#ifndef SESSIONPROTOCOL_H
#define SESSIONPROTOCOL_H

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

typedef enum SYSTEM_ENTITY
{
    CLIENT = 0,
    SERVER
}entity; 



/* 
 * defines various states the protocol can be 
 * present.
 */
typedef enum PROTOCOL_STATE
{
    RESET = 0,
    NO_CONNECTION,
    HANDSHAKE,
    HANDSHAKE_FAILED,
    ACTIVE,
    CLOSE
}protocol_state;

typedef enum HANDSHAKE_STAGES
{
    CLIENT_GREET = 0,
    SERVER_GREET,
    SERVER_KEY,
    SERVER_GREET_DONE,
    CLIENT_KEY,
    SERVER_CERTIFICATE,
    CLIENT_CERTIFICATE,
    FINISHED
}handshakeStages;

/*
 * Holds the private and secret key used for communication
 */
typedef struct ECC_SESSION_KEYS
{
    EVP_PKEY* private_key; // memory initialized during init()
    EVP_PKEY* recv_public_key; // memory initialized during init()
    size_t secret_len;
    unsigned char* secret_key;
}ecc_key;

typedef struct AES_SESSION_KEY
{
    unsigned char aes_key[32];
    unsigned char iv[16];
}aes_key;

typedef struct CIPHER_SUITE
{
    uint16_t key_generation_algo;
    uint16_t cipher_algo;
    //uint16_t hash_algo
}cipherSuite;
/*
 * Data Structure to hold server data 
 */

/*typedef struct SERVER
{
    
};*/

typedef struct HANDSHAKE_MESSAGETYPE
{
    uint16_t cipher_suite_length;
    cipherSuite cipher_suite[10];
    uint8_t compression_methods_length;
    unsigned char* compression_method; 
}handshake_hello_message;

typedef struct HANDSHAKE_KEY_EXCHANGE
{
    uint16_t key_length; 
    unsigned char public_key[65]; // uncompressed byte
}handshake_key;

typedef struct HANDSHAKE_CERTIFICATE
{
    uint16_t certificate_length;
    unsigned char certificate[128]; // Length should be changed when actual implementation is done
}handshake_certificate;

typedef union HANDSHAKE_MESSAGE
{
    handshake_hello_message hello_message;
    handshake_key key;
    handshake_certificate certificate;
}handshake_message;

typedef struct HANDSHAKE_MESSAGE_DATA
{
    handshakeStages handshake_message_stage;
    uint16_t protocol_version;
    handshake_message message_data;   
}handshake_message_data;


typedef struct PROTOCOL_MESSAGE_HANDSHAKE
{
    protocol_state message_type;
    uint16_t session_id;
    handshake_message_data protocol_data;
}protocol_message_data;

typedef struct ECC_SESSION_PROTOCOL ecc_protocol_t;

typedef struct ECC_SESSION_PROTOCOL
{
    uint32_t server_version;
    uint32_t client_version;
    uint32_t current_protocol_state;
    uint32_t session_id;
    ecc_key  session_key;
    aes_key  aes_encryption_key;
    /* Used for starting handshake*/
    int (*handshake_func)(ecc_protocol_t* ctx);
    char* cipherList;
    uint16_t cipherList_length;
    //server server_function;
    //client client_function;
    protocol_message_data* recv_packet;
    handshakeStages state;
    handshake_certificate certificate;

    int sockfd;
    entity serv_client;

}ecc_protocol;

int ecc_protocol_init(ecc_protocol* ctx, entity system_entity);
void ecc_protocol_sockfd_set(ecc_protocol* ctx, int sockfd);
int ecc_protocol_call_handshake(ecc_protocol* ctx);
void ecc_protocol_cleanup(ecc_protocol* ctx);
int recv_decrypt_data(ecc_protocol* ecc_ctx,unsigned char* decryptedtext, unsigned char* iv);
int encrypt_send_data(ecc_protocol* ecc_ctx, const unsigned char *plaintext, int plaintext_len);


#endif

