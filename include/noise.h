/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Noise Protocol Types and Functions
 *
 * Implements Noise_XX_25519_AESGCM_SHA256
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#ifndef WA_NOISE_H
#define WA_NOISE_H

#include <stdint.h>
#include <stddef.h>

/* Protocol constants */
#define NOISE_KEY_SIZE      32
#define NOISE_TAG_SIZE      16
#define NOISE_NONCE_SIZE    12
#define NOISE_HASH_SIZE     32
#define NOISE_MAX_MESSAGE   65535

/* Noise protocol name */
#define NOISE_PROTOCOL_NAME "Noise_XX_25519_AESGCM_SHA256"

/* Handshake patterns */
typedef enum {
    NOISE_PATTERN_XX,     /* XX: -> e, <- e, ee, s, es, -> s, se */
} noise_pattern_t;

/* Handshake state */
typedef enum {
    NOISE_STATE_INIT = 0,
    NOISE_STATE_WRITE_E,
    NOISE_STATE_READ_E_ES_S_ES,
    NOISE_STATE_WRITE_S_SE,
    NOISE_STATE_TRANSPORT,
    NOISE_STATE_ERROR,
} noise_state_t;

/* Cipher state for transport */
typedef struct {
    uint8_t key[NOISE_KEY_SIZE];
    uint64_t nonce;
    int has_key;
} noise_cipher_t;

/* Symmetric state for handshake */
typedef struct {
    uint8_t ck[NOISE_HASH_SIZE];    /* Chaining key */
    uint8_t h[NOISE_HASH_SIZE];     /* Handshake hash */
    noise_cipher_t cipher;
} noise_symmetric_t;

/* Keypair */
typedef struct {
    uint8_t priv[NOISE_KEY_SIZE];
    uint8_t pub[NOISE_KEY_SIZE];
} noise_keypair_t;

/* Main handshake state */
typedef struct {
    noise_state_t state;
    noise_symmetric_t symmetric;

    /* Static keys */
    noise_keypair_t s;              /* Local static */
    uint8_t rs[NOISE_KEY_SIZE];     /* Remote static public */
    int has_rs;

    /* Ephemeral keys */
    noise_keypair_t e;              /* Local ephemeral */
    uint8_t re[NOISE_KEY_SIZE];     /* Remote ephemeral public */
    int has_re;

    /* For session resumption */
    uint8_t server_static_pub[NOISE_KEY_SIZE];
    int has_server_static;
} noise_handshake_t;

/* Transport session after handshake */
typedef struct {
    noise_cipher_t send;
    noise_cipher_t recv;
    uint8_t handshake_hash[NOISE_HASH_SIZE];
} noise_session_t;

/* Initialize handshake as initiator (client) */
int noise_handshake_init(noise_handshake_t *hs, const noise_keypair_t *static_key);

/* Set prologue data */
int noise_set_prologue(noise_handshake_t *hs, const uint8_t *data, size_t len);

/* Write handshake message */
int noise_write_message(noise_handshake_t *hs, const uint8_t *payload, size_t payload_len,
                        uint8_t *out, size_t *out_len);

/* Read handshake message */
int noise_read_message(noise_handshake_t *hs, const uint8_t *message, size_t message_len,
                       uint8_t *payload, size_t *payload_len);

/* Split into transport keys after handshake */
int noise_split(noise_handshake_t *hs, noise_session_t *session);

/* Encrypt message for transport */
int noise_encrypt(noise_session_t *session, const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t *ciphertext, size_t *ciphertext_len);

/* Decrypt message from transport */
int noise_decrypt(noise_session_t *session, const uint8_t *ciphertext, size_t ciphertext_len,
                  uint8_t *plaintext, size_t *plaintext_len);

/* Generate new keypair */
int noise_generate_keypair(noise_keypair_t *kp);

/* Compute public key from private */
int noise_compute_public(const uint8_t *priv, uint8_t *pub);

/* Clean up sensitive data */
void noise_handshake_clear(noise_handshake_t *hs);
void noise_session_clear(noise_session_t *session);

#endif /* WA_NOISE_H */
