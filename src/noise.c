/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Noise Protocol XX Implementation
 *
 * Implements Noise_XX_25519_AESGCM_SHA256
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include "noise.h"

/* External crypto functions */
extern void crypto_random(uint8_t *buf, size_t len);
extern int crypto_keypair_generate(uint8_t *priv, uint8_t *pub);
extern int crypto_keypair_compute_public(const uint8_t *priv, uint8_t *pub);
extern int crypto_dh(const uint8_t *priv, const uint8_t *pub, uint8_t *shared);
extern int crypto_sha256(const uint8_t *data, size_t len, uint8_t *hash);
extern int crypto_hkdf(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len);
extern int crypto_aes_gcm_encrypt(const uint8_t *key,
                                  const uint8_t *nonce, size_t nonce_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *ciphertext, uint8_t *tag);
extern int crypto_aes_gcm_decrypt(const uint8_t *key,
                                  const uint8_t *nonce, size_t nonce_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *ciphertext, size_t ciphertext_len,
                                  uint8_t *plaintext);
extern void crypto_zero(void *buf, size_t len);

/* Protocol prologue for WhatsApp */
static const uint8_t WA_PROLOGUE[] = {0x57, 0x41, 0x06, 0x03};  /* "WA" + version 6.3 */

/*
 * Symmetric state operations
 */

/* Mix key material into the chaining key */
static void mix_key(noise_symmetric_t *ss, const uint8_t *input, size_t input_len)
{
    uint8_t out[64];

    crypto_hkdf(ss->ck, NOISE_HASH_SIZE, input, input_len, NULL, 0, out, 64);

    memcpy(ss->ck, out, 32);
    memcpy(ss->cipher.key, out + 32, 32);
    ss->cipher.nonce = 0;
    ss->cipher.has_key = 1;

    crypto_zero(out, sizeof(out));
}

/* Mix hash with data */
static void mix_hash(noise_symmetric_t *ss, const uint8_t *data, size_t len)
{
    uint8_t input[NOISE_HASH_SIZE + NOISE_MAX_MESSAGE];
    size_t input_len = NOISE_HASH_SIZE + len;

    if (len > NOISE_MAX_MESSAGE) {
        return;
    }

    memcpy(input, ss->h, NOISE_HASH_SIZE);
    memcpy(input + NOISE_HASH_SIZE, data, len);

    crypto_sha256(input, input_len, ss->h);
    crypto_zero(input, sizeof(input));
}

/* Encrypt with cipher state */
static int encrypt_with_ad(noise_cipher_t *cs, const uint8_t *ad, size_t ad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext, size_t *ciphertext_len)
{
    if (!cs->has_key) {
        /* No key, just copy */
        memcpy(ciphertext, plaintext, plaintext_len);
        *ciphertext_len = plaintext_len;
        return 0;
    }

    /* Check for nonce overflow - must rekey before this happens */
    if (cs->nonce == UINT64_MAX) {
        return -1;  /* Nonce exhausted, cannot encrypt safely */
    }

    /* Build nonce (8 bytes of 0 + 8 bytes of counter, little-endian) */
    uint8_t nonce[12] = {0};
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (cs->nonce >> (i * 8)) & 0xFF;
    }

    if (crypto_aes_gcm_encrypt(cs->key, nonce, 12, ad, ad_len,
                               plaintext, plaintext_len,
                               ciphertext, ciphertext + plaintext_len) != 0) {
        return -1;
    }

    *ciphertext_len = plaintext_len + NOISE_TAG_SIZE;
    cs->nonce++;

    return 0;
}

/* Decrypt with cipher state */
static int decrypt_with_ad(noise_cipher_t *cs, const uint8_t *ad, size_t ad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           uint8_t *plaintext, size_t *plaintext_len)
{
    if (!cs->has_key) {
        /* No key, just copy */
        memcpy(plaintext, ciphertext, ciphertext_len);
        *plaintext_len = ciphertext_len;
        return 0;
    }

    if (ciphertext_len < NOISE_TAG_SIZE) {
        return -1;
    }

    /* Check for nonce overflow - must rekey before this happens */
    if (cs->nonce == UINT64_MAX) {
        return -1;  /* Nonce exhausted, cannot decrypt safely */
    }

    /* Build nonce */
    uint8_t nonce[12] = {0};
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (cs->nonce >> (i * 8)) & 0xFF;
    }

    if (crypto_aes_gcm_decrypt(cs->key, nonce, 12, ad, ad_len,
                               ciphertext, ciphertext_len,
                               plaintext) != 0) {
        return -1;
    }

    *plaintext_len = ciphertext_len - NOISE_TAG_SIZE;
    cs->nonce++;

    return 0;
}

/* Encrypt and mix hash */
static int encrypt_and_hash(noise_symmetric_t *ss,
                            const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *ciphertext, size_t *ciphertext_len)
{
    int ret = encrypt_with_ad(&ss->cipher, ss->h, NOISE_HASH_SIZE,
                              plaintext, plaintext_len,
                              ciphertext, ciphertext_len);
    if (ret == 0) {
        mix_hash(ss, ciphertext, *ciphertext_len);
    }
    return ret;
}

/* Decrypt and mix hash - NOTE: caller must save hash before calling if needed */
__attribute__((unused))
static int decrypt_and_hash(noise_symmetric_t *ss,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            uint8_t *plaintext, size_t *plaintext_len)
{
    /* Save current hash for use as AD */
    uint8_t saved_h[NOISE_HASH_SIZE];
    memcpy(saved_h, ss->h, NOISE_HASH_SIZE);

    /* Mix hash with ciphertext */
    mix_hash(ss, ciphertext, ciphertext_len);

    /* Decrypt using saved hash as AD */
    int ret = decrypt_with_ad(&ss->cipher, saved_h, NOISE_HASH_SIZE,
                              ciphertext, ciphertext_len,
                              plaintext, plaintext_len);

    crypto_zero(saved_h, sizeof(saved_h));
    return ret;
}

/*
 * Handshake operations
 */

/* Initialize symmetric state with protocol name */
static void initialize_symmetric(noise_symmetric_t *ss)
{
    const char *protocol = NOISE_PROTOCOL_NAME;
    size_t len = strlen(protocol);

    if (len <= NOISE_HASH_SIZE) {
        sodium_memzero(ss->h, NOISE_HASH_SIZE);
        memcpy(ss->h, protocol, len);
    } else {
        crypto_sha256((const uint8_t *)protocol, len, ss->h);
    }

    memcpy(ss->ck, ss->h, NOISE_HASH_SIZE);
    sodium_memzero(&ss->cipher, sizeof(ss->cipher));
}

/* Initialize handshake */
int noise_handshake_init(noise_handshake_t *hs, const noise_keypair_t *static_key)
{
    sodium_memzero(hs, sizeof(*hs));

    /* Copy static key */
    if (static_key != NULL) {
        memcpy(&hs->s, static_key, sizeof(*static_key));
    } else {
        noise_generate_keypair(&hs->s);
    }

    /* Initialize symmetric state */
    initialize_symmetric(&hs->symmetric);

    /* Mix in prologue */
    mix_hash(&hs->symmetric, WA_PROLOGUE, sizeof(WA_PROLOGUE));

    hs->state = NOISE_STATE_INIT;

    return 0;
}

/* Set prologue (call before any messages) */
int noise_set_prologue(noise_handshake_t *hs, const uint8_t *data, size_t len)
{
    if (hs->state != NOISE_STATE_INIT) {
        return -1;
    }

    mix_hash(&hs->symmetric, data, len);
    return 0;
}

/*
 * XX Pattern:
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 */

/* Write handshake message */
int noise_write_message(noise_handshake_t *hs, const uint8_t *payload, size_t payload_len,
                        uint8_t *out, size_t *out_len)
{
    size_t pos = 0;

    switch (hs->state) {
    case NOISE_STATE_INIT:
        /* -> e */
        /* Generate ephemeral keypair */
        noise_generate_keypair(&hs->e);

        /* Write ephemeral public key */
        memcpy(out + pos, hs->e.pub, NOISE_KEY_SIZE);
        pos += NOISE_KEY_SIZE;

        /* Mix hash with e */
        mix_hash(&hs->symmetric, hs->e.pub, NOISE_KEY_SIZE);

        /* Encrypt and send payload (empty for first message usually) */
        if (payload != NULL && payload_len > 0) {
            size_t ct_len;
            encrypt_and_hash(&hs->symmetric, payload, payload_len, out + pos, &ct_len);
            pos += ct_len;
        }

        hs->state = NOISE_STATE_READ_E_ES_S_ES;
        break;

    case NOISE_STATE_WRITE_S_SE:
        /* -> s, se */

        /* Encrypt and send static public key */
        {
            size_t ct_len;
            encrypt_and_hash(&hs->symmetric, hs->s.pub, NOISE_KEY_SIZE, out + pos, &ct_len);
            pos += ct_len;
        }

        /* DH(s, re) - se */
        {
            uint8_t dh_out[NOISE_KEY_SIZE];
            crypto_dh(hs->s.priv, hs->re, dh_out);
            mix_key(&hs->symmetric, dh_out, NOISE_KEY_SIZE);
            crypto_zero(dh_out, sizeof(dh_out));
        }

        /* Encrypt payload */
        if (payload != NULL && payload_len > 0) {
            size_t ct_len;
            encrypt_and_hash(&hs->symmetric, payload, payload_len, out + pos, &ct_len);
            pos += ct_len;
        }

        hs->state = NOISE_STATE_TRANSPORT;
        break;

    default:
        return -1;
    }

    *out_len = pos;
    return 0;
}

/* Read handshake message */
int noise_read_message(noise_handshake_t *hs, const uint8_t *message, size_t message_len,
                       uint8_t *payload, size_t *payload_len)
{
    size_t pos = 0;

    switch (hs->state) {
    case NOISE_STATE_READ_E_ES_S_ES:
        /* <- e, ee, s, es */

        if (message_len < NOISE_KEY_SIZE) {
            return -1;
        }

        /* Read remote ephemeral */
        memcpy(hs->re, message + pos, NOISE_KEY_SIZE);
        pos += NOISE_KEY_SIZE;
        hs->has_re = 1;

        /* Mix hash with re */
        mix_hash(&hs->symmetric, hs->re, NOISE_KEY_SIZE);

        /* DH(e, re) - ee */
        {
            uint8_t dh_out[NOISE_KEY_SIZE];
            crypto_dh(hs->e.priv, hs->re, dh_out);
            mix_key(&hs->symmetric, dh_out, NOISE_KEY_SIZE);
            crypto_zero(dh_out, sizeof(dh_out));
        }

        /* Read encrypted remote static */
        if (message_len < pos + NOISE_KEY_SIZE + NOISE_TAG_SIZE) {
            return -1;
        }

        {
            size_t pt_len;
            uint8_t encrypted_s[NOISE_KEY_SIZE + NOISE_TAG_SIZE];
            memcpy(encrypted_s, message + pos, NOISE_KEY_SIZE + NOISE_TAG_SIZE);

            /* Decrypt remote static - need to save hash first */
            uint8_t saved_h[NOISE_HASH_SIZE];
            memcpy(saved_h, hs->symmetric.h, NOISE_HASH_SIZE);

            if (decrypt_with_ad(&hs->symmetric.cipher, saved_h, NOISE_HASH_SIZE,
                               encrypted_s, NOISE_KEY_SIZE + NOISE_TAG_SIZE,
                               hs->rs, &pt_len) != 0) {
                return -1;
            }

            /* Now mix hash with ciphertext */
            mix_hash(&hs->symmetric, encrypted_s, NOISE_KEY_SIZE + NOISE_TAG_SIZE);

            pos += NOISE_KEY_SIZE + NOISE_TAG_SIZE;
            hs->has_rs = 1;

            /* Save server static for session resumption */
            memcpy(hs->server_static_pub, hs->rs, NOISE_KEY_SIZE);
            hs->has_server_static = 1;
        }

        /* DH(e, rs) - es */
        {
            uint8_t dh_out[NOISE_KEY_SIZE];
            crypto_dh(hs->e.priv, hs->rs, dh_out);
            mix_key(&hs->symmetric, dh_out, NOISE_KEY_SIZE);
            crypto_zero(dh_out, sizeof(dh_out));
        }

        /* Decrypt payload */
        if (message_len > pos) {
            size_t remaining = message_len - pos;
            uint8_t saved_h[NOISE_HASH_SIZE];
            memcpy(saved_h, hs->symmetric.h, NOISE_HASH_SIZE);

            if (decrypt_with_ad(&hs->symmetric.cipher, saved_h, NOISE_HASH_SIZE,
                               message + pos, remaining,
                               payload, payload_len) != 0) {
                return -1;
            }

            mix_hash(&hs->symmetric, message + pos, remaining);
        } else {
            *payload_len = 0;
        }

        hs->state = NOISE_STATE_WRITE_S_SE;
        break;

    default:
        return -1;
    }

    return 0;
}

/* Split handshake into transport keys */
int noise_split(noise_handshake_t *hs, noise_session_t *session)
{
    if (hs->state != NOISE_STATE_TRANSPORT) {
        return -1;
    }

    uint8_t keys[64];

    /* Derive transport keys */
    crypto_hkdf(hs->symmetric.ck, NOISE_HASH_SIZE, NULL, 0, NULL, 0, keys, 64);

    /* Initiator sends with first key, receives with second */
    memcpy(session->send.key, keys, NOISE_KEY_SIZE);
    session->send.nonce = 0;
    session->send.has_key = 1;

    memcpy(session->recv.key, keys + NOISE_KEY_SIZE, NOISE_KEY_SIZE);
    session->recv.nonce = 0;
    session->recv.has_key = 1;

    /* Save handshake hash */
    memcpy(session->handshake_hash, hs->symmetric.h, NOISE_HASH_SIZE);

    crypto_zero(keys, sizeof(keys));

    return 0;
}

/* Encrypt for transport */
int noise_encrypt(noise_session_t *session, const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t *ciphertext, size_t *ciphertext_len)
{
    /* Check for nonce overflow - must rekey before this happens */
    if (session->send.nonce == UINT64_MAX) {
        return -1;  /* Nonce exhausted, cannot encrypt safely */
    }

    /* Build nonce */
    uint8_t nonce[12] = {0};
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (session->send.nonce >> (i * 8)) & 0xFF;
    }

    if (crypto_aes_gcm_encrypt(session->send.key, nonce, 12, NULL, 0,
                               plaintext, plaintext_len,
                               ciphertext, ciphertext + plaintext_len) != 0) {
        return -1;
    }

    *ciphertext_len = plaintext_len + NOISE_TAG_SIZE;
    session->send.nonce++;

    return 0;
}

/* Decrypt from transport */
int noise_decrypt(noise_session_t *session, const uint8_t *ciphertext, size_t ciphertext_len,
                  uint8_t *plaintext, size_t *plaintext_len)
{
    if (ciphertext_len < NOISE_TAG_SIZE) {
        return -1;
    }

    /* Check for nonce overflow - must rekey before this happens */
    if (session->recv.nonce == UINT64_MAX) {
        return -1;  /* Nonce exhausted, cannot decrypt safely */
    }

    /* Build nonce */
    uint8_t nonce[12] = {0};
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (session->recv.nonce >> (i * 8)) & 0xFF;
    }

    if (crypto_aes_gcm_decrypt(session->recv.key, nonce, 12, NULL, 0,
                               ciphertext, ciphertext_len,
                               plaintext) != 0) {
        return -1;
    }

    *plaintext_len = ciphertext_len - NOISE_TAG_SIZE;
    session->recv.nonce++;

    return 0;
}

/* Generate keypair */
int noise_generate_keypair(noise_keypair_t *kp)
{
    return crypto_keypair_generate(kp->priv, kp->pub);
}

/* Compute public from private */
int noise_compute_public(const uint8_t *priv, uint8_t *pub)
{
    return crypto_keypair_compute_public(priv, pub);
}

/* Clear handshake state */
void noise_handshake_clear(noise_handshake_t *hs)
{
    crypto_zero(hs, sizeof(*hs));
}

/* Clear session state */
void noise_session_clear(noise_session_t *session)
{
    crypto_zero(session, sizeof(*session));
}
