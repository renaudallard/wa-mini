/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Signal Protocol Key Generation
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#include "wa-mini.h"
#include "noise.h"

/* External crypto functions */
extern void crypto_random(uint8_t *buf, size_t len);
extern int crypto_keypair_generate(uint8_t *priv, uint8_t *pub);

/* Signal identity structure */
typedef struct {
    uint8_t identity_priv[32];
    uint8_t identity_pub[32];
    uint8_t signed_prekey_priv[32];
    uint8_t signed_prekey_pub[32];
    uint8_t signed_prekey_sig[64];
    uint32_t signed_prekey_id;
    uint32_t registration_id;
} signal_identity_t;

/* One-time prekey */
typedef struct {
    uint32_t key_id;
    uint8_t priv[32];
    uint8_t pub[32];
} signal_prekey_t;

/*
 * Generate a random registration ID
 * This is a 4-byte value used in Signal protocol
 */
uint32_t signal_generate_registration_id(void)
{
    /* Registration ID should be between 1 and 16380 per Signal spec */
    /* randombytes_uniform uses rejection sampling to avoid modulo bias */
    return randombytes_uniform(16380) + 1;
}

/*
 * Generate Signal identity keypair
 * Uses Curve25519 for the identity key
 */
int signal_generate_identity_key(uint8_t *priv, uint8_t *pub)
{
    return crypto_keypair_generate(priv, pub);
}

/*
 * Sign data with identity key using XEdDSA
 * WhatsApp uses XEdDSA to sign with Curve25519 keys
 */
static int xeddsa_sign(const uint8_t *priv, const uint8_t *msg, size_t msg_len,
                       uint8_t *sig)
{
    /* Convert Curve25519 private key to Ed25519 */
    uint8_t ed_priv[64];
    uint8_t ed_pub[32];

    /* Use the Curve25519 private key as Ed25519 seed */
    if (crypto_sign_seed_keypair(ed_pub, ed_priv, priv) != 0) {
        return -1;
    }

    unsigned long long sig_len;
    int ret = crypto_sign_detached(sig, &sig_len, msg, msg_len, ed_priv);

    sodium_memzero(ed_priv, sizeof(ed_priv));
    return ret;
}

/*
 * Generate a signed prekey
 * The signed prekey is a medium-term key signed by the identity key
 */
int signal_generate_signed_prekey(const uint8_t *identity_priv,
                                  uint32_t key_id,
                                  uint8_t *priv, uint8_t *pub,
                                  uint8_t *signature)
{
    /* Generate prekey keypair */
    if (crypto_keypair_generate(priv, pub) != 0) {
        return -1;
    }

    /* Sign the public key with identity key */
    if (xeddsa_sign(identity_priv, pub, 32, signature) != 0) {
        sodium_memzero(priv, 32);
        return -1;
    }

    (void)key_id;  /* Key ID is just stored, not used in signing */
    return 0;
}

/*
 * Generate one-time prekeys
 * These are single-use keys that provide forward secrecy
 */
int signal_generate_prekeys(signal_prekey_t *prekeys, int count, uint32_t start_id)
{
    for (int i = 0; i < count; i++) {
        prekeys[i].key_id = start_id + i;

        if (crypto_keypair_generate(prekeys[i].priv, prekeys[i].pub) != 0) {
            /* Clear already generated keys on error */
            for (int j = 0; j < i; j++) {
                sodium_memzero(prekeys[j].priv, 32);
            }
            return -1;
        }
    }
    return 0;
}

/*
 * Generate complete Signal identity for a new account
 */
int signal_generate_identity(signal_identity_t *identity)
{
    sodium_memzero(identity, sizeof(*identity));

    /* Generate registration ID */
    identity->registration_id = signal_generate_registration_id();

    /* Generate identity keypair */
    if (signal_generate_identity_key(identity->identity_priv,
                                     identity->identity_pub) != 0) {
        return -1;
    }

    /* Generate signed prekey (ID starts at 1) */
    identity->signed_prekey_id = 1;
    if (signal_generate_signed_prekey(identity->identity_priv,
                                      identity->signed_prekey_id,
                                      identity->signed_prekey_priv,
                                      identity->signed_prekey_pub,
                                      identity->signed_prekey_sig) != 0) {
        sodium_memzero(identity->identity_priv, 32);
        return -1;
    }

    return 0;
}

/*
 * Clear sensitive data from identity structure
 */
void signal_clear_identity(signal_identity_t *identity)
{
    sodium_memzero(identity, sizeof(*identity));
}

/*
 * Clear sensitive data from prekeys
 */
void signal_clear_prekeys(signal_prekey_t *prekeys, int count)
{
    for (int i = 0; i < count; i++) {
        sodium_memzero(prekeys[i].priv, 32);
    }
}

/*
 * Generate key bundle for registration
 * This combines identity key, signed prekey, and one-time prekeys
 */
int signal_generate_key_bundle(wa_account_t *account)
{
    signal_identity_t identity;

    /* Generate complete identity */
    if (signal_generate_identity(&identity) != 0) {
        return -1;
    }

    /* Copy to account structure */
    memcpy(account->identity_key, identity.identity_priv, 32);
    memcpy(account->identity_pub, identity.identity_pub, 32);
    memcpy(account->signed_prekey, identity.signed_prekey_priv, 32);
    memcpy(account->signed_prekey_sig, identity.signed_prekey_sig, 64);
    account->signed_prekey_id = identity.signed_prekey_id;
    account->registration_id = identity.registration_id;

    /* Generate Noise static keypair (separate from Signal identity) */
    if (crypto_keypair_generate(account->noise_static, account->noise_static_pub) != 0) {
        signal_clear_identity(&identity);
        return -1;
    }

    signal_clear_identity(&identity);
    return 0;
}

/*
 * Encode identity key for transmission
 * WhatsApp uses a specific format for the identity key
 */
int signal_encode_identity_key(const uint8_t *pub, uint8_t *out, size_t *out_len)
{
    /* Identity key is prefixed with 0x05 (DJB type) */
    out[0] = 0x05;
    memcpy(out + 1, pub, 32);
    *out_len = 33;
    return 0;
}

/*
 * Encode signed prekey for transmission
 */
int signal_encode_signed_prekey(uint32_t key_id, const uint8_t *pub,
                                const uint8_t *signature,
                                uint8_t *out, size_t *out_len)
{
    size_t pos = 0;

    /* Key ID (varint) - simplified to 4 bytes */
    out[pos++] = (key_id >> 24) & 0xFF;
    out[pos++] = (key_id >> 16) & 0xFF;
    out[pos++] = (key_id >> 8) & 0xFF;
    out[pos++] = key_id & 0xFF;

    /* Public key with DJB prefix */
    out[pos++] = 0x05;
    memcpy(out + pos, pub, 32);
    pos += 32;

    /* Signature */
    memcpy(out + pos, signature, 64);
    pos += 64;

    *out_len = pos;
    return 0;
}

/*
 * Encode one-time prekey for transmission
 */
int signal_encode_prekey(uint32_t key_id, const uint8_t *pub,
                         uint8_t *out, size_t *out_len)
{
    size_t pos = 0;

    /* Key ID (4 bytes big endian) */
    out[pos++] = (key_id >> 24) & 0xFF;
    out[pos++] = (key_id >> 16) & 0xFF;
    out[pos++] = (key_id >> 8) & 0xFF;
    out[pos++] = key_id & 0xFF;

    /* Public key with DJB prefix */
    out[pos++] = 0x05;
    memcpy(out + pos, pub, 32);
    pos += 32;

    *out_len = pos;
    return 0;
}
