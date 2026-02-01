/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Cryptographic Primitives using libsodium
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <string.h>
#include <sodium.h>
#include "noise.h"

/* Initialize libsodium */
int crypto_init(void)
{
    return sodium_init();
}

/* Generate random bytes */
void crypto_random(uint8_t *buf, size_t len)
{
    randombytes_buf(buf, len);
}

/* Generate Curve25519 keypair */
int crypto_keypair_generate(uint8_t *priv, uint8_t *pub)
{
    crypto_random(priv, 32);
    return crypto_scalarmult_curve25519_base(pub, priv);
}

/* Compute public key from private */
int crypto_keypair_compute_public(const uint8_t *priv, uint8_t *pub)
{
    return crypto_scalarmult_curve25519_base(pub, priv);
}

/* Curve25519 DH */
int crypto_dh(const uint8_t *priv, const uint8_t *pub, uint8_t *shared)
{
    return crypto_scalarmult_curve25519(shared, priv, pub);
}

/* SHA-256 hash */
int crypto_sha256(const uint8_t *data, size_t len, uint8_t *hash)
{
    return crypto_hash_sha256(hash, data, len);
}

/* HMAC-SHA256 */
int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t *mac)
{
    crypto_auth_hmacsha256_state state;

    if (crypto_auth_hmacsha256_init(&state, key, key_len) != 0) {
        return -1;
    }
    if (crypto_auth_hmacsha256_update(&state, data, data_len) != 0) {
        return -1;
    }
    return crypto_auth_hmacsha256_final(&state, mac);
}

/* HKDF-SHA256 extract */
int crypto_hkdf_extract(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t *prk)
{
    if (salt == NULL || salt_len == 0) {
        uint8_t zero_salt[32] = {0};
        return crypto_hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    }
    return crypto_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

/* HKDF-SHA256 expand */
int crypto_hkdf_expand(const uint8_t *prk, size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    uint8_t t[32] = {0};
    uint8_t counter = 1;
    size_t t_len = 0;
    size_t pos = 0;

    while (pos < okm_len) {
        crypto_auth_hmacsha256_state state;

        if (crypto_auth_hmacsha256_init(&state, prk, prk_len) != 0) {
            return -1;
        }

        if (t_len > 0) {
            crypto_auth_hmacsha256_update(&state, t, t_len);
        }

        if (info != NULL && info_len > 0) {
            crypto_auth_hmacsha256_update(&state, info, info_len);
        }

        crypto_auth_hmacsha256_update(&state, &counter, 1);
        crypto_auth_hmacsha256_final(&state, t);
        t_len = 32;

        size_t copy_len = okm_len - pos;
        if (copy_len > 32) copy_len = 32;

        memcpy(okm + pos, t, copy_len);
        pos += copy_len;
        counter++;
    }

    sodium_memzero(t, sizeof(t));
    return 0;
}

/* HKDF combined */
int crypto_hkdf(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len)
{
    uint8_t prk[32];

    if (crypto_hkdf_extract(salt, salt_len, ikm, ikm_len, prk) != 0) {
        return -1;
    }

    int ret = crypto_hkdf_expand(prk, 32, info, info_len, okm, okm_len);
    sodium_memzero(prk, sizeof(prk));
    return ret;
}

/* AES-256-GCM encrypt */
int crypto_aes_gcm_encrypt(const uint8_t *key,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext, uint8_t *tag)
{
    /* libsodium AES-GCM uses 12-byte nonce */
    if (nonce_len != 12) {
        return -1;
    }

    unsigned long long ciphertext_len;

    /* Combined encryption */
    if (crypto_aead_aes256gcm_encrypt(
            ciphertext, &ciphertext_len,
            plaintext, plaintext_len,
            aad, aad_len,
            NULL, nonce, key) != 0) {
        return -1;
    }

    /* Extract tag from end of ciphertext */
    if (tag != NULL && ciphertext_len >= 16) {
        memcpy(tag, ciphertext + plaintext_len, 16);
    }

    return 0;
}

/* AES-256-GCM decrypt */
int crypto_aes_gcm_decrypt(const uint8_t *key,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           uint8_t *plaintext)
{
    if (nonce_len != 12) {
        return -1;
    }

    unsigned long long plaintext_len;

    if (crypto_aead_aes256gcm_decrypt(
            plaintext, &plaintext_len,
            NULL,
            ciphertext, ciphertext_len,
            aad, aad_len,
            nonce, key) != 0) {
        return -1;
    }

    return 0;
}

/* Ed25519 sign */
int wa_crypto_sign(const uint8_t *priv, const uint8_t *msg, size_t msg_len,
                   uint8_t *sig)
{
    uint8_t seed[32];
    uint8_t pk[32];
    uint8_t sk[64];

    /* Convert Curve25519 private key to Ed25519 seed */
    memcpy(seed, priv, 32);

    /* Generate Ed25519 keypair from seed */
    crypto_sign_seed_keypair(pk, sk, seed);

    unsigned long long sig_len;
    int ret = crypto_sign_detached(sig, &sig_len, msg, msg_len, sk);

    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(seed, sizeof(seed));

    return ret;
}

/* Ed25519 verify */
int wa_crypto_verify(const uint8_t *pub, const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig)
{
    return crypto_sign_verify_detached(sig, msg, msg_len, pub);
}

/* Secure memory zeroing */
void crypto_zero(void *buf, size_t len)
{
    sodium_memzero(buf, len);
}

/* Constant-time comparison */
int crypto_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    return sodium_memcmp(a, b, len);
}
