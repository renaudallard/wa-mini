/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Cryptographic Primitives using libsodium
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <string.h>
#include <sodium.h>
#include <openssl/evp.h>
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
static int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
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
static int crypto_hkdf_extract(const uint8_t *salt, size_t salt_len,
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
static int crypto_hkdf_expand(const uint8_t *prk, size_t prk_len,
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

/* AES-256-GCM encrypt using OpenSSL (works on systems without AES-NI) */
int crypto_aes_gcm_encrypt(const uint8_t *key,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext, uint8_t *tag)
{
    if (nonce_len != 12) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    int ret = -1;
    int len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }

    if (aad != NULL && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            goto cleanup;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* AES-256-GCM decrypt using OpenSSL (works on systems without AES-NI) */
int crypto_aes_gcm_decrypt(const uint8_t *key,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           uint8_t *plaintext)
{
    if (nonce_len != 12 || ciphertext_len < 16) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    int ret = -1;
    int len;
    size_t data_len = ciphertext_len - 16;  /* Subtract tag */
    const uint8_t *tag = ciphertext + data_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }

    if (aad != NULL && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            goto cleanup;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)data_len) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
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
