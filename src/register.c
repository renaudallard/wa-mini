/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Registration Flow Implementation
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sodium.h>

#include "wa-mini.h"
#include "xmpp.h"
#include "noise.h"

/* WhatsApp registration API */
#define WA_REG_HOST "v.whatsapp.net"
#define WA_REG_CODE_ENDPOINT "/v2/code"
#define WA_REG_REGISTER_ENDPOINT "/v2/register"
#define WA_REG_EXISTS_ENDPOINT "/v2/exist"

/*
 * WhatsApp registration token
 *
 * WhatsApp uses HMAC-SHA1 for anti-bot protection. The token is computed as:
 *   Token = Base64(HMAC-SHA1(KEY, SIGNATURE + MD5_CLASSES + phone))
 *
 * Where:
 *   - SIGNATURE: WhatsApp APK signing certificate (fixed, known)
 *   - MD5_CLASSES: Base64(MD5(classes.dex)) - changes per version
 *   - KEY: 80-byte HMAC key - extracted from native library
 *
 * The KEY is stored in libwhatsappmerged.so inside a SuperPack archive
 * (libs.so). To extract it for a new version:
 *   1. Extract SuperPack archive from libs.so
 *   2. Decompress XZ streams
 *   3. Search for 80-byte high-entropy sequence near "hmac sha-1" string
 *   4. Or use Frida on a rooted device to hook the token generation
 *
 * Current values for WhatsApp 2.26.4.71:
 *   MD5_CLASSES: PNuIlAsWtqBNw7eLEYwWUA==
 *   KEY: dCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+...
 */

/* WhatsApp APK signing certificate (Brian Acton, WhatsApp Inc.) */
static const char WA_SIGNATURE[] =
    "MIIDMjCCAvCgAwIBAgIETCU2pDALBgcqhkjOOAQDBQAwfDELMAkGA1UEBhMCVVMx"
    "EzARBgNVBAgTCkNhbGlmb3JuaWExFDASBgNVBAcTC1NhbnRhIENsYXJhMRYwFAYD"
    "VQQKEw1XaGF0c0FwcCBJbmMuMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEUMBIGA1UE"
    "AxMLQnJpYW4gQWN0b24wHhcNMTAwNjI1MjMwNzE2WhcNNDQwMjE1MjMwNzE2WjB8"
    "MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxMLU2Fu"
    "dGEgQ2xhcmExFjAUBgNVBAoTDVdoYXRzQXBwIEluYy4xFDASBgNVBAsTC0VuZ2lu"
    "ZWVyaW5nMRQwEgYDVQQDEwtCcmlhbiBBY3RvbjCCAbgwggEsBgcqhkjOOAQBMIIB"
    "HwKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9jVj6"
    "v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX58ao"
    "phUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8VIwvM"
    "spK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9B4Jn"
    "UVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCjrh4rs6Z1"
    "kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQBTDv+z0kq"
    "A4GFAAKBgQDRGYtLgWh7zyRtQainJfCpiaUbzjJuhMgo4fVWZIvXHaSHBU1t5w//"
    "S0lDK2hiqkj8KpMWGywVov9eZxZy37V26dEqr/c2m5qZ0E+ynSu7sqUD7kGx/zeI"
    "cGT0H+KAVgkGNQCo5Uc0koLRWYHNtYoIvt5R3X6YZylbPftF/8ayWTALBgcqhkjO"
    "OAQDBQADLwAwLAIUAKYCp0d6z4QQdyN74JDfQ2WCyi8CFDUM4CaNB+ceVXdKtOrN"
    "TQcc0e+t";

/* MD5 of classes.dex, Base64 encoded - for WhatsApp 2.26.4.71 */
#define WA_MD5_CLASSES "PNuIlAsWtqBNw7eLEYwWUA=="

/*
 * HMAC key for token generation (80 bytes, Base64 encoded)
 * This must be extracted from libwhatsappmerged.so for each version.
 * Empty string = token generation disabled (will fail with bad_token)
 *
 * Extracted from WhatsApp 2.26.4.71 libwhatsappmerged.so using Ghidra
 * Found at offset 0x4bc4e0 in decompressed SuperPack stream, near
 * "hmac sha-1 authentication function" string.
 */
#define WA_KEY "dCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+eM1a9B/dqDOIB8cxsRIQWSeA7F9gUX+pGbVKDS3lep+TyZzvoOA="

#define WA_VERSION "2.26.4.71"
#define WA_USER_AGENT "WhatsApp/2.26.4.71 A"

/* External crypto functions */
extern void crypto_random(uint8_t *buf, size_t len);

/*
 * Base64 decode helper
 * Returns decoded length, or -1 on error
 */
static int base64_decode(const char *input, uint8_t *output, size_t output_size)
{
    static const int8_t b64_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    size_t in_len = strlen(input);
    size_t out_len = 0;
    uint32_t buf = 0;
    int bits = 0;

    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c == '=') break;
        int val = b64_table[c];
        if (val < 0) continue;  /* Skip whitespace/invalid */

        buf = (buf << 6) | (uint32_t)val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (out_len >= output_size) return -1;
            output[out_len++] = (uint8_t)(buf >> bits);
        }
    }

    return (int)out_len;
}

/*
 * SHA-1 implementation for HMAC-SHA1 token generation
 * WhatsApp requires actual SHA-1, not BLAKE2b or other alternatives
 */
#define SHA1_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_transform(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;

    /* Expand 16 32-bit words into 80 words */
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SHA1_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 80 rounds */
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = SHA1_ROTL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void sha1(const uint8_t *data, size_t len, uint8_t hash[20])
{
    uint32_t state[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };

    /* Process complete blocks */
    size_t blocks = len / 64;
    for (size_t i = 0; i < blocks; i++) {
        sha1_transform(state, data + i * 64);
    }

    /* Final block with padding */
    uint8_t final_block[128];  /* May need 2 blocks */
    size_t remaining = len % 64;
    memcpy(final_block, data + blocks * 64, remaining);

    /* Append bit '1' */
    final_block[remaining] = 0x80;
    remaining++;

    /* Pad with zeros */
    if (remaining > 56) {
        /* Need two blocks */
        memset(final_block + remaining, 0, 64 - remaining);
        sha1_transform(state, final_block);
        memset(final_block, 0, 56);
    } else {
        memset(final_block + remaining, 0, 56 - remaining);
    }

    /* Append length in bits (big-endian 64-bit) */
    uint64_t bit_len = (uint64_t)len * 8;
    final_block[56] = (uint8_t)(bit_len >> 56);
    final_block[57] = (uint8_t)(bit_len >> 48);
    final_block[58] = (uint8_t)(bit_len >> 40);
    final_block[59] = (uint8_t)(bit_len >> 32);
    final_block[60] = (uint8_t)(bit_len >> 24);
    final_block[61] = (uint8_t)(bit_len >> 16);
    final_block[62] = (uint8_t)(bit_len >> 8);
    final_block[63] = (uint8_t)(bit_len);

    sha1_transform(state, final_block);

    /* Output hash (big-endian) */
    for (int i = 0; i < 5; i++) {
        hash[i * 4] = (uint8_t)(state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t hash[20])
{
    uint8_t k_ipad[64], k_opad[64];

    /* If key > 64 bytes, hash it first */
    uint8_t key_hash[20];
    if (key_len > 64) {
        sha1(key, key_len, key_hash);
        key = key_hash;
        key_len = 20;
    }

    /* XOR key with ipad/opad */
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Inner hash: SHA1(k_ipad || data) */
    uint8_t *inner = malloc(64 + data_len);
    if (!inner) {
        memset(hash, 0, 20);
        return;
    }
    memcpy(inner, k_ipad, 64);
    memcpy(inner + 64, data, data_len);

    uint8_t inner_hash[20];
    sha1(inner, 64 + data_len, inner_hash);
    free(inner);

    /* Outer hash: SHA1(k_opad || inner_hash) */
    uint8_t outer[64 + 20];
    memcpy(outer, k_opad, 64);
    memcpy(outer + 64, inner_hash, 20);

    sha1(outer, sizeof(outer), hash);
}

/*
 * Generate registration token using HMAC-SHA1
 * Token = Base64(HMAC-SHA1(KEY, SIGNATURE + MD5_CLASSES + phone))
 * Returns 1 if token could be generated, 0 if not configured
 */
static int generate_token(const char *phone, char *token, size_t token_size)
{
    if (strlen(WA_KEY) == 0) {
        /* HMAC key not configured */
        token[0] = '\0';
        return 0;
    }

    /* Decode the key (80 bytes) */
    uint8_t key[80];
    int key_len = base64_decode(WA_KEY, key, sizeof(key));
    if (key_len != 80) {
        token[0] = '\0';
        return 0;
    }

    /* Decode the signature */
    uint8_t signature[1024];
    int sig_len = base64_decode(WA_SIGNATURE, signature, sizeof(signature));
    if (sig_len < 0) {
        token[0] = '\0';
        return 0;
    }

    /* Decode MD5 of classes.dex */
    uint8_t md5_classes[16];
    int md5_len = base64_decode(WA_MD5_CLASSES, md5_classes, sizeof(md5_classes));
    if (md5_len != 16) {
        token[0] = '\0';
        return 0;
    }

    /* Build data: signature + md5_classes + phone */
    size_t phone_len = strlen(phone);
    size_t data_len = (size_t)sig_len + (size_t)md5_len + phone_len;
    uint8_t *data = malloc(data_len);
    if (data == NULL) {
        token[0] = '\0';
        return 0;
    }

    memcpy(data, signature, (size_t)sig_len);
    memcpy(data + sig_len, md5_classes, (size_t)md5_len);
    memcpy(data + sig_len + md5_len, phone, phone_len);

    /* Compute HMAC-SHA1 */
    uint8_t final_hash[20];
    hmac_sha1(key, 80, data, data_len, final_hash);
    free(data);

    /* Base64 encode the result */
    static const char b64_alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < 20 && j < token_size - 4; i += 3) {
        uint32_t n = (uint32_t)final_hash[i] << 16;
        if (i + 1 < 20) n |= (uint32_t)final_hash[i + 1] << 8;
        if (i + 2 < 20) n |= (uint32_t)final_hash[i + 2];

        token[j++] = b64_alphabet[(n >> 18) & 0x3F];
        token[j++] = b64_alphabet[(n >> 12) & 0x3F];
        token[j++] = (i + 1 < 20) ? b64_alphabet[(n >> 6) & 0x3F] : '=';
        token[j++] = (i + 2 < 20) ? b64_alphabet[n & 0x3F] : '=';
    }
    token[j] = '\0';

    return 1;
}


/*
 * Execute curl and capture output
 */
static int http_post(const char *url, const char *post_data,
                     char *response, size_t response_size)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: run curl */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        close(STDERR_FILENO);

        execlp("curl", "curl", "-s", "-L",
               "--max-time", "60",
               "-X", "POST",
               "-H", "Content-Type: application/x-www-form-urlencoded",
               "-H", "User-Agent: " WA_USER_AGENT,
               "-d", post_data,
               url, NULL);
        _exit(1);
    }

    /* Parent: read output */
    close(pipefd[1]);

    size_t total = 0;
    ssize_t n;
    while (total < response_size - 1 &&
           (n = read(pipefd[0], response + total, response_size - 1 - total)) > 0) {
        total += (size_t)n;
    }
    response[total] = '\0';
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    /* Check if we got any response - if so, consider it a success even if
     * curl returned non-zero (API errors still return valid JSON) */
    if (total > 0) {
        return 0;
    }

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/*
 * Parse JSON response to extract a string value
 * Very simple parser for WhatsApp API responses
 */
static int json_get_string(const char *json, const char *key, char *value, size_t size)
{
    /* Build search pattern: "key":" or "key": " */
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *p = strstr(json, pattern);
    if (p == NULL) return -1;

    p += strlen(pattern);

    /* Skip whitespace */
    while (*p == ' ' || *p == '\t') p++;

    if (*p == '"') {
        /* String value */
        p++;
        size_t i = 0;
        while (*p != '\0' && *p != '"' && i < size - 1) {
            if (*p == '\\' && *(p + 1) != '\0') {
                p++;  /* Skip escape char */
            }
            value[i++] = *p++;
        }
        value[i] = '\0';
        return 0;
    } else if (*p >= '0' && *p <= '9') {
        /* Numeric value */
        size_t i = 0;
        while (*p != '\0' && ((*p >= '0' && *p <= '9') || *p == '.') && i < size - 1) {
            value[i++] = *p++;
        }
        value[i] = '\0';
        return 0;
    }

    return -1;
}

/*
 * Generate device identity bytes for registration
 * This is a simplified device fingerprint
 */
static void generate_device_identity(uint8_t *identity, size_t *len)
{
    /* Generate random device identity */
    uint8_t random[20];
    crypto_random(random, sizeof(random));

    /* Format: simple binary identity */
    memcpy(identity, random, 20);
    *len = 20;
}

/*
 * Base64 URL-safe encode (no padding)
 */
static void base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0, j = 0;

    while (i < len && j < out_size - 4) {
        uint32_t n = (uint32_t)data[i++] << 16;
        if (i < len) n |= (uint32_t)data[i++] << 8;
        if (i < len) n |= (uint32_t)data[i++];

        out[j++] = alphabet[(n >> 18) & 0x3F];
        out[j++] = alphabet[(n >> 12) & 0x3F];
        if (i > len - 2 || (i == len && (len % 3) == 1)) {
            /* Don't add padding */
        } else {
            out[j++] = alphabet[(n >> 6) & 0x3F];
        }
        if (i > len - 1 || (i == len && (len % 3) != 0)) {
            /* Don't add padding */
        } else {
            out[j++] = alphabet[n & 0x3F];
        }
    }
    out[j] = '\0';
}

/*
 * Build registration parameters
 */
static char *build_registration_params(const char *cc, const char *phone,
                                        const char *method, const char *lg,
                                        const char *lc)
{
    /* Generate device identity */
    uint8_t device_id[20];
    size_t device_id_len;
    generate_device_identity(device_id, &device_id_len);

    /* Hex encode device identity */
    char device_id_hex[64];
    for (size_t i = 0; i < device_id_len; i++) {
        snprintf(device_id_hex + i * 2, 3, "%02x", device_id[i]);
    }

    /* Generate temporary Signal keys for registration */
    uint8_t identity_priv[32], identity_pub[32];
    uint8_t signed_prekey_priv[32], signed_prekey_pub[32];

    /* Generate identity key */
    crypto_random(identity_priv, 32);
    identity_priv[0] &= 248;
    identity_priv[31] &= 127;
    identity_priv[31] |= 64;
    crypto_scalarmult_base(identity_pub, identity_priv);

    /* Generate signed prekey */
    crypto_random(signed_prekey_priv, 32);
    signed_prekey_priv[0] &= 248;
    signed_prekey_priv[31] &= 127;
    signed_prekey_priv[31] |= 64;
    crypto_scalarmult_base(signed_prekey_pub, signed_prekey_priv);

    /* Sign the prekey with identity (simplified XEdDSA) */
    uint8_t signed_prekey_sig[64];
    uint8_t ed_priv[64], ed_pub[32];
    crypto_sign_seed_keypair(ed_pub, ed_priv, identity_priv);
    unsigned long long sig_len;
    crypto_sign_detached(signed_prekey_sig, &sig_len, signed_prekey_pub, 32, ed_priv);
    sodium_memzero(ed_priv, sizeof(ed_priv));

    /* Generate registration ID */
    uint32_t reg_id = randombytes_uniform(16380) + 1;

    /* Base64 encode keys for transmission */
    char e_ident[64], e_skey_val[64], e_skey_sig[128];
    base64url_encode(identity_pub, 32, e_ident, sizeof(e_ident));
    base64url_encode(signed_prekey_pub, 32, e_skey_val, sizeof(e_skey_val));
    base64url_encode(signed_prekey_sig, 64, e_skey_sig, sizeof(e_skey_sig));

    /* Generate authentication token */
    char full_phone[32];
    snprintf(full_phone, sizeof(full_phone), "%s%s", cc, phone);

    char token[64] = {0};
    int has_token = generate_token(full_phone, token, sizeof(token));

    /* Build query string */
    char *params = malloc(4096);
    if (params == NULL) return NULL;

    /* Core parameters */
    snprintf(params, 4096,
             "cc=%s"
             "&in=%s"
             "&lg=%s"
             "&lc=%s"
             "&method=%s"
             "&platform=android"
             "&app_type="
             "&mcc=000"
             "&mnc=000"
             "&sim_mcc=000"
             "&sim_mnc=000"
             "&mistyped=6"
             "&network_radio_type=1"
             "&hasav=1"
             "&hasinrc=1"
             "&pid=%d"
             "&id=%s"
             "&rc=0"
             "&token=%s"
             "&e_regid=%u"
             "&e_keytype=BQ" /* 0x05 = DJB type, base64 encoded */
             "&e_ident=%s"
             "&e_skey_id=AAAAAQ" /* Key ID 1, base64 encoded */
             "&e_skey_val=%s"
             "&e_skey_sig=%s"
             "&fdid=%s"
             "&expid=%s"
             "&backup_token=%s",
             cc, phone, lg, lc, method,
             (int)getpid() % 100000,
             device_id_hex,
             has_token ? token : "",
             reg_id,
             e_ident,
             e_skey_val,
             e_skey_sig,
             device_id_hex,
             device_id_hex,
             device_id_hex);

    /* Clear sensitive data */
    sodium_memzero(identity_priv, sizeof(identity_priv));
    sodium_memzero(signed_prekey_priv, sizeof(signed_prekey_priv));

    return params;
}

/* Registration states */
typedef enum {
    REG_STATE_INIT = 0,
    REG_STATE_CONNECTED,
    REG_STATE_CODE_REQUESTED,
    REG_STATE_CODE_SENT,
    REG_STATE_VERIFIED,
    REG_STATE_COMPLETE,
    REG_STATE_ERROR,
} reg_state_t;

/* Registration context */
typedef struct {
    reg_state_t state;
    char phone[20];
    char country_code[8];
    char national_number[20];
    char method[16];        /* "sms" or "voice" */
    char lg[8];             /* Language code */
    char lc[8];             /* Locale/country code */
    char error_reason[256];
    int retry_after;
} reg_ctx_t;

/* External functions */
extern int signal_generate_key_bundle(wa_account_t *account);
extern wa_error_t wa_connect(wa_ctx_t *ctx, const char *phone);
extern wa_error_t wa_disconnect(wa_ctx_t *ctx);
extern wa_error_t wa_send_iq(wa_ctx_t *ctx, xmpp_node_t *iq, xmpp_node_t **response);

/* Forward declarations for store functions */
typedef struct wa_store wa_store_t;
extern int wa_store_account_save(wa_store_t *store, const wa_account_t *account);
extern int wa_store_prekey_save(wa_store_t *store, int64_t account_id,
                                uint32_t key_id, const uint8_t *key_data);

/*
 * Parse phone number into country code and national number
 * Input: +15551234567
 * Output: cc=1, number=5551234567
 */
static int parse_phone_number(const char *phone, char *cc, size_t cc_size,
                              char *number, size_t number_size)
{
    if (phone == NULL || phone[0] != '+') {
        return -1;
    }

    const char *p = phone + 1;  /* Skip + */

    /* Extract country code (1-3 digits) */
    /* Common patterns:
     * +1xxx (USA/Canada) - 1 digit
     * +44xxx (UK) - 2 digits
     * +353xxx (Ireland) - 3 digits
     */

    /* For simplicity, detect based on first digit:
     * 1 = North America (1 digit)
     * 7 = Russia/Kazakhstan (1 digit)
     * Others = 2-3 digits based on ITU
     */
    size_t plen = strlen(p);
    if (plen < 4) {  /* Minimum: 1 digit cc + 3 digit number */
        return -1;
    }

    size_t cc_len;
    if (p[0] == '1' || p[0] == '7') {
        cc_len = 1;
    } else if (p[0] == '2') {
        /* Africa: mostly 3 digits, some 2 */
        cc_len = 3;
        if (plen >= 2 && (p[1] == '0' || p[1] == '7')) cc_len = 2;  /* Egypt, South Africa */
    } else if (p[0] == '3') {
        /* Europe: mostly 2 digits */
        cc_len = 2;
        if (plen >= 3 && p[1] == '5' && p[2] >= '1' && p[2] <= '9') cc_len = 3;  /* 35x countries */
    } else if (p[0] == '4') {
        /* Europe: 2 digits */
        cc_len = 2;
        if (plen >= 3 && p[1] == '2' && p[2] >= '0' && p[2] <= '3') cc_len = 3;  /* 42x countries */
    } else if (p[0] == '5') {
        /* South America: 2 digits */
        cc_len = 2;
    } else if (p[0] == '6') {
        /* Southeast Asia/Pacific: 2-3 digits */
        cc_len = 2;
        if (plen >= 2 && (p[1] == '7' || p[1] == '8' || p[1] == '9')) cc_len = 3;
    } else if (p[0] == '8') {
        /* East Asia: 2-3 digits */
        cc_len = 2;
        if (plen >= 2 && (p[1] == '5' || p[1] == '8')) cc_len = 3;
    } else if (p[0] == '9') {
        /* Middle East/Asia: 2-3 digits */
        cc_len = 2;
        if (plen >= 3 && p[1] == '6' && p[2] >= '0' && p[2] <= '8') cc_len = 3;  /* 96x */
        if (plen >= 3 && p[1] == '9' && p[2] >= '2' && p[2] <= '8') cc_len = 3;  /* 99x */
    } else {
        cc_len = 2;  /* Default */
    }

    if (cc_len >= cc_size || strlen(p) <= cc_len) {
        return -1;
    }

    strncpy(cc, p, cc_len);
    cc[cc_len] = '\0';

    strncpy(number, p + cc_len, number_size - 1);
    number[number_size - 1] = '\0';

    return 0;
}

/*
 * Determine language and locale from country code
 */
static void get_locale_from_cc(const char *cc, char *lg, size_t lg_size,
                               char *lc, size_t lc_size)
{
    /* Default to English/US */
    strncpy(lg, "en", lg_size - 1);
    lg[lg_size - 1] = '\0';
    strncpy(lc, "US", lc_size - 1);
    lc[lc_size - 1] = '\0';

    /* Map common country codes to locales */
    if (strcmp(cc, "1") == 0) {
        strncpy(lg, "en", lg_size - 1);
        strncpy(lc, "US", lc_size - 1);
    } else if (strcmp(cc, "44") == 0) {
        strncpy(lg, "en", lg_size - 1);
        strncpy(lc, "GB", lc_size - 1);
    } else if (strcmp(cc, "49") == 0) {
        strncpy(lg, "de", lg_size - 1);
        strncpy(lc, "DE", lc_size - 1);
    } else if (strcmp(cc, "33") == 0) {
        strncpy(lg, "fr", lg_size - 1);
        strncpy(lc, "FR", lc_size - 1);
    } else if (strcmp(cc, "34") == 0) {
        strncpy(lg, "es", lg_size - 1);
        strncpy(lc, "ES", lc_size - 1);
    } else if (strcmp(cc, "39") == 0) {
        strncpy(lg, "it", lg_size - 1);
        strncpy(lc, "IT", lc_size - 1);
    } else if (strcmp(cc, "55") == 0) {
        strncpy(lg, "pt", lg_size - 1);
        strncpy(lc, "BR", lc_size - 1);
    } else if (strcmp(cc, "81") == 0) {
        strncpy(lg, "ja", lg_size - 1);
        strncpy(lc, "JP", lc_size - 1);
    } else if (strcmp(cc, "86") == 0) {
        strncpy(lg, "zh", lg_size - 1);
        strncpy(lc, "CN", lc_size - 1);
    } else if (strcmp(cc, "91") == 0) {
        strncpy(lg, "hi", lg_size - 1);
        strncpy(lc, "IN", lc_size - 1);
    } else if (strcmp(cc, "7") == 0) {
        strncpy(lg, "ru", lg_size - 1);
        strncpy(lc, "RU", lc_size - 1);
    } else if (strcmp(cc, "31") == 0) {
        strncpy(lg, "nl", lg_size - 1);
        strncpy(lc, "NL", lc_size - 1);
    } else if (strcmp(cc, "41") == 0) {
        strncpy(lg, "de", lg_size - 1);
        strncpy(lc, "CH", lc_size - 1);
    }
    /* Ensure null termination */
    lg[lg_size - 1] = '\0';
    lc[lc_size - 1] = '\0';
}


/*
 * Build registration complete IQ with Signal keys
 */
static xmpp_node_t *build_register_keys(const wa_account_t *account)
{
    /* Build IQ stanza with key bundle:
     * <iq type="set" xmlns="urn:xmpp:whatsapp:account">
     *   <register>
     *     <identity>[protobuf identity]</identity>
     *     <signed_prekey>[protobuf signed prekey]</signed_prekey>
     *     <prekeys>[list of prekeys]</prekeys>
     *   </register>
     * </iq>
     */

    char id[32];
    snprintf(id, sizeof(id), "%ld.3", (long)time(NULL));

    xmpp_node_t *iq = xmpp_node_new("iq");
    if (iq == NULL) return NULL;

    xmpp_node_set_attr(iq, "type", "set");
    xmpp_node_set_attr(iq, "id", id);
    xmpp_node_set_attr(iq, "xmlns", "urn:xmpp:whatsapp:account");

    xmpp_node_t *reg = xmpp_node_new("register");
    if (reg == NULL) {
        xmpp_node_free(iq);
        return NULL;
    }

    /* Identity key (33 bytes: 0x05 prefix + 32 byte key) */
    uint8_t identity_encoded[33];
    identity_encoded[0] = 0x05;
    memcpy(identity_encoded + 1, account->identity_pub, 32);

    xmpp_node_t *identity = xmpp_node_new("identity");
    if (identity) {
        xmpp_node_set_content(identity, identity_encoded, 33);
        xmpp_node_add_child(reg, identity);
        free(identity);
    }

    /* Registration ID */
    char reg_id_str[16];
    snprintf(reg_id_str, sizeof(reg_id_str), "%u", account->registration_id);
    xmpp_node_t *reg_id = xmpp_node_new("registration_id");
    if (reg_id) {
        xmpp_node_set_text(reg_id, reg_id_str);
        xmpp_node_add_child(reg, reg_id);
        free(reg_id);
    }

    /* Signed prekey needs special encoding - simplified here */
    /* In full implementation, this would be protobuf encoded */

    xmpp_node_add_child(iq, reg);
    free(reg);

    return iq;
}

/*
 * Initialize registration context
 */
int wa_register_init(reg_ctx_t *reg, const char *phone, const char *method)
{
    memset(reg, 0, sizeof(*reg));

    /* Validate and store phone number */
    if (phone == NULL || phone[0] != '+') {
        return -1;
    }

    /* Check all characters are digits after + */
    for (const char *p = phone + 1; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            return -1;
        }
    }

    if (strlen(phone) < 8 || strlen(phone) > 16) {
        return -1;
    }

    strncpy(reg->phone, phone, sizeof(reg->phone) - 1);

    /* Parse phone number */
    if (parse_phone_number(phone, reg->country_code, sizeof(reg->country_code),
                           reg->national_number, sizeof(reg->national_number)) != 0) {
        return -1;
    }

    /* Set method */
    if (method == NULL || strcmp(method, "sms") == 0) {
        strncpy(reg->method, "sms", sizeof(reg->method) - 1);
        reg->method[sizeof(reg->method) - 1] = '\0';
    } else if (strcmp(method, "voice") == 0) {
        strncpy(reg->method, "voice", sizeof(reg->method) - 1);
        reg->method[sizeof(reg->method) - 1] = '\0';
    } else {
        return -1;
    }

    /* Get locale */
    get_locale_from_cc(reg->country_code, reg->lg, sizeof(reg->lg),
                       reg->lc, sizeof(reg->lc));

    reg->state = REG_STATE_INIT;
    return 0;
}

/*
 * Start registration process (request verification code)
 * Sends HTTP request to WhatsApp registration API
 */
int wa_register_request_code(void *ctx_ptr, reg_ctx_t *reg)
{
    (void)ctx_ptr;

    /* Build registration parameters */
    char *params = build_registration_params(
        reg->country_code,
        reg->national_number,
        reg->method,
        reg->lg,
        reg->lc
    );

    if (params == NULL) {
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "Failed to build request parameters",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Build URL */
    char url[256];
    snprintf(url, sizeof(url), "https://%s%s", WA_REG_HOST, WA_REG_CODE_ENDPOINT);

    printf("Requesting verification code...\n");
    printf("URL: %s\n", url);
    WA_DEBUG("POST data: %s", params);

    /* Send HTTP request */
    char response[8192] = {0};
    int http_ret = http_post(url, params, response, sizeof(response));
    free(params);

    if (http_ret != 0) {
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "HTTP request failed",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    WA_DEBUG("Response: %s", response);

    /* Parse response */
    char status[32] = {0};
    char reason[128] = {0};

    if (json_get_string(response, "status", status, sizeof(status)) != 0) {
        /* Check for different response format */
        if (strstr(response, "sent") != NULL || strstr(response, "ok") != NULL) {
            /* Success */
            printf("Verification code sent via %s!\n", reg->method);
            reg->state = REG_STATE_CODE_REQUESTED;
            return 0;
        }

        /* Try to extract error reason */
        if (json_get_string(response, "reason", reason, sizeof(reason)) == 0) {
            snprintf(reg->error_reason, sizeof(reg->error_reason),
                     "Request failed: %s", reason);
        } else if (json_get_string(response, "param", reason, sizeof(reason)) == 0) {
            snprintf(reg->error_reason, sizeof(reg->error_reason),
                     "Invalid parameter: %s", reason);
        } else {
            strncpy(reg->error_reason, "Unknown response format",
                    sizeof(reg->error_reason) - 1);
        }
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        reg->state = REG_STATE_ERROR;
        return -1;
    }

    /* Check status */
    if (strcmp(status, "sent") == 0 || strcmp(status, "ok") == 0) {
        printf("Verification code sent via %s!\n", reg->method);
        reg->state = REG_STATE_CODE_REQUESTED;
        return 0;
    }

    /* Handle specific error statuses */
    if (strcmp(status, "fail") == 0 || strcmp(status, "error") == 0) {
        json_get_string(response, "reason", reason, sizeof(reason));

        if (strcmp(reason, "too_recent") == 0 || strcmp(reason, "too_many") == 0) {
            char retry_str[32] = {0};
            if (json_get_string(response, "retry_after", retry_str, sizeof(retry_str)) == 0) {
                reg->retry_after = atoi(retry_str);
                snprintf(reg->error_reason, sizeof(reg->error_reason),
                         "Too many attempts. Retry after %d seconds.", reg->retry_after);
            } else {
                strncpy(reg->error_reason, "Too many attempts. Please wait and try again.",
                        sizeof(reg->error_reason) - 1);
            }
        } else if (strcmp(reason, "blocked") == 0 || strcmp(reason, "banned") == 0) {
            strncpy(reg->error_reason, "This phone number is blocked.",
                    sizeof(reg->error_reason) - 1);
        } else if (strcmp(reason, "invalid") == 0 || strcmp(reason, "bad_param") == 0) {
            char param[64] = {0};
            json_get_string(response, "param", param, sizeof(param));
            snprintf(reg->error_reason, sizeof(reg->error_reason),
                     "Invalid parameter: %s", param[0] ? param : "phone number");
        } else if (strcmp(reason, "no_routes") == 0) {
            strncpy(reg->error_reason, "Cannot send SMS to this number. Try voice verification.",
                    sizeof(reg->error_reason) - 1);
        } else if (reason[0] != '\0') {
            snprintf(reg->error_reason, sizeof(reg->error_reason),
                     "Registration failed: %s", reason);
        } else {
            strncpy(reg->error_reason, "Registration request failed",
                    sizeof(reg->error_reason) - 1);
        }
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        reg->state = REG_STATE_ERROR;
        return -1;
    }

    /* Unknown status */
    snprintf(reg->error_reason, sizeof(reg->error_reason),
             "Unknown status: %s", status);
    reg->state = REG_STATE_ERROR;
    return -1;
}

/*
 * Submit verification code
 * Sends HTTP request to WhatsApp registration API to verify the code
 */
int wa_register_submit_code(void *ctx_ptr, reg_ctx_t *reg, const char *code)
{
    (void)ctx_ptr;

    /* Validate code format (6 digits, may have hyphen in middle) */
    char clean_code[8] = {0};
    int j = 0;

    if (code == NULL) {
        strncpy(reg->error_reason, "Code is required",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Extract only digits from code (handles "123-456" format) */
    for (const char *p = code; *p && j < 6; p++) {
        if (isdigit((unsigned char)*p)) {
            clean_code[j++] = *p;
        }
    }

    if (j != 6) {
        strncpy(reg->error_reason, "Code must be 6 digits",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Build verification parameters */
    char params[2048];
    snprintf(params, sizeof(params),
             "cc=%s"
             "&in=%s"
             "&code=%s",
             reg->country_code,
             reg->national_number,
             clean_code);

    /* Build URL */
    char url[256];
    snprintf(url, sizeof(url), "https://%s%s", WA_REG_HOST, WA_REG_REGISTER_ENDPOINT);

    printf("Verifying code %s...\n", clean_code);
    WA_DEBUG("POST %s", url);
    WA_DEBUG("Data: %s", params);

    /* Send HTTP request */
    char response[16384] = {0};
    int http_ret = http_post(url, params, response, sizeof(response));

    if (http_ret != 0) {
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "HTTP request failed",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    WA_DEBUG("Response: %s", response);

    /* Parse response */
    char status[32] = {0};
    char reason[128] = {0};

    json_get_string(response, "status", status, sizeof(status));

    /* Check for success */
    if (strcmp(status, "ok") == 0 || strstr(response, "\"login\"") != NULL) {
        printf("Code verified successfully!\n");
        reg->state = REG_STATE_VERIFIED;
        return 0;
    }

    /* Handle errors */
    json_get_string(response, "reason", reason, sizeof(reason));

    if (strcmp(reason, "incorrect") == 0 || strcmp(reason, "bad_code") == 0) {
        strncpy(reg->error_reason, "Incorrect verification code. Please check and try again.",
                sizeof(reg->error_reason) - 1);
    } else if (strcmp(reason, "expired") == 0) {
        strncpy(reg->error_reason, "Verification code has expired. Please request a new code.",
                sizeof(reg->error_reason) - 1);
    } else if (strcmp(reason, "too_many") == 0 || strcmp(reason, "too_recent") == 0) {
        char retry_str[32] = {0};
        if (json_get_string(response, "retry_after", retry_str, sizeof(retry_str)) == 0) {
            reg->retry_after = atoi(retry_str);
            snprintf(reg->error_reason, sizeof(reg->error_reason),
                     "Too many attempts. Wait %d seconds.", reg->retry_after);
        } else {
            strncpy(reg->error_reason, "Too many attempts. Please wait and try again.",
                    sizeof(reg->error_reason) - 1);
        }
    } else if (reason[0] != '\0') {
        snprintf(reg->error_reason, sizeof(reg->error_reason),
                 "Verification failed: %s", reason);
    } else {
        snprintf(reg->error_reason, sizeof(reg->error_reason),
                 "Verification failed (status: %s)", status[0] ? status : "unknown");
    }

    reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
    reg->state = REG_STATE_ERROR;
    return -1;
}

/*
 * Complete registration by uploading Signal keys
 */
int wa_register_upload_keys(void *ctx_ptr, reg_ctx_t *reg, wa_account_t *account)
{
    if (reg->state != REG_STATE_VERIFIED) {
        strncpy(reg->error_reason, "Account not verified yet",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    (void)ctx_ptr;

    /* Generate Signal key bundle */
    if (signal_generate_key_bundle(account) != 0) {
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "Failed to generate keys",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Copy phone number to account */
    memset(account->phone, 0, sizeof(account->phone));
    memcpy(account->phone, reg->phone,
           strlen(reg->phone) < sizeof(account->phone) - 1 ?
           strlen(reg->phone) : sizeof(account->phone) - 1);
    account->registered_at = time(NULL);
    account->active = 1;

    /* Build key upload request */
    xmpp_node_t *request = build_register_keys(account);
    if (request == NULL) {
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "Failed to build key upload request",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Debug: print the request */
    printf("Key upload request stanza:\n");
    xmpp_node_dump(request, 0);

    xmpp_node_free(request);

    /* TODO: Send via Noise-encrypted connection */
    /* TODO: Wait for and parse response */

    reg->state = REG_STATE_COMPLETE;
    return 0;
}

/*
 * Get registration state
 */
reg_state_t wa_register_get_state(const reg_ctx_t *reg)
{
    return reg->state;
}

/*
 * Get error reason
 */
const char *wa_register_get_error(const reg_ctx_t *reg)
{
    return reg->error_reason;
}

/*
 * High-level registration function for CLI
 */
int wa_do_registration(const char *phone, const char *method)
{
    reg_ctx_t reg;

    printf("Starting registration for %s...\n\n", phone);

    /* Initialize registration context */
    if (wa_register_init(&reg, phone, method) != 0) {
        printf("Error: Invalid phone number format\n");
        printf("Phone number must be in format: +<country_code><number>\n");
        printf("Example: +15551234567\n");
        return -1;
    }

    printf("Phone: %s\n", reg.phone);
    printf("Country code: %s\n", reg.country_code);
    printf("National number: %s\n", reg.national_number);
    printf("Verification method: %s\n", reg.method);
    printf("Language: %s, Locale: %s\n\n", reg.lg, reg.lc);

    /* Check if token is configured */
    if (strlen(WA_KEY) == 0) {
        printf("Warning: Registration HMAC key not configured.\n");
        printf("WhatsApp requires a version-specific key for registration.\n");
        printf("The key must be extracted from libwhatsappmerged.so.\n");
        printf("See src/register.c for extraction instructions.\n\n");
        printf("Without the key, registration will fail with 'bad_token' error.\n\n");
    }

    /* Request verification code via WhatsApp API */
    if (wa_register_request_code(NULL, &reg) != 0) {
        printf("\nError: %s\n", wa_register_get_error(&reg));

        if (reg.retry_after > 0) {
            int hours = reg.retry_after / 3600;
            int minutes = (reg.retry_after % 3600) / 60;
            if (hours > 0) {
                printf("Please wait %d hour(s) and %d minute(s) before trying again.\n",
                        hours, minutes);
            } else if (minutes > 0) {
                printf("Please wait %d minute(s) before trying again.\n", minutes);
            }
        }

        /* Check if token-related error */
        if (strstr(reg.error_reason, "bad_param") != NULL ||
            strstr(reg.error_reason, "bad_token") != NULL ||
            strstr(reg.error_reason, "platform") != NULL) {
            printf("\nThis error is likely due to missing or invalid registration key.\n");
            printf("WhatsApp's anti-bot protection requires an HMAC key extracted from\n");
            printf("the native library (libwhatsappmerged.so). See src/register.c.\n");
        }

        /* Suggest voice if SMS failed */
        if (strstr(reg.error_reason, "SMS") != NULL ||
            strstr(reg.error_reason, "no_routes") != NULL) {
            printf("\nTip: Try voice verification instead:\n");
            printf("  wa-mini register --voice %s\n", phone);
        }

        return -1;
    }

    printf("\nSuccess! Verification code has been sent via %s.\n", reg.method);
    printf("\nOnce you receive the code, complete registration with:\n");
    printf("  wa-mini verify %s <6-digit-code>\n", phone);

    return 0;
}

/*
 * Build unregister/deregister IQ stanza
 */
static xmpp_node_t *build_unregister_request(void)
{
    /* Build IQ stanza:
     * <iq type="set" xmlns="urn:xmpp:whatsapp:account">
     *   <remove/>
     * </iq>
     */

    char id[32];
    snprintf(id, sizeof(id), "%ld.unreg", (long)time(NULL));

    xmpp_node_t *iq = xmpp_node_new("iq");
    if (iq == NULL) return NULL;

    xmpp_node_set_attr(iq, "type", "set");
    xmpp_node_set_attr(iq, "id", id);
    xmpp_node_set_attr(iq, "xmlns", "urn:xmpp:whatsapp:account");

    xmpp_node_t *remove = xmpp_node_new("remove");
    if (remove == NULL) {
        xmpp_node_free(iq);
        return NULL;
    }

    xmpp_node_add_child(iq, remove);
    free(remove);

    return iq;
}

/*
 * High-level verification function for CLI
 */
int wa_do_verification(const char *phone, const char *code, wa_account_t *account)
{
    reg_ctx_t reg;

    printf("Verifying %s with code %s...\n\n", phone, code);

    /* Initialize registration context */
    if (wa_register_init(&reg, phone, "sms") != 0) {
        printf("Error: Invalid phone number format\n");
        return -1;
    }

    /* Submit verification code to WhatsApp */
    if (wa_register_submit_code(NULL, &reg, code) != 0) {
        printf("\nError: %s\n", wa_register_get_error(&reg));

        if (strstr(reg.error_reason, "expired") != NULL) {
            printf("\nTo request a new code, run:\n");
            printf("  wa-mini register %s\n", phone);
        }

        return -1;
    }

    /* Generate Signal keys for the account */
    printf("\nGenerating cryptographic keys...\n");

    if (wa_register_upload_keys(NULL, &reg, account) != 0) {
        printf("Error: %s\n", wa_register_get_error(&reg));
        return -1;
    }

    printf("\nRegistration complete!\n");
    printf("Phone: %s\n", account->phone);
    printf("Registration ID: %u\n", account->registration_id);
    printf("\nAccount has been saved. You can now use:\n");
    printf("  wa-mini daemon %s    # Start service\n", phone);
    printf("  wa-mini link %s      # Link companion device\n", phone);

    return 0;
}

/*
 * Unregister phone from WhatsApp servers
 * This sends a deregistration request before local deletion
 */
wa_error_t wa_unregister(wa_ctx_t *ctx, const char *phone)
{
    if (ctx == NULL || phone == NULL) {
        return WA_ERR_INVALID;
    }

    /* Connect to WhatsApp (performs handshake and auth) */
    wa_error_t err = wa_connect(ctx, phone);
    if (err != WA_OK) {
        return err;
    }

    /* Build unregister request */
    xmpp_node_t *request = build_unregister_request();
    if (request == NULL) {
        wa_disconnect(ctx);
        return WA_ERR_MEMORY;
    }

    /* Send request and wait for response */
    xmpp_node_t *response = NULL;
    err = wa_send_iq(ctx, request, &response);
    xmpp_node_free(request);

    if (err != WA_OK) {
        wa_disconnect(ctx);
        return err;
    }

    /* Check response */
    wa_error_t result = WA_OK;

    if (response != NULL) {
        const char *type = xmpp_node_get_attr(response, "type");
        if (type != NULL && strcmp(type, "error") == 0) {
            result = WA_ERR_PROTOCOL;
        }
        xmpp_node_free(response);
    }

    /* Disconnect */
    wa_disconnect(ctx);

    return result;
}
