/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Main Context Implementation
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>
#include <openssl/evp.h>

#include "wa-mini.h"
#include "noise.h"
#include "xmpp.h"
#include "proto.h"

/* Forward declarations for internal types */
typedef struct wa_socket wa_socket_t;
typedef struct wa_store wa_store_t;

/* External socket functions */
extern wa_socket_t *wa_socket_new(void);
extern void wa_socket_free(wa_socket_t *sock);
extern int wa_socket_connect(wa_socket_t *sock, const char *host, int port);
extern void wa_socket_disconnect(wa_socket_t *sock);
extern int wa_socket_is_connected(wa_socket_t *sock);
extern int wa_socket_write(wa_socket_t *sock, const uint8_t *data, size_t len);
extern int wa_socket_read(wa_socket_t *sock, uint8_t *data, size_t len, int timeout_ms);
extern int wa_socket_write_frame(wa_socket_t *sock, const uint8_t *data, size_t len);
extern int wa_socket_read_frame(wa_socket_t *sock, uint8_t *data, size_t max_len,
                                size_t *out_len, int timeout_ms);
extern int wa_socket_reconnect(wa_socket_t *sock);
extern time_t wa_socket_idle_time(wa_socket_t *sock);

/* External store functions */
extern wa_store_t *wa_store_open(const char *data_dir);
extern void wa_store_close(wa_store_t *store);
extern int wa_store_account_save(wa_store_t *store, const wa_account_t *account);
extern int wa_store_account_load(wa_store_t *store, const char *phone, wa_account_t *account);
extern int wa_store_account_list(wa_store_t *store, wa_account_t **accounts, int *count);
extern int wa_store_account_delete(wa_store_t *store, const char *phone);
extern int wa_store_config_get(wa_store_t *store, const char *key, char *value, size_t size);
extern int wa_store_config_set(wa_store_t *store, const char *key, const char *value);

/* External crypto init */
extern int crypto_init(void);

/* Protocol header bytes */
static const uint8_t WA_HEADER[] = {0x45, 0x44, 0x00, 0x01};  /* "ED" + version */
static const uint8_t WA_PROLOGUE[] = {0x57, 0x41, 0x06, 0x03}; /* "WA" + version 6.3 */

/* Default presence interval */
#define PRESENCE_INTERVAL_SEC 1800  /* 30 minutes */

/* Keepalive settings */
#define KEEPALIVE_INTERVAL_SEC 25   /* Send ping if no activity for 25 seconds */
#define PING_TIMEOUT_SEC 30         /* Ping timeout */

/* Main context structure */
struct wa_ctx {
    /* Data directory */
    char *data_dir;

    /* Storage */
    wa_store_t *store;

    /* Network */
    wa_socket_t *socket;

    /* Current account */
    wa_account_t *current_account;

    /* Noise session */
    noise_handshake_t handshake;
    noise_session_t session;
    int session_established;

    /* State */
    wa_state_t state;
    int running;
    time_t last_presence;
    time_t last_activity;       /* Last send/receive activity */
    time_t pending_ping_time;   /* When we sent a ping (0 if none pending) */
    uint32_t ping_counter;      /* Counter for ping IDs */

    /* Callbacks */
    wa_state_cb state_cb;
    void *state_cb_data;

    wa_message_cb message_cb;
    void *message_cb_data;

    wa_companion_cb companion_cb;
    void *companion_cb_data;

    /* Version info */
    char whatsapp_version[32];
};

/* Error strings */
static const char *error_strings[] = {
    [0] = "Success",
    [1] = "Memory allocation failed",
    [2] = "Network error",
    [3] = "Cryptographic error",
    [4] = "Protocol error",
    [5] = "Authentication failed",
    [6] = "Storage error",
    [7] = "Invalid parameter",
    [8] = "Timeout",
    [9] = "Account banned",
    [10] = "Rate limited",
};

/* State strings */
static const char *state_strings[] = {
    "Disconnected",
    "Connecting",
    "Handshake",
    "Authenticating",
    "Connected",
    "Error",
};

const char *wa_error_string(wa_error_t err)
{
    int idx = -err;
    if (idx >= 0 && idx < (int)(sizeof(error_strings) / sizeof(error_strings[0]))) {
        return error_strings[idx];
    }
    return "Unknown error";
}

const char *wa_state_string(wa_state_t state)
{
    if (state >= 0 && state < (int)(sizeof(state_strings) / sizeof(state_strings[0]))) {
        return state_strings[state];
    }
    return "Unknown state";
}

/* Set state and notify callback */
static void set_state(wa_ctx_t *ctx, wa_state_t state)
{
    if (ctx->state != state) {
        ctx->state = state;
        if (ctx->state_cb != NULL) {
            ctx->state_cb(ctx, state, ctx->state_cb_data);
        }
    }
}

/* Create new context */
wa_ctx_t *wa_ctx_new(const char *data_dir)
{
    WA_DEBUG("creating context, data_dir=%s", data_dir ? data_dir : "(default)");

    wa_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return NULL;

    /* Initialize crypto library */
    if (crypto_init() < 0) {
        free(ctx);
        return NULL;
    }

    /* Use default data dir if not specified */
    if (data_dir == NULL) {
        const char *home = getenv("HOME");
        if (home == NULL) home = "/tmp";

        size_t len = strlen(home) + 16;
        ctx->data_dir = malloc(len);
        if (ctx->data_dir == NULL) {
            free(ctx);
            return NULL;
        }
        snprintf(ctx->data_dir, len, "%s/.wa-mini", home);
    } else {
        ctx->data_dir = strdup(data_dir);
        if (ctx->data_dir == NULL) {
            free(ctx);
            return NULL;
        }
    }

    /* Open storage */
    ctx->store = wa_store_open(ctx->data_dir);
    if (ctx->store == NULL) {
        free(ctx->data_dir);
        free(ctx);
        return NULL;
    }

    /* Create socket */
    ctx->socket = wa_socket_new();
    if (ctx->socket == NULL) {
        wa_store_close(ctx->store);
        free(ctx->data_dir);
        free(ctx);
        return NULL;
    }

    /* Load WhatsApp version */
    if (wa_store_config_get(ctx->store, "whatsapp_version",
                            ctx->whatsapp_version, sizeof(ctx->whatsapp_version)) != 0) {
        /* Default version - must match WA_VERSION in register.c */
        strncpy(ctx->whatsapp_version, "2.26.4.71", sizeof(ctx->whatsapp_version) - 1);
    }

    ctx->state = WA_STATE_DISCONNECTED;

    return ctx;
}

/* Free context */
void wa_ctx_free(wa_ctx_t *ctx)
{
    if (ctx == NULL) return;

    wa_socket_free(ctx->socket);
    wa_store_close(ctx->store);
    free(ctx->current_account);
    free(ctx->data_dir);

    noise_handshake_clear(&ctx->handshake);
    noise_session_clear(&ctx->session);

    free(ctx);
}

/* Set callbacks */
void wa_set_state_callback(wa_ctx_t *ctx, wa_state_cb cb, void *userdata)
{
    ctx->state_cb = cb;
    ctx->state_cb_data = userdata;
}

void wa_set_message_callback(wa_ctx_t *ctx, wa_message_cb cb, void *userdata)
{
    ctx->message_cb = cb;
    ctx->message_cb_data = userdata;
}

void wa_set_companion_callback(wa_ctx_t *ctx, wa_companion_cb cb, void *userdata)
{
    ctx->companion_cb = cb;
    ctx->companion_cb_data = userdata;
}

/* Account management */
wa_error_t wa_account_list(wa_ctx_t *ctx, wa_account_t **accounts, int *count)
{
    if (wa_store_account_list(ctx->store, accounts, count) != 0) {
        return WA_ERR_STORAGE;
    }
    return WA_OK;
}

wa_error_t wa_account_get(wa_ctx_t *ctx, const char *phone, wa_account_t *account)
{
    if (wa_store_account_load(ctx->store, phone, account) != 0) {
        return WA_ERR_STORAGE;
    }
    return WA_OK;
}

wa_error_t wa_account_delete(wa_ctx_t *ctx, const char *phone)
{
    if (wa_store_account_delete(ctx->store, phone) != 0) {
        return WA_ERR_STORAGE;
    }
    return WA_OK;
}

void wa_account_free(wa_account_t *accounts, int count)
{
    (void)count;
    free(accounts);
}

/* Get current state */
wa_state_t wa_get_state(wa_ctx_t *ctx)
{
    return ctx->state;
}

/* Convert phone string "+15551234567" to int64 15551234567 */
static uint64_t phone_to_int64(const char *phone)
{
    uint64_t result = 0;
    const char *p = phone;

    /* Skip leading + if present */
    if (*p == '+') p++;

    while (*p != '\0') {
        if (*p >= '0' && *p <= '9') {
            result = result * 10 + (uint64_t)(*p - '0');
        }
        p++;
    }

    return result;
}

/* Parse version string "2.26.3.79" into components */
static void parse_version(const char *version, proto_app_version_t *ver)
{
    sodium_memzero(ver, sizeof(*ver));
    if (version == NULL) return;

    int parts[4] = {0};
    int part = 0;
    const char *p = version;

    while (*p != '\0' && part < 4) {
        if (*p >= '0' && *p <= '9') {
            parts[part] = parts[part] * 10 + (*p - '0');
        } else if (*p == '.') {
            part++;
        }
        p++;
    }

    ver->primary = (uint32_t)parts[0];
    ver->secondary = (uint32_t)parts[1];
    ver->tertiary = (uint32_t)parts[2];
    ver->quaternary = (uint32_t)parts[3];
}

/* Store uint32 as big-endian bytes */
static void uint32_to_be(uint32_t val, uint8_t *out)
{
    out[0] = (val >> 24) & 0xFF;
    out[1] = (val >> 16) & 0xFF;
    out[2] = (val >> 8) & 0xFF;
    out[3] = val & 0xFF;
}

/* Perform Noise handshake */
static wa_error_t do_handshake(wa_ctx_t *ctx)
{
    WA_DEBUG("starting Noise handshake");
    set_state(ctx, WA_STATE_HANDSHAKE);

    /* Initialize handshake with static key from account */
    noise_keypair_t static_key;
    memcpy(static_key.priv, ctx->current_account->noise_static, 32);
    memcpy(static_key.pub, ctx->current_account->noise_static_pub, 32);

    if (noise_handshake_init(&ctx->handshake, &static_key) != 0) {
        return WA_ERR_CRYPTO;
    }

    /*
     * Step 1: Build and send ClientHello (-> e)
     */
    uint8_t ephemeral_msg[64];
    size_t ephemeral_len;

    if (noise_write_message(&ctx->handshake, NULL, 0, ephemeral_msg, &ephemeral_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    /* Wrap in protobuf ClientHello */
    proto_client_hello_t hello;
    sodium_memzero(&hello, sizeof(hello));
    hello.ephemeral = ephemeral_msg;
    hello.ephemeral_len = ephemeral_len;

    proto_handshake_message_t wrapper;
    sodium_memzero(&wrapper, sizeof(wrapper));
    wrapper.has_client_hello = 1;
    wrapper.client_hello = hello;

    uint8_t frame[4096];
    size_t frame_len;
    if (proto_encode_handshake(&wrapper, frame, &frame_len) != 0) {
        return WA_ERR_PROTOCOL;
    }

    if (wa_socket_write_frame(ctx->socket, frame, frame_len) != 0) {
        return WA_ERR_NETWORK;
    }

    WA_DEBUG("sent ClientHello, waiting for ServerHello");

    /*
     * Step 2: Read and decode ServerHello (<- e, ee, s, es)
     */
    uint8_t server_frame[4096];
    size_t server_frame_len;

    if (wa_socket_read_frame(ctx->socket, server_frame, sizeof(server_frame),
                              &server_frame_len, 30000) != 0) {
        return WA_ERR_NETWORK;
    }

    /* Parse protobuf ServerHello */
    proto_handshake_message_t server_wrapper;
    if (proto_decode_handshake(server_frame, server_frame_len, &server_wrapper) != 0) {
        return WA_ERR_PROTOCOL;
    }

    if (!server_wrapper.has_server_hello) {
        proto_free_handshake(&server_wrapper);
        return WA_ERR_PROTOCOL;
    }

    /* Concatenate server ephemeral + encrypted static + payload for Noise */
    uint8_t server_msg[4096];
    size_t server_msg_len = 0;

    proto_server_hello_t *sh = &server_wrapper.server_hello;

    /* Validate individual field sizes for cryptographic material first */
    if (sh->ephemeral_len > 0 && sh->ephemeral_len != 32) {
        proto_free_handshake(&server_wrapper);
        return WA_ERR_PROTOCOL;  /* Ephemeral key must be 32 bytes */
    }
    if (sh->static_len > 0 && sh->static_len != 48) {
        proto_free_handshake(&server_wrapper);
        return WA_ERR_PROTOCOL;  /* Encrypted static must be 32 + 16 tag */
    }

    /* Overflow-safe total size check: ephemeral + static are now bounded (max 80) */
    size_t fixed_len = sh->ephemeral_len + sh->static_len;  /* Max 80, no overflow */
    if (sh->payload_len > sizeof(server_msg) - fixed_len) {
        proto_free_handshake(&server_wrapper);
        return WA_ERR_PROTOCOL;
    }

    if (sh->ephemeral != NULL && sh->ephemeral_len > 0) {
        memcpy(server_msg + server_msg_len, sh->ephemeral, sh->ephemeral_len);
        server_msg_len += sh->ephemeral_len;
    }
    if (sh->static_encrypted != NULL && sh->static_len > 0) {
        memcpy(server_msg + server_msg_len, sh->static_encrypted, sh->static_len);
        server_msg_len += sh->static_len;
    }
    if (sh->payload_encrypted != NULL && sh->payload_len > 0) {
        memcpy(server_msg + server_msg_len, sh->payload_encrypted, sh->payload_len);
        server_msg_len += sh->payload_len;
    }

    uint8_t server_payload[4096];
    size_t server_payload_len;

    if (noise_read_message(&ctx->handshake, server_msg, server_msg_len,
                           server_payload, &server_payload_len) != 0) {
        proto_free_handshake(&server_wrapper);
        return WA_ERR_CRYPTO;
    }

    proto_free_handshake(&server_wrapper);

    WA_DEBUG("processed ServerHello, building ClientFinish");

    /*
     * Step 3: Build and send ClientFinish (-> s, se)
     */

    /* Build client payload with device pairing info */
    proto_client_payload_t auth;
    sodium_memzero(&auth, sizeof(auth));
    auth.username = phone_to_int64(ctx->current_account->phone);
    auth.has_passive = 1;
    auth.passive = 0;  /* Primary device mode */
    auth.has_short_connect = 1;
    auth.short_connect = 0;
    auth.platform_type = 0;  /* Android */
    auth.os_version = "9";
    auth.manufacturer = "VMware, Inc.";
    auth.device_model = "VMware Virtual Platform";
    auth.os_build_number = "PI";

    /* Parse and set app version */
    auth.has_app_version = 1;
    parse_version(ctx->whatsapp_version, &auth.app_version);

    /* Connection type: 1 = WIFI_UNKNOWN */
    auth.has_connect_type = 1;
    auth.connect_type = 1;

    /* Connection reason: 1 = USER_ACTIVATED */
    auth.has_connect_reason = 1;
    auth.connect_reason = 1;

    /* OC and LC flags */
    auth.has_oc = 1;
    auth.oc = 0;
    auth.has_lc = 1;
    auth.lc = 0;

    /* Device capability metrics */
    auth.has_year_class = 1;
    auth.year_class = 2018;    /* Performance year for Android 9 device */
    auth.has_mem_class = 1;
    auth.mem_class = 256;      /* Standard memory class */

    /* Populate device pairing data (Signal keys) */
    auth.has_device_pairing = 1;

    /* Registration ID as big-endian bytes */
    uint32_to_be(ctx->current_account->registration_id, auth.device_pairing.registration_id);

    /* Key type 0x05 = DJB/Curve25519 */
    auth.device_pairing.key_type = 0x05;

    /* Signal identity public key */
    memcpy(auth.device_pairing.identity_pub, ctx->current_account->identity_pub, 32);

    /* Signed prekey ID as big-endian bytes */
    uint32_to_be(ctx->current_account->signed_prekey_id, auth.device_pairing.signed_prekey_id);

    /* Compute signed prekey public from private */
    noise_compute_public(ctx->current_account->signed_prekey, auth.device_pairing.signed_prekey_pub);

    /* Signed prekey signature */
    memcpy(auth.device_pairing.signed_prekey_sig, ctx->current_account->signed_prekey_sig, 64);

    /* Build hash - MD5 of WhatsApp version string */
    auth.device_pairing.has_build_hash = 1;
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        unsigned int md_len;
        EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
        EVP_DigestUpdate(mdctx, ctx->whatsapp_version, strlen(ctx->whatsapp_version));
        EVP_DigestFinal_ex(mdctx, auth.device_pairing.build_hash, &md_len);
        EVP_MD_CTX_free(mdctx);
    }

    uint8_t client_payload[2048];
    size_t client_payload_len;

    if (proto_encode_client_payload(&auth, client_payload, &client_payload_len) != 0) {
        return WA_ERR_PROTOCOL;
    }

    /* Debug: print ClientPayload bytes */
    WA_DEBUG("ClientPayload (%zu bytes):", client_payload_len);
    for (size_t i = 0; i < client_payload_len && i < 200; i += 16) {
        char hex[50] = {0};
        for (size_t j = 0; j < 16 && i + j < client_payload_len; j++) {
            sprintf(hex + j * 3, "%02x ", client_payload[i + j]);
        }
        WA_DEBUG("  %04zx: %s", i, hex);
    }

    /* Noise encrypt the static key and payload */
    uint8_t encrypted[4096];
    size_t encrypted_len;

    if (noise_write_message(&ctx->handshake, client_payload, client_payload_len,
                            encrypted, &encrypted_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    /* Split encrypted message into static and payload parts */
    /* First 48 bytes are encrypted static (32 key + 16 tag) */
    proto_client_finish_t finish;
    sodium_memzero(&finish, sizeof(finish));
    finish.static_encrypted = encrypted;
    finish.static_len = 32 + 16;  /* Key + GCM tag */
    finish.payload_encrypted = encrypted + 48;
    finish.payload_len = encrypted_len - 48;

    /* Wrap in protobuf ClientFinish */
    proto_handshake_message_t finish_wrapper;
    sodium_memzero(&finish_wrapper, sizeof(finish_wrapper));
    finish_wrapper.has_client_finish = 1;
    finish_wrapper.client_finish = finish;

    if (proto_encode_handshake(&finish_wrapper, frame, &frame_len) != 0) {
        return WA_ERR_PROTOCOL;
    }

    if (wa_socket_write_frame(ctx->socket, frame, frame_len) != 0) {
        return WA_ERR_NETWORK;
    }

    WA_DEBUG("sent ClientFinish, splitting transport keys");

    /*
     * Step 4: Split into transport keys
     */
    if (noise_split(&ctx->handshake, &ctx->session) != 0) {
        return WA_ERR_CRYPTO;
    }

    ctx->session_established = 1;
    WA_DEBUG("transport keys established, waiting for auth response");

    /*
     * Step 5: Read and process server's authentication response
     */
    set_state(ctx, WA_STATE_AUTHENTICATING);

    uint8_t auth_response[4096];
    size_t auth_response_len;

    if (wa_socket_read_frame(ctx->socket, auth_response, sizeof(auth_response),
                              &auth_response_len, 30000) != 0) {
        return WA_ERR_NETWORK;
    }

    /* Decrypt the response using transport keys */
    uint8_t decrypted[4096];
    size_t decrypted_len;

    if (noise_decrypt(&ctx->session, auth_response, auth_response_len,
                      decrypted, &decrypted_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    /* Parse XMPP response to check authentication status */
    size_t consumed;
    xmpp_node_t *response = xmpp_decode(decrypted, decrypted_len, &consumed);

    if (response == NULL) {
        return WA_ERR_PROTOCOL;
    }

    /* Check for failure or stream error */
    const char *tag = response->tag;
    wa_error_t result = WA_OK;

    if (tag != NULL) {
        if (strcmp(tag, "failure") == 0) {
            /* Authentication failed */
            const char *reason = xmpp_node_get_attr(response, "reason");
            if (reason != NULL) {
                if (strcmp(reason, "401") == 0 || strcmp(reason, "403") == 0) {
                    result = WA_ERR_AUTH;
                } else if (strcmp(reason, "405") == 0) {
                    result = WA_ERR_BANNED;
                } else if (strcmp(reason, "429") == 0) {
                    result = WA_ERR_RATE_LIMIT;
                } else {
                    result = WA_ERR_AUTH;
                }
            } else {
                result = WA_ERR_AUTH;
            }
        } else if (strcmp(tag, "stream:error") == 0) {
            result = WA_ERR_PROTOCOL;
        }
        /* "success" or "iq" with type="result" means auth succeeded */
    }

    xmpp_node_free(response);

    if (result != WA_OK) {
        WA_DEBUG("authentication failed: %s", wa_error_string(result));
        ctx->session_established = 0;
    } else {
        WA_DEBUG("handshake completed successfully");
    }

    return result;
}

/* Connect to WhatsApp */
wa_error_t wa_connect(wa_ctx_t *ctx, const char *phone)
{
    WA_DEBUG("connecting to WhatsApp for phone=%s", phone);

    /* Load account */
    if (ctx->current_account == NULL) {
        ctx->current_account = calloc(1, sizeof(wa_account_t));
        if (ctx->current_account == NULL) {
            return WA_ERR_MEMORY;
        }
    }

    if (wa_store_account_load(ctx->store, phone, ctx->current_account) != 0) {
        return WA_ERR_STORAGE;
    }

    WA_DEBUG("account loaded, registration_id=%u", ctx->current_account->registration_id);
    set_state(ctx, WA_STATE_CONNECTING);

    /* Connect socket */
    WA_DEBUG("connecting to g.whatsapp.net:443");
    if (wa_socket_connect(ctx->socket, NULL, 0) != 0) {
        set_state(ctx, WA_STATE_ERROR);
        return WA_ERR_NETWORK;
    }

    /* Write header */
    if (wa_socket_write(ctx->socket, WA_HEADER, sizeof(WA_HEADER)) != 0) {
        wa_socket_disconnect(ctx->socket);
        set_state(ctx, WA_STATE_ERROR);
        return WA_ERR_NETWORK;
    }

    /* Write routing info (empty for primary device) */
    uint8_t routing[] = {0x00, 0x00, 0x00};  /* 3-byte length = 0 */
    if (wa_socket_write(ctx->socket, routing, sizeof(routing)) != 0) {
        wa_socket_disconnect(ctx->socket);
        set_state(ctx, WA_STATE_ERROR);
        return WA_ERR_NETWORK;
    }

    /* Write prologue */
    if (wa_socket_write(ctx->socket, WA_PROLOGUE, sizeof(WA_PROLOGUE)) != 0) {
        wa_socket_disconnect(ctx->socket);
        set_state(ctx, WA_STATE_ERROR);
        return WA_ERR_NETWORK;
    }

    /* Perform handshake */
    wa_error_t err = do_handshake(ctx);
    if (err != WA_OK) {
        wa_socket_disconnect(ctx->socket);
        set_state(ctx, WA_STATE_ERROR);
        return err;
    }

    set_state(ctx, WA_STATE_CONNECTED);
    ctx->last_presence = time(NULL);
    ctx->last_activity = time(NULL);
    ctx->pending_ping_time = 0;

    return WA_OK;
}

/* Disconnect */
wa_error_t wa_disconnect(wa_ctx_t *ctx)
{
    wa_socket_disconnect(ctx->socket);
    noise_session_clear(&ctx->session);
    ctx->session_established = 0;
    set_state(ctx, WA_STATE_DISCONNECTED);
    return WA_OK;
}

/* Send presence */
wa_error_t wa_send_presence(wa_ctx_t *ctx, const char *status)
{
    if (ctx->state != WA_STATE_CONNECTED) {
        return WA_ERR_PROTOCOL;
    }

    if (status == NULL) status = "available";

    /* Build presence stanza */
    xmpp_node_t *presence = xmpp_presence_new(status);
    if (presence == NULL) {
        return WA_ERR_MEMORY;
    }

    /* Encode */
    uint8_t encoded[4096];
    size_t encoded_len;

    if (xmpp_encode(presence, encoded, &encoded_len) != 0) {
        xmpp_node_free(presence);
        return WA_ERR_PROTOCOL;
    }

    xmpp_node_free(presence);

    /* Encrypt and send */
    uint8_t encrypted[4096];
    size_t encrypted_len;

    if (noise_encrypt(&ctx->session, encoded, encoded_len, encrypted, &encrypted_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    if (wa_socket_write_frame(ctx->socket, encrypted, encrypted_len) != 0) {
        return WA_ERR_NETWORK;
    }

    ctx->last_presence = time(NULL);
    return WA_OK;
}

/* Send IQ request and wait for response */
wa_error_t wa_send_iq(wa_ctx_t *ctx, xmpp_node_t *iq, xmpp_node_t **response)
{
    if (ctx->state != WA_STATE_CONNECTED) {
        return WA_ERR_PROTOCOL;
    }

    /* Encode */
    uint8_t encoded[4096];
    size_t encoded_len;

    if (xmpp_encode(iq, encoded, &encoded_len) != 0) {
        return WA_ERR_PROTOCOL;
    }

    /* Encrypt and send */
    uint8_t encrypted[4096];
    size_t encrypted_len;

    if (noise_encrypt(&ctx->session, encoded, encoded_len, encrypted, &encrypted_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    if (wa_socket_write_frame(ctx->socket, encrypted, encrypted_len) != 0) {
        return WA_ERR_NETWORK;
    }

    /* Read response */
    uint8_t resp_encrypted[4096];
    size_t resp_encrypted_len;

    if (wa_socket_read_frame(ctx->socket, resp_encrypted, sizeof(resp_encrypted),
                              &resp_encrypted_len, 30000) != 0) {
        return WA_ERR_NETWORK;
    }

    /* Decrypt */
    uint8_t decrypted[4096];
    size_t decrypted_len;

    if (noise_decrypt(&ctx->session, resp_encrypted, resp_encrypted_len,
                      decrypted, &decrypted_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    /* Decode XMPP */
    size_t consumed;
    *response = xmpp_decode(decrypted, decrypted_len, &consumed);

    if (*response == NULL) {
        return WA_ERR_PROTOCOL;
    }

    return WA_OK;
}

/* Send a keepalive ping */
static wa_error_t send_keepalive_ping(wa_ctx_t *ctx)
{
    WA_DEBUG("sending keepalive ping");

    char id[32];
    snprintf(id, sizeof(id), "ping.%u", ++ctx->ping_counter);

    /* Build ping IQ: <iq type="get" xmlns="w:p" to="s.whatsapp.net" id="..."/> */
    xmpp_node_t *ping = xmpp_node_new("iq");
    if (ping == NULL) return WA_ERR_MEMORY;

    xmpp_node_set_attr(ping, "type", "get");
    xmpp_node_set_attr(ping, "xmlns", "w:p");
    xmpp_node_set_attr(ping, "to", "s.whatsapp.net");
    xmpp_node_set_attr(ping, "id", id);

    uint8_t encoded[4096];
    size_t encoded_len;

    if (xmpp_encode(ping, encoded, &encoded_len) != 0) {
        xmpp_node_free(ping);
        return WA_ERR_PROTOCOL;
    }
    xmpp_node_free(ping);

    uint8_t encrypted[4096];
    size_t encrypted_len;

    if (noise_encrypt(&ctx->session, encoded, encoded_len, encrypted, &encrypted_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    if (wa_socket_write_frame(ctx->socket, encrypted, encrypted_len) != 0) {
        return WA_ERR_NETWORK;
    }

    ctx->pending_ping_time = time(NULL);
    ctx->last_activity = ctx->pending_ping_time;
    return WA_OK;
}

/* Check if this is a ping IQ (server ping) */
static int is_ping_iq(xmpp_node_t *node)
{
    const char *xmlns = xmpp_node_get_attr(node, "xmlns");

    /* Check for urn:xmpp:ping namespace */
    if (xmlns != NULL && strcmp(xmlns, "urn:xmpp:ping") == 0) {
        return 1;
    }

    /* Check for ping child element */
    xmpp_node_t *ping = xmpp_node_find_child(node, "ping");
    if (ping != NULL) {
        return 1;
    }

    return 0;
}

/* Send pong response to ping */
static void send_pong(wa_ctx_t *ctx, const char *id)
{
    xmpp_node_t *pong = xmpp_iq_new("result", id, NULL);
    if (pong == NULL) return;

    uint8_t pong_enc[4096];
    size_t pong_enc_len;

    if (xmpp_encode(pong, pong_enc, &pong_enc_len) == 0) {
        uint8_t pong_crypt[4096];
        size_t pong_crypt_len;

        if (noise_encrypt(&ctx->session, pong_enc, pong_enc_len,
                          pong_crypt, &pong_crypt_len) == 0) {
            wa_socket_write_frame(ctx->socket, pong_crypt, pong_crypt_len);
            ctx->last_activity = time(NULL);
        }
    }
    xmpp_node_free(pong);
}

/* Process incoming messages */
wa_error_t wa_process(wa_ctx_t *ctx, int timeout_ms)
{
    if (ctx->state != WA_STATE_CONNECTED) {
        return WA_ERR_PROTOCOL;
    }

    time_t now = time(NULL);

    /* Check if we need to send presence */
    if (now - ctx->last_presence >= PRESENCE_INTERVAL_SEC) {
        wa_send_presence(ctx, "available");
    }

    /* Check for ping timeout */
    if (ctx->pending_ping_time > 0) {
        if (now - ctx->pending_ping_time >= PING_TIMEOUT_SEC) {
            /* Ping timed out - connection may be dead */
            WA_DEBUG("ping timeout after %d seconds", PING_TIMEOUT_SEC);
            ctx->pending_ping_time = 0;
            return WA_ERR_TIMEOUT;
        }
    }

    /* Check if we need to send keepalive ping */
    if (ctx->pending_ping_time == 0 && ctx->last_activity > 0) {
        if (now - ctx->last_activity >= KEEPALIVE_INTERVAL_SEC) {
            send_keepalive_ping(ctx);
        }
    }

    /* Read incoming frame */
    uint8_t encrypted[65536];
    size_t encrypted_len;

    int ret = wa_socket_read_frame(ctx->socket, encrypted, sizeof(encrypted),
                                   &encrypted_len, timeout_ms);

    if (ret < 0) {
        if (!wa_socket_is_connected(ctx->socket)) {
            set_state(ctx, WA_STATE_DISCONNECTED);
            return WA_ERR_NETWORK;
        }
        return WA_OK;  /* Timeout, no data */
    }

    /* Update activity timestamp */
    ctx->last_activity = time(NULL);

    /* Decrypt */
    uint8_t decrypted[65536];
    size_t decrypted_len;

    if (noise_decrypt(&ctx->session, encrypted, encrypted_len,
                      decrypted, &decrypted_len) != 0) {
        return WA_ERR_CRYPTO;
    }

    /* Decode XMPP */
    size_t consumed;
    xmpp_node_t *node = xmpp_decode(decrypted, decrypted_len, &consumed);

    if (node == NULL) {
        return WA_ERR_PROTOCOL;
    }

    /* Handle message based on tag */
    const char *tag = node->tag;

    if (tag != NULL) {
        WA_DEBUG("received <%s> stanza", tag);

        if (strcmp(tag, "iq") == 0) {
            const char *type = xmpp_node_get_attr(node, "type");
            const char *id = xmpp_node_get_attr(node, "id");

            if (type != NULL) {
                if (strcmp(type, "get") == 0) {
                    /* Handle ping request from server */
                    if (is_ping_iq(node) && id != NULL) {
                        WA_DEBUG("received server ping, sending pong");
                        send_pong(ctx, id);
                    }
                } else if (strcmp(type, "result") == 0) {
                    /* Handle pong response to our ping */
                    if (ctx->pending_ping_time > 0) {
                        WA_DEBUG("received pong response, latency=%lds", now - ctx->pending_ping_time);
                        /* Clear pending ping */
                        ctx->pending_ping_time = 0;
                    }
                }
            }
        }

        /* Notify callback */
        if (ctx->message_cb != NULL) {
            ctx->message_cb(ctx, decrypted, decrypted_len, ctx->message_cb_data);
        }
    }

    xmpp_node_free(node);
    return WA_OK;
}

/* Main loop */
wa_error_t wa_run(wa_ctx_t *ctx)
{
    WA_DEBUG("entering main loop");
    ctx->running = 1;

    while (ctx->running) {
        if (ctx->state == WA_STATE_CONNECTED) {
            wa_error_t err = wa_process(ctx, 10000);  /* 10 second timeout for keepalive checks */
            if (err != WA_OK && err != WA_ERR_TIMEOUT) {
                WA_DEBUG("process error: %s, attempting reconnect", wa_error_string(err));
                /* Try to reconnect */
                wa_socket_disconnect(ctx->socket);
                set_state(ctx, WA_STATE_DISCONNECTED);

                if (wa_socket_reconnect(ctx->socket) == 0) {
                    WA_DEBUG("socket reconnected, redoing handshake");
                    /* Reconnected, redo handshake */
                    wa_error_t hs_err = do_handshake(ctx);
                    if (hs_err == WA_OK) {
                        set_state(ctx, WA_STATE_CONNECTED);
                    } else {
                        WA_DEBUG("handshake failed after reconnect: %s", wa_error_string(hs_err));
                    }
                } else {
                    WA_DEBUG("socket reconnect failed");
                }
            }
        } else {
            /* Not connected, wait and try to reconnect */
            WA_DEBUG("disconnected, waiting 5 seconds before reconnect");
            sleep(5);
            if (ctx->current_account != NULL) {
                wa_connect(ctx, ctx->current_account->phone);
            }
        }
    }

    WA_DEBUG("exiting main loop");
    return WA_OK;
}

/* Stop main loop */
void wa_stop(wa_ctx_t *ctx)
{
    ctx->running = 0;
}

/* Version management */
wa_error_t wa_version_get(wa_ctx_t *ctx, char *version, size_t size)
{
    strncpy(version, ctx->whatsapp_version, size - 1);
    version[size - 1] = '\0';
    return WA_OK;
}

wa_error_t wa_version_set(wa_ctx_t *ctx, const char *version)
{
    strncpy(ctx->whatsapp_version, version, sizeof(ctx->whatsapp_version) - 1);
    ctx->whatsapp_version[sizeof(ctx->whatsapp_version) - 1] = '\0';

    if (wa_store_config_set(ctx->store, "whatsapp_version", version) != 0) {
        return WA_ERR_STORAGE;
    }

    return WA_OK;
}

/*
 * Note: Automatic version updates are disabled. The WhatsApp version and
 * registration token are tightly coupled - updating the version without
 * the corresponding HMAC key will cause registration failures.
 * See src/register.c for manual update instructions.
 */
