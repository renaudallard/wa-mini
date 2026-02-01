/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Public API
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#ifndef WA_MINI_H
#define WA_MINI_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

/* Debug logging macro - enabled with -v flag */
extern int wa_verbose;
#define WA_DEBUG(...) do { \
    if (wa_verbose) { \
        fprintf(stderr, "[DEBUG] %s:%d: ", __func__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
} while(0)

/* Version info */
#define WA_MINI_VERSION "0.1.0"

/* Error codes */
typedef enum {
    WA_OK = 0,
    WA_ERR_MEMORY = -1,
    WA_ERR_NETWORK = -2,
    WA_ERR_CRYPTO = -3,
    WA_ERR_PROTOCOL = -4,
    WA_ERR_AUTH = -5,
    WA_ERR_STORAGE = -6,
    WA_ERR_INVALID = -7,
    WA_ERR_TIMEOUT = -8,
    WA_ERR_BANNED = -9,
    WA_ERR_RATE_LIMIT = -10,
} wa_error_t;

/* Connection state */
typedef enum {
    WA_STATE_DISCONNECTED = 0,
    WA_STATE_CONNECTING,
    WA_STATE_HANDSHAKE,
    WA_STATE_AUTHENTICATING,
    WA_STATE_CONNECTED,
    WA_STATE_ERROR,
} wa_state_t;

/* Forward declarations */
typedef struct wa_ctx wa_ctx_t;
typedef struct wa_account wa_account_t;
typedef struct wa_companion wa_companion_t;

/* Account info */
struct wa_account {
    int64_t id;
    char phone[20];
    uint8_t identity_key[32];
    uint8_t identity_pub[32];
    uint8_t signed_prekey[32];
    uint8_t signed_prekey_sig[64];
    uint32_t signed_prekey_id;
    uint32_t registration_id;
    uint8_t noise_static[32];
    uint8_t noise_static_pub[32];
    uint8_t server_static_pub[32];
    int64_t registered_at;
    int active;
};

/* Companion device info */
struct wa_companion {
    int64_t id;
    int64_t account_id;
    uint32_t device_id;
    uint8_t identity_pub[32];
    char name[64];
    char platform[32];
    int64_t linked_at;
};

/* Callbacks */
typedef void (*wa_state_cb)(wa_ctx_t *ctx, wa_state_t state, void *userdata);
typedef void (*wa_message_cb)(wa_ctx_t *ctx, const uint8_t *data, size_t len, void *userdata);
typedef void (*wa_companion_cb)(wa_ctx_t *ctx, wa_companion_t *companion, void *userdata);

/* Context initialization */
wa_ctx_t *wa_ctx_new(const char *data_dir);
void wa_ctx_free(wa_ctx_t *ctx);

/* Set callbacks */
void wa_set_state_callback(wa_ctx_t *ctx, wa_state_cb cb, void *userdata);
void wa_set_message_callback(wa_ctx_t *ctx, wa_message_cb cb, void *userdata);
void wa_set_companion_callback(wa_ctx_t *ctx, wa_companion_cb cb, void *userdata);

/* Account management */
wa_error_t wa_account_list(wa_ctx_t *ctx, wa_account_t **accounts, int *count);
wa_error_t wa_account_get(wa_ctx_t *ctx, const char *phone, wa_account_t *account);
wa_error_t wa_account_delete(wa_ctx_t *ctx, const char *phone);
void wa_account_free(wa_account_t *accounts, int count);

/* Registration */
wa_error_t wa_register_request(wa_ctx_t *ctx, const char *phone, const char *method);
wa_error_t wa_register_verify(wa_ctx_t *ctx, const char *phone, const char *code);

/* Unregistration (deregister from WhatsApp servers) */
wa_error_t wa_unregister(wa_ctx_t *ctx, const char *phone);

/* Connection */
wa_error_t wa_connect(wa_ctx_t *ctx, const char *phone);
wa_error_t wa_disconnect(wa_ctx_t *ctx);
wa_state_t wa_get_state(wa_ctx_t *ctx);

/* Presence */
wa_error_t wa_send_presence(wa_ctx_t *ctx, const char *status);

/* Companion linking */
wa_error_t wa_link_get_code(wa_ctx_t *ctx, char *code_out, size_t code_size);
wa_error_t wa_link_get_qr(wa_ctx_t *ctx, char *qr_out, size_t qr_size);

/* Companion management */
wa_error_t wa_companion_list(wa_ctx_t *ctx, wa_companion_t **companions, int *count);
wa_error_t wa_companion_remove(wa_ctx_t *ctx, uint32_t device_id);
void wa_companion_free(wa_companion_t *companions, int count);

/* Main loop */
wa_error_t wa_process(wa_ctx_t *ctx, int timeout_ms);
wa_error_t wa_run(wa_ctx_t *ctx);
void wa_stop(wa_ctx_t *ctx);

/* Version management */
wa_error_t wa_version_get(wa_ctx_t *ctx, char *version, size_t size);
wa_error_t wa_version_update(wa_ctx_t *ctx);
wa_error_t wa_version_set(wa_ctx_t *ctx, const char *version);

/* Utility */
const char *wa_error_string(wa_error_t err);
const char *wa_state_string(wa_state_t state);

#endif /* WA_MINI_H */
