/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Companion Device Linking
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
#include "xmpp.h"

/* Link code alphabet (excludes confusing chars: 0,O,1,I,L) */
static const char LINK_ALPHABET[] = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
#define LINK_ALPHABET_SIZE 31

/* Link code context */
typedef struct {
    char code[9];                   /* XXXXXXXX (displayed as XXXX-XXXX) */
    uint8_t ephemeral_priv[32];
    uint8_t ephemeral_pub[32];
    uint8_t derived_key[32];        /* From PBKDF2 of link code */
    char ref[64];                   /* Reference ID */
    time_t created_at;
    int active;
} link_ctx_t;

/* External crypto functions */
extern void crypto_random(uint8_t *buf, size_t len);
extern int crypto_keypair_generate(uint8_t *priv, uint8_t *pub);

/*
 * Generate random link code (8 chars from restricted alphabet)
 */
static void generate_link_code(char *code)
{
    uint8_t random[8];
    crypto_random(random, 8);

    for (int i = 0; i < 8; i++) {
        code[i] = LINK_ALPHABET[random[i] % LINK_ALPHABET_SIZE];
    }
    code[8] = '\0';
}

/*
 * Derive key from link code using PBKDF2
 */
static int derive_key_from_code(const char *code, uint8_t *key)
{
    /* Use link code as password, empty salt, 2048 iterations */
    /* WhatsApp uses specific parameters - simplified here */
    if (crypto_pwhash(key, 32,
                      code, strlen(code),
                      (const uint8_t *)"WhatsApp", /* Salt */
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Generate reference ID
 */
static void generate_ref(char *ref, size_t size)
{
    uint8_t random[16];
    crypto_random(random, 16);

    for (size_t i = 0; i < 16 && i * 2 + 1 < size; i++) {
        snprintf(ref + i * 2, 3, "%02x", random[i]);
    }
}

/*
 * Initialize link context
 */
int link_ctx_init(link_ctx_t *ctx)
{
    sodium_memzero(ctx, sizeof(*ctx));

    /* Generate link code */
    generate_link_code(ctx->code);

    /* Generate ephemeral keypair */
    if (crypto_keypair_generate(ctx->ephemeral_priv, ctx->ephemeral_pub) != 0) {
        return -1;
    }

    /* Derive key from code */
    if (derive_key_from_code(ctx->code, ctx->derived_key) != 0) {
        sodium_memzero(ctx->ephemeral_priv, 32);
        return -1;
    }

    /* Generate reference */
    generate_ref(ctx->ref, sizeof(ctx->ref));

    ctx->created_at = time(NULL);
    ctx->active = 1;

    return 0;
}

/*
 * Get formatted link code (XXXX-XXXX)
 */
void link_get_formatted_code(const link_ctx_t *ctx, char *out, size_t size)
{
    if (size >= 10) {
        snprintf(out, size, "%.4s-%.4s", ctx->code, ctx->code + 4);
    }
}

/*
 * Build pair-device IQ stanza for link code advertisement
 */
static xmpp_node_t *build_pair_device_iq(const link_ctx_t *ctx)
{
    char id[32];
    snprintf(id, sizeof(id), "%ld.link", (long)time(NULL));

    xmpp_node_t *iq = xmpp_node_new("iq");
    if (!iq) return NULL;

    xmpp_node_set_attr(iq, "type", "set");
    xmpp_node_set_attr(iq, "id", id);
    xmpp_node_set_attr(iq, "xmlns", "md");

    xmpp_node_t *pair = xmpp_node_new("pair-device");
    if (!pair) { xmpp_node_free(iq); return NULL; }

    xmpp_node_set_attr(pair, "ref", ctx->ref);

    /* Add ephemeral public key */
    xmpp_node_t *ekey = xmpp_node_new("ephemeral_key");
    if (ekey) {
        xmpp_node_set_content(ekey, ctx->ephemeral_pub, 32);
        xmpp_node_add_child(pair, ekey);
        free(ekey);
    }

    xmpp_node_add_child(iq, pair);
    free(pair);

    return iq;
}

/*
 * Simple QR code generation using Unicode block characters
 * Generates ASCII art QR code for terminal display
 */
static void print_qr_code(const char *data)
{
    /* Simplified: just show the data in a box for now */
    /* Full implementation would use qrencode algorithm */

    size_t len = strlen(data);
    size_t width = len + 4;

    /* Top border */
    printf("\n  ");
    for (size_t i = 0; i < width; i++) printf("█");
    printf("\n");

    /* Data row with padding */
    printf("  ██");
    for (size_t i = 0; i < len; i++) printf(" ");
    printf("██\n");

    printf("  ██ %s ██\n", data);

    printf("  ██");
    for (size_t i = 0; i < len; i++) printf(" ");
    printf("██\n");

    /* Bottom border */
    printf("  ");
    for (size_t i = 0; i < width; i++) printf("█");
    printf("\n\n");
}

/*
 * Display link code for companion pairing
 */
int wa_link_display(const char *phone)
{
    link_ctx_t ctx;

    printf("Generating link code for companion device...\n\n");

    if (link_ctx_init(&ctx) != 0) {
        fprintf(stderr, "Error: Failed to generate link code\n");
        return -1;
    }

    char formatted[16];
    link_get_formatted_code(&ctx, formatted, sizeof(formatted));

    printf("Link Code: %s\n", formatted);
    printf("Reference: %s\n", ctx.ref);
    printf("Account: %s\n\n", phone ? phone : "(pending)");

    /* Build and show the IQ stanza */
    xmpp_node_t *iq = build_pair_device_iq(&ctx);
    if (iq) {
        printf("Pair-device stanza:\n");
        xmpp_node_dump(iq, 0);
        xmpp_node_free(iq);
    }

    /* Show QR-style display */
    printf("\nScan this code or enter manually in WhatsApp Web/Desktop:\n");
    print_qr_code(formatted);

    printf("Waiting for companion device to connect...\n");
    printf("(Press Ctrl+C to cancel)\n\n");

    /* In real implementation: wait for companion_hello message */
    /* Then exchange keys and establish session */

    /* Clean up sensitive data */
    sodium_memzero(&ctx, sizeof(ctx));

    return 0;
}

/*
 * Handle incoming companion hello (called when companion scans code)
 */
int link_handle_companion_hello(link_ctx_t *ctx,
                                const uint8_t *wrapped_ephemeral,
                                size_t wrapped_len,
                                const uint8_t *nonce,
                                const char *ref)
{
    if (!ctx->active || strcmp(ctx->ref, ref) != 0) {
        return -1;  /* Invalid or expired link */
    }

    /* Decrypt companion's ephemeral key using derived key */
    uint8_t companion_ephemeral[32];

    if (crypto_secretbox_open_easy(companion_ephemeral,
                                   wrapped_ephemeral, wrapped_len,
                                   nonce, ctx->derived_key) != 0) {
        return -1;  /* Decryption failed - wrong code? */
    }

    /* Would continue with key exchange here */
    printf("Companion connected! Ephemeral key received.\n");

    (void)companion_ephemeral;  /* Would use for DH */
    return 0;
}

/*
 * Clear link context
 */
void link_ctx_clear(link_ctx_t *ctx)
{
    sodium_memzero(ctx, sizeof(*ctx));
}
