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

#include "wa-mini.h"
#include "xmpp.h"
#include "noise.h"

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
 * Build code request IQ stanza
 * Requests SMS or voice verification code
 */
static xmpp_node_t *build_code_request(const reg_ctx_t *reg)
{
    /* Build IQ stanza:
     * <iq type="set" xmlns="urn:xmpp:whatsapp:account">
     *   <code_request>
     *     <method>sms</method>
     *     <phone_number_with_cc>+15551234567</phone_number_with_cc>
     *     <lg>en</lg>
     *     <lc>US</lc>
     *   </code_request>
     * </iq>
     */

    char id[32];
    snprintf(id, sizeof(id), "%ld.1", (long)time(NULL));

    xmpp_node_t *iq = xmpp_node_new("iq");
    if (iq == NULL) return NULL;

    xmpp_node_set_attr(iq, "type", "set");
    xmpp_node_set_attr(iq, "id", id);
    xmpp_node_set_attr(iq, "xmlns", "urn:xmpp:whatsapp:account");

    xmpp_node_t *code_request = xmpp_node_new("code_request");
    if (code_request == NULL) {
        xmpp_node_free(iq);
        return NULL;
    }

    /* Method */
    xmpp_node_t *method = xmpp_node_new("method");
    if (method) {
        xmpp_node_set_text(method, reg->method);
        xmpp_node_add_child(code_request, method);
        free(method);
    }

    /* Phone number */
    xmpp_node_t *phone = xmpp_node_new("phone_number_with_cc");
    if (phone) {
        xmpp_node_set_text(phone, reg->phone);
        xmpp_node_add_child(code_request, phone);
        free(phone);
    }

    /* Language */
    xmpp_node_t *lg = xmpp_node_new("lg");
    if (lg) {
        xmpp_node_set_text(lg, reg->lg);
        xmpp_node_add_child(code_request, lg);
        free(lg);
    }

    /* Locale */
    xmpp_node_t *lc = xmpp_node_new("lc");
    if (lc) {
        xmpp_node_set_text(lc, reg->lc);
        xmpp_node_add_child(code_request, lc);
        free(lc);
    }

    xmpp_node_add_child(iq, code_request);
    free(code_request);

    return iq;
}

/*
 * Build code verification IQ stanza
 */
static xmpp_node_t *build_code_verify(const reg_ctx_t *reg, const char *code)
{
    /* Build IQ stanza:
     * <iq type="set" xmlns="urn:xmpp:whatsapp:account">
     *   <verify>
     *     <code>123456</code>
     *   </verify>
     * </iq>
     */

    char id[32];
    snprintf(id, sizeof(id), "%ld.2", (long)time(NULL));

    xmpp_node_t *iq = xmpp_node_new("iq");
    if (iq == NULL) return NULL;

    xmpp_node_set_attr(iq, "type", "set");
    xmpp_node_set_attr(iq, "id", id);
    xmpp_node_set_attr(iq, "xmlns", "urn:xmpp:whatsapp:account");

    xmpp_node_t *verify = xmpp_node_new("verify");
    if (verify == NULL) {
        xmpp_node_free(iq);
        return NULL;
    }

    xmpp_node_t *code_node = xmpp_node_new("code");
    if (code_node) {
        xmpp_node_set_text(code_node, code);
        xmpp_node_add_child(verify, code_node);
        free(code_node);
    }

    (void)reg;  /* May be used for additional fields in future */

    xmpp_node_add_child(iq, verify);
    free(verify);

    return iq;
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
 * This would be called after establishing a Noise connection
 */
int wa_register_request_code(void *ctx_ptr, reg_ctx_t *reg)
{
    /* In full implementation, this would:
     * 1. Encode the code request as binary XMPP
     * 2. Encrypt with Noise session
     * 3. Send to WhatsApp server
     * 4. Wait for response
     */

    (void)ctx_ptr;

    /* Build code request */
    xmpp_node_t *request = build_code_request(reg);
    if (request == NULL) {
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "Failed to build code request",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Debug: print the request */
    printf("Code request stanza:\n");
    xmpp_node_dump(request, 0);

    /* Encode to binary */
    uint8_t encoded[4096];
    size_t encoded_len;

    if (xmpp_encode(request, encoded, &encoded_len) != 0) {
        xmpp_node_free(request);
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "Failed to encode code request",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    printf("Encoded length: %zu bytes\n", encoded_len);

    xmpp_node_free(request);

    /* TODO: Send via Noise-encrypted connection */
    /* TODO: Wait for and parse response */

    reg->state = REG_STATE_CODE_REQUESTED;
    return 0;
}

/*
 * Submit verification code
 */
int wa_register_submit_code(void *ctx_ptr, reg_ctx_t *reg, const char *code)
{
    if (reg->state != REG_STATE_CODE_REQUESTED) {
        strncpy(reg->error_reason, "Code not requested yet",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Validate code format (6 digits) */
    if (code == NULL || strlen(code) != 6) {
        strncpy(reg->error_reason, "Invalid code format",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        if (!isdigit((unsigned char)code[i])) {
            strncpy(reg->error_reason, "Code must be numeric",
                    sizeof(reg->error_reason) - 1);
            reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
            return -1;
        }
    }

    (void)ctx_ptr;

    /* Build verify request */
    xmpp_node_t *request = build_code_verify(reg, code);
    if (request == NULL) {
        reg->state = REG_STATE_ERROR;
        strncpy(reg->error_reason, "Failed to build verify request",
                sizeof(reg->error_reason) - 1);
        reg->error_reason[sizeof(reg->error_reason) - 1] = '\0';
        return -1;
    }

    /* Debug: print the request */
    printf("Verify request stanza:\n");
    xmpp_node_dump(request, 0);

    xmpp_node_free(request);

    /* TODO: Send via Noise-encrypted connection */
    /* TODO: Wait for and parse response */

    reg->state = REG_STATE_CODE_SENT;
    return 0;
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

    printf("Starting registration for %s...\n", phone);

    /* Initialize registration context */
    if (wa_register_init(&reg, phone, method) != 0) {
        fprintf(stderr, "Error: Invalid phone number format\n");
        return -1;
    }

    printf("Country code: %s\n", reg.country_code);
    printf("National number: %s\n", reg.national_number);
    printf("Method: %s\n", reg.method);
    printf("Language: %s, Locale: %s\n", reg.lg, reg.lc);

    /* TODO: Connect to WhatsApp and perform handshake */
    /* TODO: Request verification code */

    /* For now, just demonstrate the stanza building */
    printf("\n--- Building registration stanzas ---\n\n");

    if (wa_register_request_code(NULL, &reg) != 0) {
        fprintf(stderr, "Error: %s\n", wa_register_get_error(&reg));
        return -1;
    }

    printf("\nRegistration code request would be sent to WhatsApp.\n");
    printf("Once you receive the SMS code, run:\n");
    printf("  wa-mini verify <code>\n");

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

    printf("Submitting verification code: %s for %s\n", code, phone);

    /* In real implementation, we would load pending registration state */
    /* For now, simulate the flow by initializing with phone */

    if (wa_register_init(&reg, phone, "sms") != 0) {
        fprintf(stderr, "Error: Invalid phone number\n");
        return -1;
    }

    reg.state = REG_STATE_CODE_REQUESTED;  /* Assume code was requested */

    if (wa_register_submit_code(NULL, &reg, code) != 0) {
        fprintf(stderr, "Error: %s\n", wa_register_get_error(&reg));
        return -1;
    }

    /* Simulate successful verification */
    reg.state = REG_STATE_VERIFIED;

    /* Generate and upload keys */
    printf("\n--- Generating Signal keys ---\n\n");

    if (wa_register_upload_keys(NULL, &reg, account) != 0) {
        fprintf(stderr, "Error: %s\n", wa_register_get_error(&reg));
        return -1;
    }

    printf("\nRegistration complete!\n");
    printf("Registration ID: %u\n", account->registration_id);

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
