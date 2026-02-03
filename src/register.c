/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Account Unregistration
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 *
 * NOTE: Registration is not supported due to WhatsApp's Android Keystore
 * Attestation requirement. Use tools/extract_credentials.py to import
 * credentials from a rooted Android device.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wa-mini.h"
#include "xmpp.h"

/* External functions */
extern wa_error_t wa_connect(wa_ctx_t *ctx, const char *phone);
extern wa_error_t wa_disconnect(wa_ctx_t *ctx);
extern wa_error_t wa_send_iq(wa_ctx_t *ctx, xmpp_node_t *iq, xmpp_node_t **response);

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
