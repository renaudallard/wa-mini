/*
 * wa-mini - Fuzz harness for protobuf decoder
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "proto.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;

    /* Test handshake message decoding */
    proto_handshake_message_t handshake;
    memset(&handshake, 0, sizeof(handshake));

    if (proto_decode_handshake(data, size, &handshake) == 0) {
        /* Access decoded fields */
        if (handshake.has_server_hello) {
            (void)handshake.server_hello.ephemeral_len;
            (void)handshake.server_hello.static_len;
            (void)handshake.server_hello.payload_len;
        }
        if (handshake.has_client_hello) {
            (void)handshake.client_hello.ephemeral_len;
        }
        if (handshake.has_client_finish) {
            (void)handshake.client_finish.static_len;
        }

        proto_free_handshake(&handshake);
    }

    /* Test registration response decoding */
    proto_register_response_t response;
    memset(&response, 0, sizeof(response));

    if (proto_decode_register_response(data, size, &response) == 0) {
        (void)response.success;
        (void)response.retry_after;
        proto_free_register_response(&response);
    }

    return 0;
}
