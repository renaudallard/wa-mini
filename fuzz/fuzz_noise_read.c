/*
 * wa-mini - Fuzz harness for Noise protocol message reading
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "noise.h"

/* Fixed test keypair for reproducibility */
static const uint8_t test_priv[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 32) return 0;  /* Need at least ephemeral key size */

    noise_handshake_t hs;
    noise_keypair_t static_key;
    uint8_t payload[65536];
    size_t payload_len = 0;

    memset(&hs, 0, sizeof(hs));
    memset(&static_key, 0, sizeof(static_key));

    /* Use fixed private key */
    memcpy(static_key.priv, test_priv, 32);
    noise_compute_public(static_key.priv, static_key.pub);

    /* Initialize handshake */
    if (noise_handshake_init(&hs, &static_key) != 0) {
        return 0;
    }

    /* Write initial message to advance state */
    uint8_t initial_msg[128];
    size_t initial_len = 0;
    if (noise_write_message(&hs, NULL, 0, initial_msg, &initial_len) != 0) {
        noise_handshake_clear(&hs);
        return 0;
    }

    /* Now try to read fuzzed server response */
    (void)noise_read_message(&hs, data, size, payload, &payload_len);

    /* Clean up */
    noise_handshake_clear(&hs);

    return 0;
}
