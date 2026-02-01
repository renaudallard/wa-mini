/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Dictionary Operations
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dict.h"

/*
 * Find token for a given string
 * Returns 0 on success, -1 if not found
 * out_token receives the primary token or secondary index
 * out_secondary receives 0xFF if primary, or secondary table index (0-3) if secondary
 */
int dict_find_token(const char *str, uint8_t *out_token, uint8_t *out_secondary)
{
    if (str == NULL) {
        return -1;
    }

    /* Search primary dictionary */
    for (size_t i = 0; i < DICT_PRIMARY_SIZE; i++) {
        if (dict_primary[i] != NULL && strcmp(dict_primary[i], str) == 0) {
            *out_token = (uint8_t)i;
            *out_secondary = 0xFF;  /* Indicates primary */
            return 0;
        }
    }

    /* Search secondary dictionaries */
    for (size_t table = 0; table < DICT_SECONDARY_TABLES; table++) {
        for (size_t i = 0; i < dict_secondary_sizes[table]; i++) {
            if (dict_secondary[table][i] != NULL &&
                strcmp(dict_secondary[table][i], str) == 0) {
                *out_token = (uint8_t)i;
                *out_secondary = (uint8_t)table;
                return 0;
            }
        }
    }

    return -1;
}

/*
 * Encode a string token
 * Returns number of bytes written, or -1 on error
 */
int dict_encode_token(const char *str, uint8_t *out, size_t out_size)
{
    uint8_t token, secondary;

    if (dict_find_token(str, &token, &secondary) == 0) {
        if (secondary == 0xFF) {
            /* Primary token - single byte */
            if (out_size < 1) return -1;
            out[0] = token;
            return 1;
        } else {
            /* Secondary token - two bytes */
            if (out_size < 2) return -1;
            out[0] = DICT_SECONDARY_BASE + secondary;
            out[1] = token;
            return 2;
        }
    }

    /* Not in dictionary - encode as raw string */
    size_t len = strlen(str);

    if (len <= 0xFF) {
        /* 8-bit length string */
        if (out_size < 2 + len) return -1;
        out[0] = DICT_BINARY_8;
        out[1] = (uint8_t)len;
        memcpy(out + 2, str, len);
        return 2 + len;
    } else if (len <= 0xFFFFF) {
        /* 20-bit length string (3 bytes for length) */
        if (out_size < 4 + len) return -1;
        out[0] = DICT_BINARY_20;
        out[1] = (len >> 16) & 0x0F;   /* bits 19-16 */
        out[2] = (len >> 8) & 0xFF;    /* bits 15-8 */
        out[3] = len & 0xFF;           /* bits 7-0 */
        memcpy(out + 4, str, len);
        return 4 + len;
    }

    return -1;
}

/*
 * Decode a string token
 * Returns the string (from dictionary or newly allocated), or NULL on error
 * Sets *consumed to number of bytes consumed
 * If returned string is not from dictionary, caller must free it
 */
const char *dict_decode_token(const uint8_t *data, size_t len, size_t *consumed,
                              int *needs_free)
{
    if (len == 0) {
        return NULL;
    }

    *needs_free = 0;
    uint8_t byte = data[0];

    /* Check for secondary dictionary prefix */
    if (byte >= DICT_SECONDARY_BASE && byte < DICT_SECONDARY_BASE + DICT_SECONDARY_TABLES) {
        if (len < 2) return NULL;
        uint8_t table = byte - DICT_SECONDARY_BASE;
        uint8_t index = data[1];
        *consumed = 2;
        return dict_lookup_secondary(table, index);
    }

    /* Check for special encodings */
    switch (byte) {
    case DICT_BINARY_8:
        if (len < 2) return NULL;
        {
            size_t slen = data[1];
            if (len < 2 + slen) return NULL;
            char *str = malloc(slen + 1);
            if (str == NULL) return NULL;
            memcpy(str, data + 2, slen);
            str[slen] = '\0';
            *consumed = 2 + slen;
            *needs_free = 1;
            return str;
        }

    case DICT_BINARY_20:
        if (len < 4) return NULL;
        {
            size_t slen = ((size_t)(data[1] & 0x0F) << 16) |
                          ((size_t)data[2] << 8) | data[3];
            if (len < 4 + slen) return NULL;
            char *str = malloc(slen + 1);
            if (str == NULL) return NULL;
            memcpy(str, data + 4, slen);
            str[slen] = '\0';
            *consumed = 4 + slen;
            *needs_free = 1;
            return str;
        }

    case DICT_BINARY_32:
        if (len < 5) return NULL;
        {
            size_t slen = ((size_t)data[1] << 24) | ((size_t)data[2] << 16) |
                         ((size_t)data[3] << 8) | data[4];
            if (len < 5 + slen) return NULL;
            char *str = malloc(slen + 1);
            if (str == NULL) return NULL;
            memcpy(str, data + 5, slen);
            str[slen] = '\0';
            *consumed = 5 + slen;
            *needs_free = 1;
            return str;
        }

    case DICT_NIBBLE_8:
        /* Packed nibble encoding - each nibble is a digit or separator */
        if (len < 2) return NULL;
        {
            size_t nibbles = data[1];
            size_t bytes = (nibbles + 1) / 2;
            if (len < 2 + bytes) return NULL;

            char *str = malloc(nibbles + 1);
            if (str == NULL) return NULL;

            for (size_t i = 0; i < nibbles; i++) {
                uint8_t nibble = (i % 2 == 0) ?
                    (data[2 + i/2] >> 4) : (data[2 + i/2] & 0x0F);

                if (nibble < 10) {
                    str[i] = '0' + nibble;
                } else if (nibble == 10) {
                    str[i] = '-';
                } else if (nibble == 11) {
                    str[i] = '.';
                } else if (nibble == 15) {
                    /* Padding, end of string */
                    str[i] = '\0';
                    break;
                } else {
                    str[i] = '?';
                }
            }
            str[nibbles] = '\0';
            *consumed = 2 + bytes;
            *needs_free = 1;
            return str;
        }

    case DICT_HEX_8:
        /* Packed hex encoding */
        if (len < 2) return NULL;
        {
            size_t nibbles = data[1];
            size_t bytes = (nibbles + 1) / 2;
            if (len < 2 + bytes) return NULL;

            char *str = malloc(nibbles + 1);
            if (str == NULL) return NULL;

            for (size_t i = 0; i < nibbles; i++) {
                uint8_t nibble = (i % 2 == 0) ?
                    (data[2 + i/2] >> 4) : (data[2 + i/2] & 0x0F);

                if (nibble < 10) {
                    str[i] = '0' + nibble;
                } else {
                    str[i] = 'A' + (nibble - 10);
                }
            }
            str[nibbles] = '\0';
            *consumed = 2 + bytes;
            *needs_free = 1;
            return str;
        }

    default:
        /* Primary dictionary lookup */
        *consumed = 1;
        return dict_lookup_primary(byte);
    }
}
