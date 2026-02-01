/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Protobuf Encoder/Decoder
 *
 * Minimal protobuf wire format implementation without external library.
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "proto.h"

/* Protobuf wire types */
#define WIRE_VARINT  0
#define WIRE_64BIT   1
#define WIRE_BYTES   2
#define WIRE_32BIT   5

/* HandshakeMessage field numbers */
#define HANDSHAKE_CLIENT_HELLO  2
#define HANDSHAKE_SERVER_HELLO  3
#define HANDSHAKE_CLIENT_FINISH 4

/* ClientHello field numbers */
#define CLIENT_HELLO_EPHEMERAL           1
#define CLIENT_HELLO_STATIC              2
#define CLIENT_HELLO_PAYLOAD             3
#define CLIENT_HELLO_USE_EXTENDED        4
#define CLIENT_HELLO_EXTENDED_CIPHERTEXT 5

/* ServerHello field numbers */
#define SERVER_HELLO_EPHEMERAL       1
#define SERVER_HELLO_STATIC          2
#define SERVER_HELLO_PAYLOAD         3
#define SERVER_HELLO_EXTENDED_STATIC 4

/* ClientFinish field numbers */
#define CLIENT_FINISH_STATIC              1
#define CLIENT_FINISH_PAYLOAD             2
#define CLIENT_FINISH_EXTENDED_CIPHERTEXT 3

/* ClientPayload field numbers */
#define PAYLOAD_USERNAME       1   /* int64 - phone as number */
#define PAYLOAD_PASSIVE        3   /* bool */
#define PAYLOAD_USER_AGENT     5   /* message */
#define PAYLOAD_PUSH_NAME      7   /* string */
#define PAYLOAD_SESSION_ID     9   /* int32 */
#define PAYLOAD_SHORT_CONNECT  10  /* bool */
#define PAYLOAD_DEVICE_PAIRING 19  /* message - contains keys */

/* DevicePairingData field numbers */
#define PAIRING_REGID        1  /* bytes - registration ID */
#define PAIRING_KEYTYPE      2  /* bytes - key type (0x05) */
#define PAIRING_IDENTITY     3  /* bytes - identity public key */
#define PAIRING_SKEY_ID      4  /* bytes - signed prekey ID */
#define PAIRING_SKEY_VAL     5  /* bytes - signed prekey value */
#define PAIRING_SKEY_SIG     6  /* bytes - signed prekey signature */
#define PAIRING_BUILD_HASH   7  /* bytes */
#define PAIRING_DEVICE_PROPS 8  /* bytes */

/* UserAgent field numbers */
#define UA_PLATFORM        1  /* enum */
#define UA_APP_VERSION     2  /* message */
#define UA_OS_VERSION      5  /* string */
#define UA_MANUFACTURER    6  /* string */
#define UA_DEVICE          7  /* string */
#define UA_OS_BUILD_NUMBER 8  /* string */

/* AppVersion field numbers */
#define APP_VERSION_PRIMARY   1  /* uint32 */
#define APP_VERSION_SECONDARY 2  /* uint32 */
#define APP_VERSION_TERTIARY  3  /* uint32 */
#define APP_VERSION_QUATERNARY 4 /* uint32 */

/* Platform enum values */
#define PLATFORM_ANDROID 0

/*
 * Wire format helpers
 */

/* Write a varint to buffer, return bytes written */
static int write_varint(uint8_t *buf, uint64_t val)
{
    int pos = 0;
    while (val >= 0x80) {
        buf[pos++] = (uint8_t)(val | 0x80);
        val >>= 7;
    }
    buf[pos++] = (uint8_t)val;
    return pos;
}

/* Write a tag (field number + wire type) */
static int write_tag(uint8_t *buf, int field, int wire_type)
{
    uint64_t tag = ((uint64_t)field << 3) | (wire_type & 0x7);
    return write_varint(buf, tag);
}

/* Write bytes field (tag + length + data) */
static int write_bytes(uint8_t *buf, int field, const uint8_t *data, size_t len)
{
    int pos = 0;
    pos += write_tag(buf + pos, field, WIRE_BYTES);
    pos += write_varint(buf + pos, len);
    if (data != NULL && len > 0) {
        memcpy(buf + pos, data, len);
        pos += len;
    }
    return pos;
}

/* Write string field */
static int write_string(uint8_t *buf, int field, const char *str)
{
    if (str == NULL) return 0;
    return write_bytes(buf, field, (const uint8_t *)str, strlen(str));
}

/* Write uint32 as varint field */
static int write_uint32(uint8_t *buf, int field, uint32_t val)
{
    int pos = 0;
    pos += write_tag(buf + pos, field, WIRE_VARINT);
    pos += write_varint(buf + pos, val);
    return pos;
}

/* Write int64 as varint field */
static int write_int64(uint8_t *buf, int field, int64_t val)
{
    int pos = 0;
    pos += write_tag(buf + pos, field, WIRE_VARINT);
    pos += write_varint(buf + pos, (uint64_t)val);
    return pos;
}

/* Write bool as varint field */
static int write_bool(uint8_t *buf, int field, int val)
{
    int pos = 0;
    pos += write_tag(buf + pos, field, WIRE_VARINT);
    buf[pos++] = val ? 1 : 0;
    return pos;
}

/* Read a varint from buffer, return 0 on success, -1 on error */
static int read_varint(const uint8_t *buf, size_t len, uint64_t *val, size_t *consumed)
{
    uint64_t result = 0;
    size_t pos = 0;
    int shift = 0;

    while (pos < len) {
        uint8_t byte = buf[pos++];
        result |= (uint64_t)(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            *val = result;
            *consumed = pos;
            return 0;
        }
        shift += 7;
        if (shift >= 64) {
            return -1;  /* Varint too long */
        }
    }
    return -1;  /* Incomplete varint */
}

/* Read a tag, return 0 on success */
static int read_tag(const uint8_t *buf, size_t len, int *field, int *wire_type, size_t *consumed)
{
    uint64_t tag;
    size_t c;

    if (read_varint(buf, len, &tag, &c) != 0) {
        return -1;
    }

    *field = (int)(tag >> 3);
    *wire_type = (int)(tag & 0x7);
    *consumed = c;
    return 0;
}

/* Read bytes field value (after tag), return 0 on success */
static int read_bytes(const uint8_t *buf, size_t len, uint8_t **data, size_t *data_len, size_t *consumed)
{
    uint64_t field_len;
    size_t c;

    if (read_varint(buf, len, &field_len, &c) != 0) {
        return -1;
    }

    /* Check for overflow on 32-bit systems */
    if (field_len > SIZE_MAX) {
        return -1;  /* Length too large for platform */
    }

    /* Overflow-safe bounds check: ensure field_len fits in remaining buffer */
    if (c > len || field_len > len - c) {
        return -1;  /* Not enough data */
    }

    *data = (uint8_t *)(buf + c);
    *data_len = (size_t)field_len;
    *consumed = c + (size_t)field_len;
    return 0;
}

/* Skip a field based on wire type, return bytes consumed or -1 on error */
static int skip_field(const uint8_t *buf, size_t len, int wire_type)
{
    size_t consumed;
    uint64_t val;

    switch (wire_type) {
    case WIRE_VARINT:
        if (read_varint(buf, len, &val, &consumed) != 0) {
            return -1;
        }
        return (int)consumed;

    case WIRE_64BIT:
        if (len < 8) return -1;
        return 8;

    case WIRE_BYTES:
        if (read_varint(buf, len, &val, &consumed) != 0) {
            return -1;
        }
        if (consumed + val > len) return -1;
        return (int)(consumed + val);

    case WIRE_32BIT:
        if (len < 4) return -1;
        return 4;

    default:
        return -1;
    }
}

/*
 * Encode functions
 */

/* Encode ClientHello message */
int proto_encode_client_hello(const proto_client_hello_t *msg, uint8_t *out, size_t *out_len)
{
    int pos = 0;

    /* Field 1: ephemeral (bytes) */
    if (msg->ephemeral != NULL && msg->ephemeral_len > 0) {
        pos += write_bytes(out + pos, CLIENT_HELLO_EPHEMERAL,
                           msg->ephemeral, msg->ephemeral_len);
    }

    /* Field 2: static (bytes) - encrypted static key */
    if (msg->static_encrypted != NULL && msg->static_len > 0) {
        pos += write_bytes(out + pos, CLIENT_HELLO_STATIC,
                           msg->static_encrypted, msg->static_len);
    }

    /* Field 3: payload (bytes) - encrypted payload */
    if (msg->payload_encrypted != NULL && msg->payload_len > 0) {
        pos += write_bytes(out + pos, CLIENT_HELLO_PAYLOAD,
                           msg->payload_encrypted, msg->payload_len);
    }

    /* Field 4: use_extended (bool) */
    if (msg->use_extended) {
        pos += write_bool(out + pos, CLIENT_HELLO_USE_EXTENDED, 1);
    }

    /* Field 5: extended_ciphertext (bytes) */
    if (msg->extended_ciphertext != NULL && msg->extended_len > 0) {
        pos += write_bytes(out + pos, CLIENT_HELLO_EXTENDED_CIPHERTEXT,
                           msg->extended_ciphertext, msg->extended_len);
    }

    *out_len = (size_t)pos;
    return 0;
}

/* Encode ClientFinish message */
int proto_encode_client_finish(const proto_client_finish_t *msg, uint8_t *out, size_t *out_len)
{
    int pos = 0;

    /* Field 1: static (bytes) - encrypted static key */
    if (msg->static_encrypted != NULL && msg->static_len > 0) {
        pos += write_bytes(out + pos, CLIENT_FINISH_STATIC,
                           msg->static_encrypted, msg->static_len);
    }

    /* Field 2: payload (bytes) - encrypted payload */
    if (msg->payload_encrypted != NULL && msg->payload_len > 0) {
        pos += write_bytes(out + pos, CLIENT_FINISH_PAYLOAD,
                           msg->payload_encrypted, msg->payload_len);
    }

    /* Field 3: extended_ciphertext (bytes) */
    if (msg->extended_ciphertext != NULL && msg->extended_len > 0) {
        pos += write_bytes(out + pos, CLIENT_FINISH_EXTENDED_CIPHERTEXT,
                           msg->extended_ciphertext, msg->extended_len);
    }

    *out_len = (size_t)pos;
    return 0;
}

/* Encode HandshakeMessage wrapper */
int proto_encode_handshake(const proto_handshake_message_t *msg, uint8_t *out, size_t *out_len)
{
    int pos = 0;
    uint8_t inner[4096];
    size_t inner_len;

    if (msg->has_client_hello) {
        /* Encode ClientHello */
        if (proto_encode_client_hello(&msg->client_hello, inner, &inner_len) != 0) {
            return -1;
        }
        /* Write as nested message */
        pos += write_bytes(out + pos, HANDSHAKE_CLIENT_HELLO, inner, inner_len);
    }

    if (msg->has_client_finish) {
        /* Encode ClientFinish */
        if (proto_encode_client_finish(&msg->client_finish, inner, &inner_len) != 0) {
            return -1;
        }
        /* Write as nested message */
        pos += write_bytes(out + pos, HANDSHAKE_CLIENT_FINISH, inner, inner_len);
    }

    *out_len = (size_t)pos;
    return 0;
}

/* Encode AppVersion message */
static int encode_app_version(const proto_app_version_t *ver, uint8_t *out, size_t *out_len)
{
    int pos = 0;

    pos += write_uint32(out + pos, APP_VERSION_PRIMARY, ver->primary);
    pos += write_uint32(out + pos, APP_VERSION_SECONDARY, ver->secondary);
    pos += write_uint32(out + pos, APP_VERSION_TERTIARY, ver->tertiary);
    if (ver->quaternary > 0) {
        pos += write_uint32(out + pos, APP_VERSION_QUATERNARY, ver->quaternary);
    }

    *out_len = (size_t)pos;
    return 0;
}

/* Encode UserAgent message */
static int encode_user_agent(const proto_client_payload_t *msg, uint8_t *out, size_t *out_len)
{
    int pos = 0;
    uint8_t nested[64];
    size_t nested_len;

    /* Field 1: platform (enum) */
    pos += write_uint32(out + pos, UA_PLATFORM, msg->platform_type);

    /* Field 2: app_version (nested message) */
    if (msg->has_app_version) {
        if (encode_app_version(&msg->app_version, nested, &nested_len) == 0) {
            pos += write_bytes(out + pos, UA_APP_VERSION, nested, nested_len);
        }
    }

    /* Field 5: os_version (string) */
    if (msg->os_version != NULL) {
        pos += write_string(out + pos, UA_OS_VERSION, msg->os_version);
    }

    /* Field 6: manufacturer (string) */
    if (msg->manufacturer != NULL) {
        pos += write_string(out + pos, UA_MANUFACTURER, msg->manufacturer);
    }

    /* Field 7: device (string) */
    if (msg->device_model != NULL) {
        pos += write_string(out + pos, UA_DEVICE, msg->device_model);
    }

    /* Field 8: os_build_number (string) */
    if (msg->os_build_number != NULL) {
        pos += write_string(out + pos, UA_OS_BUILD_NUMBER, msg->os_build_number);
    }

    *out_len = (size_t)pos;
    return 0;
}

/* Encode DevicePairingData message */
static int encode_device_pairing(const proto_device_pairing_t *dp, uint8_t *out, size_t *out_len)
{
    int pos = 0;

    /* Field 1: registration_id (bytes - 4 bytes big endian) */
    pos += write_bytes(out + pos, PAIRING_REGID, dp->registration_id, 4);

    /* Field 2: key_type (bytes - single byte 0x05) */
    pos += write_bytes(out + pos, PAIRING_KEYTYPE, &dp->key_type, 1);

    /* Field 3: identity public key (bytes - 32 bytes) */
    pos += write_bytes(out + pos, PAIRING_IDENTITY, dp->identity_pub, 32);

    /* Field 4: signed prekey ID (bytes - 4 bytes big endian) */
    pos += write_bytes(out + pos, PAIRING_SKEY_ID, dp->signed_prekey_id, 4);

    /* Field 5: signed prekey public (bytes - 32 bytes) */
    pos += write_bytes(out + pos, PAIRING_SKEY_VAL, dp->signed_prekey_pub, 32);

    /* Field 6: signed prekey signature (bytes - 64 bytes) */
    pos += write_bytes(out + pos, PAIRING_SKEY_SIG, dp->signed_prekey_sig, 64);

    *out_len = (size_t)pos;
    return 0;
}

/* Encode ClientPayload message */
int proto_encode_client_payload(const proto_client_payload_t *msg, uint8_t *out, size_t *out_len)
{
    int pos = 0;
    uint8_t nested[1024];
    size_t nested_len;

    /* Field 1: username (uint64 - phone number as int) */
    if (msg->username > 0) {
        pos += write_int64(out + pos, PAYLOAD_USERNAME, (int64_t)msg->username);
    }

    /* Field 3: passive (bool) */
    if (msg->has_passive) {
        pos += write_bool(out + pos, PAYLOAD_PASSIVE, msg->passive);
    }

    /* Field 5: user_agent (nested message) */
    if (encode_user_agent(msg, nested, &nested_len) == 0 && nested_len > 0) {
        pos += write_bytes(out + pos, PAYLOAD_USER_AGENT, nested, nested_len);
    }

    /* Field 7: push_name (string) */
    if (msg->push_name != NULL && msg->push_name_len > 0) {
        pos += write_bytes(out + pos, PAYLOAD_PUSH_NAME, msg->push_name, msg->push_name_len);
    }

    /* Field 9: session_id (int32) */
    if (msg->has_session_id) {
        pos += write_uint32(out + pos, PAYLOAD_SESSION_ID, msg->session_id);
    }

    /* Field 10: short_connect (bool) */
    if (msg->has_short_connect) {
        pos += write_bool(out + pos, PAYLOAD_SHORT_CONNECT, msg->short_connect);
    }

    /* Field 19: device_pairing (nested message - Signal keys) */
    if (msg->has_device_pairing) {
        if (encode_device_pairing(&msg->device_pairing, nested, &nested_len) == 0) {
            pos += write_bytes(out + pos, PAYLOAD_DEVICE_PAIRING, nested, nested_len);
        }
    }

    *out_len = (size_t)pos;
    return 0;
}

/* Encode identity keys for device pairing */
int proto_encode_identity(const proto_identity_t *id, uint8_t *out, size_t *out_len)
{
    int pos = 0;

    /* Field 1: registration_id as bytes (4 bytes big endian) */
    uint8_t regid_bytes[4];
    regid_bytes[0] = (id->registration_id >> 24) & 0xFF;
    regid_bytes[1] = (id->registration_id >> 16) & 0xFF;
    regid_bytes[2] = (id->registration_id >> 8) & 0xFF;
    regid_bytes[3] = id->registration_id & 0xFF;
    pos += write_bytes(out + pos, PAIRING_REGID, regid_bytes, 4);

    /* Field 2: key_type (0x05 = DJB type) */
    uint8_t key_type = 0x05;
    pos += write_bytes(out + pos, PAIRING_KEYTYPE, &key_type, 1);

    /* Field 3: identity public key (32 bytes) */
    pos += write_bytes(out + pos, PAIRING_IDENTITY, id->identity_pub, 32);

    /* Field 4: signed prekey ID as bytes (4 bytes big endian) */
    uint8_t skey_id_bytes[4];
    skey_id_bytes[0] = (id->signed_prekey_id >> 24) & 0xFF;
    skey_id_bytes[1] = (id->signed_prekey_id >> 16) & 0xFF;
    skey_id_bytes[2] = (id->signed_prekey_id >> 8) & 0xFF;
    skey_id_bytes[3] = id->signed_prekey_id & 0xFF;
    pos += write_bytes(out + pos, PAIRING_SKEY_ID, skey_id_bytes, 4);

    /* Field 5: signed prekey public (32 bytes) */
    pos += write_bytes(out + pos, PAIRING_SKEY_VAL, id->signed_prekey_pub, 32);

    /* Field 6: signed prekey signature (64 bytes) */
    pos += write_bytes(out + pos, PAIRING_SKEY_SIG, id->signed_prekey_sig, 64);

    *out_len = (size_t)pos;
    return 0;
}

/*
 * Decode functions
 */

/* Decode ServerHello message */
int proto_decode_server_hello(const uint8_t *data, size_t len, proto_server_hello_t *msg)
{
    size_t pos = 0;

    memset(msg, 0, sizeof(*msg));

    while (pos < len) {
        int field, wire_type;
        size_t consumed;

        if (read_tag(data + pos, len - pos, &field, &wire_type, &consumed) != 0) {
            return -1;
        }
        pos += consumed;

        switch (field) {
        case SERVER_HELLO_EPHEMERAL:
            if (wire_type != WIRE_BYTES) return -1;
            if (read_bytes(data + pos, len - pos, &msg->ephemeral, &msg->ephemeral_len, &consumed) != 0) {
                return -1;
            }
            pos += consumed;
            break;

        case SERVER_HELLO_STATIC:
            if (wire_type != WIRE_BYTES) return -1;
            if (read_bytes(data + pos, len - pos, &msg->static_encrypted, &msg->static_len, &consumed) != 0) {
                return -1;
            }
            pos += consumed;
            break;

        case SERVER_HELLO_PAYLOAD:
            if (wire_type != WIRE_BYTES) return -1;
            if (read_bytes(data + pos, len - pos, &msg->payload_encrypted, &msg->payload_len, &consumed) != 0) {
                return -1;
            }
            pos += consumed;
            break;

        case SERVER_HELLO_EXTENDED_STATIC:
            if (wire_type != WIRE_BYTES) return -1;
            if (read_bytes(data + pos, len - pos, &msg->extended_static, &msg->extended_static_len, &consumed) != 0) {
                return -1;
            }
            pos += consumed;
            break;

        default:
            /* Skip unknown field */
            {
                int skip = skip_field(data + pos, len - pos, wire_type);
                if (skip < 0) return -1;
                pos += (size_t)skip;
            }
            break;
        }
    }

    return 0;
}

/* Decode HandshakeMessage wrapper */
int proto_decode_handshake(const uint8_t *data, size_t len, proto_handshake_message_t *msg)
{
    size_t pos = 0;

    memset(msg, 0, sizeof(*msg));

    while (pos < len) {
        int field, wire_type;
        size_t consumed;

        if (read_tag(data + pos, len - pos, &field, &wire_type, &consumed) != 0) {
            return -1;
        }
        pos += consumed;

        switch (field) {
        case HANDSHAKE_SERVER_HELLO:
            if (wire_type != WIRE_BYTES) return -1;
            {
                uint8_t *inner_data;
                size_t inner_len;
                if (read_bytes(data + pos, len - pos, &inner_data, &inner_len, &consumed) != 0) {
                    return -1;
                }
                pos += consumed;

                if (proto_decode_server_hello(inner_data, inner_len, &msg->server_hello) != 0) {
                    return -1;
                }
                msg->has_server_hello = 1;
            }
            break;

        default:
            /* Skip unknown field */
            {
                int skip = skip_field(data + pos, len - pos, wire_type);
                if (skip < 0) return -1;
                pos += (size_t)skip;
            }
            break;
        }
    }

    return 0;
}

/* Decode registration response (simplified) */
int proto_decode_register_response(const uint8_t *data, size_t len, proto_register_response_t *msg)
{
    /* Registration response decoding is done via HTTP JSON, not protobuf */
    /* This is a placeholder for future protobuf-based registration */
    (void)data;
    (void)len;
    memset(msg, 0, sizeof(*msg));
    return 0;
}

/*
 * Free functions
 */

/* Free handshake message (pointers point into original buffer, no alloc) */
void proto_free_handshake(proto_handshake_message_t *msg)
{
    /* All pointers point into the original buffer passed to decode,
     * so we don't need to free them. Just zero the structure. */
    memset(msg, 0, sizeof(*msg));
}

/* Free client payload */
void proto_free_client_payload(proto_client_payload_t *msg)
{
    free(msg->os_version);
    free(msg->manufacturer);
    free(msg->device_model);
    free(msg->os_build_number);
    memset(msg, 0, sizeof(*msg));
}

/* Free register response */
void proto_free_register_response(proto_register_response_t *msg)
{
    free(msg->error_code);
    free(msg->error_reason);
    memset(msg, 0, sizeof(*msg));
}
